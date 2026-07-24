//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Parallel block scanning engine and multi-pattern signature search
//!

use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
use latent_source::Source;
use rayon::prelude::*;

use crate::error::ScanError;

/// 64 KiB: the size of an EVTX chunk, and the smallest overlap that guarantees
/// a full chunk-sized structure straddling a block boundary is never split.
pub const EVTX_CHUNK: usize = 64 * 1024;

/// Default primary block size handed to each worker (8 MiB). Large enough that
/// the overlap re-scan overhead stays near 1 %, small enough to keep many
/// blocks in flight under a few-GiB budget.
pub const DEFAULT_BLOCK_SIZE: usize = 8 * 1024 * 1024;

/// Default in-flight memory budget (4 GiB), enforced by capping the number of
/// concurrent block buffers.
pub const DEFAULT_MEMORY_BUDGET: u64 = 4 * 1024 * 1024 * 1024;

/// A block can never shrink below this, so the budget is never honoured by
/// reading one byte at a time.
const MIN_BLOCK_SIZE: usize = 4 * 1024;

/// A signature match located in the source.
///
/// Ordered by absolute `offset` first, then by `pattern_id`, which is the order
/// the engine reports hits in and the order downstream code can rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hit {
    /// Absolute byte offset of the match start within the source.
    pub offset: u64,
    /// Index of the matched pattern in the pattern set passed to [`Scanner::new`].
    pub pattern_id: usize,
}

/// Tunables for a scan. Every field has a documented default; see
/// [`ScanConfig::default`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanConfig {
    /// Size of the primary region each worker owns, in bytes.
    /// Default: [`DEFAULT_BLOCK_SIZE`] (8 MiB).
    pub block_size: usize,
    /// Bytes of the following block each worker also reads, so a structure that
    /// crosses a boundary is fully present in one buffer. Must be at least the
    /// longest signature minus one; defaults to a whole EVTX chunk.
    /// Default: [`EVTX_CHUNK`] (64 KiB).
    pub overlap: usize,
    /// Number of worker threads. Default: the host's available parallelism.
    pub threads: usize,
    /// Upper bound on the total bytes held in block buffers at any instant,
    /// independent of source size. Default: [`DEFAULT_MEMORY_BUDGET`] (4 GiB).
    pub memory_budget: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            block_size: DEFAULT_BLOCK_SIZE,
            overlap: EVTX_CHUNK,
            threads: default_threads(),
            memory_budget: DEFAULT_MEMORY_BUDGET,
        }
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// A resolved, validated block layout derived from a [`ScanConfig`] and a source
/// size. Peak buffer memory is bounded by `worker_threads * (block_size + overlap)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Plan {
    block_size: usize,
    overlap: usize,
    worker_threads: usize,
    block_count: u64,
    source_size: u64,
}

impl Plan {
    fn resolve(config: &ScanConfig, source_size: u64) -> Result<Plan, ScanError> {
        if config.overlap == 0 {
            return Err(ScanError::InvalidConfig("overlap must be non-zero".into()));
        }
        if config.block_size == 0 {
            return Err(ScanError::InvalidConfig(
                "block size must be non-zero".into(),
            ));
        }
        if config.threads == 0 {
            return Err(ScanError::InvalidConfig(
                "thread count must be non-zero".into(),
            ));
        }

        // A single buffer is block_size + overlap. If the requested block does
        // not fit the budget, shrink it, but never below MIN_BLOCK_SIZE so the
        // budget is never honoured by reading a handful of bytes at a time. A
        // block the caller already sized to fit is used as-is, however small.
        let overlap = config.overlap;
        let mut block_size = config.block_size;
        if block_size as u64 + overlap as u64 > config.memory_budget {
            let smallest_buffer = MIN_BLOCK_SIZE as u64 + overlap as u64;
            if config.memory_budget < smallest_buffer {
                return Err(ScanError::InvalidConfig(format!(
                    "memory budget {} is below the {} bytes needed for one minimal block plus overlap",
                    config.memory_budget, smallest_buffer
                )));
            }
            block_size = (config.memory_budget - overlap as u64) as usize;
            tracing::warn!(
                requested = config.block_size,
                effective = block_size,
                budget = config.memory_budget,
                "block size reduced to fit the memory budget"
            );
        }

        let buffer = block_size as u64 + overlap as u64;
        let by_budget = (config.memory_budget / buffer).max(1) as usize;
        let worker_threads = config.threads.min(by_budget).max(1);

        let block_count = source_size.div_ceil(block_size as u64);

        Ok(Plan {
            block_size,
            overlap,
            worker_threads,
            block_count,
            source_size,
        })
    }
}

/// The scan engine: an Aho-Corasick automaton over a set of signature patterns,
/// searched across a source in parallel fixed-size blocks with overlap.
///
/// Construct once with the pattern set the registered extractors advertise, then
/// call [`Scanner::scan`] on any source. The scanner never writes to the source.
pub struct Scanner {
    ac: AhoCorasick,
    config: ScanConfig,
}

impl Scanner {
    /// Build a scanner for `patterns`. The index of each pattern becomes the
    /// [`Hit::pattern_id`] reported for its matches.
    ///
    /// Returns [`ScanError::NoPatterns`] when the set is empty.
    pub fn new<P>(patterns: &[P], config: ScanConfig) -> Result<Self, ScanError>
    where
        P: AsRef<[u8]>,
    {
        if patterns.is_empty() {
            return Err(ScanError::NoPatterns);
        }
        // Validate the layout up front so a hopeless config fails before any read.
        Plan::resolve(&config, 0)?;

        // Standard match semantics let us enumerate every occurrence of every
        // pattern, including overlapping ones, with memchr/SIMD fast paths.
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::Standard)
            .build(patterns.iter().map(|p| p.as_ref()))
            .map_err(|e| ScanError::InvalidConfig(format!("pattern set is invalid: {e}")))?;

        Ok(Scanner { ac, config })
    }

    /// The configuration this scanner was built with.
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scan `source` and return every signature hit, ordered by
    /// `(offset, pattern_id)`.
    ///
    /// The result is byte-identical across runs and across thread counts: blocks
    /// are processed in parallel but their hits are merged back in source order.
    /// Peak buffer memory stays within the configured budget regardless of how
    /// large the source is.
    pub fn scan(&self, source: &dyn Source) -> Result<Vec<Hit>, ScanError> {
        let source_size = source.size();
        let plan = Plan::resolve(&self.config, source_size)?;

        if plan.block_count == 0 {
            return Ok(Vec::new());
        }

        tracing::debug!(
            source_size,
            block_size = plan.block_size,
            overlap = plan.overlap,
            worker_threads = plan.worker_threads,
            block_count = plan.block_count,
            "starting scan"
        );

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(plan.worker_threads)
            .thread_name(|i| format!("latent-scan-{i}"))
            .build()
            .map_err(|e| ScanError::InvalidConfig(format!("thread pool: {e}")))?;

        // `collect` on an indexed parallel range preserves block order, so the
        // per-block hit vectors come back already sorted by source offset.
        let per_block: Result<Vec<Vec<Hit>>, ScanError> = pool.install(|| {
            (0..plan.block_count)
                .into_par_iter()
                .map(|block| self.scan_block(source, &plan, block))
                .collect()
        });

        let mut hits = Vec::new();
        for mut block_hits in per_block? {
            hits.append(&mut block_hits);
        }
        Ok(hits)
    }

    /// Read and search one block. The buffer covers the block's owned region plus
    /// the overlap tail; only hits whose match start lands in the owned region
    /// are kept, which reports every occurrence exactly once.
    fn scan_block(
        &self,
        source: &dyn Source,
        plan: &Plan,
        block: u64,
    ) -> Result<Vec<Hit>, ScanError> {
        let start = block * plan.block_size as u64;
        let owned_end = (start + plan.block_size as u64).min(plan.source_size);
        // Read the owned region plus as much overlap as the source still holds.
        let read_end = (owned_end + plan.overlap as u64).min(plan.source_size);
        let len = (read_end - start) as usize;

        let mut buf = vec![0u8; len];
        source.read_exact_at(start, &mut buf)?;

        let owned_len = (owned_end - start) as usize;
        let mut hits = Vec::new();
        for m in self.ac.find_overlapping_iter(&buf) {
            // Keep the hit only if its start is owned by this block; a signature
            // beginning in the overlap tail belongs to the next block.
            if m.start() < owned_len {
                hits.push(Hit {
                    offset: start + m.start() as u64,
                    pattern_id: m.pattern().as_usize(),
                });
            }
        }
        // find_overlapping_iter yields by end position; normalise to the
        // documented (offset, pattern_id) order within the block.
        hits.sort_unstable();
        Ok(hits)
    }
}

/// Convenience for callers that hold their source behind an [`Arc`].
impl Scanner {
    /// Same as [`Scanner::scan`], for an `Arc`-held source.
    pub fn scan_arc(&self, source: &Arc<dyn Source>) -> Result<Vec<Hit>, ScanError> {
        self.scan(source.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Arc;

    fn source(bytes: &[u8]) -> Arc<dyn Source> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let (_keep, path) = f.keep().unwrap();
        Arc::new(latent_source::RawSource::open(&path).unwrap())
    }

    /// A tiny-block config so tests exercise many blocks over small inputs.
    fn tiny(block_size: usize, overlap: usize, threads: usize) -> ScanConfig {
        ScanConfig {
            block_size,
            overlap,
            threads,
            memory_budget: DEFAULT_MEMORY_BUDGET,
        }
    }

    #[test]
    fn finds_a_signature_at_every_planted_offset() {
        let pat = b"ElfChnk\x00";
        let mut data = vec![0u8; 1000];
        for &at in &[0usize, 137, 500, 992] {
            data[at..at + pat.len()].copy_from_slice(pat);
        }
        let src = source(&data);
        let scanner = Scanner::new(&[pat.as_slice()], tiny(64, 16, 4)).unwrap();
        let hits = scanner.scan(src.as_ref()).unwrap();
        let offsets: Vec<u64> = hits.iter().map(|h| h.offset).collect();
        assert_eq!(offsets, vec![0, 137, 500, 992]);
        assert!(hits.iter().all(|h| h.pattern_id == 0));
    }

    #[test]
    fn a_signature_straddling_a_block_boundary_is_found_exactly_once() {
        let pat = b"**\x00\x00SPLIT";
        let block = 64usize;
        // Land the pattern so it starts 3 bytes before a block boundary.
        let at = block - 3;
        let mut data = vec![0xAAu8; 256];
        data[at..at + pat.len()].copy_from_slice(pat);
        let src = source(&data);
        let scanner = Scanner::new(&[pat.as_slice()], tiny(block, EVTX_CHUNK, 4)).unwrap();
        let hits = scanner.scan(src.as_ref()).unwrap();
        assert_eq!(hits.len(), 1, "straddling hit counted once");
        assert_eq!(hits[0].offset, at as u64);
    }

    #[test]
    fn hits_are_identical_across_thread_counts() {
        let pats: [&[u8]; 2] = [b"AAAA", b"BB"];
        let mut data = vec![0u8; 4096];
        for i in (0..data.len() - 4).step_by(53) {
            if i % 2 == 0 {
                data[i..i + 4].copy_from_slice(b"AAAA");
            } else {
                data[i..i + 2].copy_from_slice(b"BB");
            }
        }
        let src = source(&data);
        let one = Scanner::new(&pats, tiny(128, 32, 1))
            .unwrap()
            .scan(src.as_ref())
            .unwrap();
        let many = Scanner::new(&pats, tiny(128, 32, 8))
            .unwrap()
            .scan(src.as_ref())
            .unwrap();
        assert_eq!(one, many);
        assert!(one.windows(2).all(|w| w[0] <= w[1]), "globally ordered");
    }

    #[test]
    fn distinct_patterns_get_distinct_ids() {
        let pats: [&[u8]; 3] = [b"ElfChnk\x00", b"\x2a\x2a\x00\x00", b"ElfFile\x00"];
        let mut data = vec![0u8; 300];
        data[10..18].copy_from_slice(b"ElfFile\x00"); // id 2
        data[100..104].copy_from_slice(b"\x2a\x2a\x00\x00"); // id 1
        data[200..208].copy_from_slice(b"ElfChnk\x00"); // id 0
        let src = source(&data);
        let hits = Scanner::new(&pats, tiny(64, 16, 4))
            .unwrap()
            .scan(src.as_ref())
            .unwrap();
        assert_eq!(
            hits,
            vec![
                Hit {
                    offset: 10,
                    pattern_id: 2
                },
                Hit {
                    offset: 100,
                    pattern_id: 1
                },
                Hit {
                    offset: 200,
                    pattern_id: 0
                },
            ]
        );
    }

    #[test]
    fn truncated_trailing_block_does_not_panic() {
        // Source length is not a multiple of the block size and ends with a
        // partial copy of the pattern; the partial must not match or panic.
        let pat = b"MAGICWORD";
        let mut data = vec![7u8; 130];
        data.extend_from_slice(&pat[..4]); // 4 trailing bytes of a 9-byte pattern
        let src = source(&data);
        let hits = Scanner::new(&[pat.as_slice()], tiny(64, 16, 3))
            .unwrap()
            .scan(src.as_ref())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn empty_source_yields_no_hits() {
        let src = source(&[]);
        let hits = Scanner::new(&[b"X".as_slice()], ScanConfig::default())
            .unwrap()
            .scan(src.as_ref())
            .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn no_patterns_is_an_error() {
        let empty: [&[u8]; 0] = [];
        assert!(matches!(
            Scanner::new(&empty, ScanConfig::default()),
            Err(ScanError::NoPatterns)
        ));
    }

    #[test]
    fn plan_caps_workers_by_memory_budget() {
        // Budget only holds two (block + overlap) buffers, so however many
        // threads are asked for, at most two run concurrently.
        let config = ScanConfig {
            block_size: 1024,
            overlap: 256,
            threads: 64,
            memory_budget: 2 * (1024 + 256),
        };
        let plan = Plan::resolve(&config, 1_000_000).unwrap();
        assert_eq!(plan.worker_threads, 2);
        assert_eq!(plan.block_size, 1024);
    }

    #[test]
    fn plan_shrinks_the_block_to_fit_a_tight_budget() {
        let config = ScanConfig {
            block_size: 1024 * 1024,
            overlap: 4096,
            threads: 8,
            memory_budget: 4096 + 8192, // cannot hold the requested 1 MiB block
        };
        let plan = Plan::resolve(&config, 10_000_000).unwrap();
        assert!(plan.block_size + plan.overlap <= config.memory_budget as usize);
        assert!(plan.block_size >= MIN_BLOCK_SIZE);
        assert_eq!(plan.worker_threads, 1);
    }

    #[test]
    fn plan_rejects_a_budget_too_small_for_any_block() {
        let config = ScanConfig {
            block_size: 8192,
            overlap: 4096,
            threads: 1,
            memory_budget: 100, // below MIN_BLOCK_SIZE + overlap
        };
        assert!(matches!(
            Plan::resolve(&config, 1000),
            Err(ScanError::InvalidConfig(_))
        ));
    }

    #[test]
    fn block_count_covers_the_whole_source() {
        let config = tiny(1000, 100, 4);
        assert_eq!(Plan::resolve(&config, 0).unwrap().block_count, 0);
        assert_eq!(Plan::resolve(&config, 1).unwrap().block_count, 1);
        assert_eq!(Plan::resolve(&config, 1000).unwrap().block_count, 1);
        assert_eq!(Plan::resolve(&config, 1001).unwrap().block_count, 2);
        assert_eq!(Plan::resolve(&config, 2500).unwrap().block_count, 3);
    }
}
