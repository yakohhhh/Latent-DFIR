//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Extractor registry, hit dispatch and per-extractor diagnostics
//!

use std::sync::atomic::{AtomicU64, Ordering};

use latent_source::Source;

use crate::extractor::{Carved, Extractor};

/// Live, thread-safe counters kept per extractor.
#[derive(Default)]
struct Counters {
    seen: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    emitted: AtomicU64,
}

/// A snapshot of one extractor's counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractorStats {
    /// Extractor name from its metadata.
    pub name: &'static str,
    /// Candidates dispatched to the extractor.
    pub seen: u64,
    /// Candidates the extractor validated.
    pub accepted: u64,
    /// Candidates the extractor rejected as false positives.
    pub rejected: u64,
    /// Artefacts the extractor emitted across all accepted candidates.
    pub emitted: u64,
}

/// A snapshot of every extractor's counters, for verbose diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    pub per_extractor: Vec<ExtractorStats>,
}

impl Diagnostics {
    /// Total candidates seen across all extractors.
    pub fn total_seen(&self) -> u64 {
        self.per_extractor.iter().map(|s| s.seen).sum()
    }

    /// Total artefacts emitted across all extractors.
    pub fn total_emitted(&self) -> u64 {
        self.per_extractor.iter().map(|s| s.emitted).sum()
    }

    /// Total candidates rejected as false positives across all extractors.
    pub fn total_rejected(&self) -> u64 {
        self.per_extractor.iter().map(|s| s.rejected).sum()
    }
}

/// Holds the registered extractors, the flattened signature set fed to the scan
/// engine, and the mapping from a hit's pattern id back to the extractor that
/// owns it. Dispatch and diagnostics go through `&self`, so it can be shared
/// across the worker threads that process hits.
pub struct Registry {
    extractors: Vec<Box<dyn Extractor>>,
    /// Flattened signatures; the index is the global pattern id the scan engine
    /// reports.
    patterns: Vec<Vec<u8>>,
    /// `pattern_owner[pattern_id]` is the index of the owning extractor.
    pattern_owner: Vec<usize>,
    counters: Vec<Counters>,
}

impl Registry {
    /// Start building a registry.
    pub fn builder() -> RegistryBuilder {
        RegistryBuilder {
            extractors: Vec::new(),
        }
    }

    /// The flattened signature set, in pattern-id order, to hand to the scan
    /// engine's multi-pattern search.
    pub fn signatures(&self) -> &[Vec<u8>] {
        &self.patterns
    }

    /// The largest structure any registered extractor may inspect, used to size
    /// the scan overlap window so no structure is split across a block boundary.
    /// Returns 0 when no extractor is registered.
    pub fn max_structure_size(&self) -> usize {
        self.extractors
            .iter()
            .map(|e| e.max_structure_size())
            .max()
            .unwrap_or(0)
    }

    /// Number of registered extractors.
    pub fn len(&self) -> usize {
        self.extractors.len()
    }

    /// Whether no extractor is registered.
    pub fn is_empty(&self) -> bool {
        self.extractors.is_empty()
    }

    /// Dispatch one signature hit to its owning extractor, updating diagnostics.
    ///
    /// Reads the bounded lookahead window from `source`, hands it to the
    /// extractor, and returns the validated artefacts. A rejection, an
    /// out-of-range pattern id or a failed read all yield an empty vector and are
    /// counted, never propagated: a bad candidate must never interrupt the scan.
    pub fn extract_hit(&self, source: &dyn Source, offset: u64, pattern_id: usize) -> Vec<Carved> {
        let Some(&owner) = self.pattern_owner.get(pattern_id) else {
            tracing::warn!(pattern_id, "hit for an unknown pattern id, ignored");
            return Vec::new();
        };
        let extractor = &self.extractors[owner];
        let counters = &self.counters[owner];
        counters.seen.fetch_add(1, Ordering::Relaxed);

        // Bounded read: never ask for more than the extractor's declared maximum,
        // and never more than the source still holds.
        let window = extractor.max_structure_size();
        let remaining = source.size().saturating_sub(offset);
        let want = window.min(remaining as usize);
        let mut buf = vec![0u8; want];
        if let Err(e) = source.read_exact_at(offset, &mut buf) {
            tracing::debug!(offset, error = %e, "could not read candidate window, rejecting");
            counters.rejected.fetch_add(1, Ordering::Relaxed);
            return Vec::new();
        }

        match extractor.extract(offset, &buf) {
            Ok(carved) => {
                counters.accepted.fetch_add(1, Ordering::Relaxed);
                counters
                    .emitted
                    .fetch_add(carved.len() as u64, Ordering::Relaxed);
                carved
            }
            Err(rejection) => {
                tracing::trace!(offset, %rejection, "candidate rejected");
                counters.rejected.fetch_add(1, Ordering::Relaxed);
                Vec::new()
            }
        }
    }

    /// A consistent snapshot of every extractor's counters.
    pub fn diagnostics(&self) -> Diagnostics {
        let per_extractor = self
            .extractors
            .iter()
            .zip(&self.counters)
            .map(|(e, c)| ExtractorStats {
                name: e.metadata().name,
                seen: c.seen.load(Ordering::Relaxed),
                accepted: c.accepted.load(Ordering::Relaxed),
                rejected: c.rejected.load(Ordering::Relaxed),
                emitted: c.emitted.load(Ordering::Relaxed),
            })
            .collect();
        Diagnostics { per_extractor }
    }
}

/// Builder that collects extractors and flattens their signatures into a
/// registry. Registration order is preserved and fully determines pattern ids.
pub struct RegistryBuilder {
    extractors: Vec<Box<dyn Extractor>>,
}

impl RegistryBuilder {
    /// Register an extractor. Its signatures are appended after those of every
    /// extractor registered before it.
    #[must_use]
    pub fn register(mut self, extractor: impl Extractor + 'static) -> Self {
        self.extractors.push(Box::new(extractor));
        self
    }

    /// Register a boxed extractor, for callers assembling the set dynamically.
    #[must_use]
    pub fn register_boxed(mut self, extractor: Box<dyn Extractor>) -> Self {
        self.extractors.push(extractor);
        self
    }

    /// Finish building. Flattens every extractor's signatures into the global
    /// pattern set and records which extractor owns each pattern id.
    pub fn build(self) -> Registry {
        let mut patterns = Vec::new();
        let mut pattern_owner = Vec::new();
        for (index, extractor) in self.extractors.iter().enumerate() {
            for signature in extractor.signatures() {
                patterns.push(signature);
                pattern_owner.push(index);
            }
        }
        let counters = (0..self.extractors.len())
            .map(|_| Counters::default())
            .collect();
        Registry {
            extractors: self.extractors,
            patterns,
            pattern_owner,
            counters,
        }
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Registry::builder()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extractor::{ExtractorMetadata, Platform, Rejection};
    use std::io::Write;
    use std::sync::Arc;

    fn source(bytes: &[u8]) -> Arc<dyn Source> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let (_keep, path) = f.keep().unwrap();
        Arc::new(latent_source::RawSource::open(&path).unwrap())
    }

    /// A test double: accepts a candidate only when the four bytes after its
    /// magic equal the ASCII length of the trailing payload, mimicking a real
    /// structure's size coherence. Everything else is a silent rejection.
    struct ToyExtractor {
        name: &'static str,
        magic: &'static [u8],
    }

    impl Extractor for ToyExtractor {
        fn metadata(&self) -> ExtractorMetadata {
            ExtractorMetadata {
                name: self.name,
                platform: Platform::CrossPlatform,
                method: "carve.toy",
            }
        }
        fn signatures(&self) -> Vec<Vec<u8>> {
            vec![self.magic.to_vec()]
        }
        fn max_structure_size(&self) -> usize {
            256
        }
        fn extract(&self, offset: u64, data: &[u8]) -> Result<Vec<Carved>, Rejection> {
            // Layout: magic | u8 payload_len | payload...
            let header = self.magic.len() + 1;
            if data.len() < header {
                return Err(Rejection::Truncated {
                    needed: header,
                    available: data.len(),
                });
            }
            if &data[..self.magic.len()] != self.magic {
                return Err(Rejection::NotThisFormat);
            }
            let payload_len = data[self.magic.len()] as usize;
            // Bound the length before slicing.
            let end = header
                .checked_add(payload_len)
                .filter(|&e| e <= data.len())
                .ok_or(Rejection::LengthOutOfBounds {
                    field: "payload_len",
                    value: payload_len as u64,
                    max: (data.len().saturating_sub(header)) as u64,
                })?;
            if payload_len == 0 {
                return Err(Rejection::FailedValidation("empty payload".into()));
            }
            Ok(vec![Carved::new(
                offset,
                "toy.blob",
                self.metadata().method,
                data[..end].to_vec(),
            )])
        }
    }

    fn toy(name: &'static str, magic: &'static [u8]) -> ToyExtractor {
        ToyExtractor { name, magic }
    }

    #[test]
    fn flattens_signatures_and_maps_owners() {
        let reg = Registry::builder()
            .register(toy("a", b"AAAA"))
            .register(toy("b", b"BBBB"))
            .build();
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.signatures(), &[b"AAAA".to_vec(), b"BBBB".to_vec()]);
        assert_eq!(reg.max_structure_size(), 256);
    }

    #[test]
    fn valid_candidate_is_accepted_with_offset_and_hash() {
        // magic "MGK1" + len 3 + "xyz"
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(b"MGK1");
        data[14] = 3;
        data[15..18].copy_from_slice(b"xyz");
        let src = source(&data);
        let reg = Registry::builder().register(toy("m", b"MGK1")).build();

        let carved = reg.extract_hit(src.as_ref(), 10, 0);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].offset, 10);
        assert_eq!(carved[0].bytes, b"MGK1\x03xyz");
        assert_eq!(
            carved[0].raw_sha256,
            latent_core::sha256_reader(&b"MGK1\x03xyz"[..]).unwrap()
        );

        let diag = reg.diagnostics();
        assert_eq!(diag.per_extractor[0].seen, 1);
        assert_eq!(diag.per_extractor[0].accepted, 1);
        assert_eq!(diag.per_extractor[0].rejected, 0);
        assert_eq!(diag.per_extractor[0].emitted, 1);
    }

    #[test]
    fn garbage_matching_the_magic_is_rejected_silently() {
        // magic present but payload_len points past the window: rejected.
        let mut data = vec![0u8; 40];
        data[0..4].copy_from_slice(b"MGK1");
        data[4] = 250; // huge length, no payload
        let src = source(&data);
        let reg = Registry::builder().register(toy("m", b"MGK1")).build();

        let carved = reg.extract_hit(src.as_ref(), 0, 0);
        assert!(carved.is_empty());
        let diag = reg.diagnostics();
        assert_eq!(diag.per_extractor[0].seen, 1);
        assert_eq!(diag.per_extractor[0].accepted, 0);
        assert_eq!(diag.per_extractor[0].rejected, 1);
        assert_eq!(diag.total_emitted(), 0);
    }

    #[test]
    fn thousands_of_fake_signatures_yield_zero_artefacts_without_crashing() {
        // A source full of the magic followed by garbage lengths. Every hit is a
        // false positive; the registry must reject them all and emit nothing.
        let mut data = Vec::new();
        for i in 0..5000u32 {
            data.extend_from_slice(b"MGK1");
            data.push(0); // payload_len 0 -> FailedValidation
            data.extend_from_slice(&i.to_le_bytes());
        }
        let src = source(&data);
        let reg = Registry::builder().register(toy("m", b"MGK1")).build();

        let mut total = 0usize;
        let mut off = 0u64;
        while (off as usize) + 4 <= data.len() {
            if &data[off as usize..off as usize + 4] == b"MGK1" {
                total += reg.extract_hit(src.as_ref(), off, 0).len();
            }
            off += 1;
        }
        assert_eq!(total, 0);
        let diag = reg.diagnostics();
        assert_eq!(diag.per_extractor[0].seen, 5000);
        assert_eq!(diag.per_extractor[0].rejected, 5000);
        assert_eq!(diag.total_emitted(), 0);
    }

    #[test]
    fn dispatch_routes_each_pattern_to_its_owner() {
        let reg = Registry::builder()
            .register(toy("a", b"AAAA"))
            .register(toy("b", b"BBBB"))
            .build();
        // pattern_id 1 is owned by extractor "b".
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(b"BBBB");
        data[4] = 2;
        data[5..7].copy_from_slice(b"hi");
        let src = source(&data);

        let carved = reg.extract_hit(src.as_ref(), 0, 1);
        assert_eq!(carved.len(), 1);
        let diag = reg.diagnostics();
        assert_eq!(diag.per_extractor[0].seen, 0, "extractor a untouched");
        assert_eq!(diag.per_extractor[1].seen, 1, "extractor b dispatched");
    }

    #[test]
    fn truncated_window_at_end_of_source_does_not_panic() {
        // Magic right at the end, no room for the length byte.
        let mut data = vec![9u8; 10];
        data[6..10].copy_from_slice(b"MGK1");
        let src = source(&data);
        let reg = Registry::builder().register(toy("m", b"MGK1")).build();

        let carved = reg.extract_hit(src.as_ref(), 6, 0);
        assert!(carved.is_empty());
        assert_eq!(reg.diagnostics().per_extractor[0].rejected, 1);
    }

    #[test]
    fn unknown_pattern_id_is_ignored() {
        let reg = Registry::builder().register(toy("a", b"AAAA")).build();
        let src = source(&[0u8; 10]);
        assert!(reg.extract_hit(src.as_ref(), 0, 99).is_empty());
        assert_eq!(reg.diagnostics().total_seen(), 0);
    }
}
