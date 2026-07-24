//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! The EVTX extractor: chunk, record and file-header carving
//!

mod format;

pub use format::{EvtxConfig, FileHeaderMeta};

use format::{
    CHUNK_MAGIC, FILE_MAGIC, RECORD_MAGIC, validate_chunk, validate_file_header, validate_record,
};

use crate::extractor::{Carved, Extractor, ExtractorMetadata, Platform, Rejection};

/// Carves EVTX structures out of raw signature hits: whole 64 KiB chunks
/// (validated by their two CRC-32 checksums), individual event records
/// (validated orphan-style by size coherence, alignment, FILETIME plausibility
/// and record-id monotonicity), and file headers.
///
/// A hit on the chunk signature that fails validation is rejected as a whole;
/// the individual records inside a damaged chunk are still recovered separately
/// through the record signature, so a partly-corrupt chunk is never discarded
/// whole. Decoding the binary XML body is a later stage; this extractor only
/// validates structure and hands the raw bytes on.
#[derive(Debug, Clone, Default)]
pub struct EvtxExtractor {
    config: EvtxConfig,
}

impl EvtxExtractor {
    /// An extractor with the documented default plausibility window.
    pub fn new() -> Self {
        EvtxExtractor::default()
    }

    /// An extractor with a custom configuration.
    pub fn with_config(config: EvtxConfig) -> Self {
        EvtxExtractor { config }
    }
}

impl Extractor for EvtxExtractor {
    fn metadata(&self) -> ExtractorMetadata {
        ExtractorMetadata {
            name: "evtx",
            platform: Platform::Windows,
            method: "carve.evtx",
        }
    }

    fn signatures(&self) -> Vec<Vec<u8>> {
        vec![
            CHUNK_MAGIC.to_vec(),
            RECORD_MAGIC.to_vec(),
            FILE_MAGIC.to_vec(),
        ]
    }

    fn max_structure_size(&self) -> usize {
        format::CHUNK_SIZE
    }

    fn extract(&self, offset: u64, data: &[u8]) -> Result<Vec<Carved>, Rejection> {
        // Dispatch on the magic actually present; the scan engine may have
        // matched any of our three signatures at this offset.
        if data.starts_with(CHUNK_MAGIC) {
            let len = validate_chunk(data)?;
            Ok(vec![Carved::new(
                offset,
                "evtx.chunk",
                "carve.evtx.chunk",
                data[..len].to_vec(),
            )])
        } else if data.starts_with(FILE_MAGIC) {
            validate_file_header(data)?;
            let len = format::FILE_HEADER_SIZE.min(data.len());
            Ok(vec![Carved::new(
                offset,
                "evtx.file_header",
                "carve.evtx.file_header",
                data[..len].to_vec(),
            )])
        } else if data.starts_with(RECORD_MAGIC) {
            let frame = validate_record(data, &self.config)?;
            Ok(vec![Carved::new(
                offset,
                "evtx.record",
                "carve.evtx.record",
                data[..frame.size].to_vec(),
            )])
        } else {
            Err(Rejection::NotThisFormat)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::format::fixtures::{build_chunk, build_file_header, build_record};
    use super::*;
    use crate::registry::Registry;
    use latent_source::{RawSource, Source};
    use std::io::Write;
    use std::sync::Arc;

    const GOOD_FT: u64 = 133_000_000_000_000_000;

    fn source(bytes: &[u8]) -> Arc<dyn Source> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        let (_keep, path) = f.keep().unwrap();
        Arc::new(RawSource::open(&path).unwrap())
    }

    // Signature pattern ids as flattened by the registry for a single EvtxExtractor.
    const CHUNK_PID: usize = 0;
    const RECORD_PID: usize = 1;
    const FILE_PID: usize = 2;

    #[test]
    fn extractor_advertises_three_signatures_and_the_chunk_window() {
        let e = EvtxExtractor::new();
        assert_eq!(e.signatures().len(), 3);
        assert_eq!(e.max_structure_size(), 64 * 1024);
        assert_eq!(e.metadata().platform, Platform::Windows);
    }

    #[test]
    fn all_intact_chunks_in_an_unallocated_image_are_recovered() {
        // A synthetic unallocated-space image: garbage, then chunks at known
        // offsets separated by more garbage.
        let chunk_a = build_chunk(b"records of chunk A");
        let chunk_b = build_chunk(b"a different set of records for chunk B");
        let mut image = vec![0x5au8; 4096];
        let off_a = image.len() as u64;
        image.extend_from_slice(&chunk_a);
        image.extend_from_slice(&vec![0xffu8; 8192]);
        let off_b = image.len() as u64;
        image.extend_from_slice(&chunk_b);
        let src = source(&image);

        let reg = Registry::builder().register(EvtxExtractor::new()).build();
        let a = reg.extract_hit(src.as_ref(), off_a, CHUNK_PID);
        let b = reg.extract_hit(src.as_ref(), off_b, CHUNK_PID);

        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, "evtx.chunk");
        assert_eq!(a[0].offset, off_a);
        assert_eq!(a[0].bytes, chunk_a);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].bytes, chunk_b);
        // Provenance: source offset and a raw hash on every artefact.
        assert_eq!(
            a[0].raw_sha256,
            latent_core::sha256_reader(&chunk_a[..]).unwrap()
        );

        let diag = reg.diagnostics();
        assert_eq!(diag.per_extractor[0].accepted, 2);
        assert_eq!(diag.per_extractor[0].rejected, 0);
    }

    #[test]
    fn a_damaged_chunk_still_yields_its_individual_records() {
        // Build a chunk, embed two well-formed records in its data area, then
        // corrupt the chunk so its checksum fails. The chunk is rejected whole,
        // but each record is recovered through the record signature.
        let r1 = build_record(100, GOOD_FT, b"first salvageable record");
        let r2 = build_record(101, GOOD_FT, b"second salvageable record");
        let mut records = r1.clone();
        records.extend_from_slice(&r2);
        let mut chunk = build_chunk(&records);
        // Corrupt a header byte so the chunk-level validation fails.
        chunk[64] ^= 0xff;
        let src = source(&chunk);

        let reg = Registry::builder().register(EvtxExtractor::new()).build();

        // Chunk as a whole: rejected.
        assert!(reg.extract_hit(src.as_ref(), 0, CHUNK_PID).is_empty());

        // The records live at offset 512 and 512 + r1.len().
        let rec1 = reg.extract_hit(src.as_ref(), 512, RECORD_PID);
        let rec2 = reg.extract_hit(src.as_ref(), 512 + r1.len() as u64, RECORD_PID);
        assert_eq!(rec1.len(), 1);
        assert_eq!(rec1[0].kind, "evtx.record");
        assert_eq!(rec1[0].bytes, r1);
        assert_eq!(rec2.len(), 1);
        assert_eq!(rec2[0].bytes, r2);
    }

    #[test]
    fn file_header_is_carved_with_provenance() {
        let hdr = build_file_header();
        let mut image = vec![0u8; 2048];
        image.extend_from_slice(&hdr);
        let src = source(&image);
        let reg = Registry::builder().register(EvtxExtractor::new()).build();

        let carved = reg.extract_hit(src.as_ref(), 2048, FILE_PID);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].kind, "evtx.file_header");
        assert_eq!(carved[0].bytes.len(), 128);
        assert_eq!(carved[0].offset, 2048);
    }

    #[test]
    fn thousands_of_fake_evtx_signatures_yield_zero_records() {
        // An image full of every EVTX magic followed by garbage. Every hit is a
        // false positive; validation must reject them all and never panic.
        let mut image = Vec::new();
        let mut offsets: Vec<(u64, usize)> = Vec::new();
        for i in 0..2000u32 {
            offsets.push((image.len() as u64, CHUNK_PID));
            image.extend_from_slice(CHUNK_MAGIC);
            image.extend_from_slice(&i.to_le_bytes());
            offsets.push((image.len() as u64, RECORD_PID));
            image.extend_from_slice(RECORD_MAGIC);
            image.extend_from_slice(&0xdead_beefu32.to_le_bytes());
            offsets.push((image.len() as u64, FILE_PID));
            image.extend_from_slice(FILE_MAGIC);
            image.extend_from_slice(&i.to_le_bytes());
        }
        let src = source(&image);
        let reg = Registry::builder().register(EvtxExtractor::new()).build();

        let mut emitted = 0usize;
        for (off, pid) in &offsets {
            emitted += reg.extract_hit(src.as_ref(), *off, *pid).len();
        }
        assert_eq!(emitted, 0);
        assert_eq!(reg.diagnostics().total_emitted(), 0);
        assert_eq!(reg.diagnostics().per_extractor[0].seen, 6000);
    }

    #[test]
    fn arbitrary_bytes_at_any_offset_never_panic() {
        // Deterministic pseudo-random content, probed at many offsets with each
        // pattern id. The contract is: never panic, never over-allocate.
        let mut image = vec![0u8; 200_000];
        let mut x: u32 = 0x1234_5678;
        for b in image.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        // Sprinkle magics to force the dispatch paths on hostile data.
        for i in (0..image.len() - 8).step_by(997) {
            image[i..i + 4].copy_from_slice(RECORD_MAGIC);
        }
        let src = source(&image);
        let reg = Registry::builder().register(EvtxExtractor::new()).build();

        for off in (0..image.len() as u64).step_by(101) {
            for pid in [CHUNK_PID, RECORD_PID, FILE_PID] {
                let _ = reg.extract_hit(src.as_ref(), off, pid);
            }
        }
        // No assertion beyond "did not panic"; emitted count is whatever the
        // validators allow, but must be finite and the run must complete.
        let _ = reg.diagnostics();
    }
}
