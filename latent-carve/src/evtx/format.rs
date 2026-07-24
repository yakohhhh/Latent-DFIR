//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! EVTX on-disk layout: constants, bounded field reads and structural validation
//!

use crate::extractor::Rejection;

/// Chunk header signature.
pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";
/// File header signature.
pub const FILE_MAGIC: &[u8; 8] = b"ElfFile\x00";
/// Event record signature (`**\0\0`).
pub const RECORD_MAGIC: &[u8; 4] = &[0x2a, 0x2a, 0x00, 0x00];

/// An EVTX chunk is exactly 64 KiB. This is also the extractor's maximum
/// structure size and therefore the scan overlap window.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// The chunk header occupies the first 512 bytes of a chunk.
pub const CHUNK_HEADER_SIZE: usize = 512;
/// The file header struct is 128 bytes (inside a 4 KiB header block).
pub const FILE_HEADER_SIZE: usize = 128;
/// Fixed part of an event record: signature, size, identifier and FILETIME.
pub const RECORD_HEADER_SIZE: usize = 24;

/// FILETIME for 1990-01-01T00:00:00Z, in 100 ns since 1601. Lower bound of the
/// default record-timestamp plausibility window.
pub const FILETIME_1990: u64 = 122_756_256_000_000_000;
/// FILETIME for 2100-01-01T00:00:00Z. Upper bound of the default window.
pub const FILETIME_2100: u64 = 157_469_184_000_000_000;

/// Read a little-endian `u32` at `at`, or `None` if it runs past `data`.
fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

/// Read a little-endian `u64` at `at`, or `None` if it runs past `data`.
fn read_u64(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Tunables for EVTX carving. Held per run so output stays deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvtxConfig {
    /// Records with a FILETIME below this are rejected. Default [`FILETIME_1990`].
    pub min_filetime: u64,
    /// Records with a FILETIME above this are rejected. Default [`FILETIME_2100`].
    pub max_filetime: u64,
    /// Upper bound on a single record's size. Default [`CHUNK_SIZE`]; a record
    /// cannot exceed the chunk that holds it.
    pub max_record_size: u32,
}

impl Default for EvtxConfig {
    fn default() -> Self {
        EvtxConfig {
            min_filetime: FILETIME_1990,
            max_filetime: FILETIME_2100,
            max_record_size: CHUNK_SIZE as u32,
        }
    }
}

/// Metadata retained from a validated EVTX file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeaderMeta {
    pub first_chunk: u64,
    pub last_chunk: u64,
    pub next_record_id: u64,
    pub chunk_count: u16,
    pub flags: u32,
}

/// Validate a chunk header at the head of `data` and return the length of the
/// chunk to carve (the whole 64 KiB, or what is present if truncated).
///
/// Verifies the header CRC-32, the event-records CRC-32, and first/last record
/// identifier coherence. Every length is bounded before use.
pub fn validate_chunk(data: &[u8]) -> Result<usize, Rejection> {
    if data.len() < CHUNK_HEADER_SIZE {
        return Err(Rejection::Truncated {
            needed: CHUNK_HEADER_SIZE,
            available: data.len(),
        });
    }
    if &data[..8] != CHUNK_MAGIC {
        return Err(Rejection::NotThisFormat);
    }

    let free_space = read_u32(data, 48).unwrap() as usize;
    if !(CHUNK_HEADER_SIZE..=CHUNK_SIZE).contains(&free_space) {
        return Err(Rejection::LengthOutOfBounds {
            field: "free_space_offset",
            value: free_space as u64,
            max: CHUNK_SIZE as u64,
        });
    }

    // Header checksum: CRC-32 over bytes [0, 120) and [128, 512).
    let want_header = read_u32(data, 124).unwrap();
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&data[0..120]);
    hasher.update(&data[128..CHUNK_HEADER_SIZE]);
    if hasher.finalize() != want_header {
        return Err(Rejection::FailedValidation(
            "chunk header CRC mismatch".into(),
        ));
    }

    // Event-records checksum: CRC-32 over [512, free_space_offset).
    if data.len() < free_space {
        return Err(Rejection::Truncated {
            needed: free_space,
            available: data.len(),
        });
    }
    let want_records = read_u32(data, 52).unwrap();
    if crc32fast::hash(&data[CHUNK_HEADER_SIZE..free_space]) != want_records {
        return Err(Rejection::FailedValidation(
            "event records checksum mismatch".into(),
        ));
    }

    // Coherence: with two CRCs already matched this always holds for real
    // chunks, but check it so a crafted CRC-colliding header is still caught.
    let first_num = read_u64(data, 8).unwrap();
    let last_num = read_u64(data, 16).unwrap();
    let first_id = read_u64(data, 24).unwrap();
    let last_id = read_u64(data, 32).unwrap();
    if first_num > last_num || first_id > last_id {
        return Err(Rejection::FailedValidation(
            "first/last record identifier incoherent".into(),
        ));
    }

    Ok(CHUNK_SIZE.min(data.len()))
}

/// A validated event record: its byte length and the identifier it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordFrame {
    pub size: usize,
    pub record_id: u64,
}

/// Validate a single event record at the head of `data`, orphan-style: the size
/// at the head must equal the size trailer at the tail, the size must be
/// 8-aligned and within bounds, and the FILETIME must fall inside the
/// plausibility window. Does not decode the binary XML body.
pub fn validate_record(data: &[u8], config: &EvtxConfig) -> Result<RecordFrame, Rejection> {
    // Need the header and a distinct 4-byte tail beyond it.
    if data.len() < RECORD_HEADER_SIZE + 4 {
        return Err(Rejection::Truncated {
            needed: RECORD_HEADER_SIZE + 4,
            available: data.len(),
        });
    }
    if &data[..4] != RECORD_MAGIC {
        return Err(Rejection::NotThisFormat);
    }

    let size = read_u32(data, 4).unwrap() as usize;
    let min_size = RECORD_HEADER_SIZE + 4;
    if size < min_size || size as u64 > config.max_record_size as u64 {
        return Err(Rejection::LengthOutOfBounds {
            field: "record size",
            value: size as u64,
            max: config.max_record_size as u64,
        });
    }
    if !size.is_multiple_of(8) {
        return Err(Rejection::FailedValidation(
            "record size is not 8-byte aligned".into(),
        ));
    }
    if data.len() < size {
        return Err(Rejection::Truncated {
            needed: size,
            available: data.len(),
        });
    }

    // Head size must equal the size trailer at the tail.
    let tail = read_u32(data, size - 4).unwrap() as usize;
    if tail != size {
        return Err(Rejection::FailedValidation(
            "record head/tail size mismatch".into(),
        ));
    }

    let record_id = read_u64(data, 8).unwrap();
    let filetime = read_u64(data, 16).unwrap();
    if filetime < config.min_filetime || filetime > config.max_filetime {
        return Err(Rejection::FailedValidation(
            "record FILETIME outside the plausibility window".into(),
        ));
    }

    // If a well-formed record immediately follows, its identifier must be
    // strictly greater: record identifiers increase monotonically. A trailing
    // record that is not well-formed is simply not used as corroboration.
    if let Some(next) = data.get(size..)
        && next.len() >= RECORD_HEADER_SIZE + 4
        && &next[..4] == RECORD_MAGIC
    {
        let next_size = read_u32(next, 4).unwrap() as usize;
        if next_size >= min_size
            && next_size.is_multiple_of(8)
            && next.len() >= next_size
            && read_u32(next, next_size - 4).unwrap() as usize == next_size
        {
            let next_id = read_u64(next, 8).unwrap();
            if next_id <= record_id {
                return Err(Rejection::FailedValidation(
                    "record identifiers not monotonically increasing".into(),
                ));
            }
        }
    }

    Ok(RecordFrame { size, record_id })
}

/// Validate an EVTX file header at the head of `data` and return its metadata.
/// Verifies the header CRC-32 (over the first 120 bytes) and chunk-number
/// coherence.
pub fn validate_file_header(data: &[u8]) -> Result<FileHeaderMeta, Rejection> {
    if data.len() < FILE_HEADER_SIZE {
        return Err(Rejection::Truncated {
            needed: FILE_HEADER_SIZE,
            available: data.len(),
        });
    }
    if &data[..8] != FILE_MAGIC {
        return Err(Rejection::NotThisFormat);
    }

    let want = read_u32(data, 124).unwrap();
    if crc32fast::hash(&data[0..120]) != want {
        return Err(Rejection::FailedValidation(
            "file header CRC mismatch".into(),
        ));
    }

    let first_chunk = read_u64(data, 8).unwrap();
    let last_chunk = read_u64(data, 16).unwrap();
    if first_chunk > last_chunk {
        return Err(Rejection::FailedValidation(
            "first/last chunk number incoherent".into(),
        ));
    }
    let next_record_id = read_u64(data, 24).unwrap();
    let chunk_count = u16::from_le_bytes(data[42..44].try_into().unwrap());
    let flags = read_u32(data, 120).unwrap();

    Ok(FileHeaderMeta {
        first_chunk,
        last_chunk,
        next_record_id,
        chunk_count,
        flags,
    })
}

/// Deterministic builders for valid EVTX structures, shared between this
/// module's tests and the extractor's integration tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    /// Build a valid chunk whose event-records area holds `records`.
    pub fn build_chunk(records: &[u8]) -> Vec<u8> {
        let mut chunk = vec![0u8; CHUNK_SIZE];
        chunk[..8].copy_from_slice(CHUNK_MAGIC);
        chunk[8..16].copy_from_slice(&1u64.to_le_bytes()); // first record number
        chunk[16..24].copy_from_slice(&2u64.to_le_bytes()); // last record number
        chunk[24..32].copy_from_slice(&1u64.to_le_bytes()); // first record id
        chunk[32..40].copy_from_slice(&2u64.to_le_bytes()); // last record id
        chunk[40..44].copy_from_slice(&128u32.to_le_bytes()); // header size
        let free_space = CHUNK_HEADER_SIZE + records.len();
        chunk[512..free_space].copy_from_slice(records);
        chunk[44..48].copy_from_slice(&(free_space as u32).to_le_bytes()); // last record offset
        chunk[48..52].copy_from_slice(&(free_space as u32).to_le_bytes()); // free space offset
        let rec_crc = crc32fast::hash(&chunk[512..free_space]);
        chunk[52..56].copy_from_slice(&rec_crc.to_le_bytes());
        let mut h = crc32fast::Hasher::new();
        h.update(&chunk[0..120]);
        h.update(&chunk[128..512]);
        chunk[124..128].copy_from_slice(&h.finalize().to_le_bytes());
        chunk
    }

    /// Build a valid orphan record.
    pub fn build_record(record_id: u64, filetime: u64, body: &[u8]) -> Vec<u8> {
        let mut size = RECORD_HEADER_SIZE + body.len() + 4;
        size = size.div_ceil(8) * 8; // 8-align
        let mut rec = vec![0u8; size];
        rec[..4].copy_from_slice(RECORD_MAGIC);
        rec[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        rec[8..16].copy_from_slice(&record_id.to_le_bytes());
        rec[16..24].copy_from_slice(&filetime.to_le_bytes());
        rec[24..24 + body.len()].copy_from_slice(body);
        rec[size - 4..].copy_from_slice(&(size as u32).to_le_bytes());
        rec
    }

    /// Build a valid EVTX file header block.
    pub fn build_file_header() -> Vec<u8> {
        let mut hdr = vec![0u8; FILE_HEADER_SIZE];
        hdr[..8].copy_from_slice(FILE_MAGIC);
        hdr[8..16].copy_from_slice(&1u64.to_le_bytes()); // first chunk
        hdr[16..24].copy_from_slice(&3u64.to_le_bytes()); // last chunk
        hdr[24..32].copy_from_slice(&42u64.to_le_bytes()); // next record id
        hdr[32..36].copy_from_slice(&128u32.to_le_bytes()); // header size
        hdr[36..38].copy_from_slice(&1u16.to_le_bytes()); // minor version
        hdr[38..40].copy_from_slice(&3u16.to_le_bytes()); // major version
        hdr[40..42].copy_from_slice(&4096u16.to_le_bytes()); // header block size
        hdr[42..44].copy_from_slice(&4u16.to_le_bytes()); // number of chunks
        hdr[120..124].copy_from_slice(&1u32.to_le_bytes()); // flags: dirty
        let crc = crc32fast::hash(&hdr[0..120]);
        hdr[124..128].copy_from_slice(&crc.to_le_bytes());
        hdr
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{build_chunk, build_file_header, build_record};
    use super::*;

    const GOOD_FT: u64 = 133_000_000_000_000_000; // ~2022, inside the window

    #[test]
    fn intact_chunk_validates_and_reports_full_size() {
        let chunk = build_chunk(b"the event records area");
        assert_eq!(validate_chunk(&chunk), Ok(CHUNK_SIZE));
    }

    #[test]
    fn chunk_with_corrupt_header_crc_is_rejected() {
        let mut chunk = build_chunk(b"records");
        chunk[100] ^= 0xff; // inside the header CRC coverage
        assert!(matches!(
            validate_chunk(&chunk),
            Err(Rejection::FailedValidation(_))
        ));
    }

    #[test]
    fn chunk_with_corrupt_records_is_rejected() {
        let mut chunk = build_chunk(b"the event records area, long enough to corrupt");
        chunk[520] ^= 0xff; // inside the event-records area
        assert!(matches!(
            validate_chunk(&chunk),
            Err(Rejection::FailedValidation(_))
        ));
    }

    #[test]
    fn chunk_with_absurd_free_space_is_bounded_not_panicked() {
        let mut chunk = build_chunk(b"records");
        chunk[48..52].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(matches!(
            validate_chunk(&chunk),
            Err(Rejection::LengthOutOfBounds { .. })
        ));
    }

    #[test]
    fn truncated_chunk_header_is_truncation_not_panic() {
        let chunk = build_chunk(b"records");
        assert!(matches!(
            validate_chunk(&chunk[..300]),
            Err(Rejection::Truncated { .. })
        ));
    }

    #[test]
    fn valid_record_reports_its_frame() {
        let rec = build_record(7, GOOD_FT, b"binxml body here");
        let frame = validate_record(&rec, &EvtxConfig::default()).unwrap();
        assert_eq!(frame.size, rec.len());
        assert_eq!(frame.record_id, 7);
    }

    #[test]
    fn record_head_tail_mismatch_is_rejected() {
        let mut rec = build_record(7, GOOD_FT, b"body");
        let bad = (rec.len() + 8) as u32;
        rec[4..8].copy_from_slice(&bad.to_le_bytes()); // head now disagrees with tail
        // size still within bounds but > data.len() -> truncated, or tail mismatch
        let out = validate_record(&rec, &EvtxConfig::default());
        assert!(out.is_err());
    }

    #[test]
    fn record_with_implausible_filetime_is_rejected() {
        let rec = build_record(7, 1, b"body"); // FILETIME = 1 (year 1601)
        assert!(matches!(
            validate_record(&rec, &EvtxConfig::default()),
            Err(Rejection::FailedValidation(_))
        ));
    }

    #[test]
    fn record_size_not_aligned_is_rejected() {
        // Craft head/tail = 30 (not 8-aligned) with enough bytes present.
        let mut rec = vec![0u8; 40];
        rec[..4].copy_from_slice(RECORD_MAGIC);
        rec[4..8].copy_from_slice(&30u32.to_le_bytes());
        rec[16..24].copy_from_slice(&GOOD_FT.to_le_bytes());
        rec[26..30].copy_from_slice(&30u32.to_le_bytes());
        assert!(matches!(
            validate_record(&rec, &EvtxConfig::default()),
            Err(Rejection::FailedValidation(_))
        ));
    }

    #[test]
    fn non_monotonic_neighbour_is_rejected() {
        // Two adjacent records where the second id is not greater.
        let mut buf = build_record(10, GOOD_FT, b"first record body");
        buf.extend_from_slice(&build_record(5, GOOD_FT, b"second, lower id"));
        assert!(matches!(
            validate_record(&buf, &EvtxConfig::default()),
            Err(Rejection::FailedValidation(_))
        ));
    }

    #[test]
    fn monotonic_neighbour_is_accepted() {
        let mut buf = build_record(10, GOOD_FT, b"first record body");
        buf.extend_from_slice(&build_record(11, GOOD_FT, b"second, higher id"));
        assert_eq!(
            validate_record(&buf, &EvtxConfig::default())
                .unwrap()
                .record_id,
            10
        );
    }

    #[test]
    fn valid_file_header_yields_metadata() {
        let hdr = build_file_header();
        let meta = validate_file_header(&hdr).unwrap();
        assert_eq!(meta.first_chunk, 1);
        assert_eq!(meta.last_chunk, 3);
        assert_eq!(meta.next_record_id, 42);
        assert_eq!(meta.chunk_count, 4);
        assert_eq!(meta.flags, 1);
    }

    #[test]
    fn file_header_bad_crc_is_rejected() {
        let mut hdr = build_file_header();
        hdr[10] ^= 0xff;
        assert!(matches!(
            validate_file_header(&hdr),
            Err(Rejection::FailedValidation(_))
        ));
    }
}
