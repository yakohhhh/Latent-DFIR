//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! MBR and GPT partitions
//!

use std::sync::Arc;

use crate::Source;
use crate::error::SourceError;
use crate::window::Window;

const SECTOR: u64 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Mbr,
    Gpt,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub index: usize,
    pub kind: String,
    pub start: u64,
    pub length: u64,
    pub name: Option<String>,
}

impl Partition {
    pub fn window(&self, disk: Arc<dyn Source>) -> Result<Window, SourceError> {
        Window::range(disk, self.start, Some(self.length))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTable {
    pub scheme: Scheme,
    pub partitions: Vec<Partition>,
}

impl PartitionTable {
    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.partitions.len()
    }

    pub fn get(&self, index: usize) -> Option<&Partition> {
        self.partitions.get(index)
    }
}

pub fn read(src: &dyn Source) -> PartitionTable {
    if let Some(partitions) = read_gpt(src) {
        return PartitionTable {
            scheme: Scheme::Gpt,
            partitions,
        };
    }
    if let Some(partitions) = read_mbr(src) {
        return PartitionTable {
            scheme: Scheme::Mbr,
            partitions,
        };
    }
    tracing::warn!(
        source = %src.identity().path.display(),
        "no usable partition table, treating the whole source as one volume"
    );
    PartitionTable {
        scheme: Scheme::None,
        partitions: Vec::new(),
    }
}

fn read_gpt(src: &dyn Source) -> Option<Vec<Partition>> {
    let mut header = [0u8; SECTOR as usize];
    src.read_exact_at(SECTOR, &mut header).ok()?;
    if &header[0..8] != b"EFI PART" {
        return None;
    }

    let header_size = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
    if !(92..=SECTOR as usize).contains(&header_size) {
        return None;
    }

    let want_header_crc = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let mut h = header[..header_size].to_vec();
    h[16..20].fill(0);
    if crc32fast::hash(&h) != want_header_crc {
        tracing::warn!("GPT header CRC mismatch");
        return None;
    }

    let entry_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(header[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap());
    let want_entries_crc = u32::from_le_bytes(header[88..92].try_into().unwrap());

    if !(128..=4096).contains(&entry_size) || count == 0 || count > 4096 {
        return None;
    }

    let entries_offset = entry_lba.checked_mul(SECTOR)?;
    let mut entries = vec![0u8; count as usize * entry_size as usize];
    src.read_exact_at(entries_offset, &mut entries).ok()?;
    if crc32fast::hash(&entries) != want_entries_crc {
        tracing::warn!("GPT entry array CRC mismatch");
        return None;
    }

    let mut partitions = Vec::new();
    for chunk in entries.chunks_exact(entry_size as usize) {
        let type_guid = &chunk[0..16];
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }
        let first = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        let last = u64::from_le_bytes(chunk[40..48].try_into().unwrap());
        let (Some(start), Some(length)) = (
            first.checked_mul(SECTOR),
            last.checked_sub(first)
                .and_then(|span| span.checked_add(1))
                .and_then(|s| s.checked_mul(SECTOR)),
        ) else {
            continue;
        };
        partitions.push(Partition {
            index: partitions.len(),
            kind: guid_string(type_guid),
            start,
            length,
            name: decode_name(&chunk[56..128]),
        });
    }
    Some(partitions)
}

fn read_mbr(src: &dyn Source) -> Option<Vec<Partition>> {
    let mut sector = [0u8; SECTOR as usize];
    src.read_exact_at(0, &mut sector).ok()?;
    if sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }

    let mut partitions = Vec::new();
    let mut extended_base = None;
    for entry in sector[446..510].chunks_exact(16).take(4) {
        let kind = entry[4];
        let start = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        let count = u32::from_le_bytes(entry[12..16].try_into().unwrap()) as u64;
        match kind {
            0x00 => continue,
            0xEE => continue,
            0x05 | 0x0F | 0x85 => extended_base = Some(start),
            _ if count == 0 => continue,
            _ => partitions.push(primary(partitions.len(), kind, start, count)),
        }
    }

    if let Some(base) = extended_base {
        read_logical(src, base, &mut partitions);
    }

    if partitions.is_empty() {
        return None;
    }
    Some(partitions)
}

fn read_logical(src: &dyn Source, extended_base: u64, partitions: &mut Vec<Partition>) {
    let mut ebr = extended_base;
    let mut seen = 0;
    while seen < 1024 {
        seen += 1;
        let mut sector = [0u8; SECTOR as usize];
        if src.read_exact_at(ebr * SECTOR, &mut sector).is_err() {
            break;
        }
        if sector[510] != 0x55 || sector[511] != 0xAA {
            break;
        }

        let logical = &sector[446..462];
        let kind = logical[4];
        let start = u32::from_le_bytes(logical[8..12].try_into().unwrap()) as u64;
        let count = u32::from_le_bytes(logical[12..16].try_into().unwrap()) as u64;
        if kind != 0 && count != 0 {
            partitions.push(primary(partitions.len(), kind, ebr + start, count));
        }

        let next = &sector[462..478];
        let next_rel = u32::from_le_bytes(next[8..12].try_into().unwrap()) as u64;
        if next_rel == 0 {
            break;
        }
        let next_ebr = extended_base + next_rel;
        if next_ebr == ebr {
            break;
        }
        ebr = next_ebr;
    }
}

fn primary(index: usize, kind: u8, start_lba: u64, count: u64) -> Partition {
    Partition {
        index,
        kind: format!("0x{kind:02x}"),
        start: start_lba * SECTOR,
        length: count * SECTOR,
        name: None,
    }
}

fn guid_string(g: &[u8]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15],
    )
}

fn decode_name(bytes: &[u8]) -> Option<String> {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    (!units.is_empty()).then(|| String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawSource;
    use std::io::Write;

    const SEC: usize = SECTOR as usize;

    const LINUX_DATA: [u8; 16] = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];
    const LINUX_SWAP: [u8; 16] = [
        0x6d, 0xfd, 0x57, 0x06, 0xab, 0xa4, 0xc4, 0x43, 0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f,
        0x4f,
    ];

    fn on_disk(bytes: Vec<u8>) -> RawSource {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&bytes).unwrap();
        f.flush().unwrap();
        let (_keep, path) = f.keep().unwrap();
        RawSource::open(&path).unwrap()
    }

    fn put(disk: &mut [u8], at: usize, bytes: &[u8]) {
        disk[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn gpt_entry(type_guid: &[u8; 16], first: u64, last: u64, name: &str) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[0..16].copy_from_slice(type_guid);
        e[16..32].copy_from_slice(&[1u8; 16]);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (i, u) in name.encode_utf16().enumerate() {
            put(&mut e, 56 + i * 2, &u.to_le_bytes());
        }
        e
    }

    fn build_gpt() -> Vec<u8> {
        let mut disk = vec![0u8; SEC * 48];
        disk[446 + 4] = 0xEE;
        disk[510] = 0x55;
        disk[511] = 0xAA;

        let (num, esize) = (4u32, 128u32);
        let mut entries = vec![0u8; (num * esize) as usize];
        put(&mut entries, 0, &gpt_entry(&LINUX_DATA, 34, 39, "data-one"));
        put(&mut entries, 128, &gpt_entry(&LINUX_SWAP, 40, 45, "swap"));
        let entries_crc = crc32fast::hash(&entries);
        put(&mut disk, SEC * 2, &entries);

        let mut h = vec![0u8; 92];
        put(&mut h, 0, b"EFI PART");
        put(&mut h, 8, &[0, 0, 1, 0]);
        put(&mut h, 12, &92u32.to_le_bytes());
        put(&mut h, 24, &1u64.to_le_bytes());
        put(&mut h, 32, &47u64.to_le_bytes());
        put(&mut h, 40, &34u64.to_le_bytes());
        put(&mut h, 48, &45u64.to_le_bytes());
        put(&mut h, 56, &[9u8; 16]);
        put(&mut h, 72, &2u64.to_le_bytes());
        put(&mut h, 80, &num.to_le_bytes());
        put(&mut h, 84, &esize.to_le_bytes());
        put(&mut h, 88, &entries_crc.to_le_bytes());
        let hcrc = crc32fast::hash(&h);
        put(&mut h, 16, &hcrc.to_le_bytes());
        put(&mut disk, SEC, &h);
        disk
    }

    fn mbr_entry(kind: u8, start: u32, count: u32) -> [u8; 16] {
        let mut e = [0u8; 16];
        e[4] = kind;
        put(&mut e, 8, &start.to_le_bytes());
        put(&mut e, 12, &count.to_le_bytes());
        e
    }

    fn build_mbr() -> Vec<u8> {
        let mut disk = vec![0u8; SEC * 64];
        disk[510] = 0x55;
        disk[511] = 0xAA;
        put(&mut disk, 446, &mbr_entry(0x83, 4, 4));
        put(&mut disk, 462, &mbr_entry(0x07, 8, 4));
        put(&mut disk, 478, &mbr_entry(0x05, 20, 20));

        let ebr = SEC * 20;
        disk[ebr + 510] = 0x55;
        disk[ebr + 511] = 0xAA;
        put(&mut disk, ebr + 446, &mbr_entry(0x83, 2, 4));
        disk
    }

    #[test]
    fn gpt_enumerates_with_names_and_guids() {
        let t = read(&on_disk(build_gpt()));
        assert_eq!(t.scheme, Scheme::Gpt);
        assert_eq!(t.len(), 2);
        let p = &t.partitions[0];
        assert_eq!(p.kind, "0fc63daf-8483-4772-8e79-3d69d8477de4");
        assert_eq!(p.start, 34 * SECTOR);
        assert_eq!(p.length, 6 * SECTOR);
        assert_eq!(p.name.as_deref(), Some("data-one"));
        assert_eq!(t.partitions[1].name.as_deref(), Some("swap"));
    }

    #[test]
    fn gpt_bad_entry_crc_falls_back_to_whole_source() {
        let mut disk = build_gpt();
        disk[SEC * 2 + 40] ^= 0xff;
        let t = read(&on_disk(disk));
        assert_eq!(t.scheme, Scheme::None);
        assert!(t.is_empty());
    }

    #[test]
    fn gpt_absurd_entry_count_is_rejected_not_allocated() {
        let mut disk = build_gpt();
        put(&mut disk, SEC + 80, &5_000_000u32.to_le_bytes());
        let mut h = disk[SEC..SEC + 92].to_vec();
        h[16..20].fill(0);
        put(&mut disk, SEC + 16, &crc32fast::hash(&h).to_le_bytes());
        let t = read(&on_disk(disk));
        assert_eq!(t.scheme, Scheme::None);
    }

    #[test]
    fn gpt_overflowing_entry_lba_does_not_panic() {
        let mut disk = build_gpt();
        put(&mut disk, SEC + 72, &u64::MAX.to_le_bytes());
        let mut h = disk[SEC..SEC + 92].to_vec();
        h[16..20].fill(0);
        put(&mut disk, SEC + 16, &crc32fast::hash(&h).to_le_bytes());
        let t = read(&on_disk(disk));
        assert_eq!(t.scheme, Scheme::None);
    }

    #[test]
    fn mbr_lists_primaries_then_logicals() {
        let t = read(&on_disk(build_mbr()));
        assert_eq!(t.scheme, Scheme::Mbr);
        let got: Vec<_> = t
            .partitions
            .iter()
            .map(|p| (p.kind.as_str(), p.start, p.length))
            .collect();
        assert_eq!(
            got,
            [
                ("0x83", 4 * SECTOR, 4 * SECTOR),
                ("0x07", 8 * SECTOR, 4 * SECTOR),
                ("0x83", 22 * SECTOR, 4 * SECTOR),
            ]
        );
    }

    #[test]
    fn no_table_degrades_to_a_single_volume() {
        let t = read(&on_disk(vec![0x5a; SEC * 8]));
        assert_eq!(t.scheme, Scheme::None);
        assert!(t.is_empty());
    }

    #[test]
    fn enumeration_is_stable() {
        let disk = build_gpt();
        assert_eq!(read(&on_disk(disk.clone())), read(&on_disk(disk)));
    }

    #[test]
    fn a_partition_window_reads_only_its_bytes() {
        let mut disk = build_gpt();
        put(&mut disk, 34 * SEC, b"PART");
        let src: Arc<dyn Source> = Arc::new(on_disk(disk));
        let t = read(src.as_ref());
        let w = t.partitions[0].window(src.clone()).unwrap();
        assert_eq!(w.size(), 6 * SECTOR);
        let mut buf = [0u8; 4];
        w.read_exact_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"PART");
    }
}
