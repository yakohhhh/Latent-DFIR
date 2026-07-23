//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! VHDX fixed and dynamic reader
//!

use crate::error::SourceError;
use crate::vdisk::{le_u16, le_u32, le_u64};
use crate::{Format, Identity, Source};

const REGION_TABLE: u64 = 0x30000;

const BAT_REGION: [u8; 16] = [
    0x66, 0x77, 0xc2, 0x2d, 0x23, 0xf6, 0x00, 0x42, 0x9d, 0x64, 0x11, 0x5e, 0x9b, 0xfd, 0x4a, 0x08,
];
const METADATA_REGION: [u8; 16] = [
    0x06, 0xa2, 0x7c, 0x8b, 0x90, 0x47, 0x9a, 0x4b, 0xb8, 0xfe, 0x57, 0x5f, 0x05, 0x0f, 0x88, 0x6e,
];
const FILE_PARAMETERS: [u8; 16] = [
    0x37, 0x67, 0xa1, 0xca, 0x36, 0xfa, 0x43, 0x4d, 0xb3, 0xb6, 0x33, 0xf0, 0xaa, 0x44, 0xe7, 0x6b,
];
const VIRTUAL_DISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xa5, 0x2f, 0x1b, 0xcd, 0x76, 0x48, 0xb2, 0x11, 0x5d, 0xbe, 0xd8, 0x3b, 0xf4, 0xb8,
];
const LOGICAL_SECTOR_SIZE: [u8; 16] = [
    0x1d, 0xbf, 0x41, 0x81, 0x6f, 0xa9, 0x09, 0x47, 0xba, 0x47, 0xf2, 0x33, 0xa8, 0xfa, 0xab, 0x5f,
];

const PAYLOAD_BLOCK_FULLY_PRESENT: u64 = 6;
const OFFSET_MASK: u64 = 0xffff_ffff_fff0_0000;

pub struct VhdxSource {
    inner: Box<dyn Source>,
    identity: Identity,
    bat_offset: u64,
    block_size: u64,
    chunk_ratio: u64,
    virtual_size: u64,
}

impl VhdxSource {
    pub fn open(inner: Box<dyn Source>) -> Result<Self, SourceError> {
        let path = inner.identity().path.clone();
        let bad = |detail: &str| SourceError::Malformed {
            path: path.clone(),
            format: "vhdx",
            detail: detail.to_string(),
        };
        let src = inner.as_ref();

        let mut file_id = [0u8; 8];
        src.read_exact_at(0, &mut file_id)?;
        if &file_id != b"vhdxfile" {
            return Err(bad("bad file identifier"));
        }

        let (bat_offset, metadata) = region_table(src, &path)?;
        let meta = Metadata::read(src, metadata, &path)?;

        if meta.has_parent {
            return Err(SourceError::Unsupported {
                path: path.clone(),
                format: "vhdx",
                detail: "differencing disk with a parent is not supported".into(),
            });
        }
        if !(1 << 20..=1 << 28).contains(&meta.block_size) || meta.logical_sector_size == 0 {
            return Err(bad("implausible block or sector size"));
        }

        let chunk_ratio = (8_388_608 * meta.logical_sector_size) / meta.block_size;
        let chunk_ratio = chunk_ratio.max(1);

        let identity = Identity {
            path,
            format: Format::Vhdx,
        };
        Ok(VhdxSource {
            inner,
            identity,
            bat_offset,
            block_size: meta.block_size,
            chunk_ratio,
            virtual_size: meta.virtual_size,
        })
    }

    fn locate(&self, block: u64) -> Result<Option<u64>, SourceError> {
        let bat_index = block + block / self.chunk_ratio;
        let at = self.bat_offset.saturating_add(bat_index.saturating_mul(8));
        let entry = le_u64(self.inner.as_ref(), at)?;
        if entry & 7 != PAYLOAD_BLOCK_FULLY_PRESENT {
            return Ok(None);
        }
        Ok(Some(entry & OFFSET_MASK))
    }
}

impl Source for VhdxSource {
    fn size(&self) -> u64 {
        self.virtual_size
    }

    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
        if offset > self.virtual_size {
            return Err(SourceError::OutOfRange {
                offset,
                size: self.virtual_size,
            });
        }
        let n = buf.len().min((self.virtual_size - offset) as usize);
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let within = at % self.block_size;
            let take = ((self.block_size - within) as usize).min(n - done);
            let dst = &mut buf[done..done + take];
            match self.locate(at / self.block_size)? {
                Some(host) => self.inner.read_exact_at(host.saturating_add(within), dst)?,
                None => dst.fill(0),
            }
            done += take;
        }
        Ok(n)
    }
}

fn region_table(src: &dyn Source, path: &std::path::Path) -> Result<(u64, u64), SourceError> {
    let bad = |detail: &str| SourceError::Malformed {
        path: path.to_path_buf(),
        format: "vhdx",
        detail: detail.to_string(),
    };
    let mut sig = [0u8; 4];
    src.read_exact_at(REGION_TABLE, &mut sig)?;
    if &sig != b"regi" {
        return Err(bad("no region table"));
    }
    let count = le_u32(src, REGION_TABLE + 8)?;
    if count > 2047 {
        return Err(bad("absurd region entry count"));
    }

    let mut bat = None;
    let mut metadata = None;
    for i in 0..count as u64 {
        let entry = REGION_TABLE + 16 + i * 32;
        let mut guid = [0u8; 16];
        src.read_exact_at(entry, &mut guid)?;
        let file_offset = le_u64(src, entry + 16)?;
        match guid {
            BAT_REGION => bat = Some(file_offset),
            METADATA_REGION => metadata = Some(file_offset),
            _ => {}
        }
    }
    match (bat, metadata) {
        (Some(b), Some(m)) => Ok((b, m)),
        _ => Err(bad("missing BAT or metadata region")),
    }
}

struct Metadata {
    block_size: u64,
    virtual_size: u64,
    logical_sector_size: u64,
    has_parent: bool,
}

impl Metadata {
    fn read(src: &dyn Source, region: u64, path: &std::path::Path) -> Result<Self, SourceError> {
        let bad = |detail: &str| SourceError::Malformed {
            path: path.to_path_buf(),
            format: "vhdx",
            detail: detail.to_string(),
        };
        let mut sig = [0u8; 8];
        src.read_exact_at(region, &mut sig)?;
        if &sig != b"metadata" {
            return Err(bad("no metadata table"));
        }
        let count = le_u16(src, region + 10)?;
        if count > 2047 {
            return Err(bad("absurd metadata entry count"));
        }

        let (mut block_size, mut virtual_size, mut sector_size, mut has_parent) =
            (None, None, None, false);
        for i in 0..count as u64 {
            let entry = region + 32 + i * 32;
            let mut guid = [0u8; 16];
            src.read_exact_at(entry, &mut guid)?;
            let item = region + le_u32(src, entry + 16)? as u64;
            match guid {
                FILE_PARAMETERS => {
                    block_size = Some(le_u32(src, item)? as u64);
                    has_parent = le_u32(src, item + 4)? & 0b10 != 0;
                }
                VIRTUAL_DISK_SIZE => virtual_size = Some(le_u64(src, item)?),
                LOGICAL_SECTOR_SIZE => sector_size = Some(le_u32(src, item)? as u64),
                _ => {}
            }
        }

        Ok(Metadata {
            block_size: block_size.ok_or_else(|| bad("no file parameters"))?,
            virtual_size: virtual_size.ok_or_else(|| bad("no virtual disk size"))?,
            logical_sector_size: sector_size.ok_or_else(|| bad("no logical sector size"))?,
            has_parent,
        })
    }
}
