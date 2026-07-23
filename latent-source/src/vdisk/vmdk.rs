//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! VMDK monolithic sparse reader
//!

use crate::error::SourceError;
use crate::vdisk::{le_u32, le_u64};
use crate::{Format, Identity, Source};

const MAGIC: [u8; 4] = [0x4b, 0x44, 0x4d, 0x56];
const SECTOR: u64 = 512;
const FLAG_COMPRESSED: u32 = 1 << 16;

pub struct VmdkSource {
    inner: Box<dyn Source>,
    identity: Identity,
    grain_bytes: u64,
    gtes_per_gt: u64,
    gd_offset: u64,
    virtual_size: u64,
}

impl VmdkSource {
    pub fn open(inner: Box<dyn Source>) -> Result<Self, SourceError> {
        let path = inner.identity().path.clone();
        let bad = |detail: &str| SourceError::Malformed {
            path: path.clone(),
            format: "vmdk",
            detail: detail.to_string(),
        };
        let src = inner.as_ref();

        let mut magic = [0u8; 4];
        src.read_exact_at(0, &mut magic)?;
        if magic != MAGIC {
            return Err(bad("bad magic"));
        }
        if le_u32(src, 8)? & FLAG_COMPRESSED != 0 {
            return Err(SourceError::Unsupported {
                path: path.clone(),
                format: "vmdk",
                detail: "compressed grains are not supported".into(),
            });
        }

        let capacity = le_u64(src, 12)?;
        let grain_sectors = le_u64(src, 20)?;
        let descriptor_offset = le_u64(src, 28)?;
        let descriptor_size = le_u64(src, 36)?;
        let gtes_per_gt = le_u32(src, 44)? as u64;
        let gd_offset = le_u64(src, 56)?;

        if grain_sectors == 0 || gtes_per_gt == 0 || gd_offset == 0 {
            return Err(bad("zero grain size, GT size or grain directory offset"));
        }
        let grain_bytes = grain_sectors
            .checked_mul(SECTOR)
            .ok_or_else(|| bad("grain size overflow"))?;
        let virtual_size = capacity
            .checked_mul(SECTOR)
            .ok_or_else(|| bad("capacity overflow"))?;

        reject_if_has_parent(src, &path, descriptor_offset, descriptor_size)?;

        let identity = Identity {
            path,
            format: Format::Vmdk,
        };
        Ok(VmdkSource {
            inner,
            identity,
            grain_bytes,
            gtes_per_gt,
            gd_offset,
            virtual_size,
        })
    }

    fn locate(&self, grain: u64) -> Result<Option<u64>, SourceError> {
        let gd_index = grain / self.gtes_per_gt;
        let gde_at = self
            .gd_offset
            .saturating_mul(SECTOR)
            .saturating_add(gd_index * 4);
        let gt_sector = le_u32(self.inner.as_ref(), gde_at)? as u64;
        if gt_sector == 0 {
            return Ok(None);
        }
        let gt_index = grain % self.gtes_per_gt;
        let gte_at = gt_sector
            .saturating_mul(SECTOR)
            .saturating_add(gt_index * 4);
        let grain_sector = le_u32(self.inner.as_ref(), gte_at)? as u64;
        Ok((grain_sector != 0).then(|| grain_sector * SECTOR))
    }
}

impl Source for VmdkSource {
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
            let within = at % self.grain_bytes;
            let take = ((self.grain_bytes - within) as usize).min(n - done);
            let dst = &mut buf[done..done + take];
            match self.locate(at / self.grain_bytes)? {
                Some(host) => self.inner.read_exact_at(host + within, dst)?,
                None => dst.fill(0),
            }
            done += take;
        }
        Ok(n)
    }
}

fn reject_if_has_parent(
    src: &dyn Source,
    path: &std::path::Path,
    descriptor_offset: u64,
    descriptor_size: u64,
) -> Result<(), SourceError> {
    if descriptor_offset == 0 || descriptor_size == 0 {
        return Ok(());
    }
    let len = descriptor_size.saturating_mul(SECTOR).min(64 * 1024) as usize;
    let mut text = vec![0u8; len];
    let read = src.read_at(descriptor_offset.saturating_mul(SECTOR), &mut text)?;
    let text = String::from_utf8_lossy(&text[..read]);

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("parentCID") {
            let value = rest.trim_start_matches([' ', '=']).trim();
            if !value.eq_ignore_ascii_case("ffffffff") {
                return Err(SourceError::Unsupported {
                    path: path.to_path_buf(),
                    format: "vmdk",
                    detail: "image references a parent; only standalone images are supported"
                        .into(),
                });
            }
        }
    }
    Ok(())
}
