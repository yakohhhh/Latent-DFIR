//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! QCOW2 v3 reader
//!

use crate::error::SourceError;
use crate::vdisk::{be_u32, be_u64};
use crate::{Format, Identity, Source};

const MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xfb];
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const L2_COMPRESSED: u64 = 1 << 62;

pub struct Qcow2Source {
    inner: Box<dyn Source>,
    identity: Identity,
    cluster_size: u64,
    l2_entries: u64,
    l1_offset: u64,
    l1_size: u64,
    virtual_size: u64,
}

impl Qcow2Source {
    pub fn open(inner: Box<dyn Source>) -> Result<Self, SourceError> {
        let path = inner.identity().path.clone();
        let bad = |detail: &str| SourceError::Malformed {
            path: path.clone(),
            format: "qcow2",
            detail: detail.to_string(),
        };

        let mut magic = [0u8; 4];
        inner.read_exact_at(0, &mut magic)?;
        if magic != MAGIC {
            return Err(bad("bad magic"));
        }
        if be_u32(inner.as_ref(), 4)? != 3 {
            return Err(bad("only version 3 is handled"));
        }
        if be_u64(inner.as_ref(), 8)? != 0 {
            return Err(SourceError::Unsupported {
                path: path.clone(),
                format: "qcow2",
                detail: "image references a backing file".into(),
            });
        }
        if be_u32(inner.as_ref(), 32)? != 0 {
            return Err(SourceError::Unsupported {
                path: path.clone(),
                format: "qcow2",
                detail: "encrypted images are not supported".into(),
            });
        }
        if be_u32(inner.as_ref(), 60)? != 0 {
            return Err(SourceError::Unsupported {
                path: path.clone(),
                format: "qcow2",
                detail: "internal snapshots are not supported".into(),
            });
        }

        let cluster_bits = be_u32(inner.as_ref(), 20)?;
        if !(9..=21).contains(&cluster_bits) {
            return Err(bad("cluster_bits out of range"));
        }
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = be_u64(inner.as_ref(), 24)?;
        let l1_size = be_u32(inner.as_ref(), 36)? as u64;
        let l1_offset = be_u64(inner.as_ref(), 40)?;

        let identity = Identity {
            path,
            format: Format::Qcow2,
        };
        Ok(Qcow2Source {
            inner,
            identity,
            cluster_size,
            l2_entries: cluster_size / 8,
            l1_offset,
            l1_size,
            virtual_size,
        })
    }

    fn locate(&self, cluster: u64) -> Result<Option<u64>, SourceError> {
        let l1_index = cluster / self.l2_entries;
        if l1_index >= self.l1_size {
            return Ok(None);
        }
        let l1_at = self.l1_offset.saturating_add(l1_index * 8);
        let l2_table = be_u64(self.inner.as_ref(), l1_at)? & OFFSET_MASK;
        if l2_table == 0 {
            return Ok(None);
        }
        let l2_index = cluster % self.l2_entries;
        let entry = be_u64(self.inner.as_ref(), l2_table.saturating_add(l2_index * 8))?;
        if entry & L2_COMPRESSED != 0 {
            return Err(SourceError::Unsupported {
                path: self.identity.path.clone(),
                format: "qcow2",
                detail: "compressed clusters are not supported".into(),
            });
        }
        let host = entry & OFFSET_MASK;
        Ok((host != 0).then_some(host))
    }
}

impl Source for Qcow2Source {
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
            let within = at % self.cluster_size;
            let take = ((self.cluster_size - within) as usize).min(n - done);
            let dst = &mut buf[done..done + take];
            match self.locate(at / self.cluster_size)? {
                Some(host) => self.inner.read_exact_at(host + within, dst)?,
                None => dst.fill(0),
            }
            done += take;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceError;
    use std::io::Write;

    fn build() -> Vec<u8> {
        let mut d = vec![0u8; 512 * 4];
        d[0..4].copy_from_slice(&MAGIC);
        d[4..8].copy_from_slice(&3u32.to_be_bytes());
        d[20..24].copy_from_slice(&9u32.to_be_bytes());
        d[24..32].copy_from_slice(&2048u64.to_be_bytes());
        d[36..40].copy_from_slice(&1u32.to_be_bytes());
        d[40..48].copy_from_slice(&512u64.to_be_bytes());
        d[512..520].copy_from_slice(&1024u64.to_be_bytes());
        d[1024..1032].copy_from_slice(&1536u64.to_be_bytes());
        for (i, b) in d[1536..2048].iter_mut().enumerate() {
            *b = (i as u8) ^ 0xa5;
        }
        d
    }

    fn open(bytes: Vec<u8>) -> Result<Box<dyn Source>, SourceError> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&bytes).unwrap();
        f.flush().unwrap();
        let (_keep, path) = f.keep().unwrap();
        crate::open(&path)
    }

    #[test]
    fn allocated_reads_data_and_hole_reads_zeros() {
        let src = open(build()).unwrap();
        assert_eq!(src.size(), 2048);

        let mut data = [0u8; 512];
        src.read_exact_at(0, &mut data).unwrap();
        assert!(data.iter().enumerate().all(|(i, &b)| b == (i as u8) ^ 0xa5));

        let mut hole = [7u8; 512];
        src.read_exact_at(512, &mut hole).unwrap();
        assert_eq!(hole, [0u8; 512]);
    }

    #[test]
    fn read_across_the_alloc_hole_boundary() {
        let src = open(build()).unwrap();
        let mut buf = [0u8; 24];
        src.read_exact_at(500, &mut buf).unwrap();
        assert_eq!(&buf[12..], &[0u8; 12]);
        assert_eq!(buf[0], (500usize as u8) ^ 0xa5);
    }

    #[test]
    fn backing_file_is_rejected() {
        let mut d = build();
        d[8..16].copy_from_slice(&4096u64.to_be_bytes());
        assert!(matches!(open(d), Err(SourceError::Unsupported { .. })));
    }

    #[test]
    fn silly_cluster_bits_are_rejected() {
        let mut d = build();
        d[20..24].copy_from_slice(&40u32.to_be_bytes());
        assert!(matches!(open(d), Err(SourceError::Malformed { .. })));
    }

    #[test]
    fn l2_pointing_past_the_file_errors_not_panics() {
        let mut d = build();
        d[1024..1032].copy_from_slice(&(1u64 << 40).to_be_bytes());
        let src = open(d).unwrap();
        assert!(src.read_exact_at(0, &mut [0u8; 512]).is_err());
    }

    #[test]
    fn overflowing_l1_offset_errors_not_panics() {
        let mut d = build();
        d[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
        let src = open(d).unwrap();
        assert!(src.read_exact_at(0, &mut [0u8; 512]).is_err());
    }
}
