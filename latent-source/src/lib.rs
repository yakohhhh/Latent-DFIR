//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Source abstraction and format dispatch
//!

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

mod error;
mod raw;
mod readonly;

pub mod collection;
pub mod ewf;
pub mod integrity;
pub mod partition;
pub mod vdisk;
pub mod window;

pub use error::SourceError;
pub use integrity::{IntegrityError, VerifiedSource};
pub use partition::{Partition, PartitionTable, Scheme};
pub use raw::RawSource;
pub use window::Window;

pub trait Source: Send + Sync {
    fn size(&self) -> u64;

    fn identity(&self) -> &Identity;

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError>;

    fn read_exact_at(&self, mut offset: u64, mut buf: &mut [u8]) -> Result<(), SourceError> {
        let wanted = buf.len();
        while !buf.is_empty() {
            match self.read_at(offset, buf)? {
                0 => {
                    return Err(SourceError::ShortRead {
                        offset,
                        wanted,
                        got: wanted - buf.len(),
                    });
                }
                n => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Raw,
    Ewf,
    Qcow2,
    Vmdk,
    Vhdx,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Format::Raw => "raw",
            Format::Ewf => "ewf",
            Format::Qcow2 => "qcow2",
            Format::Vmdk => "vmdk",
            Format::Vhdx => "vhdx",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub path: PathBuf,
    pub format: Format,
}

pub fn open(path: &Path) -> Result<Box<dyn Source>, SourceError> {
    let raw = RawSource::open(path)?;
    let mut magic = [0u8; 8];
    let n = raw.read_at(0, &mut magic)?;
    let magic = &magic[..n];

    if magic.starts_with(&ewf::MAGIC) {
        ewf::open(path)
    } else if magic.starts_with(&[0x51, 0x46, 0x49, 0xfb]) {
        Ok(Box::new(vdisk::Qcow2Source::open(Box::new(raw))?))
    } else if magic.starts_with(b"KDMV") {
        Ok(Box::new(vdisk::VmdkSource::open(Box::new(raw))?))
    } else if magic.starts_with(b"vhdxfile") {
        Ok(Box::new(vdisk::VhdxSource::open(Box::new(raw))?))
    } else {
        Ok(Box::new(raw))
    }
}
