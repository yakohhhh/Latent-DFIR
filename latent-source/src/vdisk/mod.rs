//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Virtual disk containers
//!

pub mod qcow2;
pub mod vhdx;
pub mod vmdk;

pub use qcow2::Qcow2Source;
pub use vhdx::VhdxSource;
pub use vmdk::VmdkSource;

use crate::Source;
use crate::error::SourceError;

pub(crate) fn be_u32(src: &dyn Source, offset: u64) -> Result<u32, SourceError> {
    let mut b = [0u8; 4];
    src.read_exact_at(offset, &mut b)?;
    Ok(u32::from_be_bytes(b))
}

pub(crate) fn be_u64(src: &dyn Source, offset: u64) -> Result<u64, SourceError> {
    let mut b = [0u8; 8];
    src.read_exact_at(offset, &mut b)?;
    Ok(u64::from_be_bytes(b))
}

pub(crate) fn le_u16(src: &dyn Source, offset: u64) -> Result<u16, SourceError> {
    let mut b = [0u8; 2];
    src.read_exact_at(offset, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

pub(crate) fn le_u32(src: &dyn Source, offset: u64) -> Result<u32, SourceError> {
    let mut b = [0u8; 4];
    src.read_exact_at(offset, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

pub(crate) fn le_u64(src: &dyn Source, offset: u64) -> Result<u64, SourceError> {
    let mut b = [0u8; 8];
    src.read_exact_at(offset, &mut b)?;
    Ok(u64::from_le_bytes(b))
}
