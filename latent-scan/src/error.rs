//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Scan engine error types
//!

use latent_source::SourceError;
use thiserror::Error;

/// Everything the scan engine can fail on.
///
/// Reading the evidence is the only source of I/O errors; a bad configuration
/// is caught before any read happens.
#[derive(Debug, Error)]
pub enum ScanError {
    /// The scan configuration cannot be honoured, typically because the memory
    /// budget is too small to hold even a single block plus its overlap.
    #[error("invalid scan configuration: {0}")]
    InvalidConfig(String),

    /// No signature patterns were supplied, so there is nothing to search for.
    #[error("no signature patterns registered")]
    NoPatterns,

    /// A read against the evidence source failed.
    #[error(transparent)]
    Source(#[from] SourceError),
}

impl From<ScanError> for latent_core::FatalError {
    fn from(e: ScanError) -> Self {
        match e {
            ScanError::Source(s) => s.into(),
            other => latent_core::FatalError::UnusableSource(other.to_string()),
        }
    }
}
