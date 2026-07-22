//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Source error types
//!

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("read at offset {offset} runs past the source end ({size} bytes)")]
    OutOfRange { offset: u64, size: u64 },

    #[error("short read at offset {offset}: wanted {wanted}, got {got}")]
    ShortRead {
        offset: u64,
        wanted: usize,
        got: usize,
    },

    #[error("{path}: not a source format we recognise")]
    Unrecognized { path: PathBuf },

    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl SourceError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        SourceError::Io {
            path: path.into(),
            source,
        }
    }
}

impl From<SourceError> for latent_core::FatalError {
    fn from(e: SourceError) -> Self {
        match e {
            SourceError::Io { source, .. } => latent_core::FatalError::Io(source),
            other => latent_core::FatalError::UnusableSource(other.to_string()),
        }
    }
}
