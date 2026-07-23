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

    #[error("{path}: opened handle is not read-only")]
    NotReadOnly { path: PathBuf },

    #[error("{path}: malformed {format} image: {detail}")]
    Malformed {
        path: PathBuf,
        format: &'static str,
        detail: String,
    },

    #[error("{path}: {format} image is not supported: {detail}")]
    Unsupported {
        path: PathBuf,
        format: &'static str,
        detail: String,
    },

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
        use latent_core::FatalError as F;
        match e {
            SourceError::Io { source, .. } => F::Io(source),
            e @ SourceError::NotReadOnly { .. } => F::ReadOnlyViolation(e.to_string()),
            other => F::UnusableSource(other.to_string()),
        }
    }
}
