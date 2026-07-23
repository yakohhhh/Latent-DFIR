//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Recoverable and fatal error types
//!

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecoverableError {
    #[error("malformed record candidate: {0}")]
    MalformedCandidate(String),
    #[error("candidate rejected by validation: {0}")]
    RejectedByValidation(String),
}

#[derive(Debug, Error)]
pub enum FatalError {
    #[error("source integrity violation: {0}")]
    IntegrityViolation(String),
    #[error("read-only guarantee could not be enforced: {0}")]
    ReadOnlyViolation(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unusable source: {0}")]
    UnusableSource(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Recoverable(#[from] RecoverableError),
    #[error(transparent)]
    Fatal(#[from] FatalError),
}

impl Error {
    pub fn is_fatal(&self) -> bool {
        matches!(self, Error::Fatal(_))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recoverable_is_not_fatal() {
        let e: Error = RecoverableError::MalformedCandidate("short header".into()).into();
        assert!(!e.is_fatal());
    }

    #[test]
    fn integrity_and_io_are_fatal() {
        let e: Error = FatalError::IntegrityViolation("open != close".into()).into();
        assert!(e.is_fatal());

        let io = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated");
        let e: Error = FatalError::from(io).into();
        assert!(e.is_fatal());
    }
}
