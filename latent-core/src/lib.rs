//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Shared types re-exports
//!

#![forbid(unsafe_code)]

pub mod audit;
pub mod confidence;
pub mod error;
pub mod hash;
pub mod record;

pub use audit::{AuditDigest, AuditError, AuditLog, Verbosity};
pub use confidence::{Confidence, Method};
pub use error::{Error, FatalError, RecoverableError, Result};
pub use hash::sha256_reader;
pub use record::{Event, Host, Process, Provenance, Record, Source, Timestamp, User};
