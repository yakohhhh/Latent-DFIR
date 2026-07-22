//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Shared types re-exports
//!

#![forbid(unsafe_code)]

pub mod confidence;
pub mod error;
pub mod record;

pub use confidence::{Confidence, Method};
pub use error::{Error, FatalError, RecoverableError, Result};
pub use record::{Event, Host, Process, Provenance, Record, Source, Timestamp, User};
