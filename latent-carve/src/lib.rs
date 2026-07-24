//! The extractor interface and its per-format implementations. The core never depends on this crate.
//!
//! A format is added by implementing [`Extractor`] and registering it in a
//! [`Registry`]; nothing in `latent-core` or `latent-scan` changes. The registry
//! flattens every extractor's signatures into the pattern set the scan engine
//! searches for, and routes each resulting hit back to the extractor that owns
//! the matched pattern.
//!
//! A signature hit is only a candidate: random bytes match magic values
//! constantly. Extractors validate candidates and reject false positives with a
//! typed [`Rejection`] that is counted in per-extractor [`Diagnostics`] but never
//! interrupts the scan and never reaches user-facing output.

#![forbid(unsafe_code)]

mod extractor;
mod registry;

pub use extractor::{Carved, Extractor, ExtractorMetadata, Platform, Rejection};
pub use registry::{Diagnostics, ExtractorStats, Registry, RegistryBuilder};
