//! The scanning engine: parallel block reads, overlap handling and signature search.
//!
//! [`Scanner`] streams a [`latent_source::Source`] in fixed-size blocks across a
//! rayon worker pool, searches each block for a set of signature patterns with a
//! single Aho-Corasick pass, and reports every [`Hit`] with its absolute source
//! offset. Consecutive blocks overlap so a signature crossing a boundary is never
//! missed, and hits are merged back in source order so the result is identical
//! across runs and thread counts. Peak buffer memory is bounded by the configured
//! budget, independent of source size.
//!
//! The pattern set is supplied by callers (the registered extractors); this crate
//! knows nothing about the formats behind the signatures.

#![forbid(unsafe_code)]

mod engine;
mod error;

pub use engine::{DEFAULT_BLOCK_SIZE, DEFAULT_MEMORY_BUDGET, EVTX_CHUNK, Hit, ScanConfig, Scanner};
pub use error::ScanError;
