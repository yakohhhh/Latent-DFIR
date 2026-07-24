//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! The extractor interface: trait, metadata, carved artefact and rejection
//!

use thiserror::Error;

/// The operating system an artefact belongs to. Used only for reporting and to
/// let an analyst filter extractors; it never gates whether an extractor runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    /// The format is not tied to a single OS.
    CrossPlatform,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Platform::Windows => "windows",
            Platform::Linux => "linux",
            Platform::MacOs => "macos",
            Platform::CrossPlatform => "cross-platform",
        })
    }
}

/// Static description of an extractor, surfaced in diagnostics and provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractorMetadata {
    /// Short identifier, e.g. `"evtx"`.
    pub name: &'static str,
    /// The platform the artefact comes from.
    pub platform: Platform,
    /// Extraction method identifier recorded on every artefact this extractor
    /// produces, e.g. `"carve.evtx.chunk"`.
    pub method: &'static str,
}

/// A validated artefact carved from the source.
///
/// Constructed with [`Carved::new`], which hashes the raw bytes so every
/// artefact carries the SHA-256 of exactly the bytes it was built from, next to
/// the absolute source offset it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carved {
    /// Absolute byte offset of the artefact within the source.
    pub offset: u64,
    /// Artefact kind, e.g. `"evtx.chunk"` or `"evtx.record"`.
    pub kind: &'static str,
    /// Extraction method identifier, copied from the extractor's metadata.
    pub method: &'static str,
    /// Lowercase hex SHA-256 of [`Carved::bytes`].
    pub raw_sha256: String,
    /// The exact raw bytes of the validated structure.
    pub bytes: Vec<u8>,
}

impl Carved {
    /// Build an artefact from its raw bytes, computing the SHA-256 over them.
    pub fn new(offset: u64, kind: &'static str, method: &'static str, bytes: Vec<u8>) -> Self {
        let raw_sha256 =
            latent_core::sha256_reader(&bytes[..]).expect("hashing an in-memory slice cannot fail");
        Carved {
            offset,
            kind,
            method,
            raw_sha256,
            bytes,
        }
    }
}

/// Why a signature hit was not a real artefact.
///
/// Every rejection is silent: it is counted in the extractor's diagnostics and
/// never reaches user-facing output. A signature hit is very often random bytes
/// that happen to match a magic value, so rejection is the common case, not an
/// error condition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Rejection {
    /// The bytes at the offset do not actually form this structure: the magic
    /// matched by chance.
    #[error("bytes at the offset do not match this format")]
    NotThisFormat,

    /// Not enough bytes are present to validate the structure.
    #[error("truncated candidate: needed {needed} bytes, {available} available")]
    Truncated { needed: usize, available: usize },

    /// A length field read from the data exceeds its sane bound. Reported
    /// *before* the length is ever used to size an allocation or a read.
    #[error("{field} length {value} exceeds the maximum {max}")]
    LengthOutOfBounds {
        field: &'static str,
        value: u64,
        max: u64,
    },

    /// The structure was well-formed enough to parse but failed a validation
    /// check (checksum, coherence, plausibility window, ...).
    #[error("failed structural validation: {0}")]
    FailedValidation(String),
}

/// The interface every artefact format implements. Adding a format means writing
/// one `Extractor` and registering it; nothing in `latent-core` or `latent-scan`
/// changes.
///
/// # Validation obligations
///
/// A signature hit is only a *candidate*: the scan engine matched a magic value,
/// which random data reproduces constantly. An implementation MUST:
///
/// - Return [`Ok`] only for bytes it has actually validated (checksums, size
///   coherence, plausibility windows — whatever the format affords). Every other
///   candidate MUST be rejected with a [`Rejection`]. A rejection is normal and
///   silent; it must never abort the scan.
/// - **Never panic** on any input. The `data` slice is attacker-controlled.
/// - Bound every length before use: `data` is already capped to
///   [`Extractor::max_structure_size`], but any length field read *from* `data`
///   must be validated against that bound (yielding
///   [`Rejection::LengthOutOfBounds`]) before it is used to index, slice or
///   allocate. Prefer `data.get(range)` over indexing.
///
/// # Bounded lookahead
///
/// [`Extractor::extract`] receives `data`, the source bytes starting at the
/// candidate offset, already truncated to at most
/// [`Extractor::max_structure_size`] bytes (fewer at the end of the source). An
/// extractor never performs its own I/O and therefore cannot read unbounded
/// amounts of the source.
pub trait Extractor: Send + Sync {
    /// Static metadata for reporting and provenance.
    fn metadata(&self) -> ExtractorMetadata;

    /// The signature patterns the scan engine should search for on this
    /// extractor's behalf. Each returned pattern becomes a distinct entry in the
    /// engine's multi-pattern set.
    fn signatures(&self) -> Vec<Vec<u8>>;

    /// The largest structure this extractor may need to inspect from a single
    /// hit, in bytes. Used to dimension the scan overlap window and to bound the
    /// lookahead handed to [`Extractor::extract`].
    fn max_structure_size(&self) -> usize;

    /// Validate the candidate at `offset` and extract every artefact it yields.
    ///
    /// `data` is the source starting at `offset`, capped to
    /// [`Extractor::max_structure_size`] bytes. Return the validated artefacts,
    /// or a [`Rejection`] if the candidate is not a real structure. Returning an
    /// empty vector is allowed but means "valid, nothing to emit"; prefer a
    /// [`Rejection`] when the candidate is not this format at all.
    fn extract(&self, offset: u64, data: &[u8]) -> Result<Vec<Carved>, Rejection>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carved_hashes_its_bytes() {
        let c = Carved::new(4096, "test.blob", "carve.test", b"abc".to_vec());
        assert_eq!(
            c.raw_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(c.offset, 4096);
        assert_eq!(c.bytes, b"abc");
    }

    #[test]
    fn platform_and_rejection_render() {
        assert_eq!(Platform::Windows.to_string(), "windows");
        assert_eq!(
            Rejection::Truncated {
                needed: 10,
                available: 3
            }
            .to_string(),
            "truncated candidate: needed 10 bytes, 3 available"
        );
    }
}
