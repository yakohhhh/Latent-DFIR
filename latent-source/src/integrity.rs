//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Source hashing and integrity
//!

use std::io::{self, Read};
use std::path::Path;

use latent_core::audit::{self, HashPhase};

use crate::error::SourceError;
use crate::{Source, open};

pub mod exit {
    pub const HASH_MISMATCH: u8 = 20;
    pub const SOURCE_CHANGED: u8 = 21;
    pub const READONLY_VIOLATION: u8 = 22;
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("source does not match the expected hash (expected {expected}, got {computed})")]
    ExpectedMismatch { expected: String, computed: String },

    #[error("source changed during processing (open {open}, close {close})")]
    SourceChanged { open: String, close: String },

    #[error(transparent)]
    Source(#[from] SourceError),
}

impl IntegrityError {
    pub fn exit_code(&self) -> u8 {
        match self {
            IntegrityError::ExpectedMismatch { .. } => exit::HASH_MISMATCH,
            IntegrityError::SourceChanged { .. } => exit::SOURCE_CHANGED,
            IntegrityError::Source(SourceError::NotReadOnly { .. }) => exit::READONLY_VIOLATION,
            IntegrityError::Source(_) => 1,
        }
    }
}

impl From<IntegrityError> for latent_core::FatalError {
    fn from(e: IntegrityError) -> Self {
        match e {
            IntegrityError::Source(s) => s.into(),
            other => latent_core::FatalError::IntegrityViolation(other.to_string()),
        }
    }
}

pub struct VerifiedSource {
    source: Box<dyn Source>,
    open_hash: String,
}

impl std::fmt::Debug for VerifiedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedSource")
            .field("path", &self.source.identity().path)
            .field("open_hash", &self.open_hash)
            .finish()
    }
}

impl VerifiedSource {
    pub fn open(path: &Path, expected: Option<&str>) -> Result<Self, IntegrityError> {
        let source = open(path)?;
        audit::source_open(path, source.size());
        Self::wrap(source, expected)
    }

    fn wrap(source: Box<dyn Source>, expected: Option<&str>) -> Result<Self, IntegrityError> {
        let open_hash = hash_source(source.as_ref())?;
        audit::source_hash(HashPhase::Open, "sha256", &open_hash);

        if let Some(want) = expected {
            let want = want.trim().to_ascii_lowercase();
            if want != open_hash {
                return Err(IntegrityError::ExpectedMismatch {
                    expected: want,
                    computed: open_hash,
                });
            }
        }
        Ok(VerifiedSource { source, open_hash })
    }

    pub fn source(&self) -> &dyn Source {
        self.source.as_ref()
    }

    pub fn open_hash(&self) -> &str {
        &self.open_hash
    }

    pub fn size(&self) -> u64 {
        self.source.size()
    }

    pub fn finish(self) -> Result<String, IntegrityError> {
        let close_hash = hash_source(self.source.as_ref())?;
        audit::source_hash(HashPhase::Close, "sha256", &close_hash);
        audit::source_close(&self.source.identity().path);

        if close_hash != self.open_hash {
            return Err(IntegrityError::SourceChanged {
                open: self.open_hash,
                close: close_hash,
            });
        }
        Ok(close_hash)
    }
}

pub fn hash_source(src: &dyn Source) -> Result<String, SourceError> {
    latent_core::sha256_reader(SourceReader { src, pos: 0 })
        .map_err(|e| SourceError::io(&src.identity().path, e))
}

struct SourceReader<'a> {
    src: &'a dyn Source,
    pos: u64,
}

impl Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read_at(self.pos, buf).map_err(io::Error::other)?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Format, Identity};
    use std::io::Write;
    use std::sync::{Arc, Mutex, MutexGuard};

    // tracing caches callsite interest process-wide, so tests that emit audit
    // events must not run alongside the one that captures them.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn evidence(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn hash_matches_the_nist_vector() {
        let f = evidence(b"abc");
        let s = open(f.path()).unwrap();
        assert_eq!(
            hash_source(s.as_ref()).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn open_then_finish_agree_when_nothing_changes() {
        let _s = serial();
        let f = evidence(b"some evidence bytes");
        let v = VerifiedSource::open(f.path(), None).unwrap();
        let open = v.open_hash().to_string();
        assert_eq!(v.finish().unwrap(), open);
    }

    #[test]
    fn right_expected_hash_is_accepted() {
        let _s = serial();
        let f = evidence(b"payload");
        let want = hash_source(open(f.path()).unwrap().as_ref()).unwrap();
        let v =
            VerifiedSource::open(f.path(), Some(&format!("  {}  ", want.to_uppercase()))).unwrap();
        v.finish().unwrap();
    }

    #[test]
    fn wrong_expected_hash_aborts_before_use() {
        let _s = serial();
        let f = evidence(b"payload");
        let err = VerifiedSource::open(f.path(), Some(&"00".repeat(32))).unwrap_err();
        assert!(matches!(err, IntegrityError::ExpectedMismatch { .. }));
        assert_eq!(err.exit_code(), exit::HASH_MISMATCH);
    }

    #[derive(Clone)]
    struct Flip {
        byte: Arc<Mutex<u8>>,
        id: Identity,
    }

    impl Source for Flip {
        fn size(&self) -> u64 {
            64
        }
        fn identity(&self) -> &Identity {
            &self.id
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, SourceError> {
            if offset >= 64 {
                return Ok(0);
            }
            let n = buf.len().min((64 - offset) as usize);
            buf[..n].fill(*self.byte.lock().unwrap());
            Ok(n)
        }
    }

    #[test]
    fn a_source_changing_mid_run_is_caught() {
        let _s = serial();
        let flip = Flip {
            byte: Arc::new(Mutex::new(0)),
            id: Identity {
                path: "mem://flip".into(),
                format: Format::Raw,
            },
        };
        let v = VerifiedSource::wrap(Box::new(flip.clone()), None).unwrap();
        *flip.byte.lock().unwrap() = 1;
        let err = v.finish().unwrap_err();
        assert!(matches!(err, IntegrityError::SourceChanged { .. }));
        assert_eq!(err.exit_code(), exit::SOURCE_CHANGED);
    }

    #[test]
    fn both_hashes_reach_the_audit_log() {
        let _s = serial();
        use std::io;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        struct G(Arc<Mutex<Vec<u8>>>);
        impl io::Write for G {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Buf {
            type Writer = G;
            fn make_writer(&'a self) -> G {
                G(self.0.clone())
            }
        }

        let f = evidence(b"trace me");
        let sink = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Buf(sink.clone()))
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();

        let hash = tracing::subscriber::with_default(subscriber, || {
            let v = VerifiedSource::open(f.path(), None).unwrap();
            let h = v.open_hash().to_string();
            v.finish().unwrap();
            h
        });

        let log = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert_eq!(log.matches(&hash).count(), 2);
        assert!(log.contains("open"));
        assert!(log.contains("close"));
    }

    #[test]
    fn processing_touches_no_file_in_the_tree() {
        let _s = serial();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        std::fs::write(&path, vec![7u8; 4096]).unwrap();

        let snapshot = |d: &Path| -> Vec<(std::ffi::OsString, u64)> {
            let mut v: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), e.metadata().unwrap().len())
                })
                .collect();
            v.sort();
            v
        };

        let before = snapshot(dir.path());
        let v = VerifiedSource::open(&path, None).unwrap();
        v.finish().unwrap();
        assert_eq!(before, snapshot(dir.path()));
    }
}
