//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Audit log and diagnostic logging
//!

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::filter::{FilterExt, LevelFilter, filter_fn};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

use crate::hash;

pub const AUDIT_TARGET: &str = "latent::audit";

pub const AUDIT_FILE_NAME: &str = "audit.jsonl";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    Quiet,
    #[default]
    Normal,
    Verbose,
    VeryVerbose,
}

impl Verbosity {
    pub fn from_flags(quiet: bool, verbose: u8) -> Self {
        match (quiet, verbose) {
            (true, _) => Verbosity::Quiet,
            (_, 0) => Verbosity::Normal,
            (_, 1) => Verbosity::Verbose,
            _ => Verbosity::VeryVerbose,
        }
    }

    fn level(self) -> LevelFilter {
        match self {
            Verbosity::Quiet => LevelFilter::WARN,
            Verbosity::Normal => LevelFilter::INFO,
            Verbosity::Verbose => LevelFilter::DEBUG,
            Verbosity::VeryVerbose => LevelFilter::TRACE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashPhase {
    Open,
    Close,
}

impl HashPhase {
    fn as_str(self) -> &'static str {
        match self {
            HashPhase::Open => "open",
            HashPhase::Close => "close",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("could not open the audit log at {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("could not write the audit log: {0}")]
    Write(io::Error),
    #[error("a tracing subscriber is already installed")]
    AlreadyInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDigest {
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Clone)]
struct AuditWriter {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    file: BufWriter<File>,
    err: Option<io::Error>,
}

impl AuditWriter {
    fn create(path: &Path) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| AuditError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        let inner = Inner {
            file: BufWriter::new(file),
            err: None,
        };
        Ok(AuditWriter {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    fn line(&self, line: &str) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.err.is_some() {
            return;
        }
        if let Err(e) = g
            .file
            .write_all(line.as_bytes())
            .and_then(|()| g.file.write_all(b"\n"))
        {
            g.err = Some(e);
        }
    }

    fn flush(&self) -> io::Result<()> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .file
            .flush()
    }

    fn take_err(&self) -> Option<io::Error> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .err
            .take()
    }
}

fn line(mut fields: BTreeMap<String, Value>) -> String {
    if let Ok(ts) = OffsetDateTime::now_utc().format(&Rfc3339) {
        fields.insert("ts".into(), Value::String(ts));
    }
    serde_json::to_string(&fields).unwrap_or_else(|_| "{}".into())
}

struct AuditLayer {
    writer: AuditWriter,
}

impl<S: Subscriber> Layer<S> for AuditLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut v = FieldVisitor(BTreeMap::new());
        event.record(&mut v);
        self.writer.line(&line(v.0));
    }
}

struct FieldVisitor(BTreeMap<String, Value>);

impl Visit for FieldVisitor {
    fn record_str(&mut self, f: &Field, v: &str) {
        self.0.insert(f.name().into(), Value::String(v.into()));
    }
    fn record_u64(&mut self, f: &Field, v: u64) {
        self.0.insert(f.name().into(), Value::from(v));
    }
    fn record_i64(&mut self, f: &Field, v: i64) {
        self.0.insert(f.name().into(), Value::from(v));
    }
    fn record_bool(&mut self, f: &Field, v: bool) {
        self.0.insert(f.name().into(), Value::from(v));
    }
    fn record_f64(&mut self, f: &Field, v: f64) {
        self.0.insert(f.name().into(), Value::from(v));
    }
    fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
        self.0
            .insert(f.name().into(), Value::String(format!("{v:?}")));
    }
}

pub struct AuditLog {
    writer: AuditWriter,
    path: PathBuf,
}

impl AuditLog {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn close(self) -> Result<AuditDigest, AuditError> {
        self.writer.line(&line(BTreeMap::from([(
            "kind".into(),
            Value::from("run_end"),
        )])));
        self.writer.flush().map_err(AuditError::Write)?;
        if let Some(e) = self.writer.take_err() {
            return Err(AuditError::Write(e));
        }

        let open = |source| AuditError::Open {
            path: self.path.clone(),
            source,
        };
        let file = File::open(&self.path).map_err(open)?;
        let bytes = file.metadata().map_err(open)?.len();
        let sha256 = hash::sha256_reader(BufReader::new(file)).map_err(open)?;
        Ok(AuditDigest { sha256, bytes })
    }
}

fn build<W>(
    output_dir: &Path,
    verbosity: Verbosity,
    diag: W,
    version: &str,
    command: &str,
) -> Result<(AuditLog, impl Subscriber + Send + Sync + 'static), AuditError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    std::fs::create_dir_all(output_dir).map_err(|source| AuditError::Open {
        path: output_dir.to_path_buf(),
        source,
    })?;
    let path = output_dir.join(AUDIT_FILE_NAME);
    let writer = AuditWriter::create(&path)?;

    writer.line(&line(BTreeMap::from([
        ("kind".into(), Value::from("run_start")),
        ("version".into(), Value::from(version)),
        ("command".into(), Value::from(command)),
    ])));

    let audit = AuditLayer {
        writer: writer.clone(),
    }
    .with_filter(filter_fn(|m| m.target() == AUDIT_TARGET));
    let diagnostics = tracing_subscriber::fmt::layer()
        .with_writer(diag)
        .with_ansi(false)
        .with_target(false)
        .with_filter(
            verbosity
                .level()
                .and(filter_fn(|m| m.target() != AUDIT_TARGET)),
        );

    let subscriber = tracing_subscriber::registry().with(audit).with(diagnostics);
    Ok((AuditLog { writer, path }, subscriber))
}

pub fn init(
    output_dir: &Path,
    verbosity: Verbosity,
    version: &str,
    command: &str,
) -> Result<AuditLog, AuditError> {
    let (log, subscriber) = build(output_dir, verbosity, io::stderr, version, command)?;
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| AuditError::AlreadyInstalled)?;
    Ok(log)
}

pub fn source_open(path: &Path, size: u64) {
    let path = path.display().to_string();
    tracing::event!(target: AUDIT_TARGET, tracing::Level::INFO, kind = "source_open", path = path.as_str(), size = size);
}

pub fn source_hash(phase: HashPhase, algorithm: &str, digest: &str) {
    tracing::event!(target: AUDIT_TARGET, tracing::Level::INFO, kind = "source_hash", phase = phase.as_str(), algorithm = algorithm, digest = digest);
}

pub fn phase(name: &str) {
    tracing::event!(target: AUDIT_TARGET, tracing::Level::INFO, kind = "phase", name = name);
}

pub fn source_close(path: &Path) {
    let path = path.display().to_string();
    tracing::event!(target: AUDIT_TARGET, tracing::Level::INFO, kind = "source_close", path = path.as_str());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    struct BufGuard(Arc<Mutex<Vec<u8>>>);

    impl Write for BufGuard {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Buf {
        type Writer = BufGuard;
        fn make_writer(&'a self) -> BufGuard {
            BufGuard(self.0.clone())
        }
    }

    fn slurp(path: &Path) -> String {
        let mut s = String::new();
        File::open(path).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    fn a_run() -> (tempfile::TempDir, String, String, AuditDigest) {
        let dir = tempfile::tempdir().unwrap();
        let diag = Arc::new(Mutex::new(Vec::new()));
        let (log, sub) = build(
            dir.path(),
            Verbosity::VeryVerbose,
            Buf(diag.clone()),
            "9.9.9",
            "latent scan /evidence/img.dd",
        )
        .unwrap();

        tracing::subscriber::with_default(sub, || {
            source_open(Path::new("/evidence/img.dd"), 1_048_576);
            source_hash(HashPhase::Open, "sha256", "deadbeef");
            phase("scan");
            tracing::warn!("a human readable diagnostic");
            tracing::info!(count = 3, "some verbose detail");
            source_close(Path::new("/evidence/img.dd"));
        });

        let digest = log.close().unwrap();
        let audit = slurp(&dir.path().join(AUDIT_FILE_NAME));
        let diagnostics = String::from_utf8(diag.lock().unwrap().clone()).unwrap();
        (dir, audit, diagnostics, digest)
    }

    #[test]
    fn audit_file_has_every_mandatory_entry() {
        let (_d, audit, ..) = a_run();
        for needle in [
            "\"kind\":\"run_start\"",
            "\"version\":\"9.9.9\"",
            "\"command\":\"latent scan /evidence/img.dd\"",
            "\"kind\":\"source_open\"",
            "\"kind\":\"source_hash\"",
            "\"kind\":\"phase\"",
            "\"kind\":\"source_close\"",
            "\"kind\":\"run_end\"",
        ] {
            assert!(audit.contains(needle), "missing {needle}");
        }
        for l in audit.lines() {
            assert!(l.contains("\"ts\":"), "no timestamp: {l}");
        }
    }

    #[test]
    fn the_two_streams_do_not_mix() {
        let (_d, audit, diag, _) = a_run();
        assert!(!audit.contains("a human readable diagnostic"));
        assert!(!audit.contains("some verbose detail"));
        assert!(diag.contains("a human readable diagnostic"));
        assert!(!diag.contains("source_open"));
        assert!(!diag.contains("run_start"));
    }

    #[test]
    fn quiet_hides_info_keeps_warnings() {
        let dir = tempfile::tempdir().unwrap();
        let diag = Arc::new(Mutex::new(Vec::new()));
        let (log, sub) = build(
            dir.path(),
            Verbosity::Quiet,
            Buf(diag.clone()),
            "0",
            "latent",
        )
        .unwrap();
        tracing::subscriber::with_default(sub, || {
            tracing::info!("hidden");
            tracing::warn!("shown");
        });
        log.close().unwrap();
        let out = String::from_utf8(diag.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("hidden"));
        assert!(out.contains("shown"));
    }

    #[test]
    fn close_digest_matches_the_file() {
        let (dir, .., digest) = a_run();
        let path = dir.path().join(AUDIT_FILE_NAME);
        assert_eq!(
            digest.sha256,
            hash::sha256_reader(File::open(&path).unwrap()).unwrap()
        );
        assert_eq!(digest.bytes, std::fs::metadata(&path).unwrap().len());
    }

    #[test]
    fn output_dir_holds_only_the_audit_file() {
        let (dir, ..) = a_run();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [AUDIT_FILE_NAME]);
    }
}
