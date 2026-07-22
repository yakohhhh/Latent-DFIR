# Changelog

All notable changes to Latent are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- latent-core: the record model, the L0-L4 confidence scale, resolution methods and the recoverable/fatal error taxonomy, with deterministic serde output
- latent-core: tracing-based logging that keeps a machine-readable JSONL audit trail (source open, hashing, phases, close, tool version and command line) strictly apart from the human diagnostic stream, plus a streaming SHA-256 helper and an audit-file digest at close
- latent-source: the Source abstraction (positioned reads plus size), raw/dd images backed by mmap with a positioned-read fallback, and recursive deterministic enumeration of triage collection directories
- Cargo workspace skeleton: core, source, scan, carve, template, timeline, detect, output, cli and xtask crates
- CLI stub with the planned subcommands (scan, resolve, merge, gaps, report, corpus, verify, triage)
- CI pipeline: format, lint, tests on Linux/Windows/macOS, docs, dependency audit
- Release pipeline: standalone binaries for Linux (static musl), Windows and macOS on x86_64 and aarch64, with checksums and build provenance
