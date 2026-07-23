# Changelog

All notable changes to Latent are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- latent-core: the record model, the L0-L4 confidence scale, resolution methods and the recoverable/fatal error taxonomy, with deterministic serde output
- latent-core: tracing-based logging that keeps a machine-readable JSONL audit trail (source open, hashing, phases, close, tool version and command line) strictly apart from the human diagnostic stream, plus a streaming SHA-256 helper and an audit-file digest at close
- latent-source: the Source abstraction (positioned reads plus size), raw/dd images backed by mmap with a positioned-read fallback, and recursive deterministic enumeration of triage collection directories
- latent-source: strict read-only opening (O_RDONLY plus a descriptor check on Unix, GENERIC_READ on Windows) and SHA-256 integrity, hashing the source at open and again at close, comparing against an optional expected hash, and aborting with distinct exit codes when the evidence does not match or changes mid-run
- latent-source: MBR (primary and logical) and GPT (with CRC32 checks) partition parsing, an offset-and-length Window sub-source for targeting a partition or an arbitrary byte range, and a graceful whole-source fallback when there is no usable table
- latent-source: read-only VMDK (monolithic sparse), VHDX (fixed and dynamic) and QCOW2 v3 support, translating to the flat guest address space, reading unwritten regions as zeros, rejecting parent and backing chains, and bounding every table lookup against malformed input
- Cargo workspace skeleton: core, source, scan, carve, template, timeline, detect, output, cli and xtask crates
- CLI stub with the planned subcommands (scan, resolve, merge, gaps, report, corpus, verify, triage)
- CI pipeline: format, lint, tests on Linux/Windows/macOS, docs, dependency audit
- Release pipeline: standalone binaries for Linux (static musl), Windows and macOS on x86_64 and aarch64, with checksums and build provenance
