# Changelog

All notable changes to Latent are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- latent-core: the record model, the L0-L4 confidence scale, resolution methods and the recoverable/fatal error taxonomy, with deterministic serde output
- Cargo workspace skeleton: core, source, scan, carve, template, timeline, detect, output, cli and xtask crates
- CLI stub with the planned subcommands (scan, resolve, merge, gaps, report, corpus, verify, triage)
- CI pipeline: format, lint, tests on Linux/Windows/macOS, docs, dependency audit
- Release pipeline: standalone binaries for Linux (static musl), Windows and macOS on x86_64 and aarch64, with checksums and build provenance
