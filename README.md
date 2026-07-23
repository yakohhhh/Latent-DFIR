# Latent

[![CI](https://github.com/yakohhhh/Latent/actions/workflows/ci.yml/badge.svg)](https://github.com/yakohhhh/Latent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Revealing destroyed event logs through global template resolution.

Latent is a command line DFIR tool that reconstructs event logs an attacker has wiped. It carves individual log records out of disk images, unallocated space, memory dumps and corrupted files, resolves their structure through a global template database, and turns them into a normalized timeline you can defend in a report.

## Why

Clearing logs (MITRE ATT&CK T1070.001 / T1070.002) is now a standard step in ransomware playbooks. The analyst lands on an encrypted system with empty event logs, and the questions that matter (entry point, dwell time, lateral movement, exfiltration) go unanswered.

Wiping a log is almost always a logical operation, not a physical one. The record data stays on disk in unallocated space until it gets overwritten. Modern log formats are also built from self-contained blocks: a 64 KiB EVTX chunk carries its own string and template tables, so a single surviving chunk is decodable on its own even when the file around it is gone.

Existing tools either carve whole files (useless once the file is fragmented), only parse intact logs, or resolve templates within the local chunk and give up beyond it. Latent works at the record level and looks for templates across the whole image and beyond.

## How it works

Latent scans the source twice. The first pass indexes every template found in intact chunks anywhere on the image into a global template database. The second pass extracts records and resolves each one through a cascade:

1. the template referenced locally in its own chunk,
2. a matching template found elsewhere on the same source,
3. a pre-built corpus of known templates, indexed by provider, event id and OS build,
4. structural inference from the shape of the substitution array.

Every record that comes out carries an explicit confidence level:

| Level | Meaning | Use |
|-------|---------|-----|
| L0 | Intact chunk, valid checksum, local template | Direct evidence |
| L1 | Template recovered from another chunk of the same source | Evidence, worth a note in the report |
| L2 | Template from the external corpus, matching OS build | Strong lead, corroborate |
| L3 | Structure inferred from the substitution fingerprint | Investigative lead only |
| L4 | Raw substitution values, no structure | Manual interpretation |

No record is ever presented without its level, and an L3 or L4 record is never displayed as if it were intact data.

## Forensic guarantees

- Strict read-only access to evidence, enforced at the syscall level, never just by convention.
- Source hashes computed at open and at close; a mismatch is a fatal error.
- Deterministic output: same input and parameters, bit-identical results.
- Fully offline. No telemetry, no network access in normal operation.
- Every run produces an audit log and a traceability manifest suitable for attaching to an expert report.
- No log modification capability exists anywhere in the tool, and none will be added.

## Status

Early development. The workspace skeleton and CI are in place; the scanning engine and the EVTX pipeline are being built first. Progress is tracked through the [milestones](https://github.com/yakohhhh/Latent/milestones), from L0 (foundation) to L9 (1.0 release). Milestone numbering follows the roadmap lots and has nothing to do with the L0-L4 confidence scale above.

## Planned interface

```
latent scan <source>        Scan a source and extract log records
latent resolve <artefacts>  Resolve templates on an existing extraction
latent merge <a> <b> ...    Merge and deduplicate several result sets
latent gaps <source>        Analyse record gaps, build the destruction report
latent report <results>     Generate reports
latent corpus build <ref>   Build a template corpus from a reference machine
latent corpus info          List what the embedded corpus contains
latent verify <manifest>    Check a manifest against its outputs
latent triage <source>      Full pipeline with sensible defaults
```

Input formats: raw/dd, E01/EWF, VMDK, VHDX, QCOW2, collection directories (KAPE, UAC, Velociraptor), memory dumps. Target artefacts: EVTX, journald, wtmp/btmp/utmp, auditd, registry hives and transaction logs, $MFT/$UsnJrnl, and more. Output: ECS JSONL for Elastic/SOF-ELK, CSV for Timeline Explorer, HTML and Markdown reports.

## Building from source

Requires a stable Rust toolchain (1.88 or later).

```
git clone https://github.com/yakohhhh/Latent.git
cd Latent
cargo build --release
./target/release/latent --help
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Architecture notes live in [docs/architecture.md](docs/architecture.md).

## Legal notice

Latent is an investigation tool for systems you own or are explicitly authorized to examine. Using it on anything else is illegal. Reconstructed records are not equivalent to intact logs: levels L3 and L4 are investigative leads and must not be presented as direct evidence.

## License

Apache-2.0. See [LICENSE](LICENSE).
