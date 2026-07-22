# Architecture

## Workspace layout

| Crate | Role |
|-------|------|
| `latent-core` | Shared types: record model, L0-L4 confidence scale, errors, provenance. Depends on nothing else in the workspace. |
| `latent-source` | Evidence access: raw/dd, E01, VMDK, VHDX, QCOW2, partitions, strict read-only opening, source hashing. |
| `latent-scan` | Parallel block scanning, overlap windows, multi-pattern signature search, scheduling. |
| `latent-carve` | The extractor interface and one submodule per format (evtx, journald, utmp, registry, ntfs, ...). |
| `latent-template` | Global template database, the resolution cascade, structural fingerprinting, corpus management. |
| `latent-timeline` | Merge with intact logs, deduplication, UTC ordering, gap detection. |
| `latent-detect` | Anti-anti-forensics: wipe events, log resets, Sigma rules, ATT&CK tagging. |
| `latent-output` | ECS JSONL, Timeline Explorer CSV, EVTX reconstruction, HTML/Markdown reports, traceability manifest. |
| `latent-cli` | The `latent` binary: argument parsing, configuration, orchestration. |
| `xtask` | Development tooling (test corpus generation, release helpers). Not shipped. |

Two rules hold everywhere:

1. No circular dependencies between crates.
2. The core knows no extractor. Adding a format means implementing the extractor interface in `latent-carve` and registering it. Nothing else changes.

## Processing pipeline

```
source
  |- input hash
  |- parallel scan
  |    |- pass 1: index templates from intact chunks -> global template database
  |    |- pass 2: extract record candidates
  |
  template resolution (cascade L0 -> L4)
  |
  ECS normalization
  |
  merge + dedup + ordering
  |    |- gap analysis -> destruction report
  |    |- Sigma / ATT&CK
  |
  outputs -> traceability manifest + output hashes
```

The two-pass design is the point of the tool. Templates are indexed across the whole source before any decoding is attempted, which is what makes records decodable after their own chunk is destroyed. A single-pass tool cannot do this.

## Confidence scale

Every record carries a level from L0 (intact chunk, valid checksum, local template) to L4 (raw substitution values only). The level is set during template resolution, propagated through every output format, and filterable from the CLI. Downstream consumers use `latent.reconstructed` and `latent.confidence` to keep observed facts visually separate from reconstructed data.

## Forensic invariants

- Evidence is opened read-only and the mode is verified at the syscall level.
- Source hashes are computed at open and at close; divergence aborts the run.
- Output is deterministic for a given input and parameter set.
- No network access in normal operation; anything requiring it must be opt-in and off by default.
- All writes go to the designated output directory, never next to the evidence.
