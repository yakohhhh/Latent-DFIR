# Contributing

Thanks for taking the time. Latent is at an early stage, so the most useful contributions right now are picking up an open issue, reporting format edge cases, and reviewing parser code.

## Setup

A stable Rust toolchain (1.85+) is all you need. `rust-toolchain.toml` pins the channel and pulls rustfmt and clippy.

Before pushing, make sure this passes locally:

```
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

## Ground rules

- The core crates never open anything in write mode and never touch the network. Any patch that does either will be rejected, whatever the reason.
- No `unsafe` without a written justification in the code and a test covering it.
- Anything that parses evidence data is hostile-input territory: bound every length before allocating, never panic on malformed input, add a regression test for every bug found.
- No feature that modifies, forges or deletes logs. This is a hard project rule, not a style preference.

## Commits and PRs

- Conventional commit messages, in English, imperative mood: `feat(scan): add overlap window`, `fix(carve): reject chunks with a truncated header`.
- Keep PRs small and linked to an issue. One topic per PR.
- New extractors implement the extractor interface in `latent-carve` and register themselves; they must not require changes in the core crates.

## Issues

Issues are labeled by type, priority and module, and grouped into milestones L0 to L9 that mirror the roadmap lots (a numbering unrelated to the L0-L4 confidence scale). `priority: must` items are what v1.0 needs; that is where help matters most.
