## What

## Why

Closes #

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features --locked` passes
- [ ] No new `unsafe`, or it is justified in the code and covered by a test
- [ ] Nothing in this change opens evidence in write mode or touches the network
