//! Development tooling. Invoked as `cargo xtask <command>`.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // Test corpus generation and release helpers will live here.
    eprintln!("xtask: no commands defined yet");
    ExitCode::from(2)
}
