//! Command line entry point for `latent`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "latent",
    version,
    about = "Reveal destroyed event logs through global template resolution"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a source and extract log records
    Scan { source: PathBuf },
    /// Resolve templates on an existing extraction
    Resolve { artefacts: PathBuf },
    /// Merge and deduplicate several result sets
    Merge {
        #[arg(required = true, num_args = 2..)]
        inputs: Vec<PathBuf>,
    },
    /// Analyse record gaps and build the destruction report
    Gaps { source: PathBuf },
    /// Generate reports from existing results
    Report { results: PathBuf },
    /// Manage the template corpus
    Corpus {
        #[command(subcommand)]
        action: CorpusAction,
    },
    /// Check a traceability manifest against its outputs
    Verify { manifest: PathBuf },
    /// Run the full pipeline with sensible defaults
    Triage { source: PathBuf },
}

#[derive(Subcommand)]
enum CorpusAction {
    /// Build a template corpus from a clean reference machine
    Build { reference: PathBuf },
    /// List what the embedded corpus contains
    Info,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Every subcommand is a stub for now; they land one by one.
    let name = match cli.command {
        Command::Scan { .. } => "scan",
        Command::Resolve { .. } => "resolve",
        Command::Merge { .. } => "merge",
        Command::Gaps { .. } => "gaps",
        Command::Report { .. } => "report",
        Command::Corpus { .. } => "corpus",
        Command::Verify { .. } => "verify",
        Command::Triage { .. } => "triage",
    };
    eprintln!("latent: '{name}' is not implemented yet");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        super::Cli::command().debug_assert();
    }
}
