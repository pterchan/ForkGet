//! Support-matrix consistency checker.
//!
//! Exit codes: `0` the repository is consistent, `1` enforcement failures,
//! `2` usage or load errors.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fg_matrix::{CapabilityView, DEFAULT_CORPUS_DIR, MatrixError, Repository};

#[derive(Parser)]
#[command(
    name = "fg-matrix",
    about = "Support-matrix consistency and evidence enforcement"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify manifest/public-matrix agreement and evidence resolution;
    /// with --tag, also prove the tag resolves to a non-empty case set.
    Check {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = DEFAULT_CORPUS_DIR)]
        corpus: PathBuf,
        #[arg(long)]
        tag: Option<String>,
    },
    /// Resolve one capability to its evidence; unknown ids are errors.
    Capability {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = DEFAULT_CORPUS_DIR)]
        corpus: PathBuf,
        #[arg(long)]
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Check { root, corpus, tag } => check(root, corpus, tag),
        Command::Capability { root, corpus, id } => capability(root, corpus, id),
    };
    match result {
        Ok(code) => code,
        Err(error) => {
            eprintln!("fg-matrix: {error}");
            ExitCode::from(2)
        }
    }
}

fn check(root: PathBuf, corpus: PathBuf, tag: Option<String>) -> Result<ExitCode, MatrixError> {
    let repository = Repository::load(&root, &corpus)?;
    let failures = repository.check();
    if let Some(tag) = &tag {
        let selection = repository.select_tag(tag)?;
        println!(
            "tag '{tag}' resolves to {} case selections",
            selection.len()
        );
    }
    let implemented = repository
        .manifest
        .capabilities
        .iter()
        .filter(|c| c.is_implemented())
        .count();
    let planned = repository.manifest.capabilities.len() - implemented;
    println!(
        "capabilities: {implemented} implemented, {planned} planned; corpus cases: {}",
        repository.corpus.len()
    );
    if failures.is_empty() {
        println!("matrix check passed");
        Ok(ExitCode::SUCCESS)
    } else {
        for failure in &failures {
            eprintln!("fg-matrix: {failure}");
        }
        eprintln!("fg-matrix: {} enforcement failure(s)", failures.len());
        Ok(ExitCode::from(1))
    }
}

fn capability(root: PathBuf, corpus: PathBuf, id: String) -> Result<ExitCode, MatrixError> {
    let repository = Repository::load(&root, &corpus)?;
    let view: CapabilityView<'_> = repository.resolve_capability(&id)?;
    if view.planned {
        println!(
            "capability '{}' is planned; it stays visible without being counted as passed",
            view.capability.id
        );
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "capability '{}' ({})",
        view.capability.id, view.capability.status
    );
    for engine in &view.capability.engines {
        println!("  engine: {engine}");
    }
    for case in &view.capability.cases {
        println!("  case: {case}");
    }
    for file in &view.capability.files {
        println!("  file: {file}");
    }
    Ok(ExitCode::SUCCESS)
}
