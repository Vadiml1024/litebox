// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! CLI entry point for the Windows on Linux runner.

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "litebox_runner_windows_on_linux_userland")]
#[command(about = "Run Windows PE binaries on Linux", long_about = None)]
struct Args {
    /// Path to the Windows PE binary to execute
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        println!("Loading PE binary: {}", args.binary.display());
    }

    // Phase 1: Just load and inspect the PE binary
    litebox_runner_windows_on_linux_userland::load_pe_binary(&args.binary)?;

    Ok(())
}
