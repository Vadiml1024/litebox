// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner for Windows programs on Linux
//!
//! This crate provides the CLI interface for running Windows PE binaries
//! on Linux using LiteBox.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::loader::PeLoader;

/// Run Windows programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The Windows program to run (PE executable)
    #[arg(required = true, value_hint = clap::ValueHint::FilePath)]
    pub program: String,

    /// Arguments to pass to the program
    #[arg(trailing_var_arg = true)]
    pub arguments: Vec<String>,
}

/// Run Windows programs with LiteBox on unmodified Linux
pub fn run(cli_args: CliArgs) -> Result<()> {
    // Read the PE binary
    let pe_data = std::fs::read(&cli_args.program)?;

    // Load and parse the PE binary
    let pe_loader =
        PeLoader::new(pe_data).map_err(|e| anyhow!("Failed to load PE binary: {}", e))?;

    println!("Loaded PE binary: {}", cli_args.program);
    println!("  Entry point: 0x{:X}", pe_loader.entry_point());
    println!("  Image base: 0x{:X}", pe_loader.image_base());
    println!("  Sections: {}", pe_loader.section_count());

    // Initialize the platform
    let mut platform = LinuxPlatformForWindows::new();

    // For Phase 2 demo: Show that we can do basic console I/O
    let stdout_handle = platform.get_std_output();
    platform.write_console(stdout_handle, "Hello from Windows on Linux!\n")?;

    println!("\n[Phase 2 Complete: PE loader and basic NTDLL APIs implemented]");
    println!("Note: Full program execution not yet implemented - this is the foundation.");

    Ok(())
}
