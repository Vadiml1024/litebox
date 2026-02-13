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
use litebox_shim_windows::syscalls::ntdll::{NtdllApi, memory_protection};

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
    let pe_loader = PeLoader::new(pe_data).map_err(|e| anyhow!("Failed to load PE binary: {e}"))?;

    println!("Loaded PE binary: {}", cli_args.program);
    println!("  Entry point: 0x{:X}", pe_loader.entry_point());
    println!("  Image base: 0x{:X}", pe_loader.image_base());
    println!("  Sections: {}", pe_loader.section_count());

    // Get section information
    let sections = pe_loader
        .sections()
        .map_err(|e| anyhow!("Failed to get sections: {e}"))?;

    println!("\nSections:");
    for section in &sections {
        println!(
            "  {} - VA: 0x{:X}, Size: {} bytes, Characteristics: 0x{:X}",
            section.name, section.virtual_address, section.virtual_size, section.characteristics
        );
    }

    // Initialize the platform
    let mut platform = LinuxPlatformForWindows::new();

    // Calculate total image size (find max virtual address + size)
    let image_size = sections
        .iter()
        .map(|s| s.virtual_address as usize + s.virtual_size as usize)
        .max()
        .unwrap_or(0);

    println!("\nAllocating memory for PE image:");
    println!(
        "  Image size: {} bytes ({} KB)",
        image_size,
        image_size / 1024
    );

    // Allocate memory for the PE image with read/write/execute permissions
    let base_address = platform
        .nt_allocate_virtual_memory(image_size, memory_protection::PAGE_EXECUTE_READWRITE)?;

    println!("  Allocated at: 0x{base_address:X}");

    // Load sections into the allocated memory
    println!("\nLoading sections into memory...");
    // SAFETY: We just allocated memory of the correct size with the platform
    let loaded_size = unsafe {
        pe_loader
            .load_sections(base_address)
            .map_err(|e| anyhow!("Failed to load sections: {e}"))?
    };
    println!("  Loaded {loaded_size} bytes");

    // For Phase 2/3 demo: Show that we can do basic console I/O through the platform
    let stdout_handle = platform.get_std_output();
    platform.write_console(stdout_handle, "\nHello from Windows on Linux!\n")?;

    // Clean up allocated memory
    platform.nt_free_virtual_memory(base_address, image_size)?;
    println!("\nMemory deallocated successfully.");

    println!("\n[Progress: PE loader, section loading, and basic NTDLL APIs implemented]");
    println!("Note: Actual program execution not yet implemented - working on foundation.");

    Ok(())
}
