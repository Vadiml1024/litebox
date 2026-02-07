// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Core runner logic for executing Windows PE binaries on Linux.

use anyhow::{Context, Result};
use litebox_shim_windows::PeBinary;
use std::fs;
use std::path::Path;

/// Load and inspect a Windows PE binary.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid PE binary.
pub fn load_pe_binary(path: &Path) -> Result<()> {
    // Read the PE file
    let data = fs::read(path).context("Failed to read PE file")?;

    // Parse the PE binary
    let pe = PeBinary::parse(&data).context("Failed to parse PE binary")?;

    // Display basic information
    println!("PE Binary Information:");
    println!("  Entry Point: {:#x}", pe.entry_point());
    println!("  Image Base: {:#x}", pe.image_base());
    println!("  Image Size: {:#x}", pe.image_size());
    println!("  Sections: {}", pe.sections.len());

    // Display section information
    println!("\nSections:");
    for section in pe.sections {
        println!(
            "  {} - VA: {:#x}, Size: {:#x}, Characteristics: {:#x}",
            section.name_str(),
            section.virtual_address,
            section.virtual_size,
            section.characteristics
        );
    }

    // Check for relocations
    if let Some(reloc_dir) = pe.relocation_directory() {
        println!(
            "\nRelocation Directory: RVA {:#x}, Size {:#x}",
            reloc_dir.virtual_address, reloc_dir.size
        );

        let relocations = pe
            .parse_relocations()
            .context("Failed to parse relocations")?;
        println!("  Total relocations: {}", relocations.len());
    } else {
        println!("\nNo relocation directory found");
    }

    Ok(())
}
