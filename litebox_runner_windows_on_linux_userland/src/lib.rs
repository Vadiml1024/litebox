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
use litebox_shim_windows::loader::{ExecutionContext, PeLoader, call_entry_point};
use litebox_shim_windows::syscalls::ntdll::{NtdllApi, memory_protection};
use litebox_shim_windows::tracing::{
    ApiCategory, FilterRule, TraceConfig, TraceFilter, TraceFormat, TraceOutput, TracedNtdllApi,
    Tracer,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Run Windows programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The Windows program to run (PE executable)
    #[arg(required = true, value_hint = clap::ValueHint::FilePath)]
    pub program: String,

    /// Arguments to pass to the program
    #[arg(trailing_var_arg = true)]
    pub arguments: Vec<String>,

    /// Enable API call tracing
    #[arg(long = "trace-apis")]
    pub trace_apis: bool,

    /// Trace output format: text or json
    #[arg(long = "trace-format", default_value = "text")]
    pub trace_format: String,

    /// Trace output file (defaults to stdout)
    #[arg(long = "trace-output")]
    pub trace_output: Option<PathBuf>,

    /// Filter traces by function pattern (e.g., "Nt*File")
    #[arg(long = "trace-filter")]
    pub trace_filter: Option<String>,

    /// Filter traces by category (file_io, console_io, memory)
    #[arg(long = "trace-category")]
    pub trace_category: Option<String>,
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

    // Set up tracing if enabled
    let trace_config = if cli_args.trace_apis {
        let format = match cli_args.trace_format.as_str() {
            "json" => TraceFormat::Json,
            _ => TraceFormat::Text,
        };

        let output = match &cli_args.trace_output {
            Some(path) => TraceOutput::File(path.clone()),
            None => TraceOutput::Stdout,
        };

        TraceConfig::enabled()
            .with_format(format)
            .with_output(output)
    } else {
        TraceConfig::default()
    };

    // Set up trace filters
    let mut trace_filter = TraceFilter::new();
    if let Some(pattern) = &cli_args.trace_filter {
        trace_filter = trace_filter.add_rule(FilterRule::Pattern(pattern.clone()));
    }
    if let Some(category_str) = &cli_args.trace_category {
        let category = match category_str.as_str() {
            "file_io" => ApiCategory::FileIo,
            "console_io" => ApiCategory::ConsoleIo,
            "memory" => ApiCategory::Memory,
            _ => {
                return Err(anyhow!(
                    "Invalid category '{category_str}'. Valid options: file_io, console_io, memory",
                ));
            }
        };
        trace_filter = trace_filter.add_rule(FilterRule::Category(vec![category]));
    }

    // Create tracer
    let tracer = Arc::new(
        Tracer::new(trace_config, trace_filter)
            .map_err(|e| anyhow!("Failed to create tracer: {e}"))?,
    );

    // Initialize the platform (wrapped with tracing if enabled)
    let platform = LinuxPlatformForWindows::new();
    let mut platform = TracedNtdllApi::new(platform, tracer);

    // Calculate total image size (find max virtual address + size)
    let image_size = sections
        .iter()
        .filter_map(|s| (s.virtual_address as usize).checked_add(s.virtual_size as usize))
        .max()
        .ok_or_else(|| anyhow!("Failed to calculate image size: overflow or no sections"))?;

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

    // Apply relocations if needed
    println!("\nApplying relocations...");
    let image_base = pe_loader.image_base();
    if base_address == image_base {
        println!("  No relocations needed (loaded at preferred base)");
    } else {
        println!("  Rebasing from 0x{image_base:X} to 0x{base_address:X}");
        // SAFETY: We allocated the memory and just loaded the sections
        unsafe {
            pe_loader
                .apply_relocations(image_base, base_address)
                .map_err(|e| anyhow!("Failed to apply relocations: {e}"))?;
        }
        println!("  Relocations applied successfully");
    }

    // Resolve imports
    println!("\nResolving imports...");
    let imports = pe_loader
        .imports()
        .map_err(|e| anyhow!("Failed to get imports: {e}"))?;

    if imports.is_empty() {
        println!("  No imports found");
    } else {
        for import_dll in &imports {
            println!("  DLL: {}", import_dll.name);
            println!("    Functions: {}", import_dll.functions.len());

            // Load the DLL and resolve function addresses
            let dll_handle = platform
                .load_library(&import_dll.name)
                .map_err(|e| anyhow!("Failed to load DLL {}: {e}", import_dll.name))?;

            let mut resolved_addresses = Vec::new();
            for func_name in &import_dll.functions {
                match platform.get_proc_address(dll_handle, func_name) {
                    Ok(addr) => {
                        resolved_addresses.push(addr);
                        println!("      {func_name} -> 0x{addr:X}");
                    }
                    Err(e) => {
                        println!("      {func_name} -> NOT FOUND ({e})");
                        // Use a stub address (0) for missing functions
                        resolved_addresses.push(0);
                    }
                }
            }

            // Write resolved addresses to IAT
            // SAFETY: We allocated the memory and loaded the sections
            unsafe {
                pe_loader
                    .write_iat(
                        base_address,
                        &import_dll.name,
                        import_dll.iat_rva,
                        &resolved_addresses,
                    )
                    .map_err(|e| anyhow!("Failed to write IAT: {e}"))?;
            }
        }
        println!("  Import resolution complete");
    }

    // Set up execution context (TEB/PEB)
    println!("\nSetting up execution context...");
    let execution_context =
        ExecutionContext::new(base_address, 0) // Use default stack size
            .map_err(|e| anyhow!("Failed to create execution context: {e}"))?;
    println!("  TEB created at: 0x{:X}", execution_context.teb_address);
    println!(
        "  PEB created with image base: 0x{:X}",
        execution_context.peb.image_base_address
    );
    println!(
        "  Stack range: 0x{:X} - 0x{:X} ({} KB)",
        execution_context.stack_base,
        execution_context.stack_base - execution_context.stack_size,
        execution_context.stack_size / 1024
    );

    // Calculate entry point address
    let entry_point_rva = pe_loader.entry_point();
    let entry_point_address = base_address + entry_point_rva;

    println!("\n[Phase 6 Progress]");
    println!("  ✓ PE loader");
    println!("  ✓ Section loading");
    println!("  ✓ Relocation processing");
    println!("  ✓ Import resolution");
    println!("  ✓ IAT patching");
    println!("  ✓ TEB/PEB setup");
    println!("  → Entry point at: 0x{entry_point_address:X}");

    // Attempt to call the entry point
    // NOTE: This will likely fail in practice because:
    // 1. We don't have actual Windows DLL implementations (only stubs)
    // 2. The TEB is not accessible via GS register
    // 3. Stack setup is minimal
    // 4. ABI translation is incomplete
    println!("\nAttempting to call entry point...");
    println!("WARNING: Entry point execution is experimental and may crash!");
    println!("         Most Windows programs will fail due to missing DLL implementations.");

    // Try to call the entry point
    match unsafe { call_entry_point(entry_point_address, &execution_context) } {
        Ok(exit_code) => {
            println!("\n✓ Entry point executed successfully!");
            println!("  Exit code: {exit_code}");
        }
        Err(e) => {
            println!("\n✗ Entry point execution failed: {e}");
            println!("  This is expected for most Windows programs at this stage.");
            println!("  Full Windows API implementations are needed for actual execution.");
        }
    }

    // For Phase 6 demo: Show that we can do basic console I/O through the platform
    let stdout_handle = platform.get_std_output();
    platform.write_console(stdout_handle, "\nHello from Windows on Linux!\n")?;

    // Clean up allocated memory
    platform.nt_free_virtual_memory(base_address, image_size)?;
    println!("\nMemory deallocated successfully.");

    println!(
        "\n[Progress: PE loader, section loading, basic NTDLL APIs, API tracing, and DLL loading implemented]"
    );
    if cli_args.trace_apis {
        println!(
            "Tracing enabled: format={}, output={:?}",
            cli_args.trace_format,
            cli_args
                .trace_output
                .as_ref()
                .map_or("stdout", |p| p.to_str().unwrap_or("?"))
        );
    }

    Ok(())
}
