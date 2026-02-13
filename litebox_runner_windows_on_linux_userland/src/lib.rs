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
use litebox_shim_windows::syscalls::ntdll::NtdllApi;
use litebox_shim_windows::tracing::{
    FilterRule, TraceConfig, TraceFilter, TraceFormat, TraceOutput, TracedNtdllApi, Tracer,
};
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

    /// Enable API tracing
    #[arg(long, default_value = "false")]
    pub trace_apis: bool,

    /// Trace output format (text or json)
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub trace_format: String,

    /// Trace output file (default: stdout)
    #[arg(long)]
    pub trace_output: Option<String>,

    /// Filter traced functions by pattern (e.g., "Nt*File")
    #[arg(long)]
    pub trace_filter: Option<String>,

    /// Filter traced functions by category (file_io, memory, console_io)
    #[arg(long)]
    pub trace_category: Option<String>,
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

    // Configure tracing
    let mut trace_config = if cli_args.trace_apis {
        TraceConfig::enabled()
    } else {
        TraceConfig::default()
    };

    // Set trace format
    if cli_args.trace_apis {
        trace_config = match cli_args.trace_format.as_str() {
            "json" => trace_config.with_format(TraceFormat::Json),
            _ => trace_config.with_format(TraceFormat::Text),
        };

        // Set trace output
        if let Some(output_file) = cli_args.trace_output {
            trace_config = trace_config.with_output(TraceOutput::File(output_file.into()));
        }
    }

    // Configure trace filter
    let mut trace_filter = TraceFilter::new();
    if let Some(pattern) = cli_args.trace_filter {
        trace_filter = trace_filter.add_rule(FilterRule::Pattern(pattern));
    }
    if let Some(category_str) = cli_args.trace_category {
        use litebox_shim_windows::tracing::ApiCategory;
        let category = match category_str.as_str() {
            "file_io" => ApiCategory::FileIo,
            "memory" => ApiCategory::Memory,
            "console_io" => ApiCategory::ConsoleIo,
            _ => {
                return Err(anyhow!(
                    "Unknown category: {}. Valid options: file_io, memory, console_io",
                    category_str
                ));
            }
        };
        trace_filter = trace_filter.add_rule(FilterRule::Category(vec![category]));
    }

    // Create tracer
    let tracer = Arc::new(Tracer::new(trace_config, trace_filter)?);

    // Initialize the platform
    let platform = LinuxPlatformForWindows::new();

    // Wrap platform with tracing
    let mut traced_platform = TracedNtdllApi::new(platform, tracer.clone());

    // For Phase 2 demo: Show that we can do basic console I/O
    let stdout_handle = traced_platform.get_std_output();
    traced_platform.write_console(stdout_handle, "Hello from Windows on Linux!\n")?;

    println!("\n[Phase 3 Complete: API tracing framework implemented]");
    println!("Run with --trace-apis to see API calls being traced.");
    println!(
        "Example: {} --trace-apis --trace-format json",
        cli_args.program
    );

    Ok(())
}
