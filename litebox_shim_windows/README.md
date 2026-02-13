# litebox_shim_windows

Windows shim layer for running Windows PE binaries on Linux.

## Overview

This crate provides the "North" interface for Windows programs, implementing:

- **PE Loader**: Parses and loads Windows PE (Portable Executable) binaries
- **NTDLL Interface**: Defines Windows NTDLL syscall APIs
- **API Tracing**: Complete framework for tracing Windows API calls

## Phase 1: Foundation & PE Loader ✅

- ✅ PE header parsing (DOS, NT, Optional headers)
- ✅ Basic validation (signature, machine type)
- ✅ Extract entry point and image base

## Phase 2: Core NTDLL APIs ✅

- ✅ File I/O API definitions (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- ✅ Console I/O APIs
- ✅ Memory management APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)

## Phase 3: API Tracing Framework ✅

- ✅ Configurable tracing system (enable/disable at runtime)
- ✅ Multiple output formats (text, JSON)
- ✅ Flexible filtering (by function name pattern, by API category)
- ✅ Transparent tracing wrapper (TracedNtdllApi)
- ✅ Syscall-level hooks for all NTDLL APIs
- ✅ Output to stdout or file

## Usage

### Basic PE Loading

```rust
use litebox_shim_windows::loader::PeLoader;

let pe_data = std::fs::read("program.exe")?;
let loader = PeLoader::new(pe_data)?;
println!("Entry point: 0x{:X}", loader.entry_point());
```

### API Tracing

```rust
use litebox_shim_windows::tracing::{TraceConfig, TraceFilter, Tracer, TracedNtdllApi};
use litebox_shim_windows::syscalls::ntdll::NtdllApi;
use std::sync::Arc;

// Configure tracing
let config = TraceConfig::enabled()
    .with_format(TraceFormat::Text);
let filter = TraceFilter::new();
let tracer = Arc::new(Tracer::new(config, filter)?);

// Wrap your platform with tracing
let platform = /* your NtdllApi implementation */;
let mut traced_platform = TracedNtdllApi::new(platform, tracer);

// Use the API normally - all calls will be traced
traced_platform.write_console(handle, "Hello, World!")?;
```

Output:
```
[1234567890.123] [TID:main] CALL   WriteConsole(handle=0xFFFFFFFF0001, text="Hello, World!")
[1234567890.124] [TID:main] RETURN WriteConsole() -> Ok(bytes_written=13)
```
