# litebox_shim_windows

A shim that provides Windows PE binary support and Windows syscall handling for LiteBox.

## Overview

This crate enables LiteBox to load and run Windows PE (Portable Executable) binaries on Linux. It provides:

- **PE Loader**: Parses and loads Windows PE binaries into memory
- **Syscall Dispatcher**: Handles Windows syscalls (NTDLL, Kernel32)
- **API Tracing**: Hooks for tracing Windows API calls

## Components

### PE Loader (`loader/`)
- `pe.rs`: PE binary parser and loader
- `dll.rs`: DLL loading support (stub)

### Syscalls (`syscalls/`)
- `dispatch.rs`: Syscall dispatcher (stub)

### Tracing (`tracing/`)
- Tracing framework for Windows API calls (stub)

## Status

This is part of Phase 1 implementation. Currently implements:
- Basic PE header parsing
- Section loading
- Relocation handling
- Entry point extraction

## License

Licensed under the MIT license. See LICENSE file for details.
