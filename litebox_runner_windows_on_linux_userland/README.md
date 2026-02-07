# litebox_runner_windows_on_linux_userland

CLI runner for executing Windows programs on Linux.

## Overview

This is the main executable that combines the Windows shim and Linux platform layers to run Windows PE binaries on Linux.

## Usage

```bash
# Run a Windows executable on Linux
litebox_runner_windows_on_linux_userland program.exe [args...]
```

## Current Status

### Phase 1: Foundation ✅
- PE binary loading and parsing

### Phase 2: Core APIs ✅
- File I/O APIs
- Console I/O
- Memory management APIs
- Path translation

### What Works
- Loading Windows PE executables
- Parsing PE headers
- Basic console output
- File operations (through NTDLL API layer)

### What's Next (Phase 3+)
- Actual program execution
- API call tracing
- Threading support
- DLL loading

## Example

```bash
# Load and inspect a Windows PE binary
litebox_runner_windows_on_linux_userland hello.exe

# Output:
# Loaded PE binary: hello.exe
#   Entry point: 0x1400
#   Image base: 0x140000000
#   Sections: 4
# Hello from Windows on Linux!
# [Phase 2 Complete: PE loader and basic NTDLL APIs implemented]
```
