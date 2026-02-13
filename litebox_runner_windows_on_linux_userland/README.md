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
- Section enumeration and metadata extraction

### Phase 2: Core APIs ✅
- File I/O APIs (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- Console I/O (WriteConsole)
- Memory management APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)
- Path translation (Windows → Linux paths)
- Trait-based integration between shim and platform layers

### Phase 3: PE Loading ✅
- Memory allocation for PE image
- Section loading into allocated memory
- Memory cleanup

### What Works
- Loading Windows PE executables
- Parsing PE headers and sections
- Allocating memory for the PE image
- Loading sections into memory
- Basic console output through platform API
- Memory management (allocation and deallocation)

### What's Next (Phase 4+)
- Actual program execution (calling entry point)
- API call tracing framework
- Threading support
- DLL loading and import resolution
- Exception handling

## Example Output

```bash
litebox_runner_windows_on_linux_userland hello.exe

# Output:
# Loaded PE binary: hello.exe
#   Entry point: 0x1400
#   Image base: 0x140000000
#   Sections: 4
# 
# Sections:
#   .text - VA: 0x1000, Size: 8192 bytes, Characteristics: 0x60000020
#   .data - VA: 0x3000, Size: 4096 bytes, Characteristics: 0xC0000040
#   .rdata - VA: 0x4000, Size: 2048 bytes, Characteristics: 0x40000040
#   .pdata - VA: 0x5000, Size: 512 bytes, Characteristics: 0x40000040
# 
# Allocating memory for PE image:
#   Image size: 20480 bytes (20 KB)
#   Allocated at: 0x7F1234567000
# 
# Loading sections into memory...
#   Loaded 14848 bytes
# 
# Hello from Windows on Linux!
# 
# Memory deallocated successfully.
# 
# [Progress: PE loader, section loading, and basic NTDLL APIs implemented]
# Note: Actual program execution not yet implemented - working on foundation.
```
