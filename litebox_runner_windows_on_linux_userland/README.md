# litebox_runner_windows_on_linux_userland

CLI runner for executing Windows programs on Linux with API tracing.

## Overview

This is the main executable that combines the Windows shim and Linux platform layers to run Windows PE binaries on Linux. It provides comprehensive API tracing capabilities for security analysis and debugging.

## Usage

```bash
# Run a Windows executable on Linux
litebox_runner_windows_on_linux_userland program.exe [args...]

# Enable API tracing (text format to stdout)
litebox_runner_windows_on_linux_userland --trace-apis program.exe

# Trace to JSON format
litebox_runner_windows_on_linux_userland --trace-apis --trace-format json program.exe

# Save trace to file
litebox_runner_windows_on_linux_userland --trace-apis --trace-output trace.log program.exe

# Filter specific API calls
litebox_runner_windows_on_linux_userland --trace-apis --trace-filter "Nt*File" program.exe

# Filter by category (file_io, memory, console_io)
litebox_runner_windows_on_linux_userland --trace-apis --trace-category file_io program.exe
```

## Current Status

### Phase 1: Foundation ✅
- PE binary loading and parsing

### Phase 2: Core APIs ✅
- File I/O APIs (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
- Console I/O (WriteConsole)
- Memory management APIs (NtAllocateVirtualMemory, NtFreeVirtualMemory)
- Path translation (Windows → Linux)

### Phase 3: API Tracing ✅
- Configurable tracing framework
- Multiple output formats (text, JSON)
- Filtering by function pattern or category
- Output to stdout or file
- Transparent wrapper for all NTDLL APIs

### What Works
- Loading Windows PE executables
- Parsing PE headers
- Basic console output
- File operations (through NTDLL API layer)
- Comprehensive API call tracing

### What's Next (Phase 4+)
- Actual program execution
- Threading support
- DLL loading
- More Windows APIs

## Examples

### Basic Usage
```bash
litebox_runner_windows_on_linux_userland hello.exe

# Output:
# Loaded PE binary: hello.exe
#   Entry point: 0x1400
#   Image base: 0x140000000
#   Sections: 4
# Hello from Windows on Linux!
# [Phase 3 Complete: API tracing framework implemented]
```

### API Tracing (Text Format)
```bash
litebox_runner_windows_on_linux_userland --trace-apis hello.exe

# Output includes:
# [1234567890.123] [TID:main] CALL   WriteConsole(handle=0xFFFFFFFF0001, text="Hello from Windows on Linux!\n")
# [1234567890.124] [TID:main] RETURN WriteConsole() -> Ok(bytes_written=29)
```

### API Tracing (JSON Format)
```bash
litebox_runner_windows_on_linux_userland --trace-apis --trace-format json hello.exe

# Output includes:
# {"timestamp":1234567890.123456789,"thread_id":null,"event":"call","category":"console_io","function":"WriteConsole","args":"handle=0xFFFFFFFF0001, text=\"Hello from Windows on Linux!\\n\""}
# {"timestamp":1234567890.124567890,"thread_id":null,"event":"return","category":"console_io","function":"WriteConsole","return":"Ok(bytes_written=29)"}
```

### Filtered Tracing
```bash
# Only trace file I/O operations
litebox_runner_windows_on_linux_userland --trace-apis --trace-category file_io program.exe

# Only trace functions matching pattern
litebox_runner_windows_on_linux_userland --trace-apis --trace-filter "Nt*File" program.exe
```
