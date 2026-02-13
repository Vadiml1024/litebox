# litebox_platform_linux_for_windows

Linux platform implementation for Windows APIs.

## Overview

This crate provides the "South" platform layer that implements Windows NTDLL APIs using Linux syscalls.

## Implementation Status

### Phase 2: Core NTDLL API Implementation ✅

- ✅ File I/O: NtCreateFile → open(), NtReadFile → read(), NtWriteFile → write(), NtClose → close()
- ✅ Console I/O: WriteConsole → stdout
- ✅ Memory Management: NtAllocateVirtualMemory → mmap(), NtFreeVirtualMemory → munmap()
- ✅ Path Translation: Windows paths (C:\path) → Linux paths (/path)
- ✅ Handle Management: Windows handles → Linux file descriptors
- ✅ `NtdllApi` trait implementation for shim integration

## Architecture

```
Windows API Call (NtCreateFile)
    ↓
litebox_shim_windows::NtdllApi trait
    ↓
litebox_platform_linux_for_windows (translation)
    ↓
Linux Syscall (open)
```

## Usage

```rust
use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;

let mut platform = LinuxPlatformForWindows::new();

// Use through the NtdllApi trait
let handle = platform.nt_create_file("/tmp/test.txt", GENERIC_WRITE, CREATE_ALWAYS)?;
platform.nt_write_file(handle, b"Hello")?;
platform.nt_close(handle)?;

// Memory allocation
let addr = platform.nt_allocate_virtual_memory(4096, PAGE_READWRITE)?;
platform.nt_free_virtual_memory(addr, 4096)?;
```
