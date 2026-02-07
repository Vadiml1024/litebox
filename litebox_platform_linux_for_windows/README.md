# litebox_platform_linux_for_windows

Linux platform implementation for Windows APIs.

## Overview

This crate provides the "South" platform layer that implements Windows NTDLL APIs using Linux syscalls.

## Phase 2: Core NTDLL API Implementation

- ✅ File I/O: NtCreateFile → open(), NtReadFile → read(), NtWriteFile → write(), NtClose → close()
- ✅ Console I/O: WriteConsole → stdout
- ✅ Memory Management: NtAllocateVirtualMemory → mmap(), NtFreeVirtualMemory → munmap()
- ✅ Path Translation: Windows paths (C:\path) → Linux paths (/path)
- ✅ Handle Management: Windows handles → Linux file descriptors

## Architecture

```
Windows API Call (NtCreateFile)
    ↓
litebox_platform_linux_for_windows (translation)
    ↓
Linux Syscall (open)
```

## Usage

```rust
use litebox_platform_linux_for_windows::LinuxPlatformForWindows;

let mut platform = LinuxPlatformForWindows::new();
let handle = platform.nt_create_file("/tmp/test.txt", GENERIC_WRITE, CREATE_ALWAYS)?;
platform.nt_write_file(handle, b"Hello")?;
platform.nt_close(handle)?;
```
