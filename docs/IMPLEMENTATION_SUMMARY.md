# Implementation Plan Summary: Windows on Linux with API Tracing

## Quick Overview

**Goal:** Enable LiteBox to run unmodified Windows PE executables on Linux while tracing all Windows API calls for security analysis and debugging.

**Status:** ✅ Design Complete | ⏳ Implementation Pending

**Timeline:** 13-14 weeks for full implementation

## Architecture at a Glance

```
Windows .exe → litebox_shim_windows → LiteBox Core → litebox_platform_linux_for_windows → Linux Kernel
                  ↓ (tracing)
              API Trace Output (text/JSON/CSV)
```

## Three New Crates

1. **litebox_shim_windows** - PE loader, Windows syscall interface, API tracing hooks
2. **litebox_platform_linux_for_windows** - Windows API → Linux syscall translation
3. **litebox_runner_windows_on_linux_userland** - CLI runner with tracing options

## Key Features

### PE Binary Support
- Parse PE headers (DOS, NT, Optional)
- Load sections (.text, .data, .rdata)
- Handle relocations for ASLR
- Process import/export tables

### Windows API Translation
- **File I/O:** NtCreateFile → open(), NtReadFile → read()
- **Memory:** NtAllocateVirtualMemory → mmap()
- **Threading:** NtCreateThread → clone()
- **Sync:** NtCreateEvent → eventfd()

### API Tracing
- Multiple levels: syscall, Win32 API, IAT hooking
- Configurable filters: by DLL, function, category
- Output formats: text, JSON, CSV
- Low overhead: < 20% when enabled

## Minimal API Set (MVP)

### NTDLL (14 core APIs)
- File: NtCreateFile, NtReadFile, NtWriteFile, NtClose
- Memory: NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory
- Thread: NtCreateThread, NtTerminateThread, NtWaitForSingleObject
- Sync: NtCreateEvent, NtSetEvent

### Kernel32 (16 wrapper APIs)
- CreateFileW/A, ReadFile, WriteFile, CloseHandle
- VirtualAlloc, VirtualFree, VirtualProtect
- CreateThread, ExitThread, WaitForSingleObject
- GetStdHandle, WriteConsoleW/A

## Implementation Phases

| Phase | Duration | Milestone |
|-------|----------|-----------|
| 1. Foundation | 2-3 weeks | PE loader complete |
| 2. Core APIs | 3-4 weeks | Run "Hello World" |
| 3. Tracing | 2 weeks | Trace simple programs |
| 4. Threading | 2-3 weeks | Multi-threaded support |
| 5. Extended | 3-4 weeks | DLL loading, registry |
| 6. Polish | 2 weeks | Tests, docs, CI/CD |

## Success Criteria

- ✅ Run simple Windows console apps (hello world, file I/O)
- ✅ Support multi-threaded programs
- ✅ Trace all API calls with filtering
- ✅ Performance overhead < 50% (tracing off), < 20% (tracing on)
- ✅ Pass all clippy lints, >70% test coverage

## Technical Challenges

1. **ABI Differences** - Windows fastcall vs System V AMD64
   - *Solution:* Register translation at syscall boundary

2. **Handle Management** - Windows handles vs Linux FDs
   - *Solution:* Handle translation table

3. **Path Translation** - Backslashes/drives vs forward slashes
   - *Solution:* Path translation at API boundary

4. **DLL Dependencies** - Programs expect kernel32.dll, ntdll.dll
   - *Solution:* Stub DLLs with redirected exports

## Example Usage (Planned)

```bash
# Run Windows program with API tracing
./litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-filter "kernel32.*" \
  --trace-output trace.json \
  --trace-format json \
  program.exe arg1 arg2
```

## Sample Output (Planned)

```
[1234567890.123] [TID: 1001] CALL   kernel32!CreateFileW("test.txt", GENERIC_WRITE, ...)
[1234567890.125] [TID: 1001] RETURN kernel32!CreateFileW -> HANDLE: 0x0000000000000004
[1234567890.126] [TID: 1001] CALL   kernel32!WriteFile(0x0000000000000004, "Hello", 5, ...)
[1234567890.128] [TID: 1001] RETURN kernel32!WriteFile -> BOOL: TRUE, bytes_written: 5
```

## References

- **Full Plan:** [docs/windows_on_linux_implementation_plan.md](./windows_on_linux_implementation_plan.md)
- **Wine Project:** https://gitlab.winehq.org/wine/wine
- **PE Format:** Microsoft PE/COFF Specification
- **Windows Internals:** Russinovich et al.

## Next Steps

1. Review and approve implementation plan
2. Begin Phase 1: PE loader implementation
3. Set up project structure for new crates
4. Create initial test infrastructure

---

**Document Version:** 1.0  
**Last Updated:** 2026-02-07  
**Author:** GitHub Copilot Agent
