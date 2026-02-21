# Windows on Linux: Implementation Status

**Last Updated:** 2026-02-21  
**Total Tests:** 298 passing (235 platform + 47 shim + 16 runner)  
**Overall Status:** Core infrastructure complete. Windows PE binaries load and begin execution; full end-to-end execution of real-world programs is still a work in progress.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Windows PE Binary (unmodified .exe)                    │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_shim_windows (North Layer)                     │
│  - PE/DLL loader                                        │
│  - Windows syscall interface (NTDLL)                    │
│  - API tracing framework                                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_platform_linux_for_windows (South Layer)       │
│  - Linux syscall implementations                        │
│  - Windows API → Linux translation                      │
│  - Process/thread management                            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  litebox_runner_windows_on_linux_userland               │
│  - CLI tool for running Windows programs                │
│  - Configurable tracing options                         │
└─────────────────────────────────────────────────────────┘
```

---

## What Is Implemented ✅

### PE Loading
- Parse PE headers (DOS, NT, Optional headers) and validate signatures
- Load all sections into memory with correct alignment
- Apply base relocations (ASLR rebasing)
- Parse and resolve the Import Address Table (IAT)
- Patch IAT with resolved function addresses

### DLL Emulation
- `DllManager` with stub/trampoline support for KERNEL32, NTDLL, MSVCRT, WS2_32, advapi32, user32
- Case-insensitive DLL name matching
- `LoadLibrary` / `GetProcAddress` / `FreeLibrary` APIs
- 57 trampolined functions with proper Windows x64 → System V AMD64 ABI translation (18 MSVCRT + 39 KERNEL32)
- 38 remaining KERNEL32 stub exports (return plausible values / no-ops)

### Execution Context
- TEB (Thread Environment Block) and PEB (Process Environment Block) structures
- GS segment register configured to point at TEB (`%gs:0x30` returns TEB pointer)
- Real `mmap`-based stack allocation (1 MB default, grows downward)
- Assembly trampoline calling Windows x64 entry points with correct ABI:
  - 16-byte stack alignment before `call`
  - 32-byte shadow space
  - Return value in RAX

### NTDLL / Core APIs
| Category | Implemented Functions |
|---|---|
| File I/O | `NtCreateFile`, `NtReadFile`, `NtWriteFile`, `NtClose` |
| Console I/O | `GetStdOutput`, `WriteConsole`, `GetStdHandle`, `WriteConsoleW` |
| Memory | `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory` |
| Threads | `NtCreateThread`, `NtTerminateThread`, `NtWaitForSingleObject`, `NtCloseHandle` |
| Events (NTDLL) | `NtCreateEvent`, `NtSetEvent`, `NtResetEvent`, `NtWaitForEvent` |
| Environment | `GetEnvironmentVariable`, `SetEnvironmentVariable` |
| Process info | `GetCurrentProcessId` (real PID), `GetCurrentThreadId` (real TID) |
| Registry (emulated) | `RegOpenKeyEx`, `RegQueryValueEx`, `RegCloseKey` |
| Error handling | `GetLastError` / `SetLastError` (thread-local) |

### KERNEL32 Real Implementations
| Function | Implementation |
|---|---|
| `Sleep` | `std::thread::sleep` |
| `GetCurrentThreadId` | `SYS_gettid` syscall |
| `GetCurrentProcessId` | `getpid()` syscall |
| `GetProcessId` | `std::process::id()` |
| `TlsAlloc` / `TlsFree` / `TlsGetValue` / `TlsSetValue` | Thread-local storage manager |
| `CreateEventW` | Manual/auto-reset Condvar-backed events |
| `SetEvent` | `notify_one()` (auto-reset) or `notify_all()` (manual-reset) |
| `ResetEvent` | Clear event state |
| `WaitForSingleObject` | Timed wait on threads or events |
| `CloseHandle` | Removes event/thread entries |
| `GetTempPathW` | `std::env::temp_dir()` |
| `InitializeCriticalSection` / `EnterCriticalSection` / `LeaveCriticalSection` / `DeleteCriticalSection` | Mutex-backed |

### MSVCRT Implementations (18 functions)
`printf`, `fprintf`, `sprintf`, `snprintf`, `malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcpy`, `strncpy`, `strcmp`, `strncmp`, `exit`

### Exception Handling Stubs (8 functions)
`__C_specific_handler`, `SetUnhandledExceptionFilter`, `RaiseException`, `RtlCaptureContext`, `RtlLookupFunctionEntry`, `RtlUnwindEx`, `RtlVirtualUnwind`, `AddVectoredExceptionHandler`  
*(These are minimal stubs sufficient to pass CRT initialization; full SEH is not implemented.)*

### String / Wide-Char Operations
`MultiByteToWideChar`, `WideCharToMultiByte`, `lstrlenW`, `CompareStringOrdinal`

### Performance Counters
`QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetSystemTimePreciseAsFileTime`

### Heap Management
`GetProcessHeap`, `HeapAlloc`, `HeapFree`, `HeapReAlloc`

### Networking (WS2_32) — 34 functions backed by Linux POSIX sockets
| Category | Implemented Functions |
|---|---|
| Lifecycle | `WSAStartup`, `WSACleanup`, `WSAGetLastError`, `WSASetLastError` |
| Socket creation | `socket`, `WSASocketW`, `closesocket` |
| Connection | `bind`, `listen`, `accept`, `connect`, `shutdown` |
| Data transfer | `send`, `recv`, `sendto`, `recvfrom`, `WSASend`, `WSARecv` |
| Socket info | `getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `ioctlsocket` |
| Multiplexing | `select`, `__WSAFDIsSet` |
| Name resolution | `getaddrinfo`, `freeaddrinfo`, `GetHostNameW` |
| Byte order | `htons`, `htonl`, `ntohs`, `ntohl` |
| Misc | `WSADuplicateSocketW` |

### API Tracing Framework
- Text and JSON output formats with timestamps and thread IDs
- Filtering by function name pattern (wildcards), category, or exact name
- Output to stdout or file
- Zero overhead when disabled
- Categories: `file_io`, `console_io`, `memory`, `threading`, `synchronization`, `environment`, `process`, `registry`

---

## What Is NOT Implemented ❌

| Feature | Status |
|---|---|
| Full SEH / C++ exception handling | Stubs only; stack unwinding not implemented |
| GUI applications (USER32 / GDI32) | Not implemented |
| Advanced networking (WS2_32) | Core socket API implemented (see above); overlapped/async I/O (`WSAEventSelect`, `WSAAsyncSelect`, completion ports) not implemented |
| Process creation (`CreateProcessW`) | Not implemented |
| Advanced file operations (memory mapping, overlapped I/O) | Not implemented |
| Advanced registry operations (write, enumeration) | Not implemented |
| 38 remaining KERNEL32 functions | Stub no-ops only |
| Full end-to-end execution of MinGW binaries | Entry point reached; crashes during CRT global initialization (BSS / `.data` reliance on not-yet-initialized globals) |

### Known Blocker: MinGW CRT Global Initialization
Running a MinGW-compiled `hello_cli.exe` currently crashes during CRT startup at a low memory address (e.g., `0x3018`). The root cause is that BSS sections must be explicitly zero-initialized when loaded (they have `SizeOfRawData == 0` but `VirtualSize > 0`). Until this is fixed, real Windows binaries will not run to completion.

---

## Test Coverage

**298 tests total (all passing):**

| Package | Tests | Notes |
|---|---|---|
| `litebox_platform_linux_for_windows` | 235 | KERNEL32, MSVCRT, WS2_32, advapi32, user32, platform APIs |
| `litebox_shim_windows` | 47 | ABI translation, PE loader, tracing |
| `litebox_runner_windows_on_linux_userland` | 16 | 9 tracing + 7 integration tests |

**Integration tests (7):**
1. PE loader with minimal binary
2. DLL loading infrastructure
3. Command-line APIs (`GetCommandLineW`, `CommandLineToArgvW`)
4. File search APIs (`FindFirstFileW`, `FindNextFileW`, `FindClose`)
5. Memory protection APIs (`NtProtectVirtualMemory`)
6. Error handling APIs (`GetLastError` / `SetLastError`)
7. DLL exports validation (all critical KERNEL32 and WS2_32 exports)

---

## Usage

### Basic Usage

```bash
# Run a Windows PE binary
litebox_runner_windows_on_linux_userland program.exe
```

### API Tracing

```bash
# Enable tracing with text format
litebox_runner_windows_on_linux_userland --trace-apis program.exe

# Enable tracing with JSON format to file
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-format json \
  --trace-output trace.json \
  program.exe

# Filter by category (only memory operations)
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-category memory \
  program.exe

# Filter by pattern (only file operations)
litebox_runner_windows_on_linux_userland \
  --trace-apis \
  --trace-filter "Nt*File" \
  program.exe
```

---

## Code Quality

- **All 298 tests passing**
- `RUSTFLAGS=-Dwarnings cargo clippy --all-targets --all-features` — clean
- `cargo fmt --check` — clean
- All `unsafe` blocks have detailed safety comments
- Ratchet limits: globals ≤ 35, transmutes ≤ current, MaybeUninit ≤ current

---

## Development History Summary

| Phase | Description | Status |
|---|---|---|
| 1 | PE loader foundation | ✅ Complete |
| 2 | Core NTDLL APIs (file, console, memory) | ✅ Complete |
| 3 | API tracing framework | ✅ Complete |
| 4 | Threading & synchronization (NTDLL) | ✅ Complete |
| 5 | Environment variables, process info, registry emulation | ✅ Complete |
| 6 | Import resolution, IAT patching, relocations, DLL manager, TEB/PEB | ✅ Complete |
| 7 | MSVCRT, GS register, ABI trampolines, TLS, memory protection, error handling | ✅ Complete |
| 8 | Real stack allocation, Windows x64 ABI entry-point calling, exception/heap/critical-section stubs | ✅ Complete |
| 19 | Win32 event objects (KERNEL32), stub promotions (53→38), test race-condition fix | ✅ Complete |

**Next:** Fix BSS zero-initialization in `load_sections()` to unblock MinGW CRT global initialization.
