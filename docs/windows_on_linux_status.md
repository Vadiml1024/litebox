# Windows on Linux: Implementation Status

**Last Updated:** 2026-02-22  
**Total Tests:** 367 passing (304 platform + 47 shim + 16 runner + 5 dev_tests — +35 new USER32/GDI32 tests added in Phase 24)  
**Overall Status:** Core infrastructure complete. Seven Rust-based test programs (hello_cli, math_test, env_test, args_test, file_io_test, string_test, getprocaddress_test) run successfully end-to-end through the runner on Linux. **All API stub functions have been fully replaced — stub count is now 0.** Phase 24 adds GDI32 support and extended USER32 APIs for GUI program compatibility.

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
- All KERNEL32 exports have real implementations or permanently-correct no-op behavior (stub count = 0)

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
| `GetExitCodeProcess` | Returns `STILL_ACTIVE` (259) for the current process |
| `SetFileAttributesW` | Maps `FILE_ATTRIBUTE_READONLY` to Linux `chmod`; other bits silently accepted |
| `GetModuleFileNameW` | Returns current executable path via `/proc/self/exe` |
| `LoadLibraryA` / `LoadLibraryW` | Looks up registered DLL in global registry; returns synthetic HMODULE |
| `GetModuleHandleA` / `GetModuleHandleW` | Null → main module base; named → registry lookup |
| `GetProcAddress` | Looks up trampoline address in global registry by HMODULE + function name |
| `CreateHardLinkW` | `std::fs::hard_link` |
| `CreateSymbolicLinkW` | `std::os::unix::fs::symlink` |
| `LockFileEx` | `flock(2)` with `LOCK_SH`/`LOCK_EX`/`LOCK_NB` flags |
| `UnlockFile` | `flock(LOCK_UN)` |
| `VirtualQuery` | Parses `/proc/self/maps` and fills `MEMORY_BASIC_INFORMATION` (48 bytes) |
| `CancelIo` | Returns TRUE (all I/O is synchronous; no pending async I/O to cancel) |
| `UpdateProcThreadAttribute` | Returns TRUE (attribute accepted; `CreateProcessW` is not implemented) |
| `NtClose` | Delegates to `CloseHandle` to update handle tables |

### Permanently-correct no-op APIs (return appropriate Windows codes)
| Function | Return / Error |
|---|---|
| `SetConsoleCtrlHandler` | TRUE — handler registered; Linux SIGINT termination preserved |
| `SetWaitableTimer` | TRUE — waitable timers not created; no valid timer handle exists |
| `WaitOnAddress` | TRUE — returns immediately (no blocking wait; can be extended) |
| `CreateProcessW` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `CreateToolhelp32Snapshot` | `INVALID_HANDLE_VALUE` + `ERROR_NOT_SUPPORTED` (50) |
| `CreateWaitableTimerExW` | NULL + `ERROR_NOT_SUPPORTED` (50) |
| `DeviceIoControl` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `GetOverlappedResult` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `ReadFileEx` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `WriteFileEx` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `SetFileInformationByHandle` | FALSE + `ERROR_NOT_SUPPORTED` (50) |
| `Module32FirstW` / `Module32NextW` | FALSE + `ERROR_NO_MORE_FILES` (18) |

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

### USER32 — Extended GUI Support (Phase 24, 27 functions)
| Category | Implemented Functions |
|---|---|
| Basic | `MessageBoxW`, `RegisterClassExW`, `CreateWindowExW`, `ShowWindow`, `UpdateWindow`, `DestroyWindow` |
| Message loop | `GetMessageW`, `TranslateMessage`, `DispatchMessageW`, `PeekMessageW`, `PostQuitMessage` |
| Window proc | `DefWindowProcW` |
| Resources | `LoadCursorW`, `LoadIconW` |
| Window info | `GetSystemMetrics`, `SetWindowLongPtrW`, `GetWindowLongPtrW` |
| Messaging | `SendMessageW`, `PostMessageW` |
| Painting | `BeginPaint`, `EndPaint`, `GetClientRect`, `InvalidateRect` |
| Timer | `SetTimer`, `KillTimer` |
| Device context | `GetDC`, `ReleaseDC` |

All USER32 functions operate in headless mode: no real windows are created, no messages
are dispatched, and drawing operations are silently discarded.

### GDI32 — Graphics Device Interface (Phase 24, 13 functions)
| Category | Implemented Functions |
|---|---|
| Objects | `GetStockObject`, `CreateSolidBrush`, `DeleteObject`, `SelectObject` |
| Device context | `CreateCompatibleDC`, `DeleteDC` |
| Color | `SetBkColor`, `SetTextColor` |
| Drawing | `TextOutW`, `Rectangle`, `FillRect` |
| Font | `CreateFontW`, `GetTextExtentPoint32W` |

All GDI32 functions operate in headless mode: drawing is silently discarded.

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
| Full GUI rendering | USER32/GDI32 are headless stubs; no real window/drawing output |
| Overlapped (async) I/O | `ReadFileEx`, `WriteFileEx`, `GetOverlappedResult` return `ERROR_NOT_SUPPORTED` |
| Process creation (`CreateProcessW`) | Returns `ERROR_NOT_SUPPORTED`; sandboxed environment |
| Toolhelp32 enumeration | `CreateToolhelp32Snapshot`, `Module32FirstW/NextW` return `ERROR_NOT_SUPPORTED` |
| Waitable timers | `CreateWaitableTimerExW` returns `ERROR_NOT_SUPPORTED`; `SetWaitableTimer` is a no-op |
| `WaitOnAddress` blocking | Returns TRUE immediately; no blocking wait |
| Advanced networking | `WSAEventSelect`, `WSAAsyncSelect`, completion ports not implemented |

---

## Test Coverage

**367 tests total (all passing):**

| Package | Tests | Notes |
|---|---|---|
| `litebox_platform_linux_for_windows` | 304 | KERNEL32, MSVCRT, WS2_32, advapi32, user32, gdi32, platform APIs |
| `litebox_shim_windows` | 47 | ABI translation, PE loader, tracing |
| `litebox_runner_windows_on_linux_userland` | 16 | 9 tracing + 7 integration tests |
| `dev_tests` | 5 | Ratchet constraints (globals, transmutes, MaybeUninit, stubs, copyright) |

**Integration tests (7, plus 7 MinGW-gated):**
1. PE loader with minimal binary
2. DLL loading infrastructure
3. Command-line APIs (`GetCommandLineW`, `CommandLineToArgvW`)
4. File search APIs (`FindFirstFileW`, `FindNextFileW`, `FindClose`)
5. Memory protection APIs (`NtProtectVirtualMemory`)
6. Error handling APIs (`GetLastError` / `SetLastError`)
7. DLL exports validation (all critical KERNEL32, WS2_32, USER32, and GDI32 exports)

**MinGW-gated integration tests (8, require `--include-ignored`):**
- `test_hello_cli_program_exists` — checks hello_cli.exe is present
- `test_math_test_program_exists` — checks math_test.exe is present
- `test_env_test_program_exists` — checks env_test.exe is present
- `test_args_test_program_exists` — checks args_test.exe is present
- `test_file_io_test_program_exists` — **runs** file_io_test.exe end-to-end; verifies exit 0 and test header/completion output
- `test_string_test_program_exists` — **runs** string_test.exe end-to-end; verifies exit 0, test header, and 0 failures
- `test_getprocaddress_c_program` — **runs** getprocaddress_test.exe end-to-end; verifies exit 0 and 0 failures
- `test_hello_gui_program` — **runs** hello_gui.exe end-to-end; verifies exit 0 (MessageBoxW prints headless message to stderr)

**CI-validated test programs (7):**

| Program | What it tests | CI status |
|---|---|---|
| `hello_cli.exe` | Basic stdout via `println!` | ✅ Passing |
| `math_test.exe` | Arithmetic and math operations | ✅ Passing |
| `env_test.exe` | `GetEnvironmentVariableW` / `SetEnvironmentVariableW` | ✅ Passing |
| `args_test.exe` | `GetCommandLineW` / `CommandLineToArgvW` | ✅ Passing |
| `file_io_test.exe` | `CreateFileW`, `ReadFile`, `WriteFile`, directory operations | ✅ Passing |
| `string_test.exe` | Rust `String` operations (allocations, comparisons, Unicode) | ✅ Passing |
| `getprocaddress_test.exe` (C) | `GetModuleHandleA/W`, `GetProcAddress`, `LoadLibraryA`, `FreeLibrary` | ✅ Passing |

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

- **All 332 tests passing**
- `RUSTFLAGS=-Dwarnings cargo clippy --all-targets --all-features` — clean
- `cargo fmt --check` — clean
- All `unsafe` blocks have detailed safety comments
- Ratchet limits: globals ≤ 39, transmutes ≤ 3, MaybeUninit ≤ current
- **Stub count = 0** (ratchet entry removed; all stub doc-phrases eliminated)

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
| 9 | BSS zero-initialization, `__CTOR_LIST__` patching for MinGW CRT compatibility | ✅ Complete |
| 10–17 | Path security (sandbox root), handle limits, advapi32 registry APIs, WS2_32 networking, Win32 events, CI integration | ✅ Complete |
| 18 | CI test programs (hello_cli, math_test, env_test, args_test, file_io_test, string_test all pass) | ✅ Complete |
| 19 | Real `GetExitCodeProcess`, `SetFileAttributesW`, `GetModuleFileNameW`; upgraded string_test and file_io_test integration tests | ✅ Complete |
| 20 | Dynamic loading: `LoadLibraryA/W`, `GetModuleHandleA/W`, `GetProcAddress` backed by global DLL registry; `CreateHardLinkW`, `CreateSymbolicLinkW` | ✅ Complete |
| 21 | `CreateFileMappingA`, `MapViewOfFile`, `UnmapViewOfFile` (real mmap/munmap); `CreatePipe` (Linux pipe()); `DuplicateHandle`; `GetFinalPathNameByHandleW`; `GetFileInformationByHandleEx`; `InitializeProcThreadAttributeList`; stub count 29→22 | ✅ Complete |
| 22 | `VirtualQuery` (parses `/proc/self/maps`), `CancelIo`, `UpdateProcThreadAttribute`, `NtClose`; stub count 22→14 | ✅ Complete |
| 23 | `LockFileEx` / `UnlockFile` (real `flock(2)`); appropriate error codes for all permanently-unsupported APIs; **stub count 14→0** | ✅ Complete |
| 24 | Extended USER32 (18 new functions: `PostQuitMessage`, `DefWindowProcW`, `LoadCursorW`, `LoadIconW`, `GetSystemMetrics`, `SetWindowLongPtrW`, `GetWindowLongPtrW`, `SendMessageW`, `PostMessageW`, `PeekMessageW`, `BeginPaint`, `EndPaint`, `GetClientRect`, `InvalidateRect`, `SetTimer`, `KillTimer`, `GetDC`, `ReleaseDC`); new GDI32.dll (13 functions: `GetStockObject`, `CreateSolidBrush`, `DeleteObject`, `SelectObject`, `CreateCompatibleDC`, `DeleteDC`, `SetBkColor`, `SetTextColor`, `TextOutW`, `Rectangle`, `FillRect`, `CreateFontW`, `GetTextExtentPoint32W`); `hello_gui` integration test; +35 new tests | ✅ Complete |

