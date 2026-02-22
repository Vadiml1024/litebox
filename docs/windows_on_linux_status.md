# Windows on Linux: Implementation Status

**Last Updated:** 2026-02-22  
**Total Tests:** 423 passing (355 platform + 47 shim + 16 runner + 5 dev_tests — +21 new thread/file-time/char/window tests added in Phase 27)  
**Overall Status:** Core infrastructure complete. Seven Rust-based test programs (hello_cli, math_test, env_test, args_test, file_io_test, string_test, getprocaddress_test) run successfully end-to-end through the runner on Linux. **All API stub functions have been fully replaced — stub count is now 0.** Phase 27 adds thread management, process management, file-time utilities, character conversion/classification, window utilities, system directory paths, and temp file name generation.

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
- SHELL32.dll and VERSION.dll registered at startup with Phase 25 implementations

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
| `GetSystemTime` | `clock_gettime(CLOCK_REALTIME)` + `gmtime_r` → SYSTEMTIME |
| `GetLocalTime` | `clock_gettime(CLOCK_REALTIME)` + `localtime_r` → SYSTEMTIME |
| `SystemTimeToFileTime` | SYSTEMTIME → Windows FILETIME via `timegm` |
| `FileTimeToSystemTime` | Windows FILETIME → SYSTEMTIME via `gmtime_r` |
| `GetTickCount` | 32-bit truncation of `GetTickCount64` |
| `LocalAlloc` | Delegates to `HeapAlloc` (`LMEM_ZEROINIT` maps to `HEAP_ZERO_MEMORY`) |
| `LocalFree` | Delegates to `HeapFree`; returns NULL |
| `InterlockedIncrement` / `InterlockedDecrement` | `AtomicI32::fetch_add/fetch_sub` with SeqCst |
| `InterlockedExchange` / `InterlockedExchangeAdd` | `AtomicI32::swap` / `fetch_add` with SeqCst |
| `InterlockedCompareExchange` | `AtomicI32::compare_exchange` with SeqCst |
| `InterlockedCompareExchange64` | `AtomicI64::compare_exchange` with SeqCst |
| `IsWow64Process` | Returns TRUE (call succeeded); sets `*is_wow64 = 0` (not WOW64) |
| `GetNativeSystemInfo` | Delegates to `GetSystemInfo` (already returns AMD64 info) |
| `CreateMutexW` / `CreateMutexA` | Recursive mutex backed by `Arc<(Mutex<Option<(u32,u32)>>, Condvar)>` |
| `OpenMutexW` | Look up named mutex in global registry |
| `ReleaseMutex` | Release ownership; decrement recursive count; notify waiters |
| `CreateSemaphoreW` / `CreateSemaphoreA` | Counting semaphore backed by `Arc<(Mutex<i32>, Condvar)>` |
| `OpenSemaphoreW` | Look up named semaphore in global registry |
| `ReleaseSemaphore` | Increment semaphore count; notify one waiter |
| `WaitForSingleObject` | Extended to handle mutex and semaphore handles |
| `SetConsoleMode` | Accepts mode (no-op); returns TRUE |
| `SetConsoleTitleW` / `SetConsoleTitleA` | Stores title in global `CONSOLE_TITLE` |
| `GetConsoleTitleW` | Returns stored title; falls back to empty string |
| `AllocConsole` / `FreeConsole` | Returns TRUE (always have a console) |
| `GetConsoleWindow` | Returns NULL (headless) |
| `lstrlenA` | ANSI `strlen` |
| `lstrcpyW` / `lstrcpyA` | Wide/ANSI string copy; returns dst |
| `lstrcmpW` / `lstrcmpA` | Wide/ANSI string comparison |
| `lstrcmpiW` / `lstrcmpiA` | Case-insensitive wide/ANSI comparison |
| `OutputDebugStringW` / `OutputDebugStringA` | Writes debug message to stderr |
| `GetDriveTypeW` | Returns `DRIVE_FIXED` (3) for all paths |
| `GetLogicalDrives` | Returns 0x4 (only C: drive) |
| `GetLogicalDriveStringsW` | Returns `"C:\\\0\0"` (single-drive list) |
| `GetDiskFreeSpaceExW` | Returns 10 GB free / 20 GB total (fake values) |
| `GetVolumeInformationW` | Returns volume name `"LITEBOX"`, filesystem `"NTFS"` |
| `GetComputerNameW` / `GetComputerNameExW` | Reads Linux hostname via `/proc/sys/kernel/hostname` |
| `SetThreadPriority` | Accepts priority value; returns TRUE (all threads run at normal priority) |
| `GetThreadPriority` | Returns `THREAD_PRIORITY_NORMAL` (0) for all threads |
| `SuspendThread` | Returns 0 (suspension not implemented; thread continues) |
| `ResumeThread` | Returns 0 (previous suspend count; no-op) |
| `OpenThread` | Returns handle from THREAD_HANDLES if thread ID matches; NULL otherwise |
| `GetExitCodeThread` | Returns `STILL_ACTIVE` (259) or actual exit code from thread registry |
| `OpenProcess` | Returns pseudo-handle for current process; NULL for unknown PIDs |
| `GetProcessTimes` | Returns current wall-clock time as creation time; zeros for CPU times |
| `GetFileTime` | Reads file timestamps via `fstat(2)` on the underlying fd |
| `CompareFileTime` | Compares two FILETIME values; returns -1, 0, or 1 |
| `FileTimeToLocalFileTime` | Adjusts UTC FILETIME by local timezone offset via `localtime_r` |
| `GetSystemDirectoryW` | Returns `"C:\Windows\System32"` |
| `GetWindowsDirectoryW` | Returns `"C:\Windows"` |
| `GetTempFileNameW` | Generates a temp file name from path + prefix + unique hex suffix |

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
`MultiByteToWideChar`, `WideCharToMultiByte`, `lstrlenW`, `lstrlenA`, `CompareStringOrdinal`  
`lstrcpyW`, `lstrcpyA`, `lstrcmpW`, `lstrcmpA`, `lstrcmpiW`, `lstrcmpiA`, `OutputDebugStringW`, `OutputDebugStringA`

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

### USER32 — Extended GUI Support (Phases 24 + 27, 40 functions)
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
| Character conversion | `CharUpperW`, `CharLowerW`, `CharUpperA`, `CharLowerA` |
| Character classification | `IsCharAlphaW`, `IsCharAlphaNumericW`, `IsCharUpperW`, `IsCharLowerW` |
| Window utilities | `IsWindow`, `IsWindowEnabled`, `IsWindowVisible`, `EnableWindow`, `GetWindowTextW`, `SetWindowTextW`, `GetParent` |

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

### SHELL32.dll — Shell API (Phase 25, 4 functions)
| Category | Implemented Functions |
|---|---|
| Command line | `CommandLineToArgvW` (real Windows parsing with backslash/quote rules) |
| Folder paths | `SHGetFolderPathW` (maps CSIDL constants to Linux paths) |
| Process | `ShellExecuteW` (headless stub; returns success value > 32) |
| File system | `SHCreateDirectoryExW` (delegates to `CreateDirectoryW`) |

### VERSION.dll — File Version Info (Phase 25, 3 functions)
| Function | Behaviour |
|---|---|
| `GetFileVersionInfoSizeW` | Returns 0 (no version resources in emulated environment) |
| `GetFileVersionInfoW` | Returns FALSE |
| `VerQueryValueW` | Returns FALSE; clears output pointers |

### ADVAPI32 — Extended System APIs (Phase 26)
| Function | Implementation |
|---|---|
| `GetUserNameW` | Reads Linux username via `$USER` env / `getlogin_r(3)` |
| `GetUserNameA` | ANSI variant; delegates to wide version |

### Drive/Volume APIs (Phase 26, 5 functions)
| Function | Behaviour |
|---|---|
| `GetDriveTypeW` | Returns `DRIVE_FIXED` (3) for all paths |
| `GetLogicalDrives` | Returns 0x4 (only C: drive) |
| `GetLogicalDriveStringsW` | Returns `"C:\\\0\0"` drive list |
| `GetDiskFreeSpaceExW` | Returns 10 GB free / 20 GB total (fake) |
| `GetVolumeInformationW` | Returns volume `"LITEBOX"`, filesystem `"NTFS"` |

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

**423 tests total (all passing):**

| Package | Tests | Notes |
|---|---|---|
| `litebox_platform_linux_for_windows` | 355 | KERNEL32, MSVCRT, WS2_32, advapi32, user32, gdi32, shell32, version, platform APIs |
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

- **All 423 tests passing**
- `RUSTFLAGS=-Dwarnings cargo clippy --all-targets --all-features` — clean
- `cargo fmt --check` — clean
- All `unsafe` blocks have detailed safety comments
- Ratchet limits: globals ≤ 42, transmutes ≤ 3, MaybeUninit ≤ current
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
| 25 | Time APIs (`GetSystemTime`, `GetLocalTime`, `SystemTimeToFileTime`, `FileTimeToSystemTime`, `GetTickCount`); local memory (`LocalAlloc`, `LocalFree`); interlocked ops (`InterlockedIncrement/Decrement/Exchange/ExchangeAdd/CompareExchange/CompareExchange64`); system info (`IsWow64Process`, `GetNativeSystemInfo`); new SHELL32.dll (`CommandLineToArgvW`, `SHGetFolderPathW`, `ShellExecuteW`, `SHCreateDirectoryExW`); new VERSION.dll (`GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, `VerQueryValueW`); +17 new tests | ✅ Complete |
| 26 | Mutex/Semaphore sync objects (`CreateMutexW/A`, `OpenMutexW`, `ReleaseMutex`, `CreateSemaphoreW/A`, `OpenSemaphoreW`, `ReleaseSemaphore`); console extensions (`SetConsoleMode`, `SetConsoleTitleW/A`, `GetConsoleTitleW`, `AllocConsole`, `FreeConsole`, `GetConsoleWindow`); string utilities (`lstrlenA`, `lstrcpyW/A`, `lstrcmpW/A`, `lstrcmpiW/A`, `OutputDebugStringW/A`); drive/volume APIs (`GetDriveTypeW`, `GetLogicalDrives`, `GetLogicalDriveStringsW`, `GetDiskFreeSpaceExW`, `GetVolumeInformationW`); computer/user name (`GetComputerNameW/ExW`, `GetUserNameW/A`); +16 new tests; globals ratchet 39→42 | ✅ Complete |
| 27 | Thread management (`SetThreadPriority`, `GetThreadPriority`, `SuspendThread`, `ResumeThread`, `OpenThread`, `GetExitCodeThread`); process management (`OpenProcess`, `GetProcessTimes`); file-time utilities (`GetFileTime`, `CompareFileTime`, `FileTimeToLocalFileTime`); system directory paths (`GetSystemDirectoryW`, `GetWindowsDirectoryW`); temp file name (`GetTempFileNameW`); USER32 character conversion (`CharUpperW/A`, `CharLowerW/A`); character classification (`IsCharAlphaW`, `IsCharAlphaNumericW`, `IsCharUpperW`, `IsCharLowerW`); window utilities (`IsWindow`, `IsWindowEnabled`, `IsWindowVisible`, `EnableWindow`, `GetWindowTextW`, `SetWindowTextW`, `GetParent`); +21 new tests | ✅ Complete |

