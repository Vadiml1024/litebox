# Windows-on-Linux Support — Session Summary (Phase 35)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-again`
**Goal:** Phase 35 — `_vsnwprintf`, printf-length helpers (`_scprintf`, `_vscprintf`, `_scwprintf`, `_vscwprintf`), fd/Win32 handle interop (`_get_osfhandle`, `_open_osfhandle`), and extended `msvcp140.dll` stubs (`std::exception`, locale, `ios_base::Init`).

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (551 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `msvcrt__vsnwprintf` — size-limited wide-char vsnprintf (returns -1 on truncation per MSVCRT semantics)
  - Added `msvcrt__scprintf` — count characters `printf` would write (no output, variadic)
  - Added `msvcrt__vscprintf` — va_list version of `_scprintf`
  - Added `msvcrt__scwprintf` — count wide characters `wprintf` would write (variadic)
  - Added `msvcrt__vscwprintf` — va_list version of `_scwprintf`
  - Added `msvcrt__get_osfhandle` — CRT fd → Win32 HANDLE (stdin/stdout/stderr return -10/-11/-12)
  - Added `msvcrt__open_osfhandle` — Win32 HANDLE → CRT fd (reverse mapping)
  - Added 12 new unit tests
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `msvcp140__exception_what` / `_ctor` / `_ctor_msg` / `_dtor` — `std::exception` stubs
  - Added `msvcp140__Getgloballocale` — global locale stub (returns null)
  - Added `msvcp140__Lockit_ctor` / `_dtor` — locale lock stubs (no-op)
  - Added `msvcp140__ios_base_Init_ctor` / `_dtor` — `ios_base::Init` stubs (no-op)
  - Added 5 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Added 16 new `FunctionImpl` entries for all new functions
- `litebox_shim_windows/src/loader/dll.rs`
  - Added 7 new MSVCRT.dll stub exports (0xC6–0xCC)
  - Added 9 new msvcp140.dll stub exports (offsets 13–21)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 35 assertion blocks for MSVCRT.dll and msvcp140.dll new exports

### What the next session should consider

**Possible Phase 36 directions:**
1. **`sscanf`/`fscanf`/`scanf` real implementation** — currently `sscanf` is a stub returning 0. Implement using libc's sscanf with fixed-max-args trick or build a proper scanf parser.
2. **More `msvcp140.dll`** — `std::basic_string` member functions, `std::vector` operations, `std::cout`/`std::cerr` stream stubs
3. **WriteFile round-trip fix (Phase 10)** — unify kernel32 file handle registry with NtWriteFile/NtReadFile so that files opened with CreateFileW can be written via both WriteFile and NtWriteFile
4. **`__stdio_common_vsscanf`** — UCRT's sscanf entry point
5. **`_wcsdup`/`_strdup`** — string duplication functions
6. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `GetHostByName`

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run all Windows-specific tests
cargo nextest run -p litebox_shim_windows \
                 -p litebox_platform_linux_for_windows \
                 -p litebox_runner_windows_on_linux_userland

# Lint (with CI-equivalent flags)
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_shim_windows \
             -p litebox_platform_linux_for_windows \
             -p litebox_runner_windows_on_linux_userland

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `format_printf_raw` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | 582 |
| `msvcrt_vprintf` | same | ~1003 |
| `msvcrt_vsprintf` | same | ~1020 |
| `msvcrt_vsnprintf` | same | ~1045 |
| `msvcrt_vswprintf` | same | ~1070 |
| `msvcrt_vfprintf` (fixed) | same | ~968 |
| `ucrt__stdio_common_vfprintf` (fixed) | same | ~4450 |
| `msvcrt_fwprintf` | same | ~4720 |
| `msvcrt__write` | same | ~2060 |
| `msvcrt_getchar`/`msvcrt_putchar` | same | ~2080 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |

