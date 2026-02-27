# Windows-on-Linux Support — Session Summary (Phase 36)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-again`
**Goal:** Phase 36 — `sscanf` real implementation, `_wcsdup`, and `__stdio_common_vsscanf`.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (563 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `count_scanf_specifiers(fmt: &[u8]) -> usize` — counts non-suppressed format conversion specifiers in a scanf format string (handles `%%`, `%*d`, `%[...]`, length modifiers, etc.)
  - Added `format_scanf_va(buf, fmt, args: &mut VaList) -> i32` — extracts up to 16 output pointers from a Linux VaList, calls `libc::sscanf` with those 16 explicit args
  - Added `format_scanf_raw(buf, fmt, ap: *mut u8) -> i32` — bridges a Windows x64 va_list pointer (via the same `VaListTag` trick as `format_printf_raw`) to `format_scanf_va`
  - Replaced `msvcrt_sscanf` stub (always returned 0) with real implementation calling `format_scanf_va`
  - Added `msvcrt__wcsdup` — heap duplicate of a null-terminated wide string (analogous to `_strdup`)
  - Added `ucrt__stdio_common_vsscanf` — UCRT `__stdio_common_vsscanf(options, buf, buf_count, fmt, locale, arglist)` entry point; delegates to `format_scanf_raw`
  - Added 7 new unit tests (`test_wcsdup`, `test_wcsdup_null`, `test_count_scanf_specifiers`, `test_sscanf_int`, `test_sscanf_two_ints`, `test_sscanf_string`, `test_sscanf_null_input`)
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Fixed `sscanf` `num_params` from 2 → 18 (buf + fmt + up to 16 pointer args, so the trampoline actually passes all pointer arguments)
  - Added `FunctionImpl` entries for `_wcsdup` and `__stdio_common_vsscanf`
- `litebox_shim_windows/src/loader/dll.rs`
  - Added `_wcsdup` (MSVCRT_BASE + 0xCD) and `__stdio_common_vsscanf` (MSVCRT_BASE + 0xCE) stub exports
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 36 assertion block checking both new exports are resolvable

### Key design decisions
- **sscanf strategy**: Parse the format string to count non-suppressed specifiers, extract exactly that many `*mut c_void` pointers from the Linux VaList, fill the remaining 16 slots with null, then call `libc::sscanf` with all 16 explicit args. libc::sscanf only dereferences as many pointers as the format specifies, so the trailing nulls are never accessed.
- **`num_params: 18`**: The trampoline translates N positional Windows arguments to Linux System V. Setting this to 18 allows up to 16 scanf output pointers (plus buf + fmt) to pass through the trampoline correctly.
- **`MAX_SCANF_ARGS: 16`**: Constant limiting the maximum number of format specifiers handled. Sufficient for all practical use cases.

### What the next session should consider

**Possible Phase 37 directions:**
1. **`fscanf` / `scanf`** — similar to sscanf but reading from a FILE* or stdin
2. **More `msvcp140.dll`** — `std::basic_string` member functions, `std::vector` operations, `std::cout`/`std::cerr` stream stubs
3. **WriteFile round-trip fix** — unify kernel32 file handle registry with NtWriteFile/NtReadFile
4. **`__stdio_common_vsprintf`** — UCRT's `sprintf`/`snprintf` entry point (similar to `__stdio_common_vfprintf`)
5. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `GetHostByName`
6. **More numeric conversion** — `_itoa`, `_itow`, `_ultoa`, `_ui64toa`

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
| `count_scanf_specifiers` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | ~683 |
| `format_scanf_va` | same | ~745 |
| `format_scanf_raw` | same | ~785 |
| `msvcrt_sscanf` | same | ~4865 |
| `ucrt__stdio_common_vsscanf` | same | ~4780 |
| `msvcrt__wcsdup` | same | ~3060 |
| `format_printf_raw` | same | ~646 |
| `msvcrt_vprintf` | same | ~1003 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |


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

