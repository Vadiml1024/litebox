# Windows-on-Linux Support — Session Summary (Phase 38)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-another-one`
**Goal:** Phase 38 — `basic_wstring<wchar_t>`, `_wfindfirst`/`_wfindnext`/`_findclose`, locale-aware printf variants.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (600 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Added `std::basic_string<wchar_t>` full MSVC x64 ABI implementation (SSO threshold=7, 32-byte layout)
  - Functions: default ctor, construct-from-wide-cstr, copy ctor, dtor, `c_str()`, `size()`, `empty()`, copy assignment, assign-from-cstr, `append()`
  - 6 unit tests in `tests_wstring` module
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `_wfindfirst64i32` / `_wfindnext64i32` / `_findclose` — wide-character file enumeration using `libc::opendir`/`readdir`/`closedir` with a mutex-protected handle table and DP wildcard matching
  - Added `_printf_l`, `_fprintf_l`, `_sprintf_l`, `_snprintf_l`, `_wprintf_l` — locale-aware printf variants (locale ignored)
  - 8 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs` — 18 new FunctionImpl entries
- `litebox_shim_windows/src/loader/dll.rs` — 10 new msvcp140.dll stubs, 8 new MSVCRT.dll stubs
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Phase 38 resolution test block
- `dev_tests/src/ratchet.rs` — updated globals count 55→58

### Next phase suggestions
- **Phase 39**: C++ STL containers (e.g., `std::vector<T>`, `std::map<K,V>`)
- **Phase 39**: More file I/O: `_open`/`_close`/`_lseek`/`_read`/`_write` with Windows semantics
- **Phase 39**: Exception handling: `_CxxThrowException`, `__CxxFrameHandler3`
- **Phase 39**: Wide string utilities: `wcslen`, `wcscpy`, `wcscmp`, `wcscat`, `wcsstr`
- **Phase 39**: Registry stubs: `RegOpenKeyExW`, `RegQueryValueExW`, `RegCloseKey`

---

# Windows-on-Linux Support — Session Summary (Phase 37)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-on-linux-support-another-one`
**Goal:** Phase 37 — UCRT sprintf/snprintf entry points, fscanf/scanf, numeric conversions, std::basic_string<char>.

### Status at checkpoint

| Component | State |
|-----------|-------|
| All tests (585 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `ucrt__stdio_common_vsprintf` — UCRT vsprintf entry point (writes to buffer)
  - Added `ucrt__stdio_common_vsnprintf_s` — UCRT vsnprintf_s with `_TRUNCATE` semantics
  - Added `ucrt__stdio_common_vsprintf_s` — UCRT vsprintf_s (overflow-checking)
  - Added `ucrt__stdio_common_vswprintf` — UCRT wide vsprintf (UTF-16 output buffer)
  - Added `msvcrt_scanf` — scanf from stdin (up to 16 specifiers)
  - Added `msvcrt_fscanf` — fscanf from FILE* (up to 16 specifiers)
  - Added `ucrt__stdio_common_vfscanf` — UCRT fscanf entry point
  - Added `msvcrt__ultoa` — unsigned long to string
  - Added `msvcrt__i64toa` — i64 to string (delegates to `_ltoa`)
  - Added `msvcrt__ui64toa` — u64 to string (delegates to `_ultoa`)
  - Added `msvcrt__strtoi64` — string to i64 (via `libc::strtoll`)
  - Added `msvcrt__strtoui64` — string to u64 (via `libc::strtoull`)
  - Added `msvcrt__itow`, `msvcrt__ltow`, `msvcrt__ultow`, `msvcrt__i64tow`, `msvcrt__ui64tow` — integer to wide string
  - Added 17 new unit tests
- `litebox_platform_linux_for_windows/src/msvcp140.rs`
  - Implemented `std::basic_string<char>` with MSVC x64 ABI layout (SSO threshold 15):
    - `msvcp140__basic_string_ctor` — default constructor (empty SSO)
    - `msvcp140__basic_string_ctor_cstr` — construct from C string
    - `msvcp140__basic_string_copy_ctor` — copy constructor
    - `msvcp140__basic_string_dtor` — destructor (frees heap if not SSO)
    - `msvcp140__basic_string_c_str` — returns data pointer
    - `msvcp140__basic_string_size` — returns length
    - `msvcp140__basic_string_empty` — returns true if empty
    - `msvcp140__basic_string_assign_op` — copy assignment operator
    - `msvcp140__basic_string_assign_cstr` — assign from C string
    - `msvcp140__basic_string_append_cstr` — append C string
  - Added 5 new unit tests
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Added `FunctionImpl` entries for all new MSVCRT and msvcp140 functions
- `litebox_shim_windows/src/loader/dll.rs`
  - Added MSVCRT.dll stub exports (0xD0–0xE0) for Phase 37 functions
  - Added msvcp140.dll stub exports (22–31) for `basic_string<char>` members
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 37 assertion block for MSVCRT.dll and msvcp140.dll new exports

### Key design decisions
- **`std::basic_string<char>` ABI**: Matches MSVC x64 layout: 16-byte SSO buffer union + 8-byte size + 8-byte capacity. SSO threshold is 15 chars. Uses `ptr::read_unaligned`/`ptr::write_unaligned` defensively.
- **Malloc failure handling**: If heap allocation fails in `basic_string`, the object is left in a valid empty SSO state instead of storing a null heap pointer with non-zero size.
- **`ucrt__stdio_common_vfscanf`**: For stdin (stream == null), uses `libc::fdopen(0, "r")` to obtain a FILE*. All actual FILE* values are valid Linux FILE* handles.
- **Wide integer conversion**: `_itow`/`_ltow`/etc. produce ASCII-only wide strings (each char fits in u16); this covers all practical cases for decimal/hex output.

### What the next session should consider

**Possible Phase 38 directions:**
1. **WriteFile round-trip fix (Phase 10)** — unify kernel32 file handle registry with NtWriteFile/NtReadFile
2. **`std::basic_string<wchar_t>`** — wide string stubs analogous to `basic_string<char>`
3. **More msvcp140.dll** — `std::vector<T>` operations, `std::ostringstream`, `std::cout`/`std::cerr` objects
4. **More UCRT** — `_printf_l`, `_fprintf_l`, `_sprintf_l` (locale-aware variants)
5. **`_wfindfirst`/`_wfindnext`/`_findclose`** — directory enumeration via CRT
6. **WinSock completions** — `WSAEventSelect`, `WSAEnumNetworkEvents`, `gethostbyname`

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
| `ucrt__stdio_common_vsprintf` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | ~4786 |
| `ucrt__stdio_common_vfscanf` | same | ~5242 |
| `msvcrt_scanf` | same | ~5148 |
| `msvcrt_fscanf` | same | ~5190 |
| `msvcrt__ultoa` | same | ~2608 |
| `msvcrt__strtoi64` / `_strtoui64` | same | ~2660 |
| `msvcrt__itow` and wide variants | same | ~2720 |
| `std::basic_string<char>` | `litebox_platform_linux_for_windows/src/msvcp140.rs` | ~370 |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |



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

