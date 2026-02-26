# Windows-on-Linux Support — Session Summary (Phase 33)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-linux-support-one-more-time`
**Goal:** Phase 33 — Proper printf format-string support, msvcp140.dll stubs, `_wfopen`.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (525 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `PrintOpts` struct and helper functions (`format_int`, `format_uint`, `format_hex`, `format_octal`, `format_float`, `format_printf_va`)
  - Updated `msvcrt_printf`, `msvcrt_fprintf`, `msvcrt_vfprintf`, `msvcrt_sprintf`, `msvcrt_snprintf`, `msvcrt_swprintf`, `msvcrt_wprintf` to use the real formatter
  - Added `msvcrt__wfopen` for wide-char file open
  - Added unit tests for the new printf formatter (25 tests)
- `litebox_platform_linux_for_windows/src/msvcp140.rs` — New file: C++ stdlib stubs (operator new/delete, `_X*` exception helpers, locale stubs)
- `litebox_platform_linux_for_windows/src/lib.rs` — Added `pub mod msvcp140;`
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Increased `num_params` for printf-family variadic functions (printf: 8, fprintf: 8, sprintf: 9, snprintf: 9, swprintf: 8, wprintf: 8)
  - Added 13 `msvcp140.dll` function entries
  - Added `_wfopen` entry
- `litebox_shim_windows/src/loader/dll.rs` — Added `MSVCP140_BASE` constant and `load_stub_msvcp140()` with 13 exports; updated DLL count (16→17)
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Added `msvcp140.dll` exports test

### Key Phase 33 improvements

1. **Printf formatter** (`format_printf_va`) — Full format string parser with:
   - Specifiers: `%d`, `%i`, `%u`, `%x`, `%X`, `%o`, `%f`, `%e`, `%E`, `%g`, `%G`, `%s`, `%S`, `%p`, `%c`, `%C`, `%n`, `%%`
   - Flags: `-` (left-align), `0` (zero-pad), `+` (sign), ` ` (space), `#` (alt form)
   - Width and precision (static and `*` dynamic)
   - Length modifiers: `h`, `hh`, `l`, `ll`, `I64`, `I32`, `I`, `z`, `t`, `j`
   - The trampoline `num_params` is now large enough (8–9) to translate all variadic args from Windows to Linux calling convention

2. **`msvcp140.dll`** — 13 stub exports covering:
   - `operator new` / `operator delete` (plain and array variants)
   - `std::_Xbad_alloc`, `_Xlength_error`, `_Xout_of_range`, `_Xinvalid_argument`, `_Xruntime_error`, `_Xoverflow_error`
   - Locale helpers: `_Getctype`, `_Getdays`, `_Getmonths`

3. **`_wfopen`** — Wide-char file open (UTF-16 → UTF-8 → libc::fopen)

### What the next session should consider

**Possible Phase 34 directions:**
1. `msvcp140.dll` extended stubs — `std::basic_string` operations, `std::exception::what()`
2. More COM functions: `ProgIDFromCLSID`, `CLSIDFromProgID`, `CoMarshalInterface`
3. Additional wide-char I/O: `fwprintf`, `_wfgets`, `_wfreopen`
4. `vprintf` / `vsprintf` / `vsnprintf` with proper va_list passthrough
5. Windows Management Instrumentation (WMI) stubs

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


# Lint
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland -p litebox_shim_windows

# Unit tests
cargo nextest run -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland -p litebox_shim_windows

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `ole32.rs` | `litebox_platform_linux_for_windows/src/ole32.rs` | 1 |
| `kernel32_RaiseException` | `litebox_platform_linux_for_windows/src/kernel32.rs` | 1704 |
| `kernel32_RtlUnwindEx` | same | 1879 |
| `msvcrt__CxxThrowException` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | 2566 |
| `cxx_frame_handler` | same | 2640 |
| BSTR functions | `litebox_platform_linux_for_windows/src/oleaut32.rs` | 69+ |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |
| DLL manager stubs | `litebox_shim_windows/src/loader/dll.rs` | — |
