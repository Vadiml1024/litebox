# Windows-on-Linux Support — Session Summary (Phase 34)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-linux-support-please-work`
**Goal:** Phase 34 — `vprintf`/`vsprintf`/`vsnprintf` family, `_write`, `getchar`/`putchar`, `fwprintf`/`vfwprintf`, fixed `vfprintf` and `__stdio_common_vfprintf`.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (534 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/msvcrt.rs`
  - Added `format_printf_raw(fmt, ap)` — reads printf args from a Windows x64 va_list pointer by constructing a synthetic Linux `VaList` (same 24-byte layout as `__va_list_tag`) with `gp_offset=48, fp_offset=304` so all args come from `overflow_arg_area`
  - Added `msvcrt_vprintf`, `msvcrt_vsprintf`, `msvcrt_vsnprintf`, `msvcrt_vswprintf` — full va_list-based printf family using `format_printf_raw`
  - Updated `msvcrt_vfprintf` — now uses `format_printf_raw` (was broken stub writing raw format bytes)
  - Updated `ucrt__stdio_common_vfprintf` — now accepts 5th `arglist` parameter and uses `format_printf_raw` for proper formatting
  - Added `msvcrt_fwprintf`, `msvcrt_vfwprintf` — wide-char formatted output
  - Added `msvcrt__write` — low-level CRT write to file descriptor
  - Added `msvcrt_getchar`, `msvcrt_putchar` — basic stdin/stdout character I/O
  - Added 9 new unit tests for `format_printf_raw`, `vsprintf`, `vsnprintf`
- `litebox_platform_linux_for_windows/src/function_table.rs`
  - Added 11 new entries: `vprintf`, `vsprintf`, `vsnprintf`, `vswprintf`, `fwprintf`, `vfwprintf`, `_write`, `getchar`, `putchar`
  - Fixed `__stdio_common_vfprintf` `num_params` from 4 to 5
- `litebox_shim_windows/src/loader/dll.rs`
  - Added 9 new MSVCRT.dll stub exports: `vprintf`, `vsprintf`, `vsnprintf`, `vswprintf`, `fwprintf`, `vfwprintf`, `_write`, `getchar`, `putchar`
- `litebox_runner_windows_on_linux_userland/tests/integration.rs`
  - Added Phase 34 assertion block verifying all new MSVCRT.dll exports resolve correctly

### Key Phase 34 improvements

1. **`format_printf_raw`** — The key insight: `core::ffi::VaList<'_>` on x86_64-linux is 24 bytes with the same layout as `__va_list_tag`. By constructing a `VaListTag` struct with `gp_offset=48, fp_offset=304`, all argument reads come from `overflow_arg_area` (the Windows va_list pointer). This allows reusing `format_printf_va` without duplicating the 550-line format parser.

2. **Fixed `vfprintf`** — The old stub just wrote the raw format string to stdout. Now it properly formats using `format_printf_raw`.

3. **Fixed `__stdio_common_vfprintf`** — The UCRT printf entry point was a stub returning -1. Now it accepts the `arglist` 5th parameter and does real formatting. The function table `num_params` was also fixed from 4 to 5.

4. **`_write`** — Delegates to `libc::write`. This is the CRT's low-level write that many programs call either directly or through the fwrite/printf chain.

5. **`getchar`/`putchar`** — Basic character I/O using `libc::read`/`libc::write` on fd 0/1.

### What the next session should consider

**Possible Phase 35 directions:**
1. `_vsnwprintf` — Size-limited wide-char vsnprintf (Windows-specific)
2. `scanf`/`fscanf`/`sscanf` — Formatted input (currently sscanf is a stub returning 0)
3. Extended `msvcp140.dll` — `std::basic_string` operations, `std::exception::what()`
4. More COM functions: `ProgIDFromCLSID`, `CLSIDFromProgID`, `CoMarshalInterface`
5. `_get_osfhandle`/`_open_osfhandle` — File handle <-> fd conversion
6. Additional registry functions or WMI stubs

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

