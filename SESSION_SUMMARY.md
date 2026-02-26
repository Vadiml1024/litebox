# Windows-on-Linux Support — Session Summary (Phase 32)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/continue-windows-linux-support-yet-again`
**Goal:** Phase 32 — Add ole32.dll COM stubs, MSVCRT helpers, and TLS callbacks.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** |
| All tests (500 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_platform_linux_for_windows/src/ole32.rs` — New file: 12 COM initialization/memory/GUID functions
- `litebox_platform_linux_for_windows/src/lib.rs` — Added `pub mod ole32;`
- `litebox_platform_linux_for_windows/src/function_table.rs` — Added 12 ole32.dll entries + 39 new MSVCRT entries
- `litebox_platform_linux_for_windows/src/msvcrt.rs` — Added 39 new MSVCRT function implementations
- `litebox_shim_windows/src/loader/pe.rs` — Added `address_of_callbacks: u64` to `TlsInfo`
- `litebox_shim_windows/src/loader/dll.rs` — Added `load_stub_ole32()` and `OLE32_BASE`; updated DLL count test
- `litebox_runner_windows_on_linux_userland/src/lib.rs` — TLS callback execution before entry point
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Added ole32.dll exports test

### What the next session should consider

All Phase 32 features are implemented and all 500 tests pass (up from 453).

**Possible Phase 33 directions:**
1. MSVCRT printf format specifier support (currently printf/sprintf are simplified stubs)
2. More COM functions: `ProgIDFromCLSID`, `CLSIDFromProgID`, `CoMarshalInterface`
3. `msvcp140.dll` / C++ standard library stubs (`std::string`, `std::vector`, etc.)
4. More MSVCRT wide-char I/O (`_wfopen`, `fwprintf`, `_wfgets`)
5. Windows Management Instrumentation (WMI) stubs

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

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
