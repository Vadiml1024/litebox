# Windows-on-Linux Support — Session Summary (Phase 31)

## ⚡ CURRENT STATUS ⚡

**Branch:** `copilot/test-seh-cpp-test-msvc`
**Goal:** Phase 31 — Test `seh_cpp_test_msvc.exe` and update Windows-on-Linux status document.

### Status at checkpoint

| Component | State |
|-----------|-------|
| `seh_c_test.exe` | ✅ **21/21 PASS** |
| `seh_cpp_test.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_clang.exe` | ✅ **26/26 PASS** |
| `seh_cpp_test_msvc.exe` | ✅ **21/21 PASS** (all 10 tests including destructor unwinding & cross-frame) |
| All tests (453 total) | ✅ Passing |
| Ratchet tests (5) | ✅ Passing |
| Clippy (`-Dwarnings`) | ✅ Clean |

### Files changed in this session
- `litebox_runner_windows_on_linux_userland/tests/integration.rs` — Updated `test_seh_cpp_msvc_program` to verify 21 passed, 0 failed (was only checking basic catch(int) test)
- `docs/windows_on_linux_status.md` — Updated all MSVC ABI status from "tests 1-5 pass, 6-10 in progress" to fully passing 21/21
- `SESSION_SUMMARY.md` — Updated session summary to Phase 31

### What the next session should consider

All four SEH/C++ exception test programs are now fully passing. All 10 MSVC ABI C++ exception tests pass including destructor unwinding and cross-frame propagation.

**Possible Phase 32 directions:**
1. Additional C++ exception tests (nested exceptions, re-throw across DLL boundaries)
2. More MSVCRT C++ runtime functions (if programs need them)
3. TLS callbacks / DLL entry point support
4. More complete thread API (WaitForMultipleObjects with real implementation)
5. COM/OLE initialization (`CoInitialize`, `CoUninitialize`, `OleInitialize`)

### Build & test commands

```bash
cd /home/runner/work/litebox/litebox

# Quick build
cargo build -p litebox_platform_linux_for_windows

# Full build + runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run all SEH tests
cd windows_test_programs/seh_test && make all && cd ../..
./target/debug/litebox_runner_windows_on_linux_userland windows_test_programs/seh_test/seh_c_test.exe
./target/debug/litebox_runner_windows_on_linux_userland windows_test_programs/seh_test/seh_cpp_test.exe
./target/debug/litebox_runner_windows_on_linux_userland windows_test_programs/seh_test/seh_cpp_test_clang.exe
./target/debug/litebox_runner_windows_on_linux_userland windows_test_programs/seh_test/seh_cpp_test_msvc.exe

# Lint
RUSTFLAGS="-Dwarnings" cargo clippy -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland

# Unit tests
cargo nextest run -p litebox_platform_linux_for_windows -p litebox_runner_windows_on_linux_userland

# Ratchet tests
cargo test -p dev_tests
```

### Key source locations

| What | File | ~Line |
|------|------|-------|
| `kernel32_RaiseException` | `litebox_platform_linux_for_windows/src/kernel32.rs` | 1704 |
| `kernel32_RtlUnwindEx` | same | 1879 |
| `msvcrt__CxxThrowException` | `litebox_platform_linux_for_windows/src/msvcrt.rs` | 2566 |
| `cxx_frame_handler` | same | 2640 |
| BSTR functions | `litebox_platform_linux_for_windows/src/oleaut32.rs` | 69+ |
| Function table | `litebox_platform_linux_for_windows/src/function_table.rs` | — |

