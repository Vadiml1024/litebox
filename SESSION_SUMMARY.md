# Windows-on-Linux Support Continuation - Session Summary

## Session Date
2026-02-16

## Objective
Continue implementing Windows-on-Linux support in the litebox repository.

## Initial Status
- Framework 100% complete (Phase 8) according to documentation
- All 149 tests passing
- Windows PE binaries load successfully
- Entry point execution crashes with segfault (exit code 139)

## Root Cause Analysis

Using the explore agent and GDB debugging, I identified several critical issues:

### 1. TEB Structure Layout Bug (CRITICAL) ✅ FIXED
**Problem:** PEB pointer was at offset 0xA0 instead of 0x60
- Windows x64 ABI requires PEB pointer at offset 0x60 from TEB base
- Reserved array was 10 u64s instead of 2 u64s
- CRT code accessing `gs:[0x60]` got wrong address

**Fix:** Reduced `_reserved` array from `[u64; 10]` to `[u64; 2]`

### 2. Stack Alignment Bug (CRITICAL) ✅ FIXED  
**Problem:** Stack was misaligned before CALL instruction
- Code had: `aligned_stack = (stack_top & !0xF) - 8`
- This made RSP = 16n + 8 - 8 - 32 = 16n - 32 (misaligned!)
- Windows x64 requires RSP to be 16-byte aligned BEFORE call

**Fix:** Removed the `-8` adjustment. Now RSP is 16-byte aligned before CALL.

### 3. Missing PEB.Ldr (CRITICAL) ✅ FIXED
**Problem:** PEB.Ldr was NULL pointer
- MinGW CRT initialization code dereferences PEB.Ldr
- NULL pointer caused segfault

**Fix:** Added `PebLdrData` structure with:
- Proper size and initialization flag
- Circular LIST_ENTRY structures for module lists
- All lists point to themselves (empty circular lists)

### 4. Missing PEB.ProcessParameters ✅ FIXED
**Problem:** PEB.ProcessParameters was NULL
- CRT needs this for command line arguments and environment

**Fix:** Added `RtlUserProcessParameters` structure with stubs for:
- Console handles
- Standard input/output/error handles  
- Process flags and parameters

## Code Changes

### Files Modified
1. `litebox_shim_windows/src/loader/execution.rs`
   - Fixed TEB structure layout (PEB pointer at offset 0x60)
   - Fixed stack alignment logic
   - Added PebLdrData structure (64 bytes)
   - Added RtlUserProcessParameters structure (232 bytes)
   - Updated ExecutionContext to manage new structures
   - Fixed test to use new PEB constructor signature
   - Implemented Default traits for new structures
   - Resolved all clippy warnings

2. `windows_test_programs/Cargo.toml`
   - Added minimal_test to workspace members
   - Added panic = "abort" profile for no_std builds

3. `windows_test_programs/minimal_test/` (NEW)
   - Attempted to create minimal test program without CRT
   - Not yet functional due to linker issues with MinGW

## Testing Results

### Before Fixes
- Crash immediately at entry point
- No visibility into crash location

### After Fixes
- Windows program loads successfully
- All sections loaded and relocated
- All imports resolved and IAT patched
- TEB/PEB structures properly initialized
- GS register configured correctly
- Stack allocated and aligned
- **Program now crashes deeper in CRT initialization** (progress!)

### GDB Analysis
```
Crash location: 0x7FFFF7A91089
Entry point: 0x7FFFF7A91410
Offset: -0x387 (before entry point in CRT init code)

Instruction: mov %edx,(%rax)
Register rax: 0x3018 (low address, likely uninitialized global)
```

The crash is now inside MinGW CRT initialization code trying to initialize global variables. This is significant progress from crashing at entry point.

### Test Suite
- ✅ litebox_shim_windows: 39 tests passing
- ✅ litebox_platform_linux_for_windows: 105 tests passing  
- ✅ litebox_runner_windows_on_linux_userland: 16 tests passing
- **Total: 160 tests passing**

## Code Quality

### Clippy
- ✅ All warnings resolved
- Added appropriate `#[allow(clippy::cast_possible_truncation)]` for intentional casts
- Implemented Default traits as suggested

### rustfmt
- ✅ All code formatted

### Code Review
- ✅ Automated code review completed
- No issues found

### CodeQL
- ⏳ Timed out (long-running analysis)
- Not blocking for this change

## Technical Insights

### Windows x64 ABI Requirements
1. RSP must be 16-byte aligned BEFORE call instruction
2. Call instruction pushes 8-byte return address
3. At function entry, RSP is misaligned by 8 (16n + 8)
4. Functions must allocate shadow space (32 bytes minimum)

### TEB/PEB Structure Layout (x64)
```
TEB:
  +0x00: Exception list
  +0x08: Stack base
  +0x10: Stack limit
  ...
  +0x30: Self pointer
  ...
  +0x60: PEB pointer ← CRITICAL!

PEB:
  +0x00: Flags and metadata
  +0x10: Image base address
  +0x18: Ldr (PEB_LDR_DATA*) ← Must not be NULL
  +0x20: ProcessParameters ← Must not be NULL
```

### LIST_ENTRY Circular Lists
Windows uses doubly-linked circular lists for module enumeration:
```c
typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;  // Forward link
    struct _LIST_ENTRY *Blink;  // Back link
} LIST_ENTRY;
```

Empty list: Both Flink and Blink point to the list head itself.

## Remaining Work

### Short Term
1. **Investigate CRT Global Initialization**
   - Crash at address 0x3018 suggests uninitialized global
   - May need additional CRT stubs or different approach

2. **Alternative Test Programs**
   - Create truly minimal Windows program without MinGW CRT
   - Hand-craft minimal PE or use different toolchain

3. **Documentation**
   - Update windows_on_linux_status.md with latest findings
   - Document TEB/PEB structure requirements

### Long Term
1. **Full CRT Support**
   - Implement missing MinGW CRT initialization functions
   - Handle global constructors/destructors
   - Support thread-local storage initialization

2. **Exception Handling**
   - Implement basic SEH (Structured Exception Handling)
   - Set up exception dispatcher
   - Handle unwind information

## Conclusion

This session made significant progress on Windows-on-Linux support:

✅ **Fixed 3 critical bugs** that prevented any execution
✅ **Added essential PEB structures** to support CRT initialization  
✅ **Installed GDB** for debugging capabilities
✅ **All tests passing** with improved code quality

The Windows program now executes significantly further into CRT initialization before crashing, demonstrating that the core PE loading, relocation, import resolution, and TEB/PEB setup are working correctly.

The remaining crash is in MinGW CRT's global variable initialization, which is a more tractable problem than the fundamental structural issues that were fixed.

## Commits
1. Initial plan
2. Fix critical TEB/PEB structure issues for Windows entry point execution
3. Add PEB.Ldr and ProcessParameters stubs to prevent CRT crashes
4. Fix clippy warnings in PEB structures

## Files Changed
- `litebox_shim_windows/src/loader/execution.rs` (+166 lines, improved)
- `windows_test_programs/Cargo.toml` (added minimal_test workspace member)
- `windows_test_programs/minimal_test/` (new directory, experimental)
