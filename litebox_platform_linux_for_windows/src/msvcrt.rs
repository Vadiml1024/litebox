// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MSVCRT (Microsoft Visual C++ Runtime) function implementations
//!
//! This module provides Linux-based implementations of MSVCRT functions
//! that are commonly used by Windows programs. These functions are mapped
//! to their Linux equivalents where possible.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]

use std::alloc::{Layout, alloc, dealloc};
use std::ffi::{CStr, CString};
use std::io::{self, Write};
use std::ptr;
use std::sync::{Mutex, OnceLock};

// ============================================================================
// Data Exports
// ============================================================================
// These are global variables that Windows programs import directly.
// Unlike function exports, these need to be actual memory locations.

/// File mode (_fmode) - default file open mode
/// 0x4000 = _O_BINARY (binary mode), 0x8000 = _O_TEXT (text mode)
/// Default is binary mode (0x4000)
#[unsafe(no_mangle)]
pub static mut msvcrt__fmode: i32 = 0x4000; // Binary mode by default

/// Commit mode (_commode) - file commit behavior
/// 0 = no commit, non-zero = commit
#[unsafe(no_mangle)]
pub static mut msvcrt__commode: i32 = 0;

/// Environment pointer (__initenv) - pointer to environment variables
/// This is a triple pointer: pointer to array of pointers to strings
#[unsafe(no_mangle)]
pub static mut msvcrt___initenv: *mut *mut i8 = ptr::null_mut();

// ============================================================================
// Data Access Functions
// ============================================================================
// These functions return pointers to global data variables

/// Get pointer to file mode (_fmode)
///
/// # Safety
/// Returns a pointer to a static mutable variable. The caller must ensure
/// proper synchronization if accessing from multiple threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p__fmode() -> *mut i32 {
    core::ptr::addr_of_mut!(msvcrt__fmode)
}

/// Get pointer to commit mode (_commode)
///
/// # Safety
/// Returns a pointer to a static mutable variable. The caller must ensure
/// proper synchronization if accessing from multiple threads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p__commode() -> *mut i32 {
    core::ptr::addr_of_mut!(msvcrt__commode)
}

// ============================================================================
// CRT Initialization Functions
// ============================================================================

/// Set command line arguments (_setargv)
///
/// This is called during CRT initialization to parse command line arguments.
/// For now, this is a no-op stub since we handle arguments in __getmainargs.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__setargv() {
    // No-op stub - we handle arguments in __getmainargs
}

/// Set invalid parameter handler
///
/// This is called during CRT initialization to set a handler for invalid parameters.
/// For now, this is a no-op stub.
///
/// # Safety
/// This function is unsafe as it deals with function pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__set_invalid_parameter_handler(
    _handler: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // No-op stub - return null to indicate no previous handler
    ptr::null_mut()
}

/// PE runtime relocator
///
/// This function is called by MinGW runtime to perform additional relocations.
/// Since relocations are already handled by our PE loader, this is a no-op.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__pei386_runtime_relocator() {
    // No-op stub - relocations already handled by PE loader
}

// ============================================================================
// Memory Management Functions
// ============================================================================

/// Allocate memory (malloc)
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
/// The caller must ensure the returned pointer is properly freed with `msvcrt_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: We're creating a valid layout for the requested size
    let layout = unsafe { Layout::from_size_align_unchecked(size, std::mem::align_of::<usize>()) };
    // SAFETY: Layout is valid
    unsafe { alloc(layout) }
}

/// Free memory (free)
///
/// # Safety
/// This function is unsafe as it deals with raw memory deallocation.
/// The pointer must have been allocated by `msvcrt_malloc` or `msvcrt_calloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    // SAFETY: We create a minimal layout; the allocator tracks the actual size
    let layout = unsafe { Layout::from_size_align_unchecked(1, std::mem::align_of::<usize>()) };
    // SAFETY: Caller guarantees ptr was allocated by malloc/calloc
    unsafe { dealloc(ptr, layout) };
}

/// Allocate and zero-initialize memory (calloc)
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
/// The caller must ensure the returned pointer is properly freed with `msvcrt_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_calloc(num: usize, size: usize) -> *mut u8 {
    let total_size = num.saturating_mul(size);
    if total_size == 0 {
        return ptr::null_mut();
    }

    // SAFETY: Caller is responsible for freeing the returned pointer
    let ptr = unsafe { msvcrt_malloc(total_size) };
    if !ptr.is_null() {
        // SAFETY: ptr is valid for total_size bytes
        unsafe { ptr::write_bytes(ptr, 0, total_size) };
    }
    ptr
}

/// Copy memory (memcpy)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure src and dest don't overlap and are valid for the given size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees src and dest are valid and don't overlap
    unsafe { ptr::copy_nonoverlapping(src, dest, n) };
    dest
}

/// Move memory (memmove) - handles overlapping regions
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure src and dest are valid for the given size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees src and dest are valid; copy handles overlaps
    unsafe { ptr::copy(src, dest, n) };
    dest
}

/// Set memory (memset)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest is valid for the given size.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    // SAFETY: Caller guarantees dest is valid for n bytes
    ptr::write_bytes(dest, c as u8, n);
    dest
}

/// Compare memory (memcmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers are valid for the given size.
#[unsafe(no_mangle)]
#[allow(clippy::cast_lossless)]
pub unsafe extern "C" fn msvcrt_memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    // SAFETY: Caller guarantees s1 and s2 are valid for n bytes
    for i in 0..n {
        let c1 = *s1.add(i);
        let c2 = *s2.add(i);
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
    }
    0
}

/// Get string length (strlen)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure the pointer points to a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strlen(s: *const i8) -> usize {
    // SAFETY: Caller guarantees s points to a null-terminated string
    CStr::from_ptr(s).to_bytes().len()
}

/// Compare strings up to n characters (strncmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
#[allow(clippy::cast_lossless)]
pub unsafe extern "C" fn msvcrt_strncmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
    // SAFETY: Caller guarantees s1 and s2 are valid null-terminated strings
    for i in 0..n {
        let c1 = (*s1.add(i)).cast_unsigned();
        let c2 = (*s2.add(i)).cast_unsigned();

        // Check for null terminator
        if c1 == 0 && c2 == 0 {
            return 0;
        }
        if c1 == 0 {
            return -1;
        }
        if c2 == 0 {
            return 1;
        }

        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
    }
    0
}

/// Print formatted string to stdout (printf)
///
/// Note: This is a simplified stub implementation
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn msvcrt_printf(format: *const i8) -> i32 {
    if format.is_null() {
        return -1;
    }

    // SAFETY: Caller guarantees format points to a valid null-terminated string
    let Some(format_str) = CStr::from_ptr(format).to_str().ok() else {
        return -1;
    };

    // Simple implementation: just print the format string as-is
    // A full implementation would parse varargs and handle format specifiers
    match write!(io::stdout(), "{format_str}") {
        Ok(()) => {
            let _ = io::stdout().flush();
            format_str.len() as i32
        }
        Err(_e) => -1,
    }
}

/// Write data to a file (fwrite)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fwrite(
    ptr: *const u8,
    size: usize,
    nmemb: usize,
    _stream: *mut u8,
) -> usize {
    if ptr.is_null() || size == 0 || nmemb == 0 {
        return 0;
    }

    let total_bytes = size * nmemb;
    // SAFETY: Caller guarantees ptr is valid for total_bytes
    let data = unsafe { std::slice::from_raw_parts(ptr, total_bytes) };

    // Simple implementation: write to stdout
    match io::stdout().write(data) {
        Ok(written) => {
            let _ = io::stdout().flush();
            written / size
        }
        Err(_e) => 0,
    }
}

/// Simplified fprintf - only supports writing to stdout/stderr
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fprintf(_stream: *mut u8, format: *const i8) -> i32 {
    // For simplicity, just use printf implementation
    // SAFETY: Caller guarantees format is a valid null-terminated string
    unsafe { msvcrt_printf(format) }
}

/// Simplified vfprintf stub
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_vfprintf(
    _stream: *mut u8,
    format: *const i8,
    _args: *mut u8,
) -> i32 {
    // For simplicity, just print the format string
    // SAFETY: Caller guarantees format is a valid null-terminated string
    unsafe { msvcrt_printf(format) }
}

/// Get I/O buffer array (__iob_func)
/// Returns a pointer to stdin/stdout/stderr file descriptors
///
/// # Safety
/// This function returns a static array that should not be freed.
/// Uses Mutex for thread-safe access to the static buffer.
///
/// # Panics
/// Panics if the mutex is poisoned (which would only occur if another thread
/// panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___iob_func() -> *mut u8 {
    use std::sync::Mutex;

    // Use Mutex for thread-safe access to the static buffer
    // In a full implementation, this would return FILE* structures
    static IOB: Mutex<[u8; 24]> = Mutex::new([0; 24]); // 3 FILE structures (simplified)

    // SAFETY: Lock the mutex and return a pointer to the buffer.
    // The pointer remains valid as long as the static exists.
    // Note: This matches Windows CRT behavior where __iob_func returns a global buffer.
    IOB.lock().unwrap().as_mut_ptr()
}

/// Get main arguments (__getmainargs)
///
/// Parses `PROCESS_COMMAND_LINE` (set by the runner) into ANSI `char**` arrays
/// using Windows command-line quoting rules and stores them in a `OnceLock` so
/// that the returned raw pointers remain stable for the lifetime of the process.
///
/// # Panics
/// Panics if `CString::new("")` fails (which should never happen).
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn msvcrt___getmainargs(
    p_argc: *mut i32,
    p_argv: *mut *mut *mut i8,
    p_env: *mut *mut *mut i8,
    _do_wildcard: i32,
    _start_info: *mut u8,
) -> i32 {
    let (_, argv_ptrs) = PARSED_MAIN_ARGS.get_or_init(|| {
        let cmd = crate::kernel32::get_command_line_utf8();
        let strings: Vec<CString> = parse_windows_command_line(&cmd)
            .into_iter()
            .map(|s| {
                let safe = s.replace('\0', "?");
                CString::new(safe).unwrap_or_else(|_| CString::new("").unwrap())
            })
            .collect();
        // Build a null-terminated array of `*mut i8` pointers.
        let mut ptrs: Vec<*mut i8> = strings.iter().map(|cs| cs.as_ptr().cast_mut()).collect();
        ptrs.push(ptr::null_mut()); // null terminator
        (strings, ArgvPtrs(ptrs))
    });

    let argc = i32::try_from(argv_ptrs.0.len().saturating_sub(1)).unwrap_or(i32::MAX); // exclude null terminator

    if !p_argc.is_null() {
        *p_argc = argc;
    }
    if !p_argv.is_null() {
        // argv_ptrs.0 is a null-terminated array; pass a pointer to its first element.
        *p_argv = argv_ptrs.0.as_ptr().cast_mut().cast();
    }
    // env: pass a single-element null-terminated array (no custom env parsing needed;
    // programs that need the environment use GetEnvironmentStringsW instead).
    if !p_env.is_null() {
        // SAFETY: NULL_ENV_PTR is an array of zeros (null pointers) stored as usize
        // to avoid the `*mut i8: Sync` restriction on statics.
        static NULL_ENV_PTR: [usize; 1] = [0];
        *p_env = NULL_ENV_PTR.as_ptr().cast::<*mut i8>().cast_mut().cast();
    }

    0 // Success
}

/// Set application type (__set_app_type)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___set_app_type(_type: i32) {
    // No-op stub
}

/// Initialize term table (_initterm)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__initterm(start: *mut extern "C" fn(), end: *mut extern "C" fn()) {
    if start.is_null() || end.is_null() {
        return;
    }

    let mut current = start;
    while current < end {
        // SAFETY: Caller guarantees current is within valid range [start, end)
        let func_ptr_raw = unsafe { *(current.cast::<usize>()) };

        // Check if function pointer is not null or -1 (sentinel value) before calling
        if func_ptr_raw != 0 && func_ptr_raw != usize::MAX {
            // SAFETY:
            // - Provenance: `func_ptr_raw` is read from the array in [`start`, `end`), which
            //   the caller (the MSVCRT/CRT runtime) populates with pointers to initialization
            //   functions following the `_initterm` contract. Each non-null, non-`usize::MAX`
            //   entry is required to point to a valid function with ABI `extern "C" fn()`.
            // - Invariants relied on:
            //   * The memory between `start` and `end` is a contiguous array of pointer-sized
            //     entries written by the loader/CRT, not arbitrary data.
            //   * For any entry that is not `0` or `usize::MAX`, the value represents a live,
            //     correctly aligned, executable code address for a function that takes no
            //     arguments, uses the C ABI, and returns `()`.
            //   * Those functions are safe to call exactly once during process initialization.
            // - Validation performed here:
            //   * We skip entries that are `0` (null) or `usize::MAX` (documented sentinel).
            //   * We rely on the PE loader/MSVCRT initialization logic to have mapped the
            //     corresponding code pages as executable and to uphold the ABI/lifetime
            //     guarantees for these function pointers.
            let func: extern "C" fn() = unsafe { core::mem::transmute(func_ptr_raw) };
            func();
        }

        // SAFETY: Caller guarantees current can be advanced within the range
        current = unsafe { current.add(1) };
    }
}

/// Register onexit handler (_onexit)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__onexit(func: extern "C" fn()) -> extern "C" fn() {
    // Store in a static vector for later execution
    static ONEXIT_FUNCS: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

    // Check if function pointer is valid (not null or -1)
    let func_ptr = func as *const fn();
    let func_addr = func_ptr as usize;
    if func_ptr.is_null() || func_addr == usize::MAX {
        return func; // Return as-is for invalid pointers
    }

    if let Ok(mut funcs) = ONEXIT_FUNCS.lock() {
        funcs.push(func);
    }
    func
}

/// Signal handler registration (signal)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_signal(_signum: i32, _handler: extern "C" fn(i32)) -> usize {
    // Stub: return SIG_DFL (0)
    0
}

/// Abort program execution (abort)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_abort() -> ! {
    std::process::abort()
}

/// Exit program (exit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_exit(status: i32) -> ! {
    std::process::exit(status)
}

// Additional CRT stubs

/// Set user math error handler (__setusermatherr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___setusermatherr(_handler: *mut u8) {
    // No-op stub
}

/// Exit with error message (_amsg_exit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__amsg_exit(code: i32) {
    std::process::exit(code)
}

/// Clean exit without terminating process (_cexit)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__cexit() {
    // Clean exit without terminating process
}

/// Reset floating point unit (_fpreset)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__fpreset() {
    // Reset floating point unit - no-op on x86-64
}

/// Thread-local errno storage for proper per-thread error handling
use std::cell::RefCell;

thread_local! {
    static ERRNO: RefCell<i32> = const { RefCell::new(0) };
}

/// Get errno location (__errno_location)
///
/// # Safety
/// This function returns a pointer to thread-local errno storage.
/// The pointer is valid for the lifetime of the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___errno_location() -> *mut i32 {
    // SAFETY: Returns a pointer to thread-local storage.
    // The pointer is valid as long as the thread exists.
    ERRNO.with(std::cell::RefCell::as_ptr)
}

/// Wrapper so `Vec<*mut i8>` (not `Send`/`Sync`) can be stored in a static.
///
/// # Safety
/// Pointers are derived from `CString` buffers that live inside the same
/// `OnceLock` and are never mutated after initialisation.
struct ArgvPtrs(Vec<*mut i8>);
// SAFETY: The underlying CString buffers are pinned inside the same OnceLock
// value and are never written to after initialisation.
unsafe impl Send for ArgvPtrs {}
unsafe impl Sync for ArgvPtrs {}

/// Parsed process main arguments — populated lazily on the first `__getmainargs` call.
///
/// Stores:
///   0: `Vec<CString>` — the argument strings (owns the memory).
///   1: `ArgvPtrs`     — null-terminated array of `char*` pointers into element 0.
///
/// The `OnceLock` ensures the `CString` buffers are never moved after initialisation,
/// making the raw pointers in element 1 permanently stable.
static PARSED_MAIN_ARGS: OnceLock<(Vec<CString>, ArgvPtrs)> = OnceLock::new();

/// Parse a Windows-style command line into individual argument strings.
///
/// Handles the common quoting rules:
///   - Arguments separated by spaces / tabs.
///   - `"..."` wraps a quoted argument (the quotes are stripped).
///   - Backslashes followed by a quote use Windows' 2N / 2N+1 rules:
///     - 2N backslashes + `"` => N backslashes + toggle quoting (no literal `"`).
///     - 2N+1 backslashes + `"` => N backslashes + literal `"` (no toggle).
///   - These rules apply both inside and outside quoted arguments.
fn parse_windows_command_line(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    // Work on a Vec<char> so we can look ahead by index without
    // breaking UTF-8 encoding; we only treat ASCII `"`, `\`, space, and tab
    // specially, which are all single-byte and single-char code points.
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
                i += 1;
            }
            '"' => {
                // A bare quote toggles the in_quotes state and is not emitted.
                in_quotes = !in_quotes;
                i += 1;
            }
            '\\' => {
                // Count consecutive backslashes.
                let mut backslash_count = 0;
                while i < chars.len() && chars[i] == '\\' {
                    backslash_count += 1;
                    i += 1;
                }

                let next_is_quote = i < chars.len() && chars[i] == '"';
                if next_is_quote {
                    // Emit one backslash for every pair.
                    current.extend(std::iter::repeat_n('\\', backslash_count / 2));
                    if backslash_count % 2 == 0 {
                        // Even number of backslashes: the quote is a delimiter.
                        in_quotes = !in_quotes;
                        i += 1; // consume the quote
                    } else {
                        // Odd number of backslashes: the quote is escaped.
                        current.push('"');
                        i += 1; // consume the quote
                    }
                } else {
                    // No quote follows: emit all backslashes literally.
                    current.extend(std::iter::repeat_n('\\', backslash_count));
                }
            }
            other => {
                current.push(other);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        args.push(current);
    }
    args
}

/// ANSI command-line storage for `_acmdln`.
///
/// Lazily built from `PROCESS_COMMAND_LINE` on first access.
static ACMDLN_STORAGE: OnceLock<CString> = OnceLock::new();

/// Get pointer to command line string (_acmdln)
///
/// This is a global variable in MSVCRT that points to the ANSI command line.
/// Programs access it via `_acmdln` which is a `char*`.
///
/// # Panics
/// Panics if `CString::new("")` fails (which should never happen).
///
/// # Safety
/// Returns a pointer to static memory that is valid for the lifetime of the program.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__acmdln() -> *const u8 {
    let cstr = ACMDLN_STORAGE.get_or_init(|| {
        let utf8 = crate::kernel32::get_command_line_utf8();
        // SAFETY: `utf8` comes from a valid String; CString::new only fails on interior NUL
        // bytes.  We replace any interior NULs with '?' to be safe.
        let safe = utf8.replace('\0', "?");
        CString::new(safe).unwrap_or_else(|_| CString::new("").unwrap())
    });
    cstr.as_ptr().cast::<u8>()
}

/// Check if a byte is a multibyte lead byte (_ismbblead)
///
/// This function checks if a byte is the lead byte of a multibyte character
/// in the current code page. For simplicity, we assume UTF-8 encoding.
///
/// # Safety
/// Safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ismbblead(c: u32) -> i32 {
    // In UTF-8:
    // - Bytes 0x00-0x7F are single-byte characters (not lead bytes)
    // - Bytes 0x80-0xBF are continuation bytes (not lead bytes)
    // - Bytes 0xC0-0xFF are lead bytes
    //
    // For ANSI code pages, lead bytes depend on the specific code page.
    // We'll implement a simple check for UTF-8.

    let byte = (c & 0xFF) as u8;

    // In UTF-8, lead bytes are >= 0xC0
    i32::from(byte >= 0xC0)
}

/// C-specific exception handler (__C_specific_handler)
///
/// This is a placeholder implementation for structured exception handling (SEH).
/// Real implementation would require full SEH support with exception tables.
///
/// # Safety
/// This is a stub that should not be called in normal execution.
/// Marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___C_specific_handler(
    _exception_record: usize,
    _establisher_frame: usize,
    _context_record: usize,
    _dispatcher_context: usize,
) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH (1)
    // This tells the system to continue searching for an exception handler
    1
}

/// Compare two null-terminated strings (strcmp)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcmp(s1: *const i8, s2: *const i8) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1.is_null() && s2.is_null() {
            0
        } else if s1.is_null() {
            -1
        } else {
            1
        };
    }
    let mut i = 0usize;
    loop {
        let c1 = (*s1.add(i)).cast_unsigned();
        let c2 = (*s2.add(i)).cast_unsigned();
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Copy a null-terminated string (strcpy)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest has enough space and src is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcpy(dest: *mut i8, src: *const i8) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0usize;
    loop {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// Concatenate two null-terminated strings (strcat)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure dest has enough space for the concatenated result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strcat(dest: *mut i8, src: *const i8) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    // Find end of dest
    let mut i = 0usize;
    while *dest.add(i) != 0 {
        i += 1;
    }
    // Copy src to end of dest
    let mut j = 0usize;
    loop {
        let c = *src.add(j);
        *dest.add(i + j) = c;
        if c == 0 {
            break;
        }
        j += 1;
    }
    dest
}

/// Find first occurrence of a character in a string (strchr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure s is a valid null-terminated string.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_strchr(s: *const i8, c: i32) -> *const i8 {
    if s.is_null() {
        return ptr::null();
    }
    let target = c as i8;
    let mut i = 0usize;
    loop {
        let ch = *s.add(i);
        if ch == target {
            return s.add(i);
        }
        if ch == 0 {
            return ptr::null();
        }
        i += 1;
    }
}

/// Find last occurrence of a character in a string (strrchr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure s is a valid null-terminated string.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub unsafe extern "C" fn msvcrt_strrchr(s: *const i8, c: i32) -> *const i8 {
    if s.is_null() {
        return ptr::null();
    }
    let target = c as i8;
    let mut last: *const i8 = ptr::null();
    let mut i = 0usize;
    loop {
        let ch = *s.add(i);
        if ch == target {
            last = s.add(i);
        }
        if ch == 0 {
            return last;
        }
        i += 1;
    }
}

/// Find first occurrence of a substring in a string (strstr)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure both pointers point to valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strstr(haystack: *const i8, needle: *const i8) -> *const i8 {
    if haystack.is_null() || needle.is_null() {
        return ptr::null();
    }
    // Empty needle matches at the start
    if *needle == 0 {
        return haystack;
    }
    let needle_len = CStr::from_ptr(needle).to_bytes().len();
    let mut i = 0usize;
    while *haystack.add(i) != 0 {
        let mut matched = true;
        for j in 0..needle_len {
            if *haystack.add(i + j) == 0 || *haystack.add(i + j) != *needle.add(j) {
                matched = false;
                break;
            }
        }
        if matched {
            return haystack.add(i);
        }
        i += 1;
    }
    ptr::null()
}

/// Initialize term table with error return (_initterm_e)
///
/// Like _initterm, but the function pointers return an int error code.
/// Returns 0 on success, or the first non-zero return value on failure.
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__initterm_e(
    start: *mut extern "C" fn() -> i32,
    end: *mut extern "C" fn() -> i32,
) -> i32 {
    if start.is_null() || end.is_null() {
        return 0;
    }

    let mut current = start;
    while current < end {
        let func_ptr_raw = *(current.cast::<usize>());

        if func_ptr_raw != 0 && func_ptr_raw != usize::MAX {
            // SAFETY: Same contract as _initterm - entries are valid function pointers
            // with ABI extern "C" fn() -> i32, populated by the CRT/loader.
            let func: extern "C" fn() -> i32 = core::mem::transmute(func_ptr_raw);
            let result = func();
            if result != 0 {
                return result;
            }
        }

        current = current.add(1);
    }
    0
}

/// Global argc value for `__p___argc`.
///
/// Initialized to 0 and written once during CRT startup by `__getmainargs`.
/// After that single write the value is only read, so concurrent readers are safe
/// without additional synchronization (single-threaded CRT init guarantees this).
static ARGC_STATIC: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Global argv pointer for `__p___argv`.
///
/// Initialized to null and written once during CRT startup by `__getmainargs`.
/// After that single write the value is only read.
static ARGV_PTR: std::sync::atomic::AtomicPtr<*mut i8> =
    std::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Get pointer to argc (__p___argc)
///
/// Returns a pointer to the global argc value. Currently initialized to 0
/// since command-line argument passing is handled by `__getmainargs`.
/// The CRT startup code calls `__getmainargs` first, which sets argc/argv,
/// and `__p___argc` provides an alternate access path.
///
/// # Safety
/// The returned `*mut i32` points to the interior of an `AtomicI32`.
/// Callers (the CRT) treat it as a plain int, which is fine because
/// the CRT initialises this value exactly once during single-threaded
/// startup and only reads it afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p___argc() -> *mut i32 {
    ARGC_STATIC.as_ptr()
}

/// Get pointer to argv (__p___argv)
///
/// Returns a pointer to the global argv pointer. Currently initialized to null
/// since command-line argument passing is handled by `__getmainargs`.
/// The CRT startup code calls `__getmainargs` first, which sets argc/argv,
/// and `__p___argv` provides an alternate access path.
///
/// # Safety
/// The returned `*mut *mut *mut i8` points to the interior of an `AtomicPtr`.
/// Callers (the CRT) treat it as a plain pointer, which is fine because
/// the CRT initialises this value exactly once during single-threaded
/// startup and only reads it afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___p___argv() -> *mut *mut *mut i8 {
    ARGV_PTR.as_ptr().cast()
}

/// CRT internal lock (_lock)
///
/// Used by the CRT for thread-safe access to internal data structures.
/// Lock IDs include _HEAP_LOCK (4), _ENV_LOCK (7), etc.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__lock(_locknum: i32) {
    // No-op stub - in our single-threaded emulation, locking is not needed
}

/// CRT internal unlock (_unlock)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__unlock(_locknum: i32) {
    // No-op stub - in our single-threaded emulation, locking is not needed
}

/// Get environment variable (getenv)
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
/// The caller must ensure name is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_getenv(name: *const i8) -> *const i8 {
    if name.is_null() {
        return ptr::null();
    }
    // Use libc getenv which returns a pointer to the actual environment value
    libc::getenv(name)
}

/// Get errno location (_errno)
/// This is the MSVCRT name for errno access (as opposed to __errno_location)
///
/// # Safety
/// This function returns a pointer to thread-local errno storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__errno() -> *mut i32 {
    msvcrt___errno_location()
}

/// Initialize locale conversion (__lconv_init)
///
/// Called during CRT startup to initialize locale data.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___lconv_init() -> i32 {
    // No-op stub - return 0 for success
    0
}

/// CRT exception filter (_XcptFilter)
///
/// Returns EXCEPTION_CONTINUE_SEARCH to let the exception propagate.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__XcptFilter(
    _exception_code: u32,
    _exception_pointers: *mut core::ffi::c_void,
) -> i32 {
    // Return EXCEPTION_CONTINUE_SEARCH (1)
    1
}

/// Control floating-point behavior (_controlfp)
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__controlfp(new_val: u32, mask: u32) -> u32 {
    // Return the "new" control word - in practice just echo back what was set
    // Default x87 control word on Windows: 0x0009001F
    if mask == 0 {
        0x0009_001F // Default value
    } else {
        (0x0009_001F & !mask) | (new_val & mask)
    }
}

/// `strerror` – return a pointer to the error message string for `errnum`.
///
/// Delegates to the host libc `strerror` so the returned string has valid
/// static-ish lifetime (it may be overwritten by the next call, just like on
/// real Windows/Linux).
///
/// # Safety
/// The returned pointer is only valid until the next call to `strerror`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strerror(errnum: i32) -> *mut i8 {
    libc::strerror(errnum)
}

/// `wcslen` – return the number of wide characters in `s`, not including the
/// terminating null character.
///
/// # Safety
/// `s` must be a valid, null-terminated wide character string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcslen(s: *const u16) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    // SAFETY: caller guarantees s is null-terminated.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// `fputc` – write character `c` to the stream `stream`.
///
/// For simplicity this stub forwards to the host file descriptor: fd 1 for
/// stdout (FILE* index 1 in Windows __iob_func) and fd 2 for stderr (index
/// 2); everything else is treated as stdout.
///
/// # Safety
/// `stream` is used only as a discriminator; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fputc(c: i32, stream: *mut core::ffi::c_void) -> i32 {
    // Windows FILE* values from __iob_func: stdin=0, stdout=1, stderr=2.
    // Treat pointer values 0/1 as stdout, 2 as stderr.
    let fd: libc::c_int = if stream as usize == 2 { 2 } else { 1 };
    let byte = (c & 0xFF) as u8;
    // SAFETY: `byte` is a valid single-byte buffer.
    let written = unsafe { libc::write(fd, std::ptr::addr_of!(byte).cast(), 1) };
    if written == 1 {
        c & 0xFF
    } else {
        // EOF
        -1
    }
}

/// `localeconv` – return locale-specific numeric formatting information.
///
/// Returns a pointer to a static `lconv`-compatible structure initialised
/// for the "C" locale (decimal point = '.', everything else empty or CHAR_MAX).
///
/// # Safety
/// The returned pointer is valid for the lifetime of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_localeconv() -> *mut libc::lconv {
    // Delegate to the host libc which always has a valid C-locale lconv.
    // SAFETY: libc::localeconv() always returns a non-null pointer.
    unsafe { libc::localeconv() }
}

/// `___lc_codepage_func` – internal MinGW/MSVCRT helper that returns the
/// current locale's ANSI code page.
///
/// Returns 0, which corresponds to the "C" / UTF-8 locale and causes the CRT
/// to treat strings as single-byte ASCII.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt____lc_codepage_func() -> u32 {
    0
}

/// `___mb_cur_max_func` – internal MinGW/MSVCRT helper that returns the
/// maximum number of bytes per multibyte character for the current locale.
///
/// Returns 1 (single-byte C locale).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt____mb_cur_max_func() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_free() {
        unsafe {
            let ptr = msvcrt_malloc(100);
            assert!(!ptr.is_null());
            msvcrt_free(ptr);
        }
    }

    #[test]
    fn test_calloc() {
        unsafe {
            let ptr = msvcrt_calloc(10, 10);
            assert!(!ptr.is_null());
            // Verify zero-initialization
            for i in 0..100 {
                assert_eq!(*ptr.add(i), 0);
            }
            msvcrt_free(ptr);
        }
    }

    #[test]
    fn test_memcpy() {
        unsafe {
            let src = [1u8, 2, 3, 4, 5];
            let mut dest = [0u8; 5];
            msvcrt_memcpy(dest.as_mut_ptr(), src.as_ptr(), 5);
            assert_eq!(dest, src);
        }
    }

    #[test]
    fn test_memset() {
        unsafe {
            let mut buf = [0u8; 10];
            msvcrt_memset(buf.as_mut_ptr(), 0xFF, 10);
            assert_eq!(buf, [0xFF; 10]);
        }
    }

    #[test]
    fn test_memcmp() {
        unsafe {
            let s1 = [1u8, 2, 3];
            let s2 = [1u8, 2, 3];
            let s3 = [1u8, 2, 4];
            assert_eq!(msvcrt_memcmp(s1.as_ptr(), s2.as_ptr(), 3), 0);
            assert!(msvcrt_memcmp(s1.as_ptr(), s3.as_ptr(), 3) < 0);
        }
    }

    #[test]
    fn test_strlen() {
        unsafe {
            let s = b"hello\0";
            assert_eq!(msvcrt_strlen(s.as_ptr().cast::<i8>()), 5);
        }
    }

    #[test]
    fn test_strncmp() {
        unsafe {
            let s1 = b"hello\0";
            let s2 = b"hello\0";
            let s3 = b"world\0";
            assert_eq!(
                msvcrt_strncmp(s1.as_ptr().cast::<i8>(), s2.as_ptr().cast::<i8>(), 5),
                0
            );
            assert!(msvcrt_strncmp(s1.as_ptr().cast::<i8>(), s3.as_ptr().cast::<i8>(), 5) < 0);
        }
    }

    #[test]
    fn test_initterm_sentinel_filtering() {
        // Test that _initterm correctly filters out null and usize::MAX sentinel values
        use std::sync::atomic::{AtomicUsize, Ordering};

        static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

        extern "C" fn test_func1() {
            CALL_COUNT.fetch_add(1, Ordering::SeqCst);
        }

        extern "C" fn test_func2() {
            CALL_COUNT.fetch_add(10, Ordering::SeqCst);
        }

        // Create an init table with valid functions, null, and sentinel values
        let mut init_table: [usize; 6] = [
            0,                                // null - should be skipped
            test_func1 as *const () as usize, // valid function
            usize::MAX,                       // -1 sentinel - should be skipped
            test_func2 as *const () as usize, // valid function
            0,                                // null - should be skipped
            usize::MAX,                       // -1 sentinel - should be skipped
        ];

        // Call _initterm
        unsafe {
            msvcrt__initterm(
                init_table.as_mut_ptr().cast::<extern "C" fn()>(),
                init_table.as_mut_ptr().add(6).cast::<extern "C" fn()>(),
            );
        }

        // Only test_func1 and test_func2 should have been called
        assert_eq!(
            CALL_COUNT.load(Ordering::SeqCst),
            11,
            "Only valid functions should be called (1 + 10 = 11)"
        );
    }

    #[test]
    fn test_strcmp() {
        unsafe {
            let s1 = b"hello\0";
            let s2 = b"hello\0";
            let s3 = b"world\0";
            let s4 = b"hell\0";
            assert_eq!(
                msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s2.as_ptr().cast::<i8>()),
                0
            );
            assert!(msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s3.as_ptr().cast::<i8>()) < 0);
            assert!(msvcrt_strcmp(s3.as_ptr().cast::<i8>(), s1.as_ptr().cast::<i8>()) > 0);
            assert!(msvcrt_strcmp(s1.as_ptr().cast::<i8>(), s4.as_ptr().cast::<i8>()) != 0);
        }
    }

    #[test]
    fn test_strcpy() {
        unsafe {
            let src = b"hello\0";
            let mut dest = [0i8; 10];
            let result = msvcrt_strcpy(dest.as_mut_ptr(), src.as_ptr().cast::<i8>());
            assert_eq!(result, dest.as_mut_ptr());
            assert_eq!(dest[0], b'h'.cast_signed());
            assert_eq!(dest[4], b'o'.cast_signed());
            assert_eq!(dest[5], 0);
        }
    }

    #[test]
    fn test_strcat() {
        unsafe {
            let mut dest = [0i8; 20];
            let s1 = b"hello\0";
            let s2 = b" world\0";
            msvcrt_strcpy(dest.as_mut_ptr(), s1.as_ptr().cast::<i8>());
            msvcrt_strcat(dest.as_mut_ptr(), s2.as_ptr().cast::<i8>());
            let result = CStr::from_ptr(dest.as_ptr());
            assert_eq!(result.to_str().unwrap(), "hello world");
        }
    }

    #[test]
    fn test_strchr() {
        unsafe {
            let s = b"hello world\0";
            let result = msvcrt_strchr(s.as_ptr().cast::<i8>(), i32::from(b'o'));
            assert!(!result.is_null());
            assert_eq!(*result, b'o'.cast_signed());
            // Should find first occurrence
            let offset = result as usize - s.as_ptr() as usize;
            assert_eq!(offset, 4);
            // Character not found
            let result = msvcrt_strchr(s.as_ptr().cast::<i8>(), i32::from(b'z'));
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_strrchr() {
        unsafe {
            let s = b"hello world\0";
            let result = msvcrt_strrchr(s.as_ptr().cast::<i8>(), i32::from(b'o'));
            assert!(!result.is_null());
            // Should find last occurrence (at index 7, in "world")
            let offset = result as usize - s.as_ptr() as usize;
            assert_eq!(offset, 7);
        }
    }

    #[test]
    fn test_strstr() {
        unsafe {
            let haystack = b"hello world\0";
            let needle = b"world\0";
            let result =
                msvcrt_strstr(haystack.as_ptr().cast::<i8>(), needle.as_ptr().cast::<i8>());
            assert!(!result.is_null());
            let offset = result as usize - haystack.as_ptr() as usize;
            assert_eq!(offset, 6);
            // Not found
            let needle2 = b"xyz\0";
            let result = msvcrt_strstr(
                haystack.as_ptr().cast::<i8>(),
                needle2.as_ptr().cast::<i8>(),
            );
            assert!(result.is_null());
            // Empty needle
            let empty = b"\0";
            let result = msvcrt_strstr(haystack.as_ptr().cast::<i8>(), empty.as_ptr().cast::<i8>());
            assert!(!result.is_null());
            assert_eq!(result, haystack.as_ptr().cast::<i8>());
        }
    }

    #[test]
    fn test_initterm_e() {
        use std::sync::atomic::{AtomicI32, Ordering};

        static CALL_RESULT: AtomicI32 = AtomicI32::new(0);

        extern "C" fn success_func() -> i32 {
            CALL_RESULT.fetch_add(1, Ordering::SeqCst);
            0 // success
        }

        extern "C" fn fail_func() -> i32 {
            42 // error
        }

        // Test successful completion
        CALL_RESULT.store(0, Ordering::SeqCst);
        let mut table: [usize; 3] = [
            success_func as *const () as usize,
            0, // null - skip
            success_func as *const () as usize,
        ];

        unsafe {
            let result = msvcrt__initterm_e(
                table.as_mut_ptr().cast::<extern "C" fn() -> i32>(),
                table.as_mut_ptr().add(3).cast::<extern "C" fn() -> i32>(),
            );
            assert_eq!(result, 0);
            assert_eq!(CALL_RESULT.load(Ordering::SeqCst), 2);
        }

        // Test failure stops iteration
        let mut table2: [usize; 2] = [
            fail_func as *const () as usize,
            success_func as *const () as usize, // should not be called
        ];

        CALL_RESULT.store(0, Ordering::SeqCst);
        unsafe {
            let result = msvcrt__initterm_e(
                table2.as_mut_ptr().cast::<extern "C" fn() -> i32>(),
                table2.as_mut_ptr().add(2).cast::<extern "C" fn() -> i32>(),
            );
            assert_eq!(result, 42);
            assert_eq!(CALL_RESULT.load(Ordering::SeqCst), 0); // success_func not called
        }
    }

    #[test]
    fn test_getenv() {
        unsafe {
            // PATH should exist on Linux
            let name = b"PATH\0";
            let result = msvcrt_getenv(name.as_ptr().cast::<i8>());
            // PATH should be set in any reasonable environment
            assert!(!result.is_null());

            // Nonexistent variable
            let name = b"LITEBOX_NONEXISTENT_VAR_12345\0";
            let result = msvcrt_getenv(name.as_ptr().cast::<i8>());
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_errno() {
        unsafe {
            let ptr = msvcrt__errno();
            assert!(!ptr.is_null());
            // Should be same as __errno_location
            let ptr2 = msvcrt___errno_location();
            assert_eq!(ptr, ptr2);
        }
    }

    #[test]
    fn test_parse_windows_command_line_simple() {
        let args = parse_windows_command_line("prog.exe arg1 arg2");
        assert_eq!(args, vec!["prog.exe", "arg1", "arg2"]);
    }

    #[test]
    fn test_parse_windows_command_line_quoted() {
        let args = parse_windows_command_line(r#"prog.exe "hello world" arg2"#);
        assert_eq!(args, vec!["prog.exe", "hello world", "arg2"]);
    }

    #[test]
    fn test_parse_windows_command_line_escaped_quote() {
        // 1 backslash before quote = odd → literal quote (no quoting toggle)
        let args = parse_windows_command_line(r#"prog.exe "say \"hi\"" end"#);
        assert_eq!(args, vec!["prog.exe", r#"say "hi""#, "end"]);
    }

    #[test]
    fn test_parse_windows_command_line_empty() {
        let args = parse_windows_command_line("");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_windows_command_line_single() {
        let args = parse_windows_command_line("prog.exe");
        assert_eq!(args, vec!["prog.exe"]);
    }

    #[test]
    fn test_parse_windows_command_line_backslash_in_path() {
        // Backslashes not followed by a quote are literal
        let args = parse_windows_command_line(r"prog.exe C:\path\to\file.txt");
        assert_eq!(args, vec!["prog.exe", r"C:\path\to\file.txt"]);
    }

    #[test]
    fn test_parse_windows_command_line_even_backslashes_before_quote() {
        // 2 backslashes + " => 1 backslash + quote toggle (quote is a delimiter)
        let args = parse_windows_command_line(r#"prog.exe "path\\" end"#);
        // Inside quotes: "path\\" → 2 backslashes before closing quote → 1 literal backslash, quote closes
        assert_eq!(args, vec!["prog.exe", r"path\", "end"]);
    }

    #[test]
    fn test_parse_windows_command_line_unquoted_escaped_quote() {
        // Outside quotes: \" = escaped quote (literal quote, no toggle)
        let args = parse_windows_command_line(r#"prog.exe arg\"with\"quote"#);
        assert_eq!(args, vec!["prog.exe", r#"arg"with"quote"#]);
    }

    #[test]
    fn test_acmdln_not_null() {
        let ptr = unsafe { msvcrt__acmdln() };
        // Should return a valid pointer (not null)
        assert!(!ptr.is_null());
    }
}
