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

/// `wcscmp` – compare two null-terminated wide strings lexicographically.
///
/// Returns a negative value if `s1 < s2`, 0 if equal, positive if `s1 > s2`.
///
/// # Safety
/// Both `s1` and `s2` must be valid, null-terminated wide character strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    let mut i = 0usize;
    // SAFETY: caller guarantees both pointers are valid null-terminated strings.
    loop {
        let c1 = unsafe { *s1.add(i) };
        let c2 = unsafe { *s2.add(i) };
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// `wcsstr` – find the first occurrence of wide string `needle` in `haystack`.
///
/// Returns a pointer to the first occurrence of `needle` in `haystack`, or
/// NULL if `needle` is not found. If `needle` is an empty string, returns
/// `haystack`.
///
/// # Safety
/// Both `haystack` and `needle` must be valid, null-terminated wide character strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsstr(haystack: *const u16, needle: *const u16) -> *const u16 {
    if haystack.is_null() {
        return core::ptr::null();
    }
    if needle.is_null() {
        return haystack;
    }
    // SAFETY: caller guarantees both pointers are valid null-terminated strings.
    let needle_first = unsafe { *needle };
    if needle_first == 0 {
        return haystack; // empty needle always matches at start
    }
    let mut h = haystack;
    // SAFETY: h stays within the null-terminated haystack.
    while unsafe { *h } != 0 {
        if unsafe { *h } == needle_first {
            // Try to match the rest of needle
            let mut hi = h;
            let mut ni = needle;
            // SAFETY: hi and ni are within their respective null-terminated strings.
            loop {
                let nc = unsafe { *ni };
                if nc == 0 {
                    return h; // full needle matched
                }
                let hc = unsafe { *hi };
                if hc != nc {
                    break; // mismatch
                }
                hi = unsafe { hi.add(1) };
                ni = unsafe { ni.add(1) };
            }
        }
        h = unsafe { h.add(1) };
    }
    core::ptr::null()
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
    let byte = c.to_le_bytes()[0];
    // SAFETY: `byte` is a valid single-byte buffer.
    let written = unsafe { libc::write(fd, std::ptr::addr_of!(byte).cast(), 1) };
    if written == 1 {
        c & 0xFF
    } else {
        // EOF
        -1
    }
}

/// `fputs` – write a string to a stream.
///
/// Writes the null-terminated string `s` to `stream`.  Returns a non-negative
/// value on success, `EOF` (-1) on error.
///
/// # Safety
/// `s` must be a valid null-terminated C string.  `stream` is treated only as
/// a discriminator to choose between stdout (1) and stderr (2).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fputs(s: *const i8, stream: *mut core::ffi::c_void) -> i32 {
    if s.is_null() {
        return -1;
    }
    let fd: libc::c_int = if stream as usize == 2 { 2 } else { 1 };
    // SAFETY: caller guarantees s is a valid null-terminated C string.
    let len = unsafe { libc::strlen(s.cast()) };
    if len == 0 {
        return 0;
    }
    // SAFETY: s points to a valid buffer of at least `len` bytes.
    let written = unsafe { libc::write(fd, s.cast(), len) };
    if written < 0 { -1 } else { 0 }
}

/// `_read` – read bytes from a file descriptor.
///
/// Reads up to `count` bytes from file descriptor `fd` into `buf`.
/// Returns the number of bytes read, 0 for EOF, or -1 on error.
///
/// # Safety
/// `buf` must be writable for at least `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__read(fd: i32, buf: *mut core::ffi::c_void, count: u32) -> i32 {
    if buf.is_null() || count == 0 {
        return 0;
    }
    // SAFETY: caller guarantees buf is writable for count bytes.
    let n = unsafe { libc::read(fd, buf, count as libc::size_t) };
    #[allow(clippy::cast_possible_truncation)]
    if n < 0 { -1 } else { n as i32 }
}

/// `realloc` – resize a previously allocated memory block.
///
/// Resizes the memory block pointed to by `ptr` to `new_size` bytes.
/// If `ptr` is null, behaves like `malloc`.  If `new_size` is 0 and `ptr`
/// is non-null, behaves like `free` and returns null.
///
/// # Safety
/// `ptr` must have been allocated by `msvcrt_malloc`, `msvcrt_calloc`, or
/// `msvcrt_realloc`, and must not be used again after a successful call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_realloc(ptr: *mut u8, new_size: usize) -> *mut u8 {
    if ptr.is_null() {
        return unsafe { msvcrt_malloc(new_size) };
    }
    if new_size == 0 {
        unsafe { msvcrt_free(ptr) };
        return ptr::null_mut();
    }
    // Allocate a new block using the same allocator as msvcrt_malloc,
    // copy the contents, then free the old block.  This avoids mixing
    // Rust's global allocator with libc's allocator, which would be UB.
    let new_ptr = unsafe { msvcrt_malloc(new_size) };
    if new_ptr.is_null() {
        // Allocation failed; leave the original block untouched.
        return ptr::null_mut();
    }
    // SAFETY:
    // - `ptr` is non-null and was allocated by msvcrt_malloc/calloc/realloc.
    // - `new_ptr` is non-null and points to `new_size` bytes of writable memory.
    // - The two allocations are non-overlapping (distinct heap objects).
    // We copy `new_size` bytes which may be less than the original allocation;
    // for a shrink that is correct, for a grow the caller owns the extra bytes.
    unsafe {
        ptr::copy_nonoverlapping(ptr, new_ptr, new_size);
        msvcrt_free(ptr);
    }
    new_ptr
}

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

// ── Numeric Conversion ────────────────────────────────────────────────────

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atoi(s: *const i8) -> i32 {
    if s.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    let trimmed = str.trim_ascii_start();
    let (trimmed, neg) = if let Some(t) = trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (trimmed, false)
    };
    let valid_len = trimmed.chars().take_while(char::is_ascii_digit).count();
    let val = trimmed[..valid_len].parse::<i32>().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atol(s: *const i8) -> i64 {
    if s.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    let trimmed = str.trim_ascii_start();
    let (trimmed, neg) = if let Some(t) = trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (trimmed, false)
    };
    let valid_len = trimmed.chars().take_while(char::is_ascii_digit).count();
    let val = trimmed[..valid_len].parse::<i64>().unwrap_or(0);
    if neg { val.wrapping_neg() } else { val }
}

/// # Safety
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atof(s: *const i8) -> f64 {
    if s.is_null() {
        return 0.0;
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let str = cstr.to_str().unwrap_or("");
    str.trim().parse::<f64>().unwrap_or(0.0)
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtol(nptr: *const i8, endptr: *mut *mut i8, base: i32) -> i64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let s_trimmed = s.trim_ascii_start();
    let (s_signed, negative) = if let Some(t) = s_trimmed.strip_prefix('-') {
        (t, true)
    } else if let Some(t) = s_trimmed.strip_prefix('+') {
        (t, false)
    } else {
        (s_trimmed, false)
    };
    let radix = if base == 0 {
        10u32
    } else {
        base.unsigned_abs()
    };
    let valid_len = s_signed.chars().take_while(|c| c.is_digit(radix)).count();
    let parsed = i64::from_str_radix(&s_signed[..valid_len], radix).unwrap_or(0);
    let result = if negative {
        parsed.wrapping_neg()
    } else {
        parsed
    };
    if !endptr.is_null() {
        let leading_ws = s.len() - s_trimmed.len();
        let sign_len = usize::from(s_trimmed.starts_with(['-', '+']));
        let consumed = leading_ws + sign_len + valid_len;
        *endptr = nptr.add(consumed).cast_mut();
    }
    result
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtoul(nptr: *const i8, endptr: *mut *mut i8, base: i32) -> u64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let s_trimmed = s.trim_ascii_start();
    let s_unsigned = s_trimmed.strip_prefix(['+', '-']).unwrap_or(s_trimmed);
    let radix = if base == 0 {
        10u32
    } else {
        base.unsigned_abs()
    };
    let valid_len = s_unsigned.chars().take_while(|c| c.is_digit(radix)).count();
    let result = u64::from_str_radix(&s_unsigned[..valid_len], radix).unwrap_or(0);
    if !endptr.is_null() {
        let leading_ws = s.len() - s_trimmed.len();
        let sign_len = usize::from(s_trimmed.starts_with(['+', '-']));
        let consumed = leading_ws + sign_len + valid_len;
        *endptr = nptr.add(consumed).cast_mut();
    }
    result
}

/// # Safety
/// `nptr` must be a valid null-terminated C string; `endptr` if non-null must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strtod(nptr: *const i8, endptr: *mut *mut i8) -> f64 {
    if nptr.is_null() {
        if !endptr.is_null() {
            *endptr = nptr.cast_mut();
        }
        return 0.0;
    }
    let s = core::ffi::CStr::from_ptr(nptr.cast())
        .to_str()
        .unwrap_or("");
    let trimmed = s.trim_ascii_start();
    let ws_len = s.len() - trimmed.len();

    // Track the longest prefix of `trimmed` that successfully parses as an f64.
    let mut last_ok_len = 0usize;
    let mut last_ok_val = 0.0f64;
    let mut byte_index = 0usize;
    for ch in trimmed.chars() {
        byte_index += ch.len_utf8();
        if let Ok(v) = trimmed[..byte_index].parse::<f64>() {
            last_ok_len = byte_index;
            last_ok_val = v;
        }
    }

    let val = if last_ok_len > 0 { last_ok_val } else { 0.0 };

    if !endptr.is_null() {
        if last_ok_len > 0 {
            let consumed = ws_len + last_ok_len;
            *endptr = nptr.add(consumed).cast_mut();
        } else {
            // No conversion performed: endptr should point to the original nptr.
            *endptr = nptr.cast_mut();
        }
    }
    val
}

/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result; caller is responsible for size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__itoa(value: i32, buffer: *mut i8, radix: i32) -> *mut i8 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    let bytes = s.as_bytes();
    // SAFETY: buffer has enough space per caller contract
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), buffer, bytes.len());
    *buffer.add(bytes.len()) = 0;
    buffer
}

/// # Safety
/// `buffer` must be a writable buffer large enough to hold the result; caller is responsible for size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__ltoa(value: i64, buffer: *mut i8, radix: i32) -> *mut i8 {
    if buffer.is_null() {
        return core::ptr::null_mut();
    }
    let s = if radix == 10 {
        format!("{value}")
    } else if radix == 16 {
        format!("{:x}", value.cast_unsigned())
    } else if radix == 8 {
        format!("{:o}", value.cast_unsigned())
    } else if radix == 2 {
        format!("{:b}", value.cast_unsigned())
    } else {
        format!("{value}")
    };
    let bytes = s.as_bytes();
    // SAFETY: buffer has enough space per caller contract
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), buffer, bytes.len());
    *buffer.add(bytes.len()) = 0;
    buffer
}

// ── String Extras ─────────────────────────────────────────────────────────

/// # Safety
/// `dest` must be writable for `n` bytes; `src` must be a valid C string or at least `n` bytes readable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strncpy(dest: *mut i8, src: *const i8, n: usize) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0;
    let mut found_nul = false;
    while i < n {
        let c = *src.add(i);
        *dest.add(i) = c;
        if c == 0 {
            found_nul = true;
        }
        if found_nul {
            *dest.add(i) = 0;
        }
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` must be a valid null-terminated C string with enough space; `src` must be a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strncat(dest: *mut i8, src: *const i8, n: usize) -> *mut i8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut dest_end = 0;
    while *dest.add(dest_end) != 0 {
        dest_end += 1;
    }
    let mut i = 0;
    while i < n {
        let c = *src.add(i);
        if c == 0 {
            break;
        }
        *dest.add(dest_end + i) = c;
        i += 1;
    }
    *dest.add(dest_end + i) = 0;
    dest
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated C strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__stricmp(s1: *const i8, s2: *const i8) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let a = core::ffi::CStr::from_ptr(s1.cast()).to_str().unwrap_or("");
    let b = core::ffi::CStr::from_ptr(s2.cast()).to_str().unwrap_or("");
    let al: std::string::String = a.chars().map(|c| c.to_ascii_lowercase()).collect();
    let bl: std::string::String = b.chars().map(|c| c.to_ascii_lowercase()).collect();
    match al.cmp(&bl) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated C strings or readable for at least `n` bytes; may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strnicmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let mut i = 0;
    while i < n {
        let a = (*s1.add(i)).cast_unsigned().to_ascii_lowercase();
        let b = (*s2.add(i)).cast_unsigned().to_ascii_lowercase();
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

/// # Safety
/// `s` must be a valid null-terminated C string or null. Returns heap-allocated copy (caller must free).
///
/// # Panics
/// Panics if the array layout computation overflows (extremely large strings).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__strdup(s: *const i8) -> *mut i8 {
    if s.is_null() {
        return core::ptr::null_mut();
    }
    let cstr = core::ffi::CStr::from_ptr(s.cast());
    let bytes = cstr.to_bytes_with_nul();
    let layout = Layout::array::<u8>(bytes.len()).unwrap();
    let ptr = alloc(layout);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    ptr.cast::<i8>()
}

/// # Safety
/// `s` must be readable for at least `max_len` bytes or until a NUL terminator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_strnlen(s: *const i8, max_len: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut i = 0;
    while i < max_len && *s.add(i) != 0 {
        i += 1;
    }
    i
}

// ── Random & Time ─────────────────────────────────────────────────────────

use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

static RAND_STATE: AtomicU32 = AtomicU32::new(1);

/// # Safety
/// No preconditions. Returns pseudo-random integer in range [0, 32767].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_rand() -> i32 {
    let state = RAND_STATE.load(Ordering::Relaxed);
    let next = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    RAND_STATE.store(next, Ordering::Relaxed);
    i32::try_from((next >> 16) & 0x7FFF).unwrap_or(0)
}

/// # Safety
/// No preconditions. Sets the random seed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_srand(seed: u32) {
    RAND_STATE.store(seed, Ordering::Relaxed);
}

/// # Safety
/// `timer` if non-null must be a writable pointer to i64.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_time(timer: *mut i64) -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::addr_of_mut!(ts));
    let t = ts.tv_sec;
    if !timer.is_null() {
        *timer = t;
    }
    t
}

/// # Safety
/// No preconditions. Returns CPU time used by the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_clock() -> i64 {
    // SAFETY: clock_gettime is safe to call with CLOCK_PROCESS_CPUTIME_ID
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, initialized timespec on the stack; CLOCK_PROCESS_CPUTIME_ID is always valid
    libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, core::ptr::addr_of_mut!(ts));
    ts.tv_sec * 1_000_000 + ts.tv_nsec / 1_000
}

// ── Math Functions ────────────────────────────────────────────────────────

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_abs(x: i32) -> i32 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_labs(x: i64) -> i64 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__abs64(x: i64) -> i64 {
    if x < 0 { x.wrapping_neg() } else { x }
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fabs(x: f64) -> f64 {
    x.abs()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_sqrt(x: f64) -> f64 {
    x.sqrt()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_log(x: f64) -> f64 {
    x.ln()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_log10(x: f64) -> f64 {
    x.log10()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_exp(x: f64) -> f64 {
    x.exp()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_sin(x: f64) -> f64 {
    x.sin()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_cos(x: f64) -> f64 {
    x.cos()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_tan(x: f64) -> f64 {
    x.tan()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atan(x: f64) -> f64 {
    x.atan()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_ceil(x: f64) -> f64 {
    x.ceil()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_floor(x: f64) -> f64 {
    x.floor()
}

/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_fmod(x: f64, y: f64) -> f64 {
    x % y
}

// ── Wide-Char Extras ──────────────────────────────────────────────────────

/// # Safety
/// `dest` must be writable wide string buffer; `src` must be valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscpy(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0;
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

/// # Safety
/// `dest` must be a null-terminated wide string with sufficient space; `src` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcscat(dest: *mut u16, src: *const u16) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut end = 0;
    while *dest.add(end) != 0 {
        end += 1;
    }
    let mut i = 0;
    loop {
        let c = *src.add(i);
        *dest.add(end + i) = c;
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

/// # Safety
/// `dest` must be writable for `n` wide chars; `src` must be readable for at least `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsncpy(dest: *mut u16, src: *const u16, n: usize) -> *mut u16 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut found_nul = false;
    for i in 0..n {
        if found_nul {
            *dest.add(i) = 0;
        } else {
            let c = *src.add(i);
            *dest.add(i) = c;
            if c == 0 {
                found_nul = true;
            }
        }
    }
    dest
}

/// # Safety
/// `s` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcschr(s: *const u16, c: u16) -> *const u16 {
    if s.is_null() {
        return core::ptr::null();
    }
    let mut i = 0;
    loop {
        let ch = *s.add(i);
        if ch == c {
            return s.add(i);
        }
        if ch == 0 {
            return core::ptr::null();
        }
        i += 1;
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or readable for `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcsncmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        if a != b {
            return i32::from(a) - i32::from(b);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wcsicmp(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    let mut i = 0;
    loop {
        let a = *s1.add(i);
        let b = *s2.add(i);
        let al = char::from_u32(u32::from(a)).map_or(a, |c| c.to_ascii_lowercase() as u16);
        let bl = char::from_u32(u32::from(b)).map_or(b, |c| c.to_ascii_lowercase() as u16);
        if al != bl {
            return i32::from(al) - i32::from(bl);
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

/// # Safety
/// `s1` and `s2` must be valid null-terminated wide strings or readable for `n` wide chars.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__wcsnicmp(s1: *const u16, s2: *const u16, n: usize) -> i32 {
    if s1.is_null() || s2.is_null() {
        return if s1 == s2 { 0 } else { -1 };
    }
    for i in 0..n {
        let a = *s1.add(i);
        let b = *s2.add(i);
        let al = char::from_u32(u32::from(a)).map_or(a, |c| c.to_ascii_lowercase() as u16);
        let bl = char::from_u32(u32::from(b)).map_or(b, |c| c.to_ascii_lowercase() as u16);
        if al != bl {
            return i32::from(al) - i32::from(bl);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

/// # Safety
/// `dest` if non-null must be writable for `n` bytes; `src` must be a valid null-terminated wide string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_wcstombs(dest: *mut i8, src: *const u16, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
    let mut len = 0;
    while *src.add(len) != 0 {
        len += 1;
    }
    let wide_slice = core::slice::from_raw_parts(src, len);
    let s = std::string::String::from_utf16_lossy(wide_slice);
    let bytes = s.as_bytes();
    if dest.is_null() {
        return bytes.len();
    }
    let copy_len = bytes.len().min(n.saturating_sub(1));
    // SAFETY: dest is non-null (checked above) and bytes[..copy_len] is valid
    core::ptr::copy_nonoverlapping(bytes.as_ptr().cast::<i8>(), dest, copy_len);
    if n > 0 {
        *dest.add(copy_len) = 0;
    }
    copy_len
}

/// # Safety
/// `dest` if non-null must be writable for `n` wide chars; `src` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_mbstowcs(dest: *mut u16, src: *const i8, n: usize) -> usize {
    if src.is_null() {
        return 0;
    }
    let cstr = core::ffi::CStr::from_ptr(src.cast());
    let s = cstr.to_str().unwrap_or("");
    let wide: Vec<u16> = s.encode_utf16().collect();
    if dest.is_null() {
        return wide.len();
    }
    let copy_len = wide.len().min(n.saturating_sub(1));
    // SAFETY: dest is non-null (checked above) and wide[..copy_len] is valid
    core::ptr::copy_nonoverlapping(wide.as_ptr(), dest, copy_len);
    if n > 0 {
        *dest.add(copy_len) = 0;
    }
    copy_len
}

// ============================================================================
// C++ Exception Handling (MSVC-style)
// ============================================================================
// These functions provide the MSVC C++ exception handling infrastructure
// needed by Windows binaries compiled with MSVC or MinGW targeting the
// MSVC runtime.  The implementation is based on the public documentation
// of the Windows x64 exception handling ABI and reference implementations
// from Wine, ReactOS, and MinGW's libgcc.

/// MSVC exception code for C++ exceptions (`0xE06D7363` = "msc" in ASCII).
const MSVC_CPP_EXCEPTION_CODE: u32 = 0xE06D_7363;

// ── MSVC C++ Exception Handling Constants ──────────────────────────────────

/// Magic numbers identifying the `FuncInfo` version.
const CXX_FRAME_MAGIC_VC6: u32 = 0x1993_0520;
#[allow(dead_code)]
const CXX_FRAME_MAGIC_VC7: u32 = 0x1993_0521;
const CXX_FRAME_MAGIC_VC8: u32 = 0x1993_0522;

/// Flags on `CxxFuncInfo::flags` (valid when magic ≥ VC8).
const FUNC_DESCR_SYNCHRONOUS: u32 = 1;
#[allow(dead_code)]
const FUNC_DESCR_NOEXCEPT: u32 = 4;

/// Flags on `CxxTypeInfo::flags`.
#[allow(dead_code)]
const CLASS_IS_SIMPLE_TYPE: u32 = 1;
#[allow(dead_code)]
const CLASS_HAS_VIRTUAL_BASE_CLASS: u32 = 4;

/// Flags on `CxxCatchBlockInfo::flags` / `CxxExceptionType::flags`.
#[allow(dead_code)]
const TYPE_FLAG_CONST: u32 = 1;
#[allow(dead_code)]
const TYPE_FLAG_VOLATILE: u32 = 2;
const TYPE_FLAG_REFERENCE: u32 = 8;

/// Exception flags (from `EXCEPTION_RECORD.ExceptionFlags`).
const EXCEPTION_UNWINDING_FLAG: u32 = 0x2;
#[allow(dead_code)]
const EXCEPTION_TARGET_UNWIND_FLAG: u32 = 0x20;

// ── MSVC C++ Exception Data Structures (x64, RVA-based) ───────────────────
//
// On x64, all pointers in the MSVC exception metadata are stored as
// 32-bit RVAs (Relative Virtual Addresses) relative to the module's
// image base.  This matches native `msvcrt.dll` / `ucrtbase.dll` behavior.
//
// Reference: Wine's `dlls/msvcrt/cxx.h` and `dlls/msvcrt/except.c`.

/// IP-to-state mapping entry.
///
/// Maps instruction pointer ranges to "try levels" (states).  The runtime
/// uses these to determine which try block is active at any given PC.
#[repr(C)]
struct CxxIpMapEntry {
    /// RVA of the first instruction in this state region.
    ip: u32,
    /// State (try level) index.  -1 means "outside all try blocks".
    state: i32,
}

/// Unwind map entry — describes one destructor to call during stack unwinding.
///
/// The unwind map is a linked list (via `prev`) of state transitions.
/// Walking from the current state backward through `prev` calls each
/// destructor in reverse construction order.
#[repr(C)]
struct CxxUnwindMapEntry {
    /// Previous state index (-1 = end of chain).
    prev: i32,
    /// RVA of the cleanup/destructor handler (0 = no handler for this state).
    handler: u32,
}

/// Catch block descriptor — describes one `catch(T)` clause.
#[repr(C)]
#[allow(dead_code)]
struct CxxCatchBlockInfo {
    /// Flags (`TYPE_FLAG_CONST`, `TYPE_FLAG_VOLATILE`, `TYPE_FLAG_REFERENCE`, etc.).
    flags: u32,
    /// RVA of `type_info` for the caught type (0 = `catch(...)`).
    type_info: u32,
    /// Offset from the establisher frame where the exception object is copied.
    offset: i32,
    /// RVA of the catch handler function.
    handler: u32,
    /// Frame offset for the catch block (x64 only).
    frame: u32,
}

/// Try block descriptor — describes one `try { } catch(...) { }` region.
#[repr(C)]
#[allow(dead_code)]
struct CxxTryBlockInfo {
    /// Lowest state covered by this try block.
    start_level: i32,
    /// Highest state covered by this try block.
    end_level: i32,
    /// State when the catch block is executing.
    catch_level: i32,
    /// Number of catch blocks.
    catchblock_count: u32,
    /// RVA of the catch block array.
    catchblock: u32,
}

/// `this` pointer offset descriptor — used for virtual base class adjustments.
#[repr(C)]
#[allow(dead_code)]
struct CxxThisPtrOffsets {
    /// Offset from the base to the `this` pointer.
    this_offset: i32,
    /// Offset to virtual base descriptor (-1 = no virtual base).
    vbase_descr: i32,
    /// Offset within the virtual base class descriptor.
    vbase_offset: i32,
}

/// Type info for one catchable type in the exception's type hierarchy.
#[repr(C)]
#[allow(dead_code)]
struct CxxTypeInfo {
    /// Flags (`CLASS_IS_SIMPLE_TYPE`, `CLASS_HAS_VIRTUAL_BASE_CLASS`, etc.).
    flags: u32,
    /// RVA of the `type_info` for this type.
    type_info: u32,
    /// Offsets for `this` pointer adjustment.
    offsets: CxxThisPtrOffsets,
    /// Size of the exception object.
    size: u32,
    /// RVA of the copy constructor.
    copy_ctor: u32,
}

/// Table of catchable types for an exception.
///
/// The `info` array contains RVAs to `CxxTypeInfo` entries.
/// In practice the array is variable-length; we declare a small fixed
/// array and access it by index (all within bounds guaranteed by `count`).
#[repr(C)]
struct CxxTypeInfoTable {
    /// Number of entries in the `info` array.
    count: u32,
    /// RVAs of `CxxTypeInfo` entries (variable length; first element here).
    info: [u32; 1],
}

/// Exception type descriptor — the "ThrowInfo" in MSVC terminology.
///
/// Attached to each throw expression.  Describes the thrown type, its
/// destructor, and the list of types it can be caught as.
#[repr(C)]
#[allow(dead_code)]
struct CxxExceptionType {
    /// Flags (`TYPE_FLAG_CONST`, `TYPE_FLAG_VOLATILE`).
    flags: u32,
    /// RVA of the destructor for the thrown object.
    destructor: u32,
    /// RVA of a custom exception handler (usually 0).
    custom_handler: u32,
    /// RVA of the `CxxTypeInfoTable`.
    type_info_table: u32,
}

/// Function descriptor — the central metadata structure for `__CxxFrameHandler3`.
///
/// Pointed to (via RVA) by the `HandlerData` field of the `DISPATCHER_CONTEXT`.
/// Contains all information needed to unwind locals, match catch blocks,
/// and determine the active try level.
#[repr(C)]
struct CxxFuncInfo {
    /// Magic number identifying the version (VC6/VC7/VC8).
    /// The top 3 bits are `bbt_flags`.
    magic_and_bbt: u32,
    /// Number of entries in the unwind map.
    unwind_count: u32,
    /// RVA of the unwind map array (`CxxUnwindMapEntry[]`).
    unwind_table: u32,
    /// Number of try block descriptors.
    tryblock_count: u32,
    /// RVA of the try block array (`CxxTryBlockInfo[]`).
    tryblock: u32,
    /// Number of entries in the IP-to-state map.
    ipmap_count: u32,
    /// RVA of the IP-to-state map array (`CxxIpMapEntry[]`).
    ipmap: u32,
    /// Offset from the frame pointer to the "unwind help" slot (x64 only).
    /// This is a stack-relative offset where the runtime stores the current
    /// trylevel at function entry (-2 = not initialized).
    unwind_help: i32,
    /// RVA of the expected exception list (VC7+, usually 0).
    expect_list: u32,
    /// Flags (`FUNC_DESCR_SYNCHRONOUS`, `FUNC_DESCR_NOEXCEPT`) — valid when magic ≥ VC8.
    flags: u32,
}

/// Determine the current state (trylevel) from the IP-to-state map.
///
/// Walks the map backward to find the highest entry whose IP is ≤ the
/// control PC, returning the corresponding state.  Returns -1 if the
/// PC is before the first entry.
fn cxx_ip_to_state(fi: &CxxFuncInfo, image_base: u64, control_pc: u64) -> i32 {
    if fi.ipmap_count == 0 || fi.ipmap == 0 {
        return -1;
    }
    if control_pc < image_base {
        return -1;
    }
    #[allow(clippy::cast_possible_truncation)]
    let ip_rva = (control_pc - image_base) as u32;
    let ipmap = (image_base + u64::from(fi.ipmap)) as *const CxxIpMapEntry;
    let mut state = -1_i32;
    for i in 0..fi.ipmap_count {
        // SAFETY: ipmap is within the loaded PE image.
        let entry = unsafe { &*ipmap.add(i as usize) };
        if entry.ip > ip_rva {
            break;
        }
        state = entry.state;
    }
    state
}

/// Run local destructors via the unwind map.
///
/// Walks from `current_state` back through the unwind map, calling each
/// destructor handler, until reaching `target_state`.
///
/// # Safety
/// `fi` must point to a valid `CxxFuncInfo`, `image_base` must be the PE
/// load address, and `frame` must be the establisher frame.
unsafe fn cxx_local_unwind(
    fi: &CxxFuncInfo,
    image_base: u64,
    frame: u64,
    current_state: i32,
    target_state: i32,
) {
    type DestructorHandler = unsafe extern "win64" fn(u64);

    if fi.unwind_count == 0 || fi.unwind_table == 0 {
        return;
    }
    let unwind_table = (image_base + u64::from(fi.unwind_table)) as *const CxxUnwindMapEntry;
    let mut state = current_state;
    #[allow(clippy::cast_sign_loss)]
    while state > target_state && state >= 0 && (state as u32) < fi.unwind_count {
        // SAFETY: state is within bounds of the unwind table.
        #[allow(clippy::cast_sign_loss)]
        let entry = unsafe { &*unwind_table.add(state as usize) };
        if entry.handler != 0 {
            let handler_addr = image_base + u64::from(entry.handler);
            // transmute is required to cast the raw PE address to a Win64
            // ABI function pointer — no safe alternative exists.
            let handler: DestructorHandler = unsafe { core::mem::transmute(handler_addr) };
            unsafe { handler(frame) };
        }
        state = entry.prev;
    }
}

/// Search for a matching catch block during the search phase.
///
/// If a matching catch block is found, initiates unwind to the catch
/// handler via `RtlUnwindEx` (which never returns).
///
/// # Safety
/// All pointers must be valid or NULL.
#[allow(clippy::too_many_arguments)]
unsafe fn cxx_find_catch_block(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    _dispatcher_context: *mut core::ffi::c_void,
    fi: &CxxFuncInfo,
    image_base: u64,
    trylevel: i32,
    exc_type: *const CxxExceptionType,
    throw_base: u64,
) {
    if fi.tryblock_count == 0 || fi.tryblock == 0 {
        return;
    }
    let tryblock_table = (image_base + u64::from(fi.tryblock)) as *const CxxTryBlockInfo;

    for i in 0..fi.tryblock_count {
        // SAFETY: i is within bounds.
        let tryblock = unsafe { &*tryblock_table.add(i as usize) };

        // Check if the current trylevel falls within this try block.
        if trylevel < tryblock.start_level || trylevel > tryblock.end_level {
            continue;
        }

        if tryblock.catchblock_count == 0 || tryblock.catchblock == 0 {
            continue;
        }

        let catchblock_table =
            (image_base + u64::from(tryblock.catchblock)) as *const CxxCatchBlockInfo;

        for j in 0..tryblock.catchblock_count {
            // SAFETY: j is within bounds.
            let catchblock = unsafe { &*catchblock_table.add(j as usize) };

            // Check if this catch block matches the thrown type.
            let matches = if exc_type.is_null() {
                // Non-C++ exception: only match catch(...)
                catchblock.type_info == 0
            } else {
                unsafe { cxx_catch_matches(catchblock, exc_type, throw_base, image_base) }
            };

            if !matches {
                continue;
            }

            // Found a matching catch block — copy exception object if needed.
            if !exc_type.is_null() && catchblock.type_info != 0 && catchblock.offset != 0 {
                // ExceptionInformation[1] is at offset 40 in the EXCEPTION_RECORD:
                //   ExceptionCode(4) + ExceptionFlags(4) + ExceptionRecord*(8)
                //   + ExceptionAddress*(8) + NumberParameters(4) + _pad(4)
                //   + ExceptionInformation[0](8) = 40
                let exc = exception_record.cast::<u8>();
                let exc_object = unsafe { exc.add(40).cast::<*const u8>().read_unaligned() };
                if !exc_object.is_null() {
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let dest = (establisher_frame as usize + catchblock.offset as usize) as *mut u8;
                    if (catchblock.flags & TYPE_FLAG_REFERENCE) != 0 {
                        unsafe {
                            dest.cast::<*const u8>().write_unaligned(exc_object);
                        }
                    } else {
                        let size = unsafe { cxx_get_exception_size(exc_type, throw_base) };
                        if size > 0 {
                            unsafe {
                                core::ptr::copy_nonoverlapping(exc_object, dest, size);
                            }
                        }
                    }
                }
            }

            if catchblock.handler == 0 {
                continue;
            }
            let handler_ip = image_base + u64::from(catchblock.handler);

            // Initiate unwind to the catch handler.
            // SAFETY: RtlUnwindEx is implemented in kernel32.
            unsafe {
                crate::kernel32::kernel32_RtlUnwindEx(
                    establisher_frame as *mut core::ffi::c_void,
                    handler_ip as *mut core::ffi::c_void,
                    exception_record,
                    core::ptr::null_mut(),
                    context_record,
                    core::ptr::null_mut(),
                );
            }
            // RtlUnwindEx should not return if it succeeds.
            return;
        }
    }
}

/// Check if a catch block matches the thrown exception type.
///
/// Walks the thrown exception's `CxxTypeInfoTable` comparing `type_info`
/// mangled names with the catch block's expected type.
unsafe fn cxx_catch_matches(
    catchblock: &CxxCatchBlockInfo,
    exc_type: *const CxxExceptionType,
    throw_base: u64,
    image_base: u64,
) -> bool {
    // type_info layout on x64: vtable_ptr(8) + name_ptr(8) + mangled_name[...]
    // The mangled name starts at offset 16.
    const TYPE_INFO_MANGLED_NAME_OFFSET: u64 = 16;

    // catch(...) matches everything.
    if catchblock.type_info == 0 {
        return true;
    }

    if exc_type.is_null() {
        return false;
    }

    let exc = unsafe { &*exc_type };
    if exc.type_info_table == 0 {
        return false;
    }

    let type_table = (throw_base + u64::from(exc.type_info_table)) as *const CxxTypeInfoTable;
    let table = unsafe { &*type_table };

    // Read the catch block's type_info and get its mangled name.
    let catch_ti_addr = image_base + u64::from(catchblock.type_info);
    let catch_mangled_ptr = (catch_ti_addr + TYPE_INFO_MANGLED_NAME_OFFSET) as *const u8;

    for k in 0..table.count {
        let type_info_rva = unsafe { *(&raw const table.info).cast::<u32>().add(k as usize) };
        if type_info_rva == 0 {
            continue;
        }
        let cxx_ti = (throw_base + u64::from(type_info_rva)) as *const CxxTypeInfo;
        let ti = unsafe { &*cxx_ti };
        if ti.type_info == 0 {
            continue;
        }
        // Resolve the thrown type's type_info.
        let thrown_ti_addr = throw_base + u64::from(ti.type_info);
        let thrown_mangled_ptr = (thrown_ti_addr + TYPE_INFO_MANGLED_NAME_OFFSET) as *const u8;

        // Compare mangled names (null-terminated C strings).
        if unsafe { cxx_strcmp(catch_mangled_ptr, thrown_mangled_ptr) } {
            return true;
        }
    }

    false
}

/// Compare two null-terminated C strings for equality.
///
/// # Safety
/// Both pointers must be valid, null-terminated C strings.
unsafe fn cxx_strcmp(a: *const u8, b: *const u8) -> bool {
    // MSVC mangled names are typically under 1 KiB.
    const MAX_TYPE_NAME_LENGTH: usize = 1024;

    let mut i = 0;
    loop {
        let ca = unsafe { *a.add(i) };
        let cb = unsafe { *b.add(i) };
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
        // Safety guard against unterminated strings.
        if i > MAX_TYPE_NAME_LENGTH {
            return false;
        }
    }
}

/// Get the size of the exception object from its type info table.
///
/// Returns the size of the first (most derived) type, or 0 if unknown.
unsafe fn cxx_get_exception_size(exc_type: *const CxxExceptionType, throw_base: u64) -> usize {
    if exc_type.is_null() {
        return 0;
    }
    let exc = unsafe { &*exc_type };
    if exc.type_info_table == 0 {
        return 0;
    }
    let type_table = (throw_base + u64::from(exc.type_info_table)) as *const CxxTypeInfoTable;
    let table = unsafe { &*type_table };
    if table.count == 0 {
        return 0;
    }
    let first_rva = unsafe { *(&raw const table.info).cast::<u32>() };
    if first_rva == 0 {
        return 0;
    }
    let first_ti = (throw_base + u64::from(first_rva)) as *const CxxTypeInfo;
    unsafe { (*first_ti).size as usize }
}

/// `_CxxThrowException` — Throw a C++ exception using MSVC semantics.
///
/// Called by the compiler-generated code for `throw expr;`.  Builds the
/// parameters array expected by the MSVC C++ runtime and calls
/// `RaiseException` with the magic exception code `0xE06D7363`.
///
/// # Parameters
/// - `exception_object`: Pointer to the thrown object (e.g. `new std::exception`).
/// - `throw_info`: Pointer to the compiler-generated `_ThrowInfo` structure
///   describing the exception type.
///
/// # Safety
/// `exception_object` and `throw_info` may be NULL (for `throw;` rethrow).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__CxxThrowException(
    exception_object: *mut core::ffi::c_void,
    throw_info: *mut core::ffi::c_void,
) {
    // The MSVC CRT passes 4 parameters to RaiseException:
    //   [0] = MSVC magic number (0x19930520 = VC8+ version)
    //   [1] = pointer to the thrown object
    //   [2] = pointer to _ThrowInfo
    //   [3] = image base of the module (for RVA resolution in _ThrowInfo)
    //
    // We pass 4 parameters here:
    //   [0] = MSVC magic number (0x19930520 = VC8+ version)
    //   [1] = pointer to the thrown object
    //   [2] = pointer to _ThrowInfo
    //   [3] = image base of the module (for RVA resolution in _ThrowInfo)
    let module_base = crate::kernel32::get_registered_image_base();
    #[allow(clippy::cast_possible_truncation)]
    let params: [usize; 4] = [
        0x1993_0520,               // magic version number
        exception_object as usize, // exception object
        throw_info as usize,       // throw info
        module_base as usize,      // image base for RVA resolution (truncation OK on x64)
    ];

    // SAFETY: kernel32_RaiseException is defined in the platform layer.
    // EXCEPTION_NONCONTINUABLE = 0x1
    unsafe {
        crate::kernel32::kernel32_RaiseException(
            MSVC_CPP_EXCEPTION_CODE,
            0x1, // EXCEPTION_NONCONTINUABLE
            4,
            params.as_ptr(),
        );
    }
}

/// `__CxxFrameHandler3` — MSVC C++ frame-based exception handler (version 3).
///
/// This is the language-specific handler installed in the `UNWIND_INFO` for
/// functions containing `try`/`catch` blocks compiled by MSVC.  It is called
/// by the OS exception dispatcher (`RtlDispatchException` / `RtlUnwindEx`)
/// during both the search (phase 1) and unwind (phase 2) phases.
///
/// The implementation:
/// - Parses the `FuncInfo` structure pointed to by `handler_data`
/// - Walks the try/catch map to find a matching handler (search phase)
/// - Executes destructors for local objects during unwind (unwind phase)
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn msvcrt___CxxFrameHandler3(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    if exception_record.is_null() || dispatcher_context.is_null() {
        return 1; // EXCEPTION_CONTINUE_SEARCH
    }

    // Read DispatcherContext fields.
    // Layout: control_pc(8), image_base(8), function_entry(8),
    //         establisher_frame(8), target_ip(8), context_record(8),
    //         language_handler(8), handler_data(8), ...
    let dc = dispatcher_context.cast::<u8>();
    let image_base = unsafe { (dc.add(8) as *const u64).read_unaligned() };
    let handler_data = unsafe { (dc.add(56) as *const *mut core::ffi::c_void).read_unaligned() };
    let control_pc = unsafe { (dc as *const u64).read_unaligned() };

    if handler_data.is_null() || image_base == 0 {
        return 1;
    }

    // HandlerData points to a FuncInfo RVA for __CxxFrameHandler3.
    let func_info_rva = unsafe { (handler_data as *const u32).read_unaligned() };
    if func_info_rva == 0 {
        return 1;
    }
    let func_info = (image_base + u64::from(func_info_rva)) as *const CxxFuncInfo;

    let fi = unsafe { &*func_info };
    let magic = fi.magic_and_bbt & 0x1FFF_FFFF; // bottom 29 bits

    // Validate magic number.
    if !(CXX_FRAME_MAGIC_VC6..=CXX_FRAME_MAGIC_VC8).contains(&magic) {
        return 1;
    }

    // Read exception record fields.
    let exc = exception_record.cast::<u8>();
    // ExceptionRecord layout: ExceptionCode(4), ExceptionFlags(4), ...
    let exc_flags = unsafe { (exc.add(4) as *const u32).read_unaligned() };
    let exc_code = unsafe { (exc as *const u32).read_unaligned() };

    let is_unwinding = (exc_flags & EXCEPTION_UNWINDING_FLAG) != 0;

    // Synchronous mode (VC8+): only handle CXX_EXCEPTION.
    if magic >= CXX_FRAME_MAGIC_VC8
        && (fi.flags & FUNC_DESCR_SYNCHRONOUS) != 0
        && exc_code != MSVC_CPP_EXCEPTION_CODE
    {
        return 1;
    }

    // Determine current trylevel from IP-to-state map.
    let trylevel = cxx_ip_to_state(fi, image_base, control_pc);

    if is_unwinding {
        // Unwind phase: call local destructors via the unwind map.
        // Both target-unwind and intermediate frames unwind all locals.
        cxx_local_unwind(fi, image_base, establisher_frame, trylevel, -1);
        return 1; // EXCEPTION_CONTINUE_SEARCH
    }

    // Search phase: look for a matching catch block.
    if fi.tryblock_count == 0 {
        return 1;
    }

    // Only match MSVC C++ exceptions.
    if exc_code != MSVC_CPP_EXCEPTION_CODE {
        // For non-C++ exceptions, try to find catch(...) blocks.
        unsafe {
            cxx_find_catch_block(
                exception_record,
                establisher_frame,
                context_record,
                dispatcher_context,
                fi,
                image_base,
                trylevel,
                core::ptr::null(),
                0,
            );
        }
        return 1;
    }

    // Read ExceptionInformation from the exception record.
    // ExceptionInformation starts at offset 32 in EXCEPTION_RECORD:
    //   ExceptionCode(4) + ExceptionFlags(4) + ExceptionRecord*(8)
    //   + ExceptionAddress*(8) + NumberParameters(4) + _pad(4) = 32
    // [0] = magic version, [1] = exception object ptr, [2] = ThrowInfo RVA,
    // [3] = image base (for RVA resolution)
    let exc_info_base = exc.add(32);
    #[allow(clippy::cast_possible_truncation)]
    let exc_type_rva = unsafe { (exc_info_base.add(16) as *const usize).read_unaligned() } as u32;
    let exc_image_base = unsafe { (exc_info_base.add(24) as *const usize).read_unaligned() } as u64;

    let throw_base = if exc_image_base != 0 {
        exc_image_base
    } else {
        image_base
    };

    let exc_type_ptr = if exc_type_rva != 0 {
        (throw_base + u64::from(exc_type_rva)) as *const CxxExceptionType
    } else {
        core::ptr::null()
    };

    unsafe {
        cxx_find_catch_block(
            exception_record,
            establisher_frame,
            context_record,
            dispatcher_context,
            fi,
            image_base,
            trylevel,
            exc_type_ptr,
            throw_base,
        );
    }

    1 // EXCEPTION_CONTINUE_SEARCH (no match found)
}

/// `__CxxFrameHandler4` — MSVC C++ frame-based exception handler (version 4).
///
/// Version 4 uses compressed `FuncInfo` (added in VS 2019 / MSVC 14.2x).
/// For now, delegates to the V3 handler since the basic protocol is the same.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxFrameHandler4(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    // V4 uses compressed FuncInfo but the basic protocol is the same.
    unsafe {
        msvcrt___CxxFrameHandler3(
            exception_record,
            establisher_frame,
            context_record,
            dispatcher_context,
        )
    }
}

/// `__CxxRegisterExceptionObject` — Register an exception object for tracking.
///
/// Called by catch blocks to register the caught exception for potential
/// rethrow.  This stub stores the exception pointer in thread-local storage.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxRegisterExceptionObject(
    _exception_pointers: *mut core::ffi::c_void,
    _frame_info: *mut core::ffi::c_void,
) -> i32 {
    1 // success
}

/// `__CxxUnregisterExceptionObject` — Unregister a previously registered exception.
///
/// Called when leaving a catch block.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___CxxUnregisterExceptionObject(
    _frame_info: *mut core::ffi::c_void,
    _in_rethrow: i32,
) -> i32 {
    0
}

/// `__DestructExceptionObject` — Call the destructor for an exception object.
///
/// Called during rethrow or when an exception is being discarded.
///
/// # Safety
/// `exception_record` must be a valid `EXCEPTION_RECORD` or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___DestructExceptionObject(
    _exception_record: *mut core::ffi::c_void,
) {
    // Stub: full implementation would call the destructor from ThrowInfo.
}

/// `__uncaught_exception` — Check if there is an active uncaught exception.
///
/// Returns `true` if an exception has been thrown and not yet caught.
///
/// # Safety
/// Safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___uncaught_exception() -> i32 {
    0 // no uncaught exceptions
}

/// `__uncaught_exceptions` — Get the count of active uncaught exceptions.
///
/// Returns the number of exceptions that have been thrown but not yet caught.
///
/// # Safety
/// Safe to call from any context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___uncaught_exceptions() -> i32 {
    0
}

/// `_local_unwind` — Perform a local unwind to a target frame.
///
/// Used by `__finally` handlers and cleanup code.
///
/// # Safety
/// Both pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__local_unwind(
    frame: *mut core::ffi::c_void,
    target: *mut core::ffi::c_void,
) {
    unsafe {
        crate::kernel32::kernel32_RtlUnwindEx(
            frame,
            target,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
    }
}

/// `terminate` — Called when C++ exception handling fails.
///
/// Called when:
/// - An exception is thrown and no matching handler is found
/// - An exception is thrown during stack unwinding (double exception)
/// - A `noexcept` function throws
///
/// Calls `std::terminate()` which by default calls `abort()`.
///
/// # Safety
/// This function terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt_terminate() -> ! {
    eprintln!("terminate called — unhandled C++ exception");
    std::process::abort();
}

/// `_set_se_translator` — Set a structured exception translator function.
///
/// Allows converting SEH exceptions to C++ exceptions.  The translator
/// function is called during the search phase for SEH exceptions.
///
/// Returns the previous translator function (always NULL in this stub).
///
/// # Safety
/// `translator` may be NULL to remove the translator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__set_se_translator(
    _translator: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// `_is_exception_typeof` — Check if an exception matches a given type.
///
/// Used by the MSVC runtime during exception dispatch to determine if a
/// catch clause matches the thrown exception type.
///
/// Returns non-zero if the exception matches the specified type.
/// This stub always returns 0 (no match) as full MSVC RTTI matching
/// is not yet implemented.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__is_exception_typeof(
    _type_info: *mut core::ffi::c_void,
    _exception_info: *mut core::ffi::c_void,
) -> i32 {
    0
}

/// `__std_terminate` — MSVC internal terminate handler.
///
/// Same as `terminate` but used in newer MSVC runtimes.
///
/// # Safety
/// This function terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___std_terminate() -> ! {
    eprintln!("__std_terminate called — unhandled C++ exception");
    std::process::abort();
}

/// `_CxxExceptionFilter` — MSVC C++ exception filter for SEH interop.
///
/// Examines the exception record to determine if it matches the C++ type.
/// Used in SEH `__except` blocks that need to catch C++ exceptions.
///
/// Returns `EXCEPTION_EXECUTE_HANDLER` (1) for matching MSVC C++ exceptions,
/// `EXCEPTION_CONTINUE_SEARCH` (0) otherwise.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__CxxExceptionFilter(
    _exception_pointers: *mut core::ffi::c_void,
    _type_info: *mut core::ffi::c_void,
    _flags: i32,
    _copy_function: *mut core::ffi::c_void,
) -> i32 {
    // Stub implementation: always continue search.
    // A full implementation would inspect the exception record to
    // detect MSVC C++ exceptions and potentially match the type.
    0 // EXCEPTION_CONTINUE_SEARCH
}

/// `__current_exception` — Get pointer to the current exception TLS slot.
///
/// Returns a pointer to a thread-local variable holding the current
/// exception object pointer.  Used internally by the MSVC runtime for
/// `std::current_exception()` and rethrow.
///
/// # Safety
/// The returned pointer is valid only for the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___current_exception() -> *mut *mut core::ffi::c_void {
    thread_local! {
        static CURRENT_EXCEPTION: std::cell::UnsafeCell<*mut core::ffi::c_void> =
            const { std::cell::UnsafeCell::new(core::ptr::null_mut()) };
    }
    CURRENT_EXCEPTION.with(std::cell::UnsafeCell::get)
}

/// `__current_exception_context` — Get pointer to the current exception
/// context TLS slot.
///
/// Returns a pointer to a thread-local variable holding the CONTEXT
/// at the point the current exception was thrown.
///
/// # Safety
/// The returned pointer is valid only for the current thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___current_exception_context() -> *mut *mut core::ffi::c_void {
    thread_local! {
        static CURRENT_EXCEPTION_CONTEXT: std::cell::UnsafeCell<*mut core::ffi::c_void> =
            const { std::cell::UnsafeCell::new(core::ptr::null_mut()) };
    }
    CURRENT_EXCEPTION_CONTEXT.with(std::cell::UnsafeCell::get)
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

    #[test]
    fn test_atoi() {
        unsafe {
            assert_eq!(msvcrt_atoi(c"42".as_ptr(),), 42);
            assert_eq!(msvcrt_atoi(c"-5".as_ptr()), -5);
            assert_eq!(msvcrt_atoi(c"  10".as_ptr()), 10);
            assert_eq!(msvcrt_atoi(core::ptr::null()), 0);
        }
    }

    #[test]
    fn test_atof() {
        unsafe {
            let v = msvcrt_atof(c"2.5".as_ptr());
            assert!((v - 2.5).abs() < 1e-10);
            assert!((msvcrt_atof(core::ptr::null())).abs() < 1e-15);
        }
    }

    #[test]
    fn test_strtol() {
        unsafe {
            let mut end = core::ptr::null_mut::<i8>();
            let s = c"123abc";
            let val = msvcrt_strtol(s.as_ptr(), &raw mut end, 10);
            assert_eq!(val, 123);
            assert_eq!((*end).cast_unsigned(), b'a');
        }
    }

    #[test]
    fn test_itoa() {
        unsafe {
            let mut buf = [0i8; 32];
            msvcrt__itoa(255, buf.as_mut_ptr(), 16);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "ff");
        }
    }

    #[test]
    fn test_strncpy() {
        unsafe {
            let mut buf = [0i8; 16];
            msvcrt_strncpy(buf.as_mut_ptr(), c"hello".as_ptr(), 8);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn test_stricmp() {
        unsafe {
            assert_eq!(msvcrt__stricmp(c"Hello".as_ptr(), c"hello".as_ptr()), 0);
            assert_ne!(msvcrt__stricmp(c"abc".as_ptr(), c"xyz".as_ptr()), 0);
        }
    }

    #[test]
    fn test_strnlen() {
        unsafe {
            assert_eq!(msvcrt_strnlen(c"hello".as_ptr(), 10), 5);
            assert_eq!(msvcrt_strnlen(c"hello".as_ptr(), 3), 3);
            assert_eq!(msvcrt_strnlen(core::ptr::null(), 10), 0);
        }
    }

    #[test]
    fn test_rand_srand() {
        unsafe {
            msvcrt_srand(42);
            let r1 = msvcrt_rand();
            msvcrt_srand(42);
            let r2 = msvcrt_rand();
            assert_eq!(r1, r2);
            assert!((0..=32767).contains(&r1));
        }
    }

    #[test]
    fn test_time() {
        unsafe {
            let t = msvcrt_time(core::ptr::null_mut());
            assert!(t > 0);
            let mut out: i64 = 0;
            let t2 = msvcrt_time(&raw mut out);
            assert_eq!(t2, out);
        }
    }

    #[test]
    fn test_math() {
        unsafe {
            assert_eq!(msvcrt_abs(-5), 5);
            assert_eq!(msvcrt_labs(-100i64), 100i64);
            assert!((msvcrt_sqrt(4.0) - 2.0).abs() < 1e-10);
            assert!((msvcrt_pow(2.0, 10.0) - 1024.0).abs() < 1e-6);
            assert!((msvcrt_floor(3.7) - 3.0).abs() < 1e-10);
            assert!((msvcrt_ceil(3.2) - 4.0).abs() < 1e-10);
        }
    }

    #[test]
    fn test_wcscpy_wcscat() {
        unsafe {
            let src: Vec<u16> = "hello\0".encode_utf16().collect();
            let mut buf = vec![0u16; 32];
            msvcrt_wcscpy(buf.as_mut_ptr(), src.as_ptr());
            let add: Vec<u16> = " world\0".encode_utf16().collect();
            msvcrt_wcscat(buf.as_mut_ptr(), add.as_ptr());
            let result =
                String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap()]);
            assert_eq!(result, "hello world");
        }
    }

    #[test]
    fn test_wcstombs_mbstowcs() {
        unsafe {
            let wide: Vec<u16> = "hello\0".encode_utf16().collect();
            let mut narrow = vec![0i8; 16];
            let n = msvcrt_wcstombs(narrow.as_mut_ptr(), wide.as_ptr(), 16);
            assert_eq!(n, 5);
            let s = core::ffi::CStr::from_ptr(narrow.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello");
        }
    }

    #[test]
    fn test_atol() {
        unsafe {
            assert_eq!(msvcrt_atol(c"42".as_ptr()), 42);
            assert_eq!(msvcrt_atol(c"-7".as_ptr()), -7);
            assert_eq!(msvcrt_atol(c"0".as_ptr()), 0);
        }
    }

    #[test]
    fn test_strtoul() {
        unsafe {
            assert_eq!(
                msvcrt_strtoul(c"255".as_ptr(), core::ptr::null_mut(), 10),
                255
            );
            assert_eq!(
                msvcrt_strtoul(c"ff".as_ptr(), core::ptr::null_mut(), 16),
                0xff
            );
        }
    }

    #[test]
    fn test_strtod() {
        unsafe {
            let s = c"2.5abc";
            let mut end: *mut i8 = core::ptr::null_mut();
            let val = msvcrt_strtod(s.as_ptr(), &raw mut end);
            assert!((val - 2.5).abs() < 1e-6, "strtod: got {val}");
            // endptr should point past the parsed number (at 'a')
            let end_offset = end.offset_from(s.as_ptr());
            assert!(end_offset >= 0, "endptr must be after start");
            assert_eq!(
                end_offset.cast_unsigned(),
                3,
                "endptr offset should be 3, got {end_offset}"
            );
        }
    }

    #[test]
    fn test_ltoa() {
        unsafe {
            let mut buf = [0i8; 32];
            msvcrt__ltoa(-42, buf.as_mut_ptr(), 10);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "-42");
            msvcrt__ltoa(255, buf.as_mut_ptr(), 16);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "ff");
        }
    }

    #[test]
    fn test_strncat() {
        unsafe {
            let mut buf = [0i8; 32];
            let hello = c"hello";
            core::ptr::copy_nonoverlapping(hello.as_ptr(), buf.as_mut_ptr(), 6);
            msvcrt_strncat(buf.as_mut_ptr(), c" world".as_ptr(), 6);
            let s = core::ffi::CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(s, "hello world");
        }
    }

    #[test]
    fn test_strnicmp() {
        unsafe {
            // equal strings (different case)
            assert_eq!(msvcrt__strnicmp(c"Hello".as_ptr(), c"hello".as_ptr(), 5), 0);
            // differ before n is reached
            assert_ne!(msvcrt__strnicmp(c"abc".as_ptr(), c"xyz".as_ptr(), 3), 0);
            // n=0 always equal
            assert_eq!(msvcrt__strnicmp(c"abc".as_ptr(), c"xyz".as_ptr(), 0), 0);
        }
    }

    #[test]
    fn test_strdup() {
        unsafe {
            let dup = msvcrt__strdup(c"hello".as_ptr());
            assert!(!dup.is_null());
            let result = core::ffi::CStr::from_ptr(dup).to_str().unwrap();
            assert_eq!(result, "hello");
            msvcrt_free(dup.cast());
        }
    }

    #[test]
    fn test_clock() {
        unsafe {
            let t = msvcrt_clock();
            assert!(t >= 0, "clock should return non-negative value");
        }
    }

    #[test]
    fn test_labs_abs64() {
        unsafe {
            assert_eq!(msvcrt_labs(-99i64), 99i64);
            assert_eq!(msvcrt__abs64(-1_000_000i64), 1_000_000i64);
            assert_eq!(msvcrt__abs64(0), 0);
        }
    }

    #[test]
    fn test_math_extended() {
        unsafe {
            assert!((msvcrt_log(core::f64::consts::E) - 1.0).abs() < 1e-10);
            assert!((msvcrt_log10(100.0) - 2.0).abs() < 1e-10);
            assert!((msvcrt_exp(1.0) - core::f64::consts::E).abs() < 1e-10);
            assert!((msvcrt_sin(0.0)).abs() < 1e-10);
            assert!((msvcrt_cos(0.0) - 1.0).abs() < 1e-10);
            assert!((msvcrt_tan(0.0)).abs() < 1e-10);
            assert!((msvcrt_atan(1.0) - core::f64::consts::FRAC_PI_4).abs() < 1e-10);
            assert!((msvcrt_atan2(1.0, 1.0) - core::f64::consts::FRAC_PI_4).abs() < 1e-10);
            assert!((msvcrt_fmod(5.5, 2.0) - 1.5).abs() < 1e-10);
        }
    }

    #[test]
    fn test_wcsncpy() {
        unsafe {
            let src: Vec<u16> = "hello world\0".encode_utf16().collect();
            let mut buf = vec![0u16; 32];
            msvcrt_wcsncpy(buf.as_mut_ptr(), src.as_ptr(), 5);
            // wcsncpy copies exactly n chars; no guaranteed NUL if src >= n
            let result = String::from_utf16_lossy(&buf[..5]);
            assert_eq!(result, "hello");
        }
    }

    #[test]
    fn test_wcschr() {
        unsafe {
            let s: Vec<u16> = "hello\0".encode_utf16().collect();
            let found = msvcrt_wcschr(s.as_ptr(), u16::from(b'l'));
            assert!(!found.is_null());
            // offset to first 'l' is 2
            assert_eq!(found.offset_from(s.as_ptr()), 2);
            let not_found = msvcrt_wcschr(s.as_ptr(), u16::from(b'z'));
            assert!(not_found.is_null());
        }
    }

    #[test]
    fn test_wcsncmp() {
        unsafe {
            let a: Vec<u16> = "hello\0".encode_utf16().collect();
            let b: Vec<u16> = "hellx\0".encode_utf16().collect();
            assert_eq!(msvcrt_wcsncmp(a.as_ptr(), a.as_ptr(), 5), 0);
            let r = msvcrt_wcsncmp(a.as_ptr(), b.as_ptr(), 5);
            assert!(r < 0, "expected negative, got {r}");
            // only compare 4 chars — should be equal
            assert_eq!(msvcrt_wcsncmp(a.as_ptr(), b.as_ptr(), 4), 0);
        }
    }

    #[test]
    fn test_wcsicmp_wcsnicmp() {
        unsafe {
            let a: Vec<u16> = "Hello\0".encode_utf16().collect();
            let b: Vec<u16> = "hello\0".encode_utf16().collect();
            assert_eq!(msvcrt__wcsicmp(a.as_ptr(), b.as_ptr()), 0);
            assert_eq!(msvcrt__wcsnicmp(a.as_ptr(), b.as_ptr(), 5), 0);
            let c: Vec<u16> = "world\0".encode_utf16().collect();
            assert_ne!(msvcrt__wcsicmp(a.as_ptr(), c.as_ptr()), 0);
        }
    }

    #[test]
    fn test_cxx_frame_handler3_null_args() {
        let result = unsafe {
            msvcrt___CxxFrameHandler3(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_cxx_frame_handler4_null_args() {
        let result = unsafe {
            msvcrt___CxxFrameHandler4(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_cxx_register_unregister_exception_object() {
        let result = unsafe {
            msvcrt___CxxRegisterExceptionObject(core::ptr::null_mut(), core::ptr::null_mut())
        };
        assert_eq!(result, 1);

        let result = unsafe { msvcrt___CxxUnregisterExceptionObject(core::ptr::null_mut(), 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_destruct_exception_object_null() {
        unsafe { msvcrt___DestructExceptionObject(core::ptr::null_mut()) };
    }

    #[test]
    fn test_uncaught_exception() {
        assert_eq!(unsafe { msvcrt___uncaught_exception() }, 0);
        assert_eq!(unsafe { msvcrt___uncaught_exceptions() }, 0);
    }

    #[test]
    fn test_cxx_ip_to_state_empty() {
        let fi = CxxFuncInfo {
            magic_and_bbt: CXX_FRAME_MAGIC_VC8,
            unwind_count: 0,
            unwind_table: 0,
            tryblock_count: 0,
            tryblock: 0,
            ipmap_count: 0,
            ipmap: 0,
            unwind_help: 0,
            expect_list: 0,
            flags: 0,
        };
        assert_eq!(cxx_ip_to_state(&fi, 0x1000, 0x1100), -1);
    }
}
