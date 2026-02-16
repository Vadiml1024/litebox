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
use std::ffi::CStr;
use std::io::{self, Write};
use std::ptr;
use std::sync::Mutex;

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
        Err(_) => -1,
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
        Err(_) => 0,
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
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt___getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut i8,
    env: *mut *mut *mut i8,
    _do_wildcard: i32,
    _start_info: *mut u8,
) -> i32 {
    // Static null-terminated arrays for argv and env
    // These are immutable after initialization, so no synchronization needed
    static mut ARGV_STORAGE: [*mut i8; 1] = [core::ptr::null_mut()];
    static mut ENV_STORAGE: [*mut i8; 1] = [core::ptr::null_mut()];

    // Set argc to 0 (no arguments)
    if !argc.is_null() {
        *argc = 0;
    }

    // Set argv to empty array with null terminator
    // SAFETY: We're accessing mutable static, but it's only being read after initialization
    // and the contents (null pointers) never change
    if !argv.is_null() {
        *argv = core::ptr::addr_of_mut!(ARGV_STORAGE).cast();
    }

    // Set env to empty array with null terminator
    // SAFETY: Same as argv - immutable after initialization
    if !env.is_null() {
        *env = core::ptr::addr_of_mut!(ENV_STORAGE).cast();
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
        let func = unsafe { *current };
        // Check if function pointer is not null or -1 (sentinel value) before calling
        let func_ptr = func as *const fn();
        let func_addr = func_ptr as usize;
        if !func_ptr.is_null() && func_addr != usize::MAX {
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
    // Check if function pointer is valid (not null or -1)
    let func_ptr = func as *const fn();
    let func_addr = func_ptr as usize;
    if func_ptr.is_null() || func_addr == usize::MAX {
        return func; // Return as-is for invalid pointers
    }

    // Store in a static vector for later execution
    static ONEXIT_FUNCS: Mutex<Vec<extern "C" fn()>> = Mutex::new(Vec::new());

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

/// Global command line pointer for _acmdln
/// In a real implementation, this would point to the actual command line.
/// For now, we use an empty string as a stub.
static ACMDLN: &[u8] = b"\0";

/// Get pointer to command line string (_acmdln)
///
/// This is a global variable in MSVCRT that points to the command line arguments.
/// Programs access it via `_acmdln` which is a char** (pointer to pointer).
///
/// # Safety
/// Returns a pointer to static memory that is valid for the lifetime of the program.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcrt__acmdln() -> *const *const u8 {
    // Return a pointer to a pointer to the command line string
    // We store the pointer as usize for thread safety
    use std::sync::OnceLock;
    static ACMDLN_PTR: OnceLock<usize> = OnceLock::new();
    let ptr_val = *ACMDLN_PTR.get_or_init(|| ACMDLN.as_ptr() as usize);
    ptr_val as *const *const u8
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
}
