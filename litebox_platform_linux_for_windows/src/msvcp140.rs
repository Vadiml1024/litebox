// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MSVCP140.DLL (Microsoft C++ Standard Library) stub implementations
//!
//! This module provides minimal stubs for the most commonly imported
//! symbols from `msvcp140.dll` so that C++ programs compiled with MSVC
//! can load without immediately failing on an unresolved import.
//!
//! The C++ mangled names are registered in `function_table.rs` using the
//! `name` field, while the actual Rust implementations use descriptive names.

// Allow unsafe operations inside unsafe functions since the entire file
// uses C ABI functions that are inherently unsafe.
#![allow(unsafe_op_in_unsafe_fn)]

use std::ptr;

// ============================================================================
// Global operator new / delete
// ============================================================================
// Use libc malloc/free so that the allocation and deallocation sites are a
// matched pair regardless of Rust's global allocator internals.

/// `operator new(size)` — allocate `size` bytes.
///
/// Exported as the mangled name `??2@YAPEAX_K@Z`.
///
/// # Safety
/// Returns a valid non-null pointer on success, null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_new(size: usize) -> *mut u8 {
    // Always allocate at least 1 byte so the returned pointer can safely be
    // passed to `msvcp140_operator_delete`, which always calls `libc::free`.
    let alloc_size = if size == 0 { 1 } else { size };
    // SAFETY: alloc_size > 0.
    unsafe { libc::malloc(alloc_size).cast() }
}

/// `operator delete(ptr)` — free a pointer allocated by `operator new`.
///
/// Exported as the mangled name `??3@YAXPEAX@Z`.
///
/// # Safety
/// `ptr` must have been allocated by `msvcp140_operator_new`, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_delete(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr was allocated by libc::malloc in msvcp140_operator_new.
    unsafe { libc::free(ptr.cast()) };
}

/// `operator new[](size)` — allocate array.
///
/// Exported as the mangled name `??_U@YAPEAX_K@Z`.
///
/// # Safety
/// See `msvcp140_operator_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_new_array(size: usize) -> *mut u8 {
    unsafe { msvcp140_operator_new(size) }
}

/// `operator delete[](ptr)` — free array.
///
/// Exported as the mangled name `??_V@YAXPEAX@Z`.
///
/// # Safety
/// See `msvcp140_operator_delete`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140_operator_delete_array(ptr: *mut u8) {
    unsafe { msvcp140_operator_delete(ptr) }
}

// ============================================================================
// Standard-library exception helpers
// ============================================================================
// These helpers are called by MSVC STL code when it needs to throw a standard
// C++ exception.  Because we cannot propagate real C++ exceptions, we abort.

/// `std::_Xbad_alloc()` — called when `std::bad_alloc` should be thrown.
///
/// Exported as the mangled name `?_Xbad_alloc@std@@YAXXZ`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xbad_alloc() -> ! {
    eprintln!("[litebox] msvcp140: std::bad_alloc thrown — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xlength_error(msg)` — called when `std::length_error` should be thrown.
///
/// Exported as the mangled name `?_Xlength_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xlength_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "length_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("length_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::length_error({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xout_of_range(msg)` — called when `std::out_of_range` should be thrown.
///
/// Exported as the mangled name `?_Xout_of_range@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xout_of_range(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "out_of_range"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("out_of_range")
        }
    };
    eprintln!("[litebox] msvcp140: std::out_of_range({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xinvalid_argument(msg)`.
///
/// Exported as the mangled name `?_Xinvalid_argument@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xinvalid_argument(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "invalid_argument"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("invalid_argument")
        }
    };
    eprintln!("[litebox] msvcp140: std::invalid_argument({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xruntime_error(msg)`.
///
/// Exported as the mangled name `?_Xruntime_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xruntime_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "runtime_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("runtime_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::runtime_error({m}) — aborting");
    unsafe { libc::abort() }
}

/// `std::_Xoverflow_error(msg)`.
///
/// Exported as the mangled name `?_Xoverflow_error@std@@YAXPEBD@Z`.
///
/// # Safety
/// Terminates the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Xoverflow_error(msg: *const i8) -> ! {
    let m = if msg.is_null() {
        "overflow_error"
    } else {
        unsafe {
            std::ffi::CStr::from_ptr(msg)
                .to_str()
                .unwrap_or("overflow_error")
        }
    };
    eprintln!("[litebox] msvcp140: std::overflow_error({m}) — aborting");
    unsafe { libc::abort() }
}

// ============================================================================
// Locale / facet stubs
// ============================================================================
// These are C++ non-static member functions (`__thiscall` / `QEBA` in mangled
// names), so they receive an implicit `this` pointer as their first argument.

/// `std::_Locinfo::_Getctype()` — returns a pointer to the locale C-type table.
///
/// Exported as `?_Getctype@_Locinfo@std@@QEBAPBU_Ctypevec@@XZ` (mangled).
/// Stub: ignores `this` and returns null.
///
/// # Safety
/// Always safe to call; the return value must not be dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getctype(_this: *const u8) -> *const u8 {
    ptr::null()
}

/// `std::_Locinfo::_Getdays()` — returns locale day-name string.
///
/// Exported as `?_Getdays@_Locinfo@std@@QEBAPEBDXZ`.
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getdays(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

/// `std::_Locinfo::_Getmonths()` — returns locale month-name string.
///
/// Exported as `?_Getmonths@_Locinfo@std@@QEBAPEBDXZ`.
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getmonths(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

// ============================================================================
// Concurrency stubs
// ============================================================================

/// `Concurrency::details::_ReaderWriterLock::_AcquireRead()` stub.
///
/// No-op in our single-threaded environment.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__concurrency_acquire_read(_lock: *mut u8) {}

/// `Concurrency::details::_ReaderWriterLock::_ReleaseRead()` stub.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__concurrency_release_read(_lock: *mut u8) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_new_delete() {
        unsafe {
            let p = msvcp140_operator_new(64);
            assert!(!p.is_null());
            msvcp140_operator_delete(p);
        }
    }

    #[test]
    fn test_operator_new_zero() {
        unsafe {
            let p = msvcp140_operator_new(0);
            // Zero-size allocation returns a dangling non-null pointer
            assert!(!p.is_null());
            // Do not free the dangling pointer
        }
    }

    #[test]
    fn test_operator_new_array_delete_array() {
        unsafe {
            let p = msvcp140_operator_new_array(128);
            assert!(!p.is_null());
            msvcp140_operator_delete_array(p);
        }
    }

    #[test]
    fn test_operator_delete_null() {
        // Deleting null must not crash
        unsafe { msvcp140_operator_delete(ptr::null_mut()) };
    }
}
