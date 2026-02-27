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

// ============================================================================
// Phase 35: std::exception and additional std:: stubs
// ============================================================================

/// `std::exception::what() const` — returns the exception message.
///
/// Exported as `?what@exception@std@@UEBAPEBDXZ` (mangled MSVC name).
/// Stub: ignores `this` and returns an empty string pointer.
///
/// # Safety
/// Returns a pointer to a static string literal; always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_what(_this: *const u8) -> *const i8 {
    c"".as_ptr()
}

/// `std::exception::~exception()` — destructor.
///
/// Exported as `??1exception@std@@UEAA@XZ`.
/// Stub: no-op since our exception objects have no owned resources.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_dtor(_this: *mut u8) {}

/// `std::exception::exception()` — default constructor.
///
/// Exported as `??0exception@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_ctor(_this: *mut u8) {}

/// `std::exception::exception(char const*)` — message constructor.
///
/// Exported as `??0exception@std@@QEAA@PEBD@Z`.
/// Stub: no-op (message string is not stored).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__exception_ctor_msg(_this: *mut u8, _msg: *const i8) {}

/// `std::locale::_Getgloballocale()` — returns the global locale object pointer.
///
/// Exported as `?_Getgloballocale@locale@std@@CAPEAV_Lobj@12@XZ`.
/// Stub: returns null; programs that use locale operations will need real
/// locale support in a future phase.
///
/// # Safety
/// Always safe to call; the return value must not be dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Getgloballocale() -> *mut u8 {
    ptr::null_mut()
}

/// `std::_Lockit::_Lockit(int)` — locale lock constructor.
///
/// Exported as `??0_Lockit@std@@QEAA@H@Z`.
/// Stub: no-op (single-threaded environment).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Lockit_ctor(_this: *mut u8, _kind: i32) {}

/// `std::_Lockit::~_Lockit()` — locale lock destructor.
///
/// Exported as `??1_Lockit@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__Lockit_dtor(_this: *mut u8) {}

/// `std::ios_base::Init::Init()` — `ios` base initializer constructor.
///
/// Exported as `??0Init@ios_base@std@@QEAA@XZ`.
/// Stub: no-op (we don't maintain C++ iostream state).
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ios_base_Init_ctor(_this: *mut u8) {}

/// `std::ios_base::Init::~Init()` — `ios` base initializer destructor.
///
/// Exported as `??1Init@ios_base@std@@QEAA@XZ`.
/// Stub: no-op.
///
/// # Safety
/// Always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__ios_base_Init_dtor(_this: *mut u8) {}

// ============================================================================
// Phase 37: std::basic_string<char> — MSVC x64 ABI implementation
// ============================================================================
//
// MSVC x64 `std::string` (`basic_string<char>`) internal layout (32 bytes):
//
//   [0..16)  union { char _Buf[16]; char* _Ptr; }   — SSO buffer or heap pointer
//   [16..24) size_t _Mysize                          — current length (excl. NUL)
//   [24..32) size_t _Myres                           — capacity (excl. NUL)
//
// SSO threshold: strings up to 15 chars use the inline buffer (`_Myres == 15`);
// longer strings use a heap allocation via `libc::malloc` / `libc::free`.

/// SSO capacity for MSVC `std::string` (inline buffer size minus NUL byte).
const MSVCRT_STR_SSO_CAP: usize = 15;

/// Read `_Mysize` field from a `basic_string<char>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_mysize(this: *const u8) -> usize {
    // The `basic_string` object is received as a `*const u8` (byte pointer) and
    // its alignment is only guaranteed to be 1-byte aligned from our perspective.
    // Even though the 16-byte union field that precedes `_Mysize` ensures 8-byte
    // natural alignment in practice, `read_unaligned` is used defensively to avoid
    // triggering alignment-related undefined behaviour if the pointer is ever
    // less than 8-byte aligned.
    unsafe { ptr::read_unaligned(this.add(16).cast::<usize>()) }
}

/// Read `_Myres` (capacity) from a `basic_string<char>` object at `this`.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_myres(this: *const u8) -> usize {
    // See `bstr_mysize` for the rationale for using `read_unaligned`.
    unsafe { ptr::read_unaligned(this.add(24).cast::<usize>()) }
}

/// Return a pointer to the character data of a `basic_string<char>` object.
///
/// # Safety
/// `this` must point to a valid, initialized `basic_string<char>` (32 bytes).
#[inline]
unsafe fn bstr_data(this: *const u8) -> *const i8 {
    let cap = unsafe { bstr_myres(this) };
    if cap == MSVCRT_STR_SSO_CAP {
        // SSO: data is inline at offset 0.
        this.cast::<i8>()
    } else {
        // Heap: first 8 bytes hold the pointer; may not be pointer-aligned.
        unsafe { ptr::read_unaligned(this.cast::<*const i8>()) }
    }
}

/// `std::basic_string<char>::basic_string()` — default constructor.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ`.
/// Initialises to an empty string using SSO.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_ctor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    // Zero the SSO buffer and set _Mysize = 0, _Myres = SSO_CAP.
    unsafe {
        ptr::write_bytes(this, 0, 16);
        ptr::write_unaligned(this.add(16).cast::<usize>(), 0);
        ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP);
    }
}

/// `std::basic_string<char>::basic_string(char const*)` — construct from C string.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@PEBD@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_ctor_cstr(this: *mut u8, s: *const i8) {
    unsafe { msvcp140__basic_string_ctor(this) };
    if s.is_null() {
        return;
    }
    // SAFETY: s is a valid null-terminated C string per caller contract.
    let len = unsafe { libc::strlen(s) };
    unsafe { msvcp140_basic_string_assign_impl(this, s, len) };
}

/// `std::basic_string<char>::basic_string(basic_string const&)` — copy constructor.
///
/// Exported as `??0?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@AEBV01@@Z`.
///
/// # Safety
/// `this` must point to at least 32 bytes of writable memory.
/// `other` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_copy_ctor(this: *mut u8, other: *const u8) {
    unsafe { msvcp140__basic_string_ctor(this) };
    if other.is_null() {
        return;
    }
    let len = unsafe { bstr_mysize(other) };
    let src = unsafe { bstr_data(other) };
    unsafe { msvcp140_basic_string_assign_impl(this, src, len) };
}

/// `std::basic_string<char>::~basic_string()` — destructor.
///
/// Exported as `??1?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAA@XZ`.
/// Frees the heap buffer if SSO is not active.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_dtor(this: *mut u8) {
    if this.is_null() {
        return;
    }
    let cap = unsafe { bstr_myres(this) };
    if cap != MSVCRT_STR_SSO_CAP {
        // Heap allocation: free the pointer stored at offset 0.
        let ptr_val = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !ptr_val.is_null() {
            // SAFETY: ptr_val was allocated by libc::malloc in msvcp140_basic_string_assign_impl.
            unsafe { libc::free(ptr_val.cast()) };
        }
    }
    // Zero the object to prevent use-after-free.
    unsafe { ptr::write_bytes(this, 0, 32) };
}

/// Internal helper: assign `len` bytes from `s` into `this`.
///
/// # Safety
/// `this` must point to a valid (possibly empty) `basic_string<char>`.
/// `s` must point to at least `len` readable bytes.
/// `s` must NOT alias the existing character buffer of `this`; callers that
/// may alias (e.g. self-assignment) must copy `s` to a temporary first.
unsafe fn msvcp140_basic_string_assign_impl(this: *mut u8, s: *const i8, len: usize) {
    if this.is_null() {
        return;
    }
    // Guard against length overflow when computing malloc size.
    let Some(alloc_size) = len.checked_add(1) else {
        // Length overflow — leave the string unchanged.
        return;
    };
    // Free existing heap allocation if any.
    let old_cap = unsafe { bstr_myres(this) };
    if old_cap != MSVCRT_STR_SSO_CAP {
        let old_ptr = unsafe { ptr::read_unaligned(this.cast::<*mut u8>()) };
        if !old_ptr.is_null() {
            unsafe { libc::free(old_ptr.cast()) };
        }
    }

    if len <= MSVCRT_STR_SSO_CAP {
        // Use SSO buffer.
        if !s.is_null() && len > 0 {
            // SAFETY: s points to at least `len` readable bytes; buf is 16 bytes.
            unsafe { ptr::copy_nonoverlapping(s, this.cast::<i8>(), len) };
        }
        // NUL terminate.
        unsafe { *this.add(len).cast::<i8>() = 0 };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP) };
    } else {
        // Heap allocation.
        // SAFETY: alloc_size > 0 (checked above).
        let buf = unsafe { libc::malloc(alloc_size).cast::<i8>() };
        if buf.is_null() {
            // Allocation failed: leave the string in a valid empty SSO state
            // rather than storing a null heap pointer with non-zero size.
            unsafe { ptr::write_bytes(this, 0, 16) };
            unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), 0) };
            unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), MSVCRT_STR_SSO_CAP) };
            return;
        }
        if !s.is_null() {
            // SAFETY: s points to at least `len` readable bytes.
            unsafe { ptr::copy_nonoverlapping(s, buf, len) };
        }
        // NUL terminate.
        unsafe { *buf.add(len) = 0 };
        // Store heap pointer at offset 0.
        unsafe { ptr::write_unaligned(this.cast::<*mut i8>(), buf) };
        unsafe { ptr::write_unaligned(this.add(16).cast::<usize>(), len) };
        unsafe { ptr::write_unaligned(this.add(24).cast::<usize>(), len) };
    }
}

/// `std::basic_string<char>::c_str() const` — return null-terminated character pointer.
///
/// Exported as `?c_str@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBAPEBDXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_c_str(this: *const u8) -> *const i8 {
    if this.is_null() {
        return c"".as_ptr();
    }
    unsafe { bstr_data(this) }
}

/// `std::basic_string<char>::size() const` — return string length.
///
/// Exported as `?size@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_KXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_size(this: *const u8) -> usize {
    if this.is_null() {
        return 0;
    }
    unsafe { bstr_mysize(this) }
}

/// `std::basic_string<char>::empty() const` — return true if string is empty.
///
/// Exported as `?empty@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEBA_NXZ`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_empty(this: *const u8) -> bool {
    unsafe { msvcp140__basic_string_size(this) == 0 }
}

/// `std::basic_string<char>::operator=(basic_string const&)` — copy assignment.
///
/// Exported as
/// `??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@AEBV01@@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` and `other` must each point to valid initialized `basic_string<char>` objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_assign_op(
    this: *mut u8,
    other: *const u8,
) -> *mut u8 {
    if !other.is_null() {
        // Guard against self-assignment: if this == other and the string is
        // heap-backed, msvcp140_basic_string_assign_impl would free the buffer
        // before copying from it, causing use-after-free.
        if std::ptr::eq(this, other) {
            return this;
        }
        let len = unsafe { bstr_mysize(other) };
        let src = unsafe { bstr_data(other) };
        unsafe { msvcp140_basic_string_assign_impl(this, src, len) };
    }
    this
}

/// `std::basic_string<char>::operator=(char const*)` — assign from C string.
///
/// Exported as
/// `??4?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV01@PEBD@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_assign_cstr(
    this: *mut u8,
    s: *const i8,
) -> *mut u8 {
    if !s.is_null() {
        let len = unsafe { libc::strlen(s) };
        unsafe { msvcp140_basic_string_assign_impl(this, s, len) };
    }
    this
}

/// `std::basic_string<char>::append(char const*)` — append a C string.
///
/// Exported as
/// `?append@?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@QEAAAEAV12@PEBD@Z`.
/// Returns `this`.
///
/// # Safety
/// `this` must point to a valid initialized `basic_string<char>`.
/// `s` must be a valid null-terminated C string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msvcp140__basic_string_append_cstr(
    this: *mut u8,
    s: *const i8,
) -> *mut u8 {
    if this.is_null() || s.is_null() {
        return this;
    }
    let cur_len = unsafe { bstr_mysize(this) };
    let add_len = unsafe { libc::strlen(s) };

    // Guard against length overflow.
    let Some(new_len) = cur_len.checked_add(add_len) else {
        // Overflow — leave string unchanged.
        return this;
    };
    let Some(alloc_size) = new_len.checked_add(1) else {
        // Allocation size overflow — leave string unchanged.
        return this;
    };

    // Build a temporary buffer with the concatenated result.
    let cur_data = unsafe { bstr_data(this) };
    // SAFETY: alloc_size > 0 and was computed with checked_add.
    let tmp = unsafe { libc::malloc(alloc_size).cast::<i8>() };
    if tmp.is_null() {
        return this;
    }
    if cur_len > 0 {
        // SAFETY: cur_data points to at least cur_len readable bytes.
        unsafe { ptr::copy_nonoverlapping(cur_data, tmp, cur_len) };
    }
    // SAFETY: s points to add_len readable bytes.
    unsafe { ptr::copy_nonoverlapping(s, tmp.add(cur_len), add_len) };
    unsafe { *tmp.add(new_len) = 0 };

    unsafe { msvcp140_basic_string_assign_impl(this, tmp, new_len) };
    // SAFETY: tmp was allocated by libc::malloc above.
    unsafe { libc::free(tmp.cast()) };
    this
}

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

    #[test]
    fn test_exception_what_returns_nonnull() {
        let p = unsafe { msvcp140__exception_what(ptr::null()) };
        assert!(!p.is_null());
    }

    #[test]
    fn test_exception_ctor_dtor_noop() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__exception_ctor(obj.as_mut_ptr());
            msvcp140__exception_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_lockit_ctor_dtor_noop() {
        let mut obj = [0u8; 16];
        unsafe {
            msvcp140__Lockit_ctor(obj.as_mut_ptr(), 0);
            msvcp140__Lockit_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_default_ctor_is_empty() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor(obj.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 0);
            assert!(msvcp140__basic_string_empty(obj.as_ptr()));
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert!(!cs.is_null());
            assert_eq!(*cs, 0);
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_ctor_from_cstr() {
        let mut obj = [0u8; 32];
        let hello = c"hello";
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), hello.as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 5);
            assert!(!msvcp140__basic_string_empty(obj.as_ptr()));
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert!(!cs.is_null());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_copy_ctor() {
        let mut src = [0u8; 32];
        let mut dst = [0u8; 32];
        let text = c"copy me";
        unsafe {
            msvcp140__basic_string_ctor_cstr(src.as_mut_ptr(), text.as_ptr());
            msvcp140__basic_string_copy_ctor(dst.as_mut_ptr(), src.as_ptr());
            assert_eq!(msvcp140__basic_string_size(dst.as_ptr()), 7);
            let cs = msvcp140__basic_string_c_str(dst.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "copy me");
            msvcp140__basic_string_dtor(src.as_mut_ptr());
            msvcp140__basic_string_dtor(dst.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_append() {
        let mut obj = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), c"hel".as_ptr());
            msvcp140__basic_string_append_cstr(obj.as_mut_ptr(), c"lo".as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 5);
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_long_string_uses_heap() {
        let mut obj = [0u8; 32];
        // A 20-char string exceeds the SSO threshold (15 chars).
        let long_str = c"this_is_twenty_chars"; // 20 chars
        unsafe {
            msvcp140__basic_string_ctor_cstr(obj.as_mut_ptr(), long_str.as_ptr());
            assert_eq!(msvcp140__basic_string_size(obj.as_ptr()), 20);
            let cs = msvcp140__basic_string_c_str(obj.as_ptr());
            assert_eq!(
                std::ffi::CStr::from_ptr(cs).to_str().unwrap(),
                "this_is_twenty_chars"
            );
            msvcp140__basic_string_dtor(obj.as_mut_ptr());
        }
    }

    #[test]
    fn test_basic_string_self_assign_does_not_corrupt() {
        // SSO string: self-assignment should be a no-op.
        let mut sso = [0u8; 32];
        unsafe {
            msvcp140__basic_string_ctor_cstr(sso.as_mut_ptr(), c"hello".as_ptr());
            let ret = msvcp140__basic_string_assign_op(sso.as_mut_ptr(), sso.as_ptr());
            assert_eq!(ret, sso.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(sso.as_ptr()), 5);
            let cs = msvcp140__basic_string_c_str(sso.as_ptr());
            assert_eq!(std::ffi::CStr::from_ptr(cs).to_str().unwrap(), "hello");
            msvcp140__basic_string_dtor(sso.as_mut_ptr());
        }

        // Heap-backed string: self-assignment must not free the buffer before copying.
        let mut heap = [0u8; 32];
        unsafe {
            // "this_is_twenty_chars" (20 chars) forces heap allocation.
            msvcp140__basic_string_ctor_cstr(heap.as_mut_ptr(), c"this_is_twenty_chars".as_ptr());
            let ret = msvcp140__basic_string_assign_op(heap.as_mut_ptr(), heap.as_ptr());
            assert_eq!(ret, heap.as_mut_ptr());
            assert_eq!(msvcp140__basic_string_size(heap.as_ptr()), 20);
            let cs = msvcp140__basic_string_c_str(heap.as_ptr());
            assert_eq!(
                std::ffi::CStr::from_ptr(cs).to_str().unwrap(),
                "this_is_twenty_chars"
            );
            msvcp140__basic_string_dtor(heap.as_mut_ptr());
        }
    }
}
