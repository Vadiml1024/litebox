// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! KERNEL32.dll function implementations
//!
//! This module provides Linux-based implementations of KERNEL32 functions
//! that are commonly used by Windows programs. These are higher-level wrappers
//! around NTDLL functions.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings as we're implementing Windows API which requires specific integer types
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]

use std::alloc;
use std::cell::Cell;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Code page constants for MultiByteToWideChar and WideCharToMultiByte
const CP_ACP: u32 = 0;
const CP_UTF8: u32 = 65001;

// Heap constants for HeapAlloc
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

// Epoch difference between Windows (1601-01-01) and Unix (1970-01-01) in seconds
const EPOCH_DIFF: i64 = 11_644_473_600;

/// Thread Local Storage (TLS) manager
///
/// Windows TLS allows each thread to store thread-specific data.
/// This is implemented using a global HashMap where the key is
/// (thread_id, slot_index) and the value is the stored pointer.
struct TlsManager {
    /// Next available TLS slot index
    next_slot: u32,
    /// Map of (thread_id, slot_index) -> value
    storage: HashMap<(u32, u32), usize>,
}

impl TlsManager {
    fn new() -> Self {
        Self {
            next_slot: 0,
            storage: HashMap::new(),
        }
    }

    fn alloc_slot(&mut self) -> Option<u32> {
        // Windows TLS has a limited number of slots (64 or 1088 depending on version)
        // We'll use a generous limit
        const MAX_TLS_SLOTS: u32 = 1088;
        if self.next_slot >= MAX_TLS_SLOTS {
            return None;
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        Some(slot)
    }

    fn free_slot(&mut self, slot: u32, thread_id: u32) -> bool {
        // Remove the value for this thread and slot
        self.storage.remove(&(thread_id, slot));
        true
    }

    fn get_value(&self, slot: u32, thread_id: u32) -> usize {
        self.storage.get(&(thread_id, slot)).copied().unwrap_or(0)
    }

    fn set_value(&mut self, slot: u32, thread_id: u32, value: usize) -> bool {
        self.storage.insert((thread_id, slot), value);
        true
    }
}

/// Global TLS manager protected by a mutex
static TLS_MANAGER: Mutex<Option<TlsManager>> = Mutex::new(None);

/// Initialize the TLS manager (called once)
fn ensure_tls_manager_initialized() {
    let mut manager = TLS_MANAGER.lock().unwrap();
    if manager.is_none() {
        *manager = Some(TlsManager::new());
    }
}

/// Heap allocation tracker
///
/// Tracks allocation sizes for HeapAlloc so that HeapFree and HeapReAlloc
/// can properly deallocate memory using the correct Layout.
struct HeapAllocationTracker {
    /// Map of pointer address -> (size, alignment)
    allocations: HashMap<usize, (usize, usize)>,
}

impl HeapAllocationTracker {
    fn new() -> Self {
        Self {
            allocations: HashMap::new(),
        }
    }

    fn track_allocation(&mut self, ptr: *mut u8, size: usize, align: usize) {
        if !ptr.is_null() {
            self.allocations.insert(ptr as usize, (size, align));
        }
    }

    fn get_allocation(&self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.get(&(ptr as usize)).copied()
    }

    fn remove_allocation(&mut self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.remove(&(ptr as usize))
    }
}

/// Global heap allocation tracker protected by a mutex
static HEAP_TRACKER: Mutex<Option<HeapAllocationTracker>> = Mutex::new(None);

/// Initialize the heap tracker (called once)
fn ensure_heap_tracker_initialized() {
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if tracker.is_none() {
        *tracker = Some(HeapAllocationTracker::new());
    }
}

/// Sleep for specified milliseconds (Sleep)
///
/// This is the Windows Sleep function that suspends execution for the specified duration.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Sleep(milliseconds: u32) {
    thread::sleep(Duration::from_millis(u64::from(milliseconds)));
}

/// Get the current thread ID (GetCurrentThreadId)
///
/// Returns the unique identifier for the current thread.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThreadId() -> u32 {
    // SAFETY: gettid is a safe syscall
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    // Truncate to u32 to match Windows API
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    (tid as u32)
}

/// Get the current process ID (GetCurrentProcessId)
///
/// Returns the unique identifier for the current process.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcessId() -> u32 {
    // SAFETY: getpid is a safe syscall
    let pid = unsafe { libc::getpid() };
    // Convert to u32 to match Windows API
    #[allow(clippy::cast_sign_loss)]
    (pid as u32)
}

/// Allocate a thread local storage (TLS) slot index (TlsAlloc)
///
/// Allocates a TLS index for thread-specific data. Returns TLS_OUT_OF_INDEXES (0xFFFFFFFF)
/// on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsAlloc() -> u32 {
    ensure_tls_manager_initialized();
    let mut manager = TLS_MANAGER.lock().unwrap();
    manager
        .as_mut()
        .and_then(TlsManager::alloc_slot)
        .unwrap_or(0xFFFF_FFFF) // TLS_OUT_OF_INDEXES
}

/// Free a thread local storage (TLS) slot (TlsFree)
///
/// Releases a TLS index previously allocated by TlsAlloc.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsFree(slot: u32) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.free_slot(slot, thread_id)),
    )
}

/// Get a value from thread local storage (TlsGetValue)
///
/// Retrieves the value stored in the specified TLS slot for the current thread.
/// Returns 0 if no value has been set.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for interpreting the returned pointer correctly.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsGetValue(slot: u32) -> usize {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let manager = TLS_MANAGER.lock().unwrap();
    manager.as_ref().map_or(0, |m| m.get_value(slot, thread_id))
}

/// Set a value in thread local storage (TlsSetValue)
///
/// Stores a value in the specified TLS slot for the current thread.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for managing the lifetime of the data pointed to by `value`.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsSetValue(slot: u32, value: usize) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.set_value(slot, thread_id, value)),
    )
}

//
// Phase 8.2: Critical Sections
//
// Critical sections provide thread synchronization primitives for Windows programs.
// We implement them using pthread mutexes on Linux.
//

/// Windows CRITICAL_SECTION structure (opaque to us, but Windows expects ~40 bytes)
///
/// In real Windows, CRITICAL_SECTION is 40 bytes on x64 and contains:
/// - DebugInfo pointer
/// - LockCount
/// - RecursionCount
/// - OwningThread
/// - LockSemaphore
/// - SpinCount
///
/// We treat it as an opaque structure that just needs to hold a pointer to our internal data.
#[repr(C)]
pub struct CriticalSection {
    /// Internal data pointer (points to `Arc<Mutex<CriticalSectionData>>`)
    internal: usize,
    /// Padding to match Windows CRITICAL_SECTION size (40 bytes total)
    _padding: [u8; 32],
}

/// Internal data for a critical section
struct CriticalSectionData {
    /// Mutex for synchronization
    mutex: std::sync::Mutex<CriticalSectionInner>,
}

/// Inner state protected by the mutex
struct CriticalSectionInner {
    /// Current owner thread ID (0 if not owned)
    owner: u32,
    /// Recursion count (how many times the owner has entered)
    recursion: u32,
}

/// Initialize a critical section (InitializeCriticalSection)
///
/// This creates a new critical section object. The caller must provide
/// a pointer to a CRITICAL_SECTION structure (at least 40 bytes).
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` points to valid memory of at least 40 bytes
/// - The memory remains valid until `DeleteCriticalSection` is called
/// - The structure is not used concurrently during initialization
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSection(
    critical_section: *mut CriticalSection,
) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid
    let cs = unsafe { &mut *critical_section };

    // Create the internal data structure
    let data = Arc::new(CriticalSectionData {
        mutex: std::sync::Mutex::new(CriticalSectionInner {
            owner: 0,
            recursion: 0,
        }),
    });

    // Store the Arc as a raw pointer in the structure
    cs.internal = Arc::into_raw(data) as usize;
}

/// Enter a critical section (acquire the lock).
///
/// If the critical section is already owned by this thread, increments the recursion count.
/// If owned by another thread, waits until it becomes available.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized with `InitializeCriticalSection`
/// - The structure has not been deleted with `DeleteCriticalSection`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EnterCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex and check ownership
    {
        let mut inner = data.mutex.lock().unwrap();

        if inner.owner == current_thread {
            // Recursive lock - just increment the count
            inner.recursion += 1;
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
        } else {
            // Another thread owns it - this shouldn't happen with a mutex lock
            // But if it does, just wait and try again
            drop(inner);
            let mut inner2 = data.mutex.lock().unwrap();
            inner2.owner = current_thread;
            inner2.recursion = 1;
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Leave a critical section (release the lock).
///
/// Decrements the recursion count. If the count reaches zero, releases ownership.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - This thread currently owns the critical section
/// - Each `Leave` matches an `Enter`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LeaveCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex
    {
        let mut inner = data.mutex.lock().unwrap();

        // Decrement recursion count
        if inner.recursion > 0 {
            inner.recursion -= 1;
            if inner.recursion == 0 {
                // Release ownership
                inner.owner = 0;
            }
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Try to enter a critical section without blocking (TryEnterCriticalSection)
///
/// This attempts to acquire the critical section lock. If it's already held
/// by another thread, returns FALSE (0) immediately without blocking.
/// Returns TRUE (1) on success.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TryEnterCriticalSection(
    critical_section: *mut CriticalSection,
) -> u32 {
    if critical_section.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return 0; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Try to lock the mutex
    let result = if let Ok(mut inner) = data.mutex.try_lock() {
        if inner.owner == current_thread {
            // Recursive lock
            inner.recursion += 1;
            1
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
            1
        } else {
            // Another thread owns it
            0
        }
    } else {
        // Failed to acquire mutex
        0
    };

    // Don't drop the Arc
    core::mem::forget(data);

    result
}

/// Delete a critical section (DeleteCriticalSection)
///
/// This releases all resources associated with a critical section.
/// The caller must ensure no threads are waiting on or holding the lock.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - No threads are currently using the critical section
/// - The critical section will not be used after this call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &mut *critical_section };
    if cs.internal == 0 {
        return; // Not initialized or already deleted
    }

    // Reconstruct the Arc and let it drop to deallocate
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let _data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };
    // The Arc will drop here, deallocating the data if this was the last reference

    // Clear the internal pointer
    cs.internal = 0;
}

//
// Phase 8: Exception Handling Stubs
//
// These are minimal stub implementations to allow MinGW CRT to initialize.
// Real exception handling (SEH) would require significant additional work.
//

/// Windows exception handler function type
///
/// This is a stub implementation. Real SEH would require:
/// - Parsing .pdata and .xdata sections for unwind info
/// - Implementing exception dispatching
/// - Managing exception chains
/// - Supporting __try/__except/__finally
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers,
/// as it only returns a constant value and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32___C_specific_handler(
    _exception_record: *mut core::ffi::c_void,
    _establisher_frame: u64,
    _context_record: *mut core::ffi::c_void,
    _dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    // EXCEPTION_CONTINUE_SEARCH (1) - Tell the system to keep looking for handlers
    // For now, we don't handle any exceptions, just let them propagate
    1
}

/// Set unhandled exception filter
///
/// This is a stub that accepts the filter but doesn't actually use it.
/// Returns the previous filter (always NULL in this stub).
///
/// # Safety
/// This function is safe to call with any argument including NULL pointers.
/// It only returns a constant NULL value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetUnhandledExceptionFilter(
    _filter: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL (no previous filter)
    core::ptr::null_mut()
}

/// Raise an exception
///
/// This stub implementation aborts the process, which is a reasonable
/// fallback for unhandled exceptions.
///
/// # Safety
/// This function always aborts the process, so it never returns.
/// Safe to call with any arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RaiseException(
    exception_code: u32,
    _exception_flags: u32,
    _number_parameters: u32,
    _arguments: *const usize,
) -> ! {
    // For now, any raised exception causes an abort
    eprintln!("Windows exception raised (code: {exception_code:#x}) - aborting");
    std::process::abort()
}

/// Capture CPU context for exception handling
///
/// This stub zeros out the context structure. Real implementation would
/// capture all CPU registers (RAX, RBX, RCX, RDX, RSI, RDI, etc.)
///
/// # Safety
/// Caller must ensure `context` points to a valid writable memory region
/// of at least 1232 bytes (size of Windows CONTEXT structure for x64).
/// Passing NULL is safe (function checks and does nothing).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlCaptureContext(context: *mut core::ffi::c_void) {
    if !context.is_null() {
        // Zero out the context (size of Windows CONTEXT structure is ~1200 bytes for x64)
        // SAFETY: Caller ensures context points to valid CONTEXT structure
        unsafe {
            core::ptr::write_bytes(context.cast::<u8>(), 0, 1232);
        }
    }
}

/// Lookup function entry for exception handling
///
/// This stub returns NULL, indicating no unwind info found.
/// Real implementation would parse .pdata section.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It only returns NULL and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlLookupFunctionEntry(
    _control_pc: u64,
    _image_base: *mut u64,
    _history_table: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL - no function entry found
    core::ptr::null_mut()
}

/// Perform stack unwinding
///
/// This stub does nothing. Real implementation would unwind the stack
/// using information from .pdata and .xdata sections.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It does nothing and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlUnwindEx(
    _target_frame: *mut core::ffi::c_void,
    _target_ip: *mut core::ffi::c_void,
    _exception_record: *mut core::ffi::c_void,
    _return_value: *mut core::ffi::c_void,
    _context_record: *mut core::ffi::c_void,
    _history_table: *mut core::ffi::c_void,
) {
    // Stub: do nothing
}

/// Virtual unwind for exception handling
///
/// This stub returns a failure code. Real implementation would
/// simulate unwinding one stack frame.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It only returns NULL and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlVirtualUnwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *mut core::ffi::c_void,
    _context_record: *mut core::ffi::c_void,
    _handler_data: *mut *mut core::ffi::c_void,
    _establisher_frame: *mut u64,
    _context_pointers: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL - indicates failure/no handler
    core::ptr::null_mut()
}

/// Add vectored exception handler
///
/// This stub accepts the handler but doesn't register it.
/// Returns a non-NULL handle to indicate success.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It returns a fake non-NULL handle without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_AddVectoredExceptionHandler(
    _first: u32,
    _handler: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return a fake handle (non-NULL to indicate success)
    // Real implementation would register the handler
    0x1000 as *mut core::ffi::c_void
}

//
// Phase 8.3: String Operations
//
// Windows uses UTF-16 (wide characters) while Linux uses UTF-8.
// These functions handle conversion between the two encodings.
//

/// Convert multibyte string to wide-character string
///
/// This implements MultiByteToWideChar for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `multi_byte_str`: Source multibyte string
/// - `multi_byte_len`: Length of source string (-1 = null-terminated)
/// - `wide_char_str`: Destination buffer for wide chars (NULL = query size)
/// - `wide_char_len`: Size of destination buffer in characters
///
/// # Returns
/// Number of wide characters written (or required if `wide_char_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `multi_byte_str` points to valid memory
/// - If `multi_byte_len` != -1, at least `multi_byte_len` bytes are readable
/// - If `wide_char_str` is not NULL, at least `wide_char_len` u16s are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MultiByteToWideChar(
    code_page: u32,
    _flags: u32,
    multi_byte_str: *const u8,
    multi_byte_len: i32,
    wide_char_str: *mut u16,
    wide_char_len: i32,
) -> i32 {
    if multi_byte_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate multi_byte_len (must be -1 or >= 0)
    if multi_byte_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if multi_byte_len == -1 {
        // SAFETY: Caller guarantees multi_byte_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *multi_byte_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (multi_byte_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees multi_byte_str points to at least input_len bytes
    let input_bytes = unsafe { core::slice::from_raw_parts(multi_byte_str, input_len) };

    // Convert to UTF-8 string (assume input is UTF-8)
    let Ok(utf8_str) = core::str::from_utf8(input_bytes) else {
        return 0; // Invalid UTF-8
    };

    // Convert to UTF-16
    let utf16_chars: Vec<u16> = utf8_str.encode_utf16().collect();
    let required_len = if include_null {
        utf16_chars.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf16_chars.len() // No null terminator when length was explicit
    };

    // If wide_char_str is NULL, return required size
    if wide_char_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if wide_char_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees wide_char_str has space for wide_char_len u16s
    let output = unsafe { core::slice::from_raw_parts_mut(wide_char_str, wide_char_len as usize) };

    // Copy the UTF-16 characters
    output[..utf16_chars.len()].copy_from_slice(&utf16_chars);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf16_chars.len()] = 0;
    }

    required_len as i32
}

/// Convert wide-character string to multibyte string
///
/// This implements WideCharToMultiByte for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `wide_char_str`: Source wide-character string
/// - `wide_char_len`: Length of source string (-1 = null-terminated)
/// - `multi_byte_str`: Destination buffer for multibyte chars (NULL = query size)
/// - `multi_byte_len`: Size of destination buffer in bytes
/// - `default_char`: Default char for unmappable characters (NULL = use default)
/// - `used_default_char`: Pointer to flag set if default char was used (NULL = ignore)
///
/// # Returns
/// Number of bytes written (or required if `multi_byte_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `wide_char_str` points to valid memory
/// - If `wide_char_len` != -1, at least `wide_char_len` u16s are readable
/// - If `multi_byte_str` is not NULL, at least `multi_byte_len` bytes are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WideCharToMultiByte(
    code_page: u32,
    _flags: u32,
    wide_char_str: *const u16,
    wide_char_len: i32,
    multi_byte_str: *mut u8,
    multi_byte_len: i32,
    _default_char: *const u8,
    _used_default_char: *mut i32,
) -> i32 {
    if wide_char_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate wide_char_len (must be -1 or >= 0)
    if wide_char_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if wide_char_len == -1 {
        // SAFETY: Caller guarantees wide_char_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *wide_char_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (wide_char_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees wide_char_str points to at least input_len u16s
    let input_chars = unsafe { core::slice::from_raw_parts(wide_char_str, input_len) };

    // Convert from UTF-16 to String (UTF-8)
    let utf8_string = String::from_utf16_lossy(input_chars);
    let utf8_bytes = utf8_string.as_bytes();
    let required_len = if include_null {
        utf8_bytes.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf8_bytes.len() // No null terminator when length was explicit
    };

    // If multi_byte_str is NULL, return required size
    if multi_byte_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if multi_byte_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees multi_byte_str has space for multi_byte_len bytes
    let output =
        unsafe { core::slice::from_raw_parts_mut(multi_byte_str, multi_byte_len as usize) };

    // Copy the UTF-8 bytes
    output[..utf8_bytes.len()].copy_from_slice(utf8_bytes);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf8_bytes.len()] = 0;
    }

    required_len as i32
}

/// Get the length of a wide-character string
///
/// This implements lstrlenW, which returns the length of a null-terminated
/// wide-character string (excluding the null terminator).
///
/// # Safety
/// The caller must ensure `wide_str` points to a valid null-terminated wide string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrlenW(wide_str: *const u16) -> i32 {
    if wide_str.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees wide_str is a valid null-terminated string
    let mut len = 0;
    while unsafe { *wide_str.add(len) } != 0 {
        len += 1;
    }

    len as i32
}

/// Compare two Unicode strings using ordinal (binary) comparison
///
/// This implements CompareStringOrdinal, which performs a code-point by code-point
/// comparison of two Unicode strings.
///
/// # Arguments
/// - `string1`: First string to compare
/// - `count1`: Length of first string (-1 = null-terminated)
/// - `string2`: Second string to compare
/// - `count2`: Length of second string (-1 = null-terminated)
/// - `ignore_case`: TRUE to ignore case, FALSE for case-sensitive
///
/// # Returns
/// - CSTR_LESS_THAN (1): string1 < string2
/// - CSTR_EQUAL (2): string1 == string2
/// - CSTR_GREATER_THAN (3): string1 > string2
/// - 0: Error
///
/// # Safety
/// The caller must ensure both string pointers point to valid memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CompareStringOrdinal(
    string1: *const u16,
    count1: i32,
    string2: *const u16,
    count2: i32,
    ignore_case: i32,
) -> i32 {
    if string1.is_null() || string2.is_null() {
        return 0; // Error
    }

    // Validate count1 and count2 (must be -1 or >= 0)
    if count1 < -1 || count2 < -1 {
        return 0; // Invalid parameter
    }

    // Get length of first string
    let len1 = if count1 == -1 {
        // SAFETY: Caller guarantees string1 is null-terminated
        let mut len = 0;
        while unsafe { *string1.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count1 as usize
    };

    // Get length of second string
    let len2 = if count2 == -1 {
        // SAFETY: Caller guarantees string2 is null-terminated
        let mut len = 0;
        while unsafe { *string2.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count2 as usize
    };

    // SAFETY: Caller guarantees the pointers are valid
    let slice1 = unsafe { core::slice::from_raw_parts(string1, len1) };
    let slice2 = unsafe { core::slice::from_raw_parts(string2, len2) };

    // Perform ordinal (binary) comparison on UTF-16 code units
    // This matches Windows' ordinal semantics (code-unit by code-unit comparison)
    let min_len = core::cmp::min(len1, len2);
    let mut result = core::cmp::Ordering::Equal;

    for i in 0..min_len {
        let mut c1 = slice1[i];
        let mut c2 = slice2[i];

        if ignore_case != 0 {
            // ASCII case fold: 'A'..='Z' -> 'a'..='z'
            // This provides basic case-insensitive comparison for ASCII characters
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c1) {
                c1 += u16::from(b'a') - u16::from(b'A');
            }
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c2) {
                c2 += u16::from(b'a') - u16::from(b'A');
            }
        }

        if c1 < c2 {
            result = core::cmp::Ordering::Less;
            break;
        } else if c1 > c2 {
            result = core::cmp::Ordering::Greater;
            break;
        }
    }

    // If all compared code units are equal, shorter string is "less"
    if result == core::cmp::Ordering::Equal {
        result = len1.cmp(&len2);
    }

    // Convert to Windows constants
    match result {
        core::cmp::Ordering::Less => 1,    // CSTR_LESS_THAN
        core::cmp::Ordering::Equal => 2,   // CSTR_EQUAL
        core::cmp::Ordering::Greater => 3, // CSTR_GREATER_THAN
    }
}

//
// Phase 8.4: Performance Counters
//
// Windows programs often use high-resolution performance counters for timing.
// On Linux, we implement these using clock_gettime(CLOCK_MONOTONIC).
//

/// Windows FILETIME structure (64-bit value representing 100-nanosecond intervals since 1601-01-01)
#[repr(C)]
pub struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

/// Query the performance counter
///
/// This implements QueryPerformanceCounter which returns a high-resolution timestamp.
/// On Linux, we use clock_gettime(CLOCK_MONOTONIC) which provides nanosecond precision.
///
/// # Safety
/// The caller must ensure `counter` points to a valid u64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceCounter(counter: *mut i64) -> i32 {
    if counter.is_null() {
        return 0; // FALSE - error
    }

    // SAFETY: Use libc to get monotonic time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        return 0; // FALSE - error
    }

    // Convert to a counter value (nanoseconds)
    let nanoseconds = ts
        .tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec);

    // SAFETY: Caller guarantees counter is valid
    unsafe {
        *counter = nanoseconds;
    }

    1 // TRUE - success
}

/// Query the performance counter frequency
///
/// This implements QueryPerformanceFrequency which returns the frequency of the
/// performance counter in counts per second. Since we use nanoseconds, the frequency
/// is 1,000,000,000 (1 billion counts per second).
///
/// # Safety
/// The caller must ensure `frequency` points to a valid i64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceFrequency(frequency: *mut i64) -> i32 {
    if frequency.is_null() {
        return 0; // FALSE - error
    }

    // Our counter is in nanoseconds, so frequency is 1 billion counts/second
    // SAFETY: Caller guarantees frequency is valid
    unsafe {
        *frequency = 1_000_000_000;
    }

    1 // TRUE - success
}

/// Get system time as FILETIME with high precision
///
/// This implements GetSystemTimePreciseAsFileTime which returns the current system time
/// in FILETIME format (100-nanosecond intervals since January 1, 1601 UTC).
///
/// # Safety
/// The caller must ensure `filetime` points to a valid FILETIME structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemTimePreciseAsFileTime(filetime: *mut FileTime) {
    if filetime.is_null() {
        return;
    }

    // SAFETY: Use libc to get real time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        // On error, return epoch
        unsafe {
            (*filetime).low_date_time = 0;
            (*filetime).high_date_time = 0;
        }
        return;
    }

    // Convert Unix timestamp (seconds since 1970-01-01) to Windows FILETIME
    // (100-nanosecond intervals since 1601-01-01)
    //
    // The difference between 1601-01-01 and 1970-01-01 is 11644473600 seconds

    // Convert to 100-nanosecond intervals
    let seconds_since_1601 = ts.tv_sec + EPOCH_DIFF;
    let intervals = seconds_since_1601
        .saturating_mul(10_000_000) // seconds to 100-nanosecond intervals
        .saturating_add(ts.tv_nsec / 100); // add nanoseconds converted to 100-ns intervals

    // Split into low and high parts
    // SAFETY: Caller guarantees filetime is valid
    unsafe {
        (*filetime).low_date_time = (intervals & 0xFFFF_FFFF) as u32;
        (*filetime).high_date_time = ((intervals >> 32) & 0xFFFF_FFFF) as u32;
    }
}

//
// Phase 8.5: File I/O Trampolines
//
// These are KERNEL32 wrappers around file operations.
// They provide a Windows-compatible API but use simple stub implementations
// since full file I/O is handled through NTDLL APIs.
//

/// Create or open a file (CreateFileW)
///
/// This is a minimal stub that always fails. Real file operations
/// are handled through NtCreateFile in the NTDLL layer.
///
/// # Safety
/// This function is safe to call with any arguments.
/// It always returns INVALID_HANDLE_VALUE without dereferencing pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileW(
    _file_name: *const u16,
    _desired_access: u32,
    _share_mode: u32,
    _security_attributes: *mut core::ffi::c_void,
    _creation_disposition: u32,
    _flags_and_attributes: u32,
    _template_file: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return INVALID_HANDLE_VALUE (-1 cast to pointer)
    // Real file operations go through NtCreateFile
    usize::MAX as *mut core::ffi::c_void
}

/// Read from a file (ReadFile)
///
/// This is a minimal stub that always fails. Real file operations
/// are handled through NtReadFile in the NTDLL layer.
///
/// # Safety
/// This function is safe to call with any arguments.
/// It always returns FALSE without dereferencing pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFile(
    _file: *mut core::ffi::c_void,
    _buffer: *mut u8,
    _number_of_bytes_to_read: u32,
    _number_of_bytes_read: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    // Return FALSE (0) - operation failed
    // Real file operations go through NtReadFile
    0
}

/// Write to a file (WriteFile)
///
/// This implements basic file write functionality, with special handling
/// for stdout and stderr handles.
///
/// # Safety
/// This function is unsafe as it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFile(
    file: *mut core::ffi::c_void,
    buffer: *const u8,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    // STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    let stdout_handle = kernel32_GetStdHandle((-11i32) as u32);
    let stderr_handle = kernel32_GetStdHandle((-12i32) as u32);

    // Check if this is stdout or stderr
    let is_stdout = file == stdout_handle;
    let is_stderr = file == stderr_handle;

    if !is_stdout && !is_stderr {
        // ERROR_INVALID_HANDLE = 6
        kernel32_SetLastError(6);
        return 0; // Not stdout/stderr, fail
    }

    if buffer.is_null() || number_of_bytes_to_write == 0 {
        // SAFETY: number_of_bytes_written is an optional out-parameter from the caller.
        // It may be null; if non-null, it must be valid for writing a single u32 value.
        if !number_of_bytes_written.is_null() {
            unsafe {
                *number_of_bytes_written = 0;
            }
        }
        // ERROR_INVALID_PARAMETER = 87
        kernel32_SetLastError(87);
        return 0;
    }

    // SAFETY: Caller guarantees buffer is valid for number_of_bytes_to_write bytes
    let data = unsafe { std::slice::from_raw_parts(buffer, number_of_bytes_to_write as usize) };

    // Write to stdout or stderr
    let result = if is_stdout {
        std::io::Write::write(&mut std::io::stdout(), data)
    } else {
        std::io::Write::write(&mut std::io::stderr(), data)
    };

    match result {
        Ok(written) => {
            if !number_of_bytes_written.is_null() {
                // SAFETY: Caller guarantees number_of_bytes_written is valid
                unsafe { *number_of_bytes_written = written as u32 };
            }
            // Flush to ensure output appears
            if is_stdout {
                let _ = std::io::Write::flush(&mut std::io::stdout());
            } else {
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
            1 // TRUE - success
        }
        Err(_e) => {
            // ERROR_WRITE_FAULT = 29
            kernel32_SetLastError(29);
            0 // FALSE - failure
        }
    }
}

/// Close a handle (CloseHandle)
///
/// This is a minimal stub that always succeeds. Real handle cleanup
/// is handled through NtClose in the NTDLL layer.
///
/// # Safety
/// This function is safe to call with any arguments.
/// It always returns TRUE without dereferencing pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CloseHandle(_handle: *mut core::ffi::c_void) -> i32 {
    // Return TRUE (1) - operation succeeded
    // Real handle cleanup goes through NtClose
    1
}

//
// Phase 8.6: Heap Management Trampolines
//
// Windows programs often use HeapAlloc/HeapFree for dynamic memory.
// These are wrappers around the standard malloc/free functions.
//

/// Get the default process heap handle
///
/// In Windows, processes have a default heap. We return a fake
/// non-NULL handle since programs check for NULL.
///
/// # Safety
/// This function is safe to call. It returns a constant non-NULL value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessHeap() -> *mut core::ffi::c_void {
    // Return a fake heap handle (non-NULL)
    // Real heap operations use malloc/free directly
    0x1000 as *mut core::ffi::c_void
}

/// Allocate memory from a heap
///
/// This wraps malloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored, we use the global allocator)
/// - `flags`: Allocation flags (HEAP_ZERO_MEMORY = 0x00000008)
/// - `size`: Number of bytes to allocate
///
/// # Returns
/// Pointer to allocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The returned pointer must be freed with HeapFree.
/// The caller must ensure the size is reasonable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapAlloc(
    _heap: *mut core::ffi::c_void,
    flags: u32,
    size: usize,
) -> *mut core::ffi::c_void {
    // Windows HeapAlloc can return a non-NULL pointer for 0-byte allocation
    // Allocate a minimal block (1 byte) to match Windows semantics
    let alloc_size = if size == 0 { 1 } else { size };

    // Allocate using the global allocator
    let Ok(layout) =
        core::alloc::Layout::from_size_align(alloc_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    // SAFETY: Layout is valid, size is non-zero
    let ptr = unsafe { alloc::alloc(layout) };

    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Zero memory if requested
    if flags & HEAP_ZERO_MEMORY != 0 {
        // SAFETY: ptr is valid and has alloc_size bytes allocated
        unsafe {
            core::ptr::write_bytes(ptr, 0, alloc_size);
        }
    }

    // Track this allocation for later deallocation
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if let Some(ref mut t) = *tracker {
        t.track_allocation(ptr, alloc_size, layout.align());
    }

    ptr.cast()
}

/// Free memory allocated from a heap
///
/// This wraps dealloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Free flags (ignored)
/// - `mem`: Pointer to memory to free
///
/// # Returns
/// TRUE (1) on success, FALSE (0) on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - `mem` is not freed twice
/// - `mem` is not used after being freed
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapFree(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *mut core::ffi::c_void,
) -> i32 {
    if mem.is_null() {
        return 1; // TRUE - freeing NULL is a no-op
    }

    // Retrieve and remove the allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        // If tracker doesn't exist, we can't free safely
        return 0; // FALSE - failure
    };

    let Some((size, align)) = t.remove_allocation(mem) else {
        // Allocation not found - this is either a double-free or
        // memory not allocated with HeapAlloc
        return 0; // FALSE - failure
    };

    // Create the layout and deallocate
    // SAFETY: We're recreating the same layout that was used for allocation
    let Ok(layout) = core::alloc::Layout::from_size_align(size, align) else {
        return 0; // FALSE - invalid layout (shouldn't happen)
    };

    // SAFETY: ptr was allocated with alloc::alloc using this layout
    unsafe {
        alloc::dealloc(mem.cast(), layout);
    }

    1 // TRUE - success
}

/// Reallocate memory in a heap
///
/// This wraps realloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Realloc flags (HEAP_ZERO_MEMORY supported)
/// - `mem`: Pointer to memory to reallocate (or NULL to allocate new)
/// - `size`: New size in bytes
///
/// # Returns
/// Pointer to reallocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - The old pointer is not used after reallocation
/// - The returned pointer must be freed with HeapFree
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapReAlloc(
    heap: *mut core::ffi::c_void,
    flags: u32,
    mem: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    if mem.is_null() {
        // Allocate new memory
        return unsafe { kernel32_HeapAlloc(heap, flags, size) };
    }

    if size == 0 {
        // Free the memory
        unsafe { kernel32_HeapFree(heap, flags, mem) };
        return core::ptr::null_mut();
    }

    // Get the current allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        return core::ptr::null_mut(); // Tracker not initialized
    };

    let Some((old_size, old_align)) = t.get_allocation(mem) else {
        // Memory not tracked - can't reallocate safely
        return core::ptr::null_mut();
    };

    // Prepare new allocation
    let new_size = if size == 0 { 1 } else { size };
    let Ok(new_layout) =
        core::alloc::Layout::from_size_align(new_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    let Ok(old_layout) = core::alloc::Layout::from_size_align(old_size, old_align) else {
        return core::ptr::null_mut();
    };

    // Remove the old allocation entry BEFORE realloc, since realloc may move the memory
    t.remove_allocation(mem);

    // SAFETY: mem was allocated with the old_layout
    let new_ptr = unsafe { alloc::realloc(mem.cast(), old_layout, new_size) };

    if new_ptr.is_null() {
        // Realloc failed - the original allocation is still valid
        // Re-insert the original allocation back into the tracker
        t.track_allocation(mem.cast(), old_size, old_align);
        return core::ptr::null_mut();
    }

    // If growing the allocation and HEAP_ZERO_MEMORY is set, zero the new bytes
    if new_size > old_size && (flags & HEAP_ZERO_MEMORY != 0) {
        // SAFETY: new_ptr is valid for new_size bytes, and we're only writing
        // to the newly allocated portion
        unsafe {
            core::ptr::write_bytes(new_ptr.add(old_size), 0, new_size - old_size);
        }
    }

    // Track the new allocation (whether it moved or stayed in place)
    t.track_allocation(new_ptr, new_size, new_layout.align());

    new_ptr.cast()
}

/// STARTUPINFOA structure - contains information about window station, desktop, standard handles, etc.
/// This is a simplified version that matches the Windows API layout.
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoA {
    cb: u32,
    lpReserved: *mut u8,
    lpDesktop: *mut u8,
    lpTitle: *mut u8,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// STARTUPINFOW structure - wide-character version
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// GetStartupInfoA - retrieves the STARTUPINFO structure for the current process
///
/// This is a minimal implementation that sets the structure to default values.
/// In a real Windows environment, this would contain information passed to CreateProcess.
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOA structure
/// - The pointer is properly aligned for a STARTUPINFOA structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoA(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoA structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoA>()) };

    // Initialize the structure with default values
    // In a real implementation, these would come from the process's startup information
    info.cb = core::mem::size_of::<StartupInfoA>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0; // Could be mapped to actual stdin fd
    info.hStdOutput = 1; // Could be mapped to actual stdout fd
    info.hStdError = 2; // Could be mapped to actual stderr fd
}

/// GetStartupInfoW - retrieves the STARTUPINFOW structure for the current process (wide-char version)
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOW structure
/// - The pointer is properly aligned for a STARTUPINFOW structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoW(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoW structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoW>()) };

    // Initialize the structure with default values
    info.cb = core::mem::size_of::<StartupInfoW>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0;
    info.hStdOutput = 1;
    info.hStdError = 2;
}

//
// Stub implementations for missing APIs
//
// These are minimal implementations that return failure or no-op.
// They allow programs to link and run, but don't provide full functionality.
//

/// CancelIo stub - cancels pending I/O operations
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CancelIo(_file: *mut core::ffi::c_void) -> i32 {
    0 // FALSE - not implemented
}

/// CopyFileExW stub - copies a file
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CopyFileExW(
    _existing_file_name: *const u16,
    _new_file_name: *const u16,
    _progress_routine: *mut core::ffi::c_void,
    _data: *mut core::ffi::c_void,
    _cancel: *mut i32,
    _copy_flags: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateDirectoryW stub - creates a directory
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateDirectoryW(
    _path_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateEventW stub - creates an event object
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateEventW(
    _security_attributes: *mut core::ffi::c_void,
    _manual_reset: i32,
    _initial_state: i32,
    _name: *const u16,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// CreateFileMappingA stub - creates a file mapping object
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileMappingA(
    _file: *mut core::ffi::c_void,
    _security_attributes: *mut core::ffi::c_void,
    _protect: u32,
    _maximum_size_high: u32,
    _maximum_size_low: u32,
    _name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// CreateHardLinkW stub - creates a hard link
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateHardLinkW(
    _file_name: *const u16,
    _existing_file_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreatePipe stub - creates a pipe
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreatePipe(
    _read_pipe: *mut *mut core::ffi::c_void,
    _write_pipe: *mut *mut core::ffi::c_void,
    _pipe_attributes: *mut core::ffi::c_void,
    _size: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateProcessW stub - creates a new process
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateProcessW(
    _application_name: *const u16,
    _command_line: *mut u16,
    _process_attributes: *mut core::ffi::c_void,
    _thread_attributes: *mut core::ffi::c_void,
    _inherit_handles: i32,
    _creation_flags: u32,
    _environment: *mut core::ffi::c_void,
    _current_directory: *const u16,
    _startup_info: *mut core::ffi::c_void,
    _process_information: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateSymbolicLinkW stub - creates a symbolic link
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateSymbolicLinkW(
    _symlink_file_name: *const u16,
    _target_file_name: *const u16,
    _flags: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateThread stub - creates a thread
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateThread(
    _thread_attributes: *mut core::ffi::c_void,
    _stack_size: usize,
    _start_address: *mut core::ffi::c_void,
    _parameter: *mut core::ffi::c_void,
    _creation_flags: u32,
    _thread_id: *mut u32,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// CreateToolhelp32Snapshot stub - creates a snapshot of processes/threads/etc
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateToolhelp32Snapshot(
    _flags: u32,
    _process_id: u32,
) -> *mut core::ffi::c_void {
    usize::MAX as *mut core::ffi::c_void // INVALID_HANDLE_VALUE
}

/// CreateWaitableTimerExW stub - creates a waitable timer
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateWaitableTimerExW(
    _timer_attributes: *mut core::ffi::c_void,
    _timer_name: *const u16,
    _flags: u32,
    _desired_access: u32,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// DeleteFileW stub - deletes a file
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteFileW(_file_name: *const u16) -> i32 {
    0 // FALSE - not implemented
}

/// DeleteProcThreadAttributeList stub - deletes a process thread attribute list
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteProcThreadAttributeList(
    _attribute_list: *mut core::ffi::c_void,
) {
    // No-op stub
}

/// DeviceIoControl stub - sends a control code to a device driver
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeviceIoControl(
    _device: *mut core::ffi::c_void,
    _io_control_code: u32,
    _in_buffer: *mut core::ffi::c_void,
    _in_buffer_size: u32,
    _out_buffer: *mut core::ffi::c_void,
    _out_buffer_size: u32,
    _bytes_returned: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// DuplicateHandle stub - duplicates a handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DuplicateHandle(
    _source_process_handle: *mut core::ffi::c_void,
    _source_handle: *mut core::ffi::c_void,
    _target_process_handle: *mut core::ffi::c_void,
    _target_handle: *mut *mut core::ffi::c_void,
    _desired_access: u32,
    _inherit_handle: i32,
    _options: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// FlushFileBuffers stub - flushes file buffers
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlushFileBuffers(_file: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - pretend success
}

/// FormatMessageW stub - formats a message string
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FormatMessageW(
    _flags: u32,
    _source: *const core::ffi::c_void,
    _message_id: u32,
    _language_id: u32,
    _buffer: *mut u16,
    _size: u32,
    _arguments: *mut *mut core::ffi::c_void,
) -> u32 {
    0 // 0 - error/not implemented
}

/// GetCurrentDirectoryW - gets the current working directory
///
/// Returns the length of the path copied to the buffer (not including null terminator).
/// If the buffer is too small, returns the required buffer size (including null terminator).
///
/// # Safety
/// Caller must ensure buffer is valid and buffer_length is accurate if buffer is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentDirectoryW(
    buffer_length: u32,
    buffer: *mut u16,
) -> u32 {
    // Get current directory from std::env
    let Ok(current_dir) = std::env::current_dir() else {
        // Set last error to ERROR_ACCESS_DENIED (5)
        kernel32_SetLastError(5);
        return 0;
    };

    // Convert to string
    let dir_str = current_dir.to_string_lossy();

    // Convert Windows-style if needed (for consistency with Windows behavior)
    // But since we're on Linux, keep it as-is

    // Convert to UTF-16
    let mut utf16: Vec<u16> = dir_str.encode_utf16().collect();
    utf16.push(0); // Null terminator

    // Check if buffer is large enough
    if buffer.is_null() || buffer_length < utf16.len() as u32 {
        // Return required buffer size (including null terminator)
        return utf16.len() as u32;
    }

    // Copy to buffer
    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    // Return length without null terminator
    (utf16.len() - 1) as u32
}

/// GetExitCodeProcess stub - gets the exit code of a process
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetExitCodeProcess(
    _process: *mut core::ffi::c_void,
    _exit_code: *mut u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// GetFileAttributesW stub - gets file attributes
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileAttributesW(_file_name: *const u16) -> u32 {
    0xFFFF_FFFF // INVALID_FILE_ATTRIBUTES
}

/// GetFileInformationByHandle stub - gets file information by handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandle(
    _file: *mut core::ffi::c_void,
    _file_information: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// GetFileType stub - gets the type of a file
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileType(_file: *mut core::ffi::c_void) -> u32 {
    0 // FILE_TYPE_UNKNOWN
}

/// GetFullPathNameW stub - gets the full path name of a file
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFullPathNameW(
    _file_name: *const u16,
    _buffer_length: u32,
    _buffer: *mut u16,
    _file_part: *mut *mut u16,
) -> u32 {
    0 // 0 - error
}

// Thread-local storage for last error codes
//
// Each thread maintains its own error code without global synchronization.
// This eliminates the unbounded memory growth issue from the previous
// implementation and improves performance by removing mutex contention.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// GetLastError - gets the last error code for the current thread
///
/// In Windows, this is thread-local and set by many APIs.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLastError() -> u32 {
    LAST_ERROR.with(Cell::get)
}

/// GetModuleHandleW stub - gets a module handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleW(
    _module_name: *const u16,
) -> *mut core::ffi::c_void {
    // Return a fake non-null handle for the main module (NULL parameter)
    0x400000 as *mut core::ffi::c_void
}

/// GetProcAddress stub - gets a procedure address
///
/// Note: This is already handled by the DLL manager, but we provide
/// a stub in case it's called directly.
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcAddress(
    _module: *mut core::ffi::c_void,
    _proc_name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// GetStdHandle stub - gets a standard device handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStdHandle(std_handle: u32) -> *mut core::ffi::c_void {
    // STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    // Return non-null handles
    #[allow(clippy::cast_possible_wrap)]
    match std_handle as i32 {
        -10 => 0x10 as *mut core::ffi::c_void, // stdin
        -11 => 0x11 as *mut core::ffi::c_void, // stdout
        -12 => 0x12 as *mut core::ffi::c_void, // stderr
        _ => core::ptr::null_mut(),
    }
}

/// GetCommandLineW - returns the command line for the current process (wide version)
///
/// Returns a pointer to a static wide string containing the command line.
/// For simplicity, we return an empty string.
///
/// # Safety
/// This function is safe to call. It returns a pointer to a static buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCommandLineW() -> *const u16 {
    // Static empty wide string (just null terminator)
    static COMMAND_LINE: [u16; 1] = [0];
    // SAFETY: We're returning a pointer to a static immutable buffer
    COMMAND_LINE.as_ptr()
}

/// GetEnvironmentStringsW - returns the environment strings (wide version)
///
/// Returns a pointer to a block of null-terminated wide strings, ending with
/// an additional null terminator. For simplicity, we return an empty block.
///
/// # Safety
/// This function is safe to call. It returns a pointer to a static buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentStringsW() -> *const u16 {
    // Static empty environment block (two null terminators)
    static ENV_STRINGS: [u16; 2] = [0, 0];
    // SAFETY: We're returning a pointer to a static immutable buffer
    ENV_STRINGS.as_ptr()
}

/// FreeEnvironmentStringsW - frees the environment strings (wide version)
///
/// This is a no-op since we return a static buffer.
///
/// # Safety
/// This function is safe to call with any argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeEnvironmentStringsW(_env_strings: *const u16) -> i32 {
    1 // TRUE - success
}

/// LoadLibraryA stub - loads a library (ANSI version)
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryA(
    _lib_file_name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// LoadLibraryW stub - loads a library (wide version)
///
/// Note: This is already handled by the DLL manager, but we provide
/// a stub in case it's called directly.
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryW(
    _lib_file_name: *const u16,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// SetConsoleCtrlHandler stub - sets a console control handler
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleCtrlHandler(
    _handler_routine: *mut core::ffi::c_void,
    _add: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SetFilePointerEx stub - sets the file pointer
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFilePointerEx(
    _file: *mut core::ffi::c_void,
    _distance_to_move: i64,
    _new_file_pointer: *mut i64,
    _move_method: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// SetLastError - sets the last error code for the current thread
///
/// In Windows, this is thread-local storage used by many APIs to report errors.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetLastError(error_code: u32) {
    LAST_ERROR.with(|error| error.set(error_code));
}

/// WaitForSingleObject stub - waits for an object
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForSingleObject(
    _handle: *mut core::ffi::c_void,
    _milliseconds: u32,
) -> u32 {
    0 // WAIT_OBJECT_0 - pretend object is signaled
}

/// WriteConsoleW stub - writes to the console (wide version)
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteConsoleW(
    _console_output: *mut core::ffi::c_void,
    buffer: *const u16,
    number_of_chars_to_write: u32,
    number_of_chars_written: *mut u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // Try to write to stdout
    if !buffer.is_null() && number_of_chars_to_write > 0 {
        let slice = core::slice::from_raw_parts(buffer, number_of_chars_to_write as usize);
        if let Ok(s) = String::from_utf16(slice) {
            print!("{s}");
            let _ = std::io::stdout().flush();
            if !number_of_chars_written.is_null() {
                *number_of_chars_written = number_of_chars_to_write;
            }
            return 1; // TRUE
        }
    }
    0 // FALSE
}

// Additional stubs for remaining missing APIs

/// GetFileInformationByHandleEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandleEx(
    _file: *mut core::ffi::c_void,
    _file_information_class: u32,
    _file_information: *mut core::ffi::c_void,
    _buffer_size: u32,
) -> i32 {
    0 // FALSE
}

/// GetFileSizeEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileSizeEx(
    _file: *mut core::ffi::c_void,
    _file_size: *mut i64,
) -> i32 {
    0 // FALSE
}

/// GetFinalPathNameByHandleW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFinalPathNameByHandleW(
    _file: *mut core::ffi::c_void,
    _file_path: *mut u16,
    _file_path_size: u32,
    _flags: u32,
) -> u32 {
    0 // 0 = error
}

/// GetOverlappedResult stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOverlappedResult(
    _file: *mut core::ffi::c_void,
    _overlapped: *mut core::ffi::c_void,
    _number_of_bytes_transferred: *mut u32,
    _wait: i32,
) -> i32 {
    0 // FALSE
}

/// GetProcessId stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessId(_process: *mut core::ffi::c_void) -> u32 {
    1 // Return a fake process ID
}

/// GetSystemDirectoryW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemDirectoryW(_buffer: *mut u16, _size: u32) -> u32 {
    0 // 0 = error
}

/// GetTempPathW stub - gets the temporary directory path
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32 {
    if buffer.is_null() || buffer_length == 0 {
        return 0;
    }

    // Return "/tmp/" as the temp path
    let temp_path = [
        u16::from(b'/'),
        u16::from(b't'),
        u16::from(b'm'),
        u16::from(b'p'),
        u16::from(b'/'),
        0u16,
    ];

    if buffer_length < temp_path.len() as u32 {
        return temp_path.len() as u32; // Required buffer size
    }

    // Copy the temp path
    for (i, &ch) in temp_path.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    (temp_path.len() - 1) as u32 // Length without null terminator
}

/// GetWindowsDirectoryW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetWindowsDirectoryW(_buffer: *mut u16, _size: u32) -> u32 {
    0 // 0 = error
}

/// InitOnceBeginInitialize stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceBeginInitialize(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    pending: *mut i32,
    _context: *mut *mut core::ffi::c_void,
) -> i32 {
    // Set pending to FALSE, indicating initialization is complete
    if !pending.is_null() {
        *pending = 0;
    }
    1 // TRUE
}

/// InitOnceComplete stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceComplete(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    _context: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// InitializeProcThreadAttributeList stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeProcThreadAttributeList(
    _attribute_list: *mut core::ffi::c_void,
    _attribute_count: u32,
    _flags: u32,
    _size: *mut usize,
) -> i32 {
    0 // FALSE
}

/// LockFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LockFileEx(
    _file: *mut core::ffi::c_void,
    _flags: u32,
    _reserved: u32,
    _number_of_bytes_to_lock_low: u32,
    _number_of_bytes_to_lock_high: u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE - pretend success
}

/// MapViewOfFile stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MapViewOfFile(
    _file_mapping_object: *mut core::ffi::c_void,
    _desired_access: u32,
    _file_offset_high: u32,
    _file_offset_low: u32,
    _number_of_bytes_to_map: usize,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL
}

/// Module32FirstW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32FirstW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// Module32NextW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32NextW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// MoveFileExW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MoveFileExW(
    _existing_file_name: *const u16,
    _new_file_name: *const u16,
    _flags: u32,
) -> i32 {
    0 // FALSE
}

/// ReadFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFileEx(
    _file: *mut core::ffi::c_void,
    _buffer: *mut u8,
    _number_of_bytes_to_read: u32,
    _overlapped: *mut core::ffi::c_void,
    _completion_routine: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// RemoveDirectoryW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RemoveDirectoryW(_path_name: *const u16) -> i32 {
    0 // FALSE
}

/// SetCurrentDirectoryW - sets the current working directory
///
/// Returns 1 (TRUE) on success, 0 (FALSE) on failure.
///
/// # Safety
/// Caller must ensure path_name points to a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetCurrentDirectoryW(path_name: *const u16) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // Read UTF-16 string until null terminator
    let mut len = 0;
    while *path_name.add(len) != 0 {
        len += 1;
        // Safety check: prevent infinite loop
        if len > 32768 {
            // MAX_PATH is 260, but we allow more
            kernel32_SetLastError(206); // ERROR_FILENAME_EXCEED_RANGE
            return 0;
        }
    }

    // Convert to Rust string
    let slice = core::slice::from_raw_parts(path_name, len);
    let path_str = String::from_utf16_lossy(slice);

    // Try to set the current directory
    if std::env::set_current_dir(std::path::Path::new(path_str.as_str())).is_ok() {
        1 // TRUE - success
    } else {
        // Set last error to ERROR_FILE_NOT_FOUND (2)
        kernel32_SetLastError(2);
        0 // FALSE - failure
    }
}

/// SetFileAttributesW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileAttributesW(
    _file_name: *const u16,
    _file_attributes: u32,
) -> i32 {
    0 // FALSE
}

/// SetFileInformationByHandle stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileInformationByHandle(
    _file: *mut core::ffi::c_void,
    _file_information_class: u32,
    _file_information: *mut core::ffi::c_void,
    _buffer_size: u32,
) -> i32 {
    0 // FALSE
}

/// SetFileTime stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileTime(
    _file: *mut core::ffi::c_void,
    _creation_time: *const core::ffi::c_void,
    _last_access_time: *const core::ffi::c_void,
    _last_write_time: *const core::ffi::c_void,
) -> i32 {
    1 // TRUE - pretend success
}

/// SetHandleInformation stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetHandleInformation(
    _object: *mut core::ffi::c_void,
    _mask: u32,
    _flags: u32,
) -> i32 {
    1 // TRUE - pretend success
}

/// UnlockFile stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnlockFile(
    _file: *mut core::ffi::c_void,
    _offset_low: u32,
    _offset_high: u32,
    _number_of_bytes_to_unlock_low: u32,
    _number_of_bytes_to_unlock_high: u32,
) -> i32 {
    1 // TRUE - pretend success
}

/// UnmapViewOfFile stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnmapViewOfFile(_base_address: *const core::ffi::c_void) -> i32 {
    1 // TRUE - pretend success
}

/// UpdateProcThreadAttribute stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UpdateProcThreadAttribute(
    _attribute_list: *mut core::ffi::c_void,
    _flags: u32,
    _attribute: usize,
    _value: *mut core::ffi::c_void,
    _size: usize,
    _previous_value: *mut core::ffi::c_void,
    _return_size: *mut usize,
) -> i32 {
    0 // FALSE
}

/// WriteFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFileEx(
    _file: *mut core::ffi::c_void,
    _buffer: *const u8,
    _number_of_bytes_to_write: u32,
    _overlapped: *mut core::ffi::c_void,
    _completion_routine: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// SetThreadStackGuarantee stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetThreadStackGuarantee(_stack_size_in_bytes: *mut u32) -> i32 {
    1 // TRUE - pretend success
}

/// SetWaitableTimer stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetWaitableTimer(
    _timer: *mut core::ffi::c_void,
    _due_time: *const i64,
    _period: i32,
    _completion_routine: *mut core::ffi::c_void,
    _arg_to_completion_routine: *mut core::ffi::c_void,
    _resume: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SleepEx stub - sleep with alertable wait
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SleepEx(milliseconds: u32, _alertable: i32) -> u32 {
    if milliseconds > 0 {
        thread::sleep(Duration::from_millis(u64::from(milliseconds)));
    }
    0 // Return 0 (not alertable)
}

/// SwitchToThread stub - yields execution to another thread
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SwitchToThread() -> i32 {
    thread::yield_now();
    1 // TRUE
}

/// TerminateProcess stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TerminateProcess(
    _process: *mut core::ffi::c_void,
    _exit_code: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// WaitForMultipleObjects stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForMultipleObjects(
    _count: u32,
    _handles: *const *mut core::ffi::c_void,
    _wait_all: i32,
    _milliseconds: u32,
) -> u32 {
    0 // WAIT_OBJECT_0 - pretend first object is signaled
}

/// ExitProcess - terminates the calling process and all its threads
///
/// # Safety
/// This function terminates the process immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ExitProcess(exit_code: u32) {
    std::process::exit(exit_code as i32);
}

/// GetCurrentProcess - returns a pseudo-handle for the current process
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcess() -> *mut core::ffi::c_void {
    // Windows returns -1 (0xFFFFFFFFFFFFFFFF) as the pseudo-handle for the current process
    -1_i64 as usize as *mut core::ffi::c_void
}

/// GetCurrentThread - returns a pseudo-handle for the current thread
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThread() -> *mut core::ffi::c_void {
    // Windows returns -2 (0xFFFFFFFFFFFFFFFE) as the pseudo-handle for the current thread
    -2_i64 as usize as *mut core::ffi::c_void
}

/// GetModuleHandleA - returns the module handle for a named module (ANSI version)
///
/// # Safety
/// This function is a stub that returns a default base address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleA(
    _module_name: *const u8,
) -> *mut core::ffi::c_void {
    // Return default image base address
    0x400000_usize as *mut core::ffi::c_void
}

/// GetModuleFileNameW - retrieves the fully qualified path for the file that contains a module
///
/// # Safety
/// Caller must ensure `filename` points to a valid buffer of at least `size` u16 elements
/// when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleFileNameW(
    _module: *mut core::ffi::c_void,
    _filename: *mut u16,
    _size: u32,
) -> u32 {
    0 // Failure - not implemented
}

/// Windows SYSTEM_INFO structure (x86_64 layout).
///
/// Matches the Windows API `SYSTEM_INFO` struct at
/// <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info>.
/// Field names follow Windows naming conventions. Pointer-sized fields use `u64`
/// to match the fixed x86_64 Windows ABI layout (always 8 bytes).
#[repr(C)]
struct SystemInfo {
    w_processor_architecture: u16,
    w_reserved: u16,
    dw_page_size: u32,
    lp_minimum_application_address: u64,
    lp_maximum_application_address: u64,
    dw_active_processor_mask: u64,
    dw_number_of_processors: u32,
    dw_processor_type: u32,
    dw_allocation_granularity: u32,
    w_processor_level: u16,
    w_processor_revision: u16,
}

/// GetSystemInfo - retrieves information about the current system
///
/// # Safety
/// Caller must ensure `system_info` points to a valid buffer of at least
/// `core::mem::size_of::<SystemInfo>()` bytes when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemInfo(system_info: *mut u8) {
    if system_info.is_null() {
        return;
    }
    let info = SystemInfo {
        w_processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
        w_reserved: 0,
        dw_page_size: 4096,
        lp_minimum_application_address: 0x10000,
        lp_maximum_application_address: 0x7FFF_FFFE_FFFF,
        dw_active_processor_mask: 1,
        dw_number_of_processors: 1,
        dw_processor_type: 8664, // PROCESSOR_AMD_X8664
        dw_allocation_granularity: 65536,
        w_processor_level: 6,
        w_processor_revision: 0,
    };
    // SAFETY: Caller guarantees system_info points to a valid buffer of sufficient size.
    core::ptr::copy_nonoverlapping(
        (&raw const info).cast::<u8>(),
        system_info,
        core::mem::size_of::<SystemInfo>(),
    );
}

/// GetConsoleMode - retrieves the current input mode of a console's input buffer
///
/// # Safety
/// Caller must ensure `mode` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleMode(
    _console_handle: *mut core::ffi::c_void,
    mode: *mut u32,
) -> i32 {
    if !mode.is_null() {
        // SAFETY: Caller guarantees mode is valid and non-null (checked above).
        *mode = 3; // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT
    }
    1 // TRUE - success
}

/// GetConsoleOutputCP - retrieves the output code page used by the console
///
/// # Safety
/// This function is safe to call. It returns a constant value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleOutputCP() -> u32 {
    65001 // UTF-8
}

/// ReadConsoleW - reads character input from the console input buffer (wide version)
///
/// # Safety
/// Caller must ensure `chars_read` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadConsoleW(
    _console_input: *mut core::ffi::c_void,
    _buffer: *mut u16,
    _chars_to_read: u32,
    chars_read: *mut u32,
    _input_control: *mut core::ffi::c_void,
) -> i32 {
    if !chars_read.is_null() {
        // SAFETY: Caller guarantees chars_read is valid and non-null (checked above).
        *chars_read = 0;
    }
    1 // TRUE - success (no input available)
}

/// GetEnvironmentVariableW - retrieves the value of an environment variable (wide version)
///
/// # Safety
/// This function is a stub that returns 0 (variable not found).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentVariableW(
    _name: *const u16,
    _buffer: *mut u16,
    _size: u32,
) -> u32 {
    0 // Not found
}

/// SetEnvironmentVariableW - sets the value of an environment variable (wide version)
///
/// # Safety
/// This function is a stub that returns success without modifying anything.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEnvironmentVariableW(
    _name: *const u16,
    _value: *const u16,
) -> i32 {
    1 // TRUE - success
}

/// VirtualProtect - changes the protection on a region of committed pages
///
/// # Safety
/// Caller must ensure `old_protect` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualProtect(
    _address: *mut core::ffi::c_void,
    _size: usize,
    _new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if !old_protect.is_null() {
        // SAFETY: Caller guarantees old_protect is valid and non-null (checked above).
        *old_protect = 0x40; // PAGE_EXECUTE_READWRITE
    }
    1 // TRUE - success
}

/// VirtualQuery - retrieves information about a range of pages
///
/// # Safety
/// This function is a stub that returns 0 (failure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualQuery(
    _address: *const core::ffi::c_void,
    _buffer: *mut u8,
    _length: usize,
) -> usize {
    0 // Failure - not implemented
}

/// FreeLibrary - frees the loaded dynamic-link library module
///
/// # Safety
/// This function is a stub that returns success without freeing anything.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeLibrary(_module: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - success
}

/// FindFirstFileExW - searches a directory for a file or subdirectory (wide version)
///
/// # Safety
/// This function is a stub that returns INVALID_HANDLE_VALUE.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstFileExW(
    _filename: *const u16,
    _info_level: u32,
    _find_data: *mut u8,
    _search_op: u32,
    _search_filter: *mut core::ffi::c_void,
    _additional_flags: u32,
) -> *mut core::ffi::c_void {
    // INVALID_HANDLE_VALUE
    -1_i64 as usize as *mut core::ffi::c_void
}

/// FindNextFileW - continues a file search from a previous call to FindFirstFile
///
/// # Safety
/// This function is a stub that returns 0 (no more files).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindNextFileW(
    _find_file: *mut core::ffi::c_void,
    _find_data: *mut u8,
) -> i32 {
    0 // FALSE - no more files
}

/// FindClose - closes a file search handle
///
/// # Safety
/// This function is a stub that returns success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindClose(_find_file: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - success
}

/// WaitOnAddress - waits for the value at the specified address to change
///
/// # Safety
/// This function is a stub that returns success immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitOnAddress(
    _address: *mut core::ffi::c_void,
    _compare_address: *mut core::ffi::c_void,
    _address_size: usize,
    _milliseconds: u32,
) -> i32 {
    1 // TRUE - success
}

/// WakeByAddressAll - wakes all threads waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressAll(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// WakeByAddressSingle - wakes one thread waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressSingle(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// GetACP - returns the current ANSI code page identifier
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetACP() -> u32 {
    // Return UTF-8 code page (65001) for compatibility
    65001
}

/// IsProcessorFeaturePresent - checks if a processor feature is present
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsProcessorFeaturePresent(feature: u32) -> i32 {
    // PF_FASTFAIL_AVAILABLE = 23
    // PF_SSE2_INSTRUCTIONS_AVAILABLE = 10
    // PF_NX_ENABLED = 12
    match feature {
        // SSE2 (10), NX (12), and FastFail (23) are available on x86-64
        10 | 12 | 23 => 1,
        _ => 0,
    }
}

/// IsDebuggerPresent - checks if a debugger is attached to the process
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsDebuggerPresent() -> i32 {
    0 // No debugger attached
}

/// GetStringTypeW - retrieves character type information for wide characters
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStringTypeW(
    _dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if lp_src_str.is_null() || lp_char_type.is_null() {
        return 0; // FALSE
    }

    let len = if cch_src == -1 {
        // Count until null terminator
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n
    } else {
        cch_src as usize
    };

    // Fill with basic character type info
    // C1_ALPHA = 0x100, C1_LOWER = 0x002, C1_UPPER = 0x001
    for i in 0..len {
        let ch = *lp_src_str.add(i);
        let mut char_type: u16 = 0;
        // Only classify ASCII-range characters
        if ch < 128 {
            let byte = ch as u8;
            if byte.is_ascii_alphabetic() {
                char_type |= 0x100; // C1_ALPHA
                if byte.is_ascii_lowercase() {
                    char_type |= 0x002; // C1_LOWER
                } else if byte.is_ascii_uppercase() {
                    char_type |= 0x001; // C1_UPPER
                }
            } else if byte.is_ascii_digit() {
                char_type |= 0x004; // C1_DIGIT
            } else if byte.is_ascii_whitespace() {
                char_type |= 0x008; // C1_SPACE
            } else if byte.is_ascii_punctuation() {
                char_type |= 0x010; // C1_PUNCT
            } else if byte.is_ascii_control() {
                char_type |= 0x020; // C1_CNTRL
            }
        }
        *lp_char_type.add(i) = char_type;
    }

    1 // TRUE (success)
}

/// HeapSize - returns the size of a memory block allocated from a heap
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapSize(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *const core::ffi::c_void,
) -> usize {
    if mem.is_null() {
        return usize::MAX; // Error indicator
    }
    // We can't reliably determine the size of a Rust-allocated block
    // without tracking allocations. Return error to signal this limitation.
    usize::MAX
}

/// InitializeCriticalSectionAndSpinCount - initialize with spin count
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionAndSpinCount(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// InitializeCriticalSectionEx - extended initialization
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionEx(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
    _flags: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// FlsAlloc - allocate a fiber-local storage (FLS) index
///
/// FLS is similar to TLS but works with fibers. We implement it as a wrapper
/// around our TLS implementation since we don't support fibers.
///
/// # Safety
/// This function is unsafe as it deals with function pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsAlloc(_callback: *mut core::ffi::c_void) -> u32 {
    // Use TLS allocation since we don't support fibers
    kernel32_TlsAlloc()
}

/// FlsFree - free a fiber-local storage (FLS) index
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsFree(fls_index: u32) -> i32 {
    // Use TLS free since FLS maps to TLS
    kernel32_TlsFree(fls_index) as i32
}

/// FlsGetValue - get value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsGetValue(fls_index: u32) -> usize {
    kernel32_TlsGetValue(fls_index)
}

/// FlsSetValue - set value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsSetValue(fls_index: u32, fls_data: usize) -> i32 {
    kernel32_TlsSetValue(fls_index, fls_data) as i32
}

/// IsValidCodePage - check if a code page is valid
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsValidCodePage(code_page: u32) -> i32 {
    // Support common code pages
    match code_page {
        437 | 850 | 1252 | 65001 | 20127 => 1, // TRUE
        _ => 0,                                // FALSE
    }
}

/// GetOEMCP - get OEM code page
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOEMCP() -> u32 {
    437 // US English OEM code page
}

/// GetCPInfo - get code page information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCPInfo(code_page: u32, cp_info: *mut u8) -> i32 {
    if cp_info.is_null() {
        return 0; // FALSE
    }

    // CPINFO structure: MaxCharSize (UINT, 4 bytes) + DefaultChar (2 bytes) + LeadByte (12 bytes) = 18 bytes
    // Zero-initialize first
    core::ptr::write_bytes(cp_info, 0, 18);

    // Set MaxCharSize based on code page
    let max_char_size: u32 = match code_page {
        65001 => 4, // UTF-8: up to 4 bytes per character
        _ => 1,     // Single-byte code pages and default
    };
    core::ptr::copy_nonoverlapping((&raw const max_char_size).cast::<u8>(), cp_info, 4);

    // DefaultChar: '?' (0x3F)
    *cp_info.add(4) = 0x3F;

    1 // TRUE (success)
}

/// GetLocaleInfoW - get locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn kernel32_GetLocaleInfoW(
    _locale: u32,
    _lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    if cch_data == 0 || lp_lc_data.is_null() {
        // Return required size including null terminator
        return 2; // Minimum: one char + null
    }

    // Return a minimal response (just a null-terminated empty-ish string)
    if cch_data >= 1 {
        *lp_lc_data = 0; // Null terminator
    }
    1
}

/// LCMapStringW - map a string using locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LCMapStringW(
    _locale: u32,
    _map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    if lp_src_str.is_null() {
        return 0;
    }

    let src_len = if cch_src == -1 {
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n + 1 // Include null terminator
    } else {
        cch_src as usize
    };

    if cch_dest == 0 {
        // Return required buffer size
        return src_len as i32;
    }

    // Simple copy (no actual locale transformation)
    let copy_len = core::cmp::min(src_len, cch_dest as usize);
    core::ptr::copy_nonoverlapping(lp_src_str, lp_dest_str, copy_len);

    copy_len as i32
}

/// VirtualAlloc - reserves, commits, or changes the state of a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualAlloc(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    _allocation_type: u32,
    _protect: u32,
) -> *mut core::ffi::c_void {
    if dw_size == 0 {
        return core::ptr::null_mut();
    }

    // Use mmap to allocate memory
    let addr = if lp_address.is_null() {
        core::ptr::null_mut()
    } else {
        lp_address
    };

    let ptr = libc::mmap(
        addr,
        dw_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr == libc::MAP_FAILED {
        core::ptr::null_mut()
    } else {
        ptr
    }
}

/// VirtualFree - releases, decommits, or releases and decommits a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory deallocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualFree(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    if lp_address.is_null() {
        return 0; // FALSE
    }

    // MEM_RELEASE = 0x8000
    if dw_free_type == 0x8000 {
        // For MEM_RELEASE, Windows requires dwSize == 0 and releases the entire region.
        // Since we don't track allocation sizes, callers must pass the original size
        // via dw_size as a workaround, or we fall back to one page.
        let size = if dw_size == 0 { 4096 } else { dw_size };
        if libc::munmap(lp_address, size) == 0 {
            return 1; // TRUE
        }
    }

    0 // FALSE
}

/// DecodePointer - decodes a previously encoded pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DecodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, pointers are not actually encoded, so just return as-is
    ptr
}

/// EncodePointer - encodes a pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EncodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, we don't actually encode pointers
    ptr
}

/// GetTickCount64 - retrieves the number of milliseconds since system start
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTickCount64() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// SetEvent - sets the specified event object to the signaled state
///
/// # Safety
/// This function is a stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEvent(_event: *mut core::ffi::c_void) -> i32 {
    1 // TRUE (success stub)
}

/// ResetEvent - resets the specified event object to nonsignaled
///
/// # Safety
/// This function is a stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ResetEvent(_event: *mut core::ffi::c_void) -> i32 {
    1 // TRUE (success stub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep() {
        // Sleep for 10ms
        let start = std::time::Instant::now();
        unsafe { kernel32_Sleep(10) };
        let elapsed = start.elapsed();
        // Should sleep at least 10ms (allow some tolerance)
        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(50)); // Not too long
    }

    #[test]
    fn test_get_current_thread_id() {
        let tid = unsafe { kernel32_GetCurrentThreadId() };
        // Thread ID should be non-zero
        assert_ne!(tid, 0);
    }

    #[test]
    fn test_get_current_process_id() {
        let pid = unsafe { kernel32_GetCurrentProcessId() };
        // Process ID should be non-zero
        assert_ne!(pid, 0);
    }

    #[test]
    fn test_tls_alloc_free() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF); // Should not be TLS_OUT_OF_INDEXES

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1); // Should succeed
    }

    #[test]
    fn test_tls_get_set_value() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Initially should be 0
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, 0);

        // Set a value
        let test_value = 0x1234_5678_ABCD_EF00_usize;
        let result = unsafe { kernel32_TlsSetValue(slot, test_value) };
        assert_eq!(result, 1); // Should succeed

        // Get the value back
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, test_value);

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_tls_multiple_slots() {
        // Allocate multiple slots
        let slot1 = unsafe { kernel32_TlsAlloc() };
        let slot2 = unsafe { kernel32_TlsAlloc() };
        let slot3 = unsafe { kernel32_TlsAlloc() };

        assert_ne!(slot1, 0xFFFF_FFFF);
        assert_ne!(slot2, 0xFFFF_FFFF);
        assert_ne!(slot3, 0xFFFF_FFFF);

        // Each slot should be different
        assert_ne!(slot1, slot2);
        assert_ne!(slot2, slot3);
        assert_ne!(slot1, slot3);

        // Set different values in each slot
        let value1 = 0x1111_usize;
        let value2 = 0x2222_usize;
        let value3 = 0x3333_usize;

        unsafe {
            kernel32_TlsSetValue(slot1, value1);
            kernel32_TlsSetValue(slot2, value2);
            kernel32_TlsSetValue(slot3, value3);
        }

        // Verify each slot has its own value
        assert_eq!(unsafe { kernel32_TlsGetValue(slot1) }, value1);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot2) }, value2);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot3) }, value3);

        // Free all slots
        unsafe {
            kernel32_TlsFree(slot1);
            kernel32_TlsFree(slot2);
            kernel32_TlsFree(slot3);
        }
    }

    #[test]
    fn test_tls_thread_isolation() {
        use std::sync::Arc;
        use std::sync::Barrier;

        // Allocate a shared TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Use a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = vec![];

        for thread_num in 1..=2 {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Each thread sets its own value in the same slot
                #[allow(clippy::cast_sign_loss)]
                let value = (thread_num * 1000) as usize;
                unsafe {
                    kernel32_TlsSetValue(slot, value);
                }

                // Wait for all threads to set their values
                barrier.wait();

                // Verify this thread's value hasn't been affected by other threads
                let retrieved = unsafe { kernel32_TlsGetValue(slot) };
                assert_eq!(retrieved, value);
            });
            handles.push(handle);
        }

        // Main thread also sets a value
        let main_value = 9999_usize;
        unsafe {
            kernel32_TlsSetValue(slot, main_value);
        }

        // Wait for all threads
        barrier.wait();

        // Verify main thread's value is still intact
        let retrieved = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(retrieved, main_value);

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Free the slot
        unsafe {
            kernel32_TlsFree(slot);
        }
    }

    #[test]
    fn test_exception_handling_stubs() {
        // Test __C_specific_handler returns EXCEPTION_CONTINUE_SEARCH
        let result = unsafe {
            kernel32___C_specific_handler(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1); // EXCEPTION_CONTINUE_SEARCH

        // Test SetUnhandledExceptionFilter returns NULL
        let prev_filter = unsafe { kernel32_SetUnhandledExceptionFilter(core::ptr::null_mut()) };
        assert!(prev_filter.is_null());

        // Test RtlCaptureContext doesn't crash
        let mut context = vec![0u8; 1232]; // Size of Windows CONTEXT structure
        unsafe { kernel32_RtlCaptureContext(context.as_mut_ptr().cast()) };
        // Should zero out the buffer
        assert!(context.iter().all(|&b| b == 0));

        // Test RtlLookupFunctionEntry returns NULL
        let mut image_base = 0u64;
        let entry = unsafe {
            kernel32_RtlLookupFunctionEntry(
                0x1000,
                core::ptr::addr_of_mut!(image_base),
                core::ptr::null_mut(),
            )
        };
        assert!(entry.is_null());

        // Test RtlUnwindEx doesn't crash (returns nothing)
        unsafe {
            kernel32_RtlUnwindEx(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }

        // Test RtlVirtualUnwind returns NULL
        let unwind = unsafe {
            kernel32_RtlVirtualUnwind(
                0,
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(unwind.is_null());

        // Test AddVectoredExceptionHandler returns non-NULL
        let handler = unsafe { kernel32_AddVectoredExceptionHandler(1, core::ptr::null_mut()) };
        assert!(!handler.is_null());
    }

    #[test]
    fn test_critical_section_basic() {
        // Allocate a critical section
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };
        assert_ne!(cs.internal, 0); // Should be initialized

        // Enter the critical section
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the critical section
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Delete the critical section
        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
        assert_eq!(cs.internal, 0); // Should be cleared
    }

    #[test]
    fn test_critical_section_recursion() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Enter multiple times (recursion)
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the same number of times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Should be able to enter again after leaving all
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_try_enter() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Try to enter - should succeed when not held
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Try to enter again (same thread) - should succeed (recursion)
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Leave both times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_multi_thread() {
        use std::sync::Arc;
        use std::thread;

        // Allocate a critical section in shared memory
        let cs = Arc::new(std::sync::Mutex::new(CriticalSection {
            internal: 0,
            _padding: [0; 32],
        }));

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut *cs.lock().unwrap()) };

        // Shared counter
        let counter = Arc::new(std::sync::Mutex::new(0));

        // Spawn multiple threads
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cs = Arc::clone(&cs);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..100 {
                        // Enter critical section
                        unsafe { kernel32_EnterCriticalSection(&raw mut *cs.lock().unwrap()) };

                        // Increment counter (protected by critical section)
                        let mut c = counter.lock().unwrap();
                        *c += 1;
                        drop(c);

                        // Leave critical section
                        unsafe { kernel32_LeaveCriticalSection(&raw mut *cs.lock().unwrap()) };
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Check that all increments happened
        assert_eq!(*counter.lock().unwrap(), 500);

        // Clean up
        unsafe { kernel32_DeleteCriticalSection(&raw mut *cs.lock().unwrap()) };
    }

    #[test]
    fn test_critical_section_null_safe() {
        // All functions should handle NULL gracefully
        unsafe { kernel32_InitializeCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_EnterCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_LeaveCriticalSection(core::ptr::null_mut()) };
        let result = unsafe { kernel32_TryEnterCriticalSection(core::ptr::null_mut()) };
        assert_eq!(result, 0); // Should return false for NULL
        unsafe { kernel32_DeleteCriticalSection(core::ptr::null_mut()) };
    }

    //
    // Phase 8.3: String Operations Tests
    //

    #[test]
    fn test_multibyte_to_wide_char_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = b"Hello";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (5 chars, no null terminator when length is explicit)
        assert_eq!(result, 5);
        // Verify the conversion
        assert_eq!(output[0], u16::from(b'H'));
        assert_eq!(output[1], u16::from(b'e'));
        assert_eq!(output[2], u16::from(b'l'));
        assert_eq!(output[3], u16::from(b'l'));
        assert_eq!(output[4], u16::from(b'o'));
    }

    #[test]
    fn test_multibyte_to_wide_char_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = b"Hello World";

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
            )
        };

        // Should return 11 (11 chars, no null terminator when length is explicit)
        assert_eq!(result, 11);
    }

    #[test]
    fn test_multibyte_to_wide_char_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = b"Test\0";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (4 chars + null terminator)
        assert_eq!(result, 5);
        assert_eq!(output[0], u16::from(b'T'));
        assert_eq!(output[3], u16::from(b't'));
        assert_eq!(output[4], 0);
    }

    #[test]
    fn test_wide_char_to_multibyte_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = [u16::from(b'H'), u16::from(b'i'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                2, // Length without null
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 2 (2 chars, no null terminator when length is explicit)
        assert_eq!(result, 2);
        assert_eq!(output[0], b'H');
        assert_eq!(output[1], b'i');
    }

    #[test]
    fn test_wide_char_to_multibyte_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            u16::from(b' '),
            u16::from(b'!'),
        ];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 6 (6 chars, no null terminator when length is explicit)
        assert_eq!(result, 6);
    }

    #[test]
    fn test_wide_char_to_multibyte_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = [u16::from(b'A'), u16::from(b'B'), u16::from(b'C'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 4 (3 chars + null terminator)
        assert_eq!(result, 4);
        assert_eq!(output[0], b'A');
        assert_eq!(output[1], b'B');
        assert_eq!(output[2], b'C');
        assert_eq!(output[3], 0);
    }

    #[test]
    fn test_lstrlenw_basic() {
        // Test basic wide string length
        let input = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 5);
    }

    #[test]
    fn test_lstrlenw_empty() {
        // Test empty string
        let input = [0u16];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_lstrlenw_null() {
        // Test NULL pointer
        let result = unsafe { kernel32_lstrlenW(core::ptr::null()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_compare_string_ordinal_equal() {
        // Test equal strings
        let str1 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];
        let str2 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                4,
                str2.as_ptr(),
                4,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    #[test]
    fn test_compare_string_ordinal_less_than() {
        // Test str1 < str2
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'C'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 1); // CSTR_LESS_THAN
    }

    #[test]
    fn test_compare_string_ordinal_greater_than() {
        // Test str1 > str2
        let str1 = [u16::from(b'Z'), u16::from(b'Z'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'A'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 3); // CSTR_GREATER_THAN
    }

    #[test]
    fn test_compare_string_ordinal_ignore_case() {
        // Test case-insensitive comparison
        let str1 = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];
        let str2 = [
            u16::from(b'h'),
            u16::from(b'E'),
            u16::from(b'L'),
            u16::from(b'L'),
            u16::from(b'O'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                5,
                str2.as_ptr(),
                5,
                1, // Ignore case
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL (case-insensitive)
    }

    #[test]
    fn test_compare_string_ordinal_null_terminated() {
        // Test with -1 (null-terminated strings)
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'B'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                -1, // Null-terminated
                str2.as_ptr(),
                -1, // Null-terminated
                0,  // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    //
    // Phase 8.4: Performance Counters Tests
    //

    #[test]
    fn test_query_performance_counter() {
        let mut counter: i64 = 0;

        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter)) };

        assert_eq!(result, 1); // TRUE - success
        assert!(counter > 0); // Should be positive
    }

    #[test]
    fn test_query_performance_counter_monotonic() {
        let mut counter1: i64 = 0;
        let mut counter2: i64 = 0;

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter1)) };

        // Do some work
        for _ in 0..1000 {
            core::hint::black_box(42);
        }

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter2)) };

        // counter2 should be >= counter1 (monotonic)
        assert!(counter2 >= counter1);
    }

    #[test]
    fn test_query_performance_counter_null() {
        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_query_performance_frequency() {
        let mut frequency: i64 = 0;

        let result =
            unsafe { kernel32_QueryPerformanceFrequency(core::ptr::addr_of_mut!(frequency)) };

        assert_eq!(result, 1); // TRUE - success
        assert_eq!(frequency, 1_000_000_000); // 1 billion (nanoseconds)
    }

    #[test]
    fn test_query_performance_frequency_null() {
        let result = unsafe { kernel32_QueryPerformanceFrequency(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_get_system_time_precise_as_filetime() {
        let mut filetime = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime)) };

        // Should have non-zero values (representing time since 1601)
        assert!(filetime.high_date_time > 0);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_increases() {
        let mut filetime1 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut filetime2 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime1)) };

        // Sleep a tiny bit
        thread::sleep(Duration::from_millis(1));

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime2)) };

        // Reconstruct the 64-bit values
        let time1 =
            u64::from(filetime1.low_date_time) | (u64::from(filetime1.high_date_time) << 32);
        let time2 =
            u64::from(filetime2.low_date_time) | (u64::from(filetime2.high_date_time) << 32);

        // time2 should be > time1
        assert!(time2 > time1);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_null() {
        // Should not crash with NULL
        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::null_mut()) };
    }

    //
    // Phase 8.5: File I/O Trampolines Tests
    //

    #[test]
    fn test_create_file_w_returns_invalid_handle() {
        // CreateFileW should return INVALID_HANDLE_VALUE
        let handle = unsafe {
            kernel32_CreateFileW(
                core::ptr::null(),
                0,
                0,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
            )
        };

        // INVALID_HANDLE_VALUE is usize::MAX
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_read_file_returns_false() {
        // ReadFile should return FALSE (0)
        let result = unsafe {
            kernel32_ReadFile(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_write_file_returns_false() {
        // WriteFile should return FALSE (0)
        let result = unsafe {
            kernel32_WriteFile(
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_close_handle_returns_true() {
        // CloseHandle should return TRUE (1)
        let result = unsafe { kernel32_CloseHandle(core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    //
    // Phase 8.6: Heap Management Trampolines Tests
    //

    #[test]
    fn test_get_process_heap() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Should return non-NULL
        assert!(!heap.is_null());
    }

    #[test]
    fn test_heap_alloc_basic() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 1024;

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Clean up (even though our implementation leaks)
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 256;

        let ptr = unsafe { kernel32_HeapAlloc(heap, HEAP_ZERO_MEMORY, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Verify memory is zeroed
        let slice = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), size) };
        assert!(slice.iter().all(|&b| b == 0));

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 0) };

        // Windows HeapAlloc returns a non-NULL pointer for 0-byte allocation
        // We allocate a minimal block (1 byte) to match Windows semantics
        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_free_null() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Freeing NULL should succeed
        let result = unsafe { kernel32_HeapFree(heap, 0, core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    #[test]
    fn test_heap_realloc_null_to_alloc() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // ReAlloc with NULL pointer should allocate new memory
        let ptr = unsafe { kernel32_HeapReAlloc(heap, 0, core::ptr::null_mut(), 512) };

        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };

        // ReAlloc to zero size should free memory
        let result = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, 0) };

        assert!(result.is_null());
    }

    #[test]
    fn test_heap_alloc_free_cycle() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 512;

        // Allocate memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };
        assert!(!ptr.is_null());

        // Write some data to verify it's writable
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), size);
            slice.fill(0xAB);
        }

        // Free it
        let result = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result, 1); // TRUE - success
    }

    #[test]
    fn test_heap_realloc_grow() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to larger size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify original data is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), initial_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_shrink() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 1024;
        let new_size = 256;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), new_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to smaller size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify data in the remaining portion is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), new_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_new_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate and reallocate with HEAP_ZERO_MEMORY flag
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill initial allocation with non-zero data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            slice.fill(0xFF);
        }

        // Reallocate to larger size with zero flag
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, HEAP_ZERO_MEMORY, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify that the new portion (beyond initial_size) is zeroed
        unsafe {
            let slice = core::slice::from_raw_parts(
                new_ptr.cast::<u8>().add(initial_size),
                new_size - initial_size,
            );
            assert!(slice.iter().all(|&b| b == 0), "New memory not zeroed");
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_free_double_free_protection() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        assert!(!ptr.is_null());

        // First free should succeed
        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result1, 1); // TRUE

        // Second free should fail (allocation not found)
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result2, 0); // FALSE
    }

    #[test]
    fn test_heap_multiple_allocations() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Allocate multiple blocks
        let ptr1 = unsafe { kernel32_HeapAlloc(heap, 0, 128) };
        let ptr2 = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        let ptr3 = unsafe { kernel32_HeapAlloc(heap, 0, 512) };

        assert!(!ptr1.is_null());
        assert!(!ptr2.is_null());
        assert!(!ptr3.is_null());

        // All pointers should be different
        assert_ne!(ptr1, ptr2);
        assert_ne!(ptr2, ptr3);
        assert_ne!(ptr1, ptr3);

        // Free in different order
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr2) };
        assert_eq!(result2, 1);

        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr1) };
        assert_eq!(result1, 1);

        let result3 = unsafe { kernel32_HeapFree(heap, 0, ptr3) };
        assert_eq!(result3, 1);
    }

    #[test]
    fn test_get_set_last_error() {
        // Initially, last error should be 0
        let initial_error = unsafe { kernel32_GetLastError() };
        assert_eq!(initial_error, 0, "Initial error should be 0");

        // Set an error code
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED

        // Get the error back
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 5, "GetLastError should return the set error code");

        // Set a different error
        unsafe { kernel32_SetLastError(2) }; // ERROR_FILE_NOT_FOUND

        let error2 = unsafe { kernel32_GetLastError() };
        assert_eq!(error2, 2, "GetLastError should return the new error code");

        // Reset to 0
        unsafe { kernel32_SetLastError(0) };
        let error3 = unsafe { kernel32_GetLastError() };
        assert_eq!(error3, 0, "Error should be reset to 0");
    }

    #[test]
    fn test_last_error_thread_isolation() {
        use std::sync::{Arc, Barrier};

        // Create a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();

        // Set error in main thread
        unsafe { kernel32_SetLastError(100) };

        // Spawn a thread that sets a different error
        let handle = std::thread::spawn(move || {
            // Set error in spawned thread
            unsafe { kernel32_SetLastError(200) };

            // Wait for main thread
            barrier_clone.wait();

            // Check that spawned thread's error is isolated
            let error = unsafe { kernel32_GetLastError() };
            assert_eq!(error, 200, "Spawned thread should have its own error");
        });

        // Wait for spawned thread
        barrier.wait();

        // Check that main thread's error is still 100
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 100, "Main thread error should be isolated");

        // Wait for thread to finish
        handle.join().unwrap();
    }

    #[test]
    fn test_get_current_directory() {
        // Get current directory
        let buffer_size = 1024u32;
        let mut buffer = vec![0u16; buffer_size as usize];

        let result = unsafe { kernel32_GetCurrentDirectoryW(buffer_size, buffer.as_mut_ptr()) };
        assert!(result > 0, "GetCurrentDirectoryW should succeed");
        assert!(result < buffer_size, "Result should fit in buffer");

        // Convert to string and verify it's a valid path
        let dir_str = String::from_utf16_lossy(&buffer[..result as usize]);
        assert!(!dir_str.is_empty(), "Directory should not be empty");
    }

    #[test]
    fn test_set_current_directory() {
        // Get original directory to restore later
        let buffer_size = 1024u32;
        let mut orig_buffer = vec![0u16; buffer_size as usize];
        let orig_len =
            unsafe { kernel32_GetCurrentDirectoryW(buffer_size, orig_buffer.as_mut_ptr()) };
        assert!(orig_len > 0);

        // Try to set to /tmp (which should exist on Linux)
        let tmp_path: Vec<u16> = "/tmp\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(tmp_path.as_ptr()) };
        assert_eq!(result, 1, "SetCurrentDirectoryW to /tmp should succeed");

        // Verify it changed
        let mut new_buffer = vec![0u16; buffer_size as usize];
        let new_len =
            unsafe { kernel32_GetCurrentDirectoryW(buffer_size, new_buffer.as_mut_ptr()) };
        assert!(new_len > 0);
        let new_dir = String::from_utf16_lossy(&new_buffer[..new_len as usize]);
        assert!(
            new_dir.contains("tmp"),
            "Current directory should now be /tmp"
        );

        // Restore original directory
        let restore_result = unsafe { kernel32_SetCurrentDirectoryW(orig_buffer.as_ptr()) };
        assert_eq!(restore_result, 1, "Should restore original directory");
    }

    #[test]
    fn test_set_current_directory_invalid() {
        // Try to set to a non-existent directory
        let invalid_path: Vec<u16> = "/nonexistent_dir_12345\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(invalid_path.as_ptr()) };
        assert_eq!(
            result, 0,
            "SetCurrentDirectoryW should fail for invalid path"
        );

        // Check that last error was set
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 2, "Last error should be ERROR_FILE_NOT_FOUND");
    }

    #[test]
    fn test_write_file_stdout() {
        // Get stdout handle
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        assert!(!stdout.is_null());

        // Write some data
        let data = b"test output";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 1, "WriteFile should succeed for stdout");
        assert_eq!(bytes_written, data.len() as u32, "Should write all bytes");
    }

    #[test]
    fn test_write_file_invalid_handle() {
        // Try to write to invalid handle
        let invalid_handle = 0x9999 as *mut core::ffi::c_void;
        let data = b"test";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                invalid_handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for invalid handle");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 6, "Should set ERROR_INVALID_HANDLE");
    }

    #[test]
    fn test_write_file_null_buffer() {
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        let mut bytes_written = 0xFFFF_FFFFu32; // Set to non-zero to verify it gets cleared

        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                core::ptr::null(),
                10,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for null buffer");
        assert_eq!(bytes_written, 0, "bytes_written should be set to 0");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 87, "Should set ERROR_INVALID_PARAMETER");
    }

    #[test]
    fn test_get_command_line_w() {
        let cmd_line = unsafe { kernel32_GetCommandLineW() };
        assert!(
            !cmd_line.is_null(),
            "GetCommandLineW should not return null"
        );

        // Should be null-terminated
        let first_char = unsafe { *cmd_line };
        assert_eq!(
            first_char, 0,
            "Empty command line should have null terminator"
        );
    }

    #[test]
    fn test_get_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        assert!(
            !env.is_null(),
            "GetEnvironmentStringsW should not return null"
        );

        // Should have double null terminator (empty block)
        let first_char = unsafe { *env };
        assert_eq!(first_char, 0, "First char should be null");
        let second_char = unsafe { *env.add(1) };
        assert_eq!(second_char, 0, "Second char should be null (double-null)");
    }

    #[test]
    fn test_free_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        let result = unsafe { kernel32_FreeEnvironmentStringsW(env) };
        assert_eq!(result, 1, "FreeEnvironmentStringsW should return TRUE");
    }

    #[test]
    fn test_get_current_process() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        assert!(
            !handle.is_null(),
            "GetCurrentProcess should return non-null"
        );
        // Windows pseudo-handle for current process is -1
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_get_current_thread() {
        let handle = unsafe { kernel32_GetCurrentThread() };
        assert!(!handle.is_null(), "GetCurrentThread should return non-null");
        // Windows pseudo-handle for current thread is -2
        assert_eq!(handle as usize, usize::MAX - 1);
    }

    #[test]
    fn test_get_module_handle_a() {
        let handle = unsafe { kernel32_GetModuleHandleA(core::ptr::null()) };
        assert!(
            !handle.is_null(),
            "GetModuleHandleA(NULL) should return non-null"
        );
        assert_eq!(handle as usize, 0x400000);
    }

    #[test]
    fn test_get_system_info() {
        let mut info = [0u8; 48]; // SystemInfo is 48 bytes
        unsafe { kernel32_GetSystemInfo(info.as_mut_ptr()) };

        // Verify page size (offset 0x04, u32)
        let page_size = u32::from_le_bytes(info[4..8].try_into().unwrap());
        assert_eq!(page_size, 4096, "Page size should be 4096");

        // Verify number of processors (offset 0x20, u32)
        let num_processors = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        assert!(num_processors >= 1, "Should have at least 1 processor");
    }

    #[test]
    fn test_get_console_mode() {
        let mut mode: u32 = 0;
        let result = unsafe { kernel32_GetConsoleMode(std::ptr::dangling_mut(), &raw mut mode) };
        assert_eq!(result, 1, "GetConsoleMode should return TRUE");
        assert_ne!(mode, 0, "Mode should be non-zero");
    }

    #[test]
    fn test_get_console_output_cp() {
        let cp = unsafe { kernel32_GetConsoleOutputCP() };
        assert_eq!(cp, 65001, "Console output code page should be UTF-8");
    }

    #[test]
    fn test_virtual_protect() {
        let mut old_protect: u32 = 0;
        let result = unsafe {
            kernel32_VirtualProtect(
                0x1000 as *mut core::ffi::c_void,
                4096,
                0x04, // PAGE_READWRITE
                &raw mut old_protect,
            )
        };
        assert_eq!(result, 1, "VirtualProtect should return TRUE");
        assert_eq!(
            old_protect, 0x40,
            "Old protect should be PAGE_EXECUTE_READWRITE"
        );
    }

    #[test]
    fn test_free_library() {
        let result = unsafe { kernel32_FreeLibrary(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FreeLibrary should return TRUE");
    }

    #[test]
    fn test_find_close() {
        let result = unsafe { kernel32_FindClose(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FindClose should return TRUE");
    }

    #[test]
    fn test_get_environment_variable_w() {
        let name: [u16; 5] = [
            u16::from(b'P'),
            u16::from(b'A'),
            u16::from(b'T'),
            u16::from(b'H'),
            0,
        ];
        let result =
            unsafe { kernel32_GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
        assert_eq!(result, 0, "GetEnvironmentVariableW stub should return 0");
    }

    #[test]
    fn test_set_environment_variable_w() {
        let name: [u16; 2] = [u16::from(b'X'), 0];
        let value: [u16; 2] = [u16::from(b'Y'), 0];
        let result = unsafe { kernel32_SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 1, "SetEnvironmentVariableW should return TRUE");
    }

    #[test]
    fn test_get_acp() {
        let result = unsafe { kernel32_GetACP() };
        assert_eq!(result, 65001); // UTF-8
    }

    #[test]
    fn test_is_processor_feature_present() {
        unsafe {
            assert_eq!(kernel32_IsProcessorFeaturePresent(10), 1); // SSE2
            assert_eq!(kernel32_IsProcessorFeaturePresent(12), 1); // NX
            assert_eq!(kernel32_IsProcessorFeaturePresent(23), 1); // FastFail
            assert_eq!(kernel32_IsProcessorFeaturePresent(99), 0); // Unknown
        }
    }

    #[test]
    fn test_is_debugger_present() {
        let result = unsafe { kernel32_IsDebuggerPresent() };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_fls_operations() {
        unsafe {
            let index = kernel32_FlsAlloc(core::ptr::null_mut());
            assert_ne!(index, 0xFFFFFFFF); // TLS_OUT_OF_INDEXES

            let set_result = kernel32_FlsSetValue(index, 0x42);
            assert_eq!(set_result, 1); // TRUE

            let value = kernel32_FlsGetValue(index);
            assert_eq!(value, 0x42);

            let free_result = kernel32_FlsFree(index);
            assert_eq!(free_result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_oem_cp() {
        let result = unsafe { kernel32_GetOEMCP() };
        assert_eq!(result, 437);
    }

    #[test]
    fn test_is_valid_code_page() {
        unsafe {
            assert_eq!(kernel32_IsValidCodePage(65001), 1); // UTF-8
            assert_eq!(kernel32_IsValidCodePage(1252), 1); // Windows-1252
            assert_eq!(kernel32_IsValidCodePage(99999), 0); // Invalid
        }
    }

    #[test]
    fn test_get_cp_info() {
        unsafe {
            let mut cp_info = [0u8; 18];
            let result = kernel32_GetCPInfo(65001, cp_info.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // First 4 bytes are MaxCharSize (should be 4 for UTF-8)
            let max_char_size =
                u32::from_le_bytes([cp_info[0], cp_info[1], cp_info[2], cp_info[3]]);
            assert_eq!(max_char_size, 4);
            // DefaultChar should be '?'
            assert_eq!(cp_info[4], 0x3F);
        }
    }

    #[test]
    fn test_decode_encode_pointer() {
        unsafe {
            let original = 0x12345678usize as *mut core::ffi::c_void;
            let encoded = kernel32_EncodePointer(original);
            let decoded = kernel32_DecodePointer(encoded);
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn test_get_tick_count_64() {
        unsafe {
            let tick1 = kernel32_GetTickCount64();
            assert!(tick1 > 0);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let tick2 = kernel32_GetTickCount64();
            assert!(tick2 >= tick1);
        }
    }

    #[test]
    fn test_virtual_alloc_free() {
        unsafe {
            let ptr = kernel32_VirtualAlloc(
                core::ptr::null_mut(),
                4096,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            );
            assert!(!ptr.is_null());

            // Write to the allocated memory to verify it's usable
            *ptr.cast::<u8>() = 42;
            assert_eq!(*(ptr as *const u8), 42);

            let result = kernel32_VirtualFree(ptr, 4096, 0x8000); // MEM_RELEASE
            assert_eq!(result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_string_type_w() {
        unsafe {
            let input: [u16; 4] = [u16::from(b'A'), u16::from(b'1'), u16::from(b' '), 0];
            let mut output = [0u16; 3];
            let result = kernel32_GetStringTypeW(1, input.as_ptr(), 3, output.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // 'A' should have C1_ALPHA | C1_UPPER
            assert_ne!(output[0] & 0x100, 0); // C1_ALPHA
            assert_ne!(output[0] & 0x001, 0); // C1_UPPER
            // '1' should have C1_DIGIT
            assert_ne!(output[1] & 0x004, 0); // C1_DIGIT
            // ' ' should have C1_SPACE
            assert_ne!(output[2] & 0x008, 0); // C1_SPACE
        }
    }

    #[test]
    fn test_initialize_critical_section_and_spin_count() {
        unsafe {
            let mut cs = core::mem::zeroed::<CriticalSection>();
            let result = kernel32_InitializeCriticalSectionAndSpinCount(&raw mut cs, 4000);
            assert_eq!(result, 1); // TRUE
            kernel32_DeleteCriticalSection(&raw mut cs);
        }
    }
}
