// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! KERNEL32.dll function implementations
//!
//! This module provides Linux-based implementations of KERNEL32 functions
//! that are commonly used by Windows programs. These are higher-level wrappers
//! around NTDLL functions.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

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
}
