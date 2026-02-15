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
    manager.as_mut().and_then(TlsManager::alloc_slot).unwrap_or(0xFFFF_FFFF) // TLS_OUT_OF_INDEXES
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
}
