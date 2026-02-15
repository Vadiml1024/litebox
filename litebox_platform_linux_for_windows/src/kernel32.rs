// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! KERNEL32.dll function implementations
//!
//! This module provides Linux-based implementations of KERNEL32 functions
//! that are commonly used by Windows programs. These are higher-level wrappers
//! around NTDLL functions.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]

use std::thread;
use std::time::Duration;

/// Sleep for specified milliseconds (Sleep)
///
/// This is the Windows Sleep function that suspends execution for the specified duration.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Sleep(milliseconds: u32) {
    thread::sleep(Duration::from_millis(u64::from(milliseconds)));
}

/// Get the current thread ID (GetCurrentThreadId)
///
/// Returns the unique identifier for the current thread.
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
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
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcessId() -> u32 {
    // SAFETY: getpid is a safe syscall
    let pid = unsafe { libc::getpid() };
    // Convert to u32 to match Windows API
    #[allow(clippy::cast_sign_loss)]
    (pid as u32)
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
}
