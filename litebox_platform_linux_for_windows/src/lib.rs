// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux platform implementation for Windows APIs
//!
//! This crate implements Windows NTDLL APIs using Linux syscalls.
//! This is the "South" platform layer that translates Windows API calls
//! to Linux syscalls.

extern crate std;

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use thiserror::Error;

use litebox_shim_windows::syscalls::ntdll::{
    ConsoleHandle, EventHandle, FileHandle, NtdllApi, ThreadEntryPoint, ThreadHandle,
};

/// Platform errors
#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid handle: {0}")]
    InvalidHandle(u64),

    #[error("Path translation error: {0}")]
    PathTranslation(String),

    #[error("Memory error: {0}")]
    MemoryError(String),

    #[error("Thread error: {0}")]
    ThreadError(String),

    #[error("Synchronization error: {0}")]
    SyncError(String),

    #[error("Timeout")]
    Timeout,
}

pub type Result<T> = core::result::Result<T, PlatformError>;

/// Windows file handle (maps to Linux FD)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WinHandle(u64);

/// Thread information
struct ThreadInfo {
    join_handle: Option<JoinHandle<u32>>,
    exit_code: Arc<Mutex<Option<u32>>>,
}

/// Event object for synchronization
struct EventObject {
    manual_reset: bool,
    state: Arc<(Mutex<bool>, Condvar)>,
}

/// Linux platform for Windows API implementation
pub struct LinuxPlatformForWindows {
    /// Handle to file descriptor mapping
    handles: HashMap<u64, File>,
    /// Next handle ID
    next_handle: u64,
    /// Thread handle mapping
    threads: HashMap<u64, ThreadInfo>,
    /// Event handle mapping
    events: HashMap<u64, EventObject>,
}

impl LinuxPlatformForWindows {
    /// Create a new platform instance
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle: 0x1000, // Start at a high value to avoid conflicts
            threads: HashMap::new(),
            events: HashMap::new(),
        }
    }

    /// Allocate a new handle ID
    fn allocate_handle(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    /// NtCreateFile - Create or open a file (internal implementation)
    fn nt_create_file_impl(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> Result<u64> {
        let linux_path = translate_windows_path_to_linux(path);

        let mut options = OpenOptions::new();

        // Translate access flags
        if access & 0x80000000 != 0 {
            // GENERIC_READ
            options.read(true);
        }
        if access & 0x40000000 != 0 {
            // GENERIC_WRITE
            options.write(true);
        }

        // Translate creation disposition
        match create_disposition {
            1 => {
                options.create_new(true);
            } // CREATE_NEW
            2 => {
                options.create(true).truncate(true);
            } // CREATE_ALWAYS
            4 => {
                options.create(true);
            } // OPEN_ALWAYS
            3 => { /* OPEN_EXISTING - default */ }
            _ => { /* Unknown - treat as OPEN_EXISTING */ }
        }

        let file = options.open(&linux_path)?;
        let handle = self.allocate_handle();
        self.handles.insert(handle, file);

        Ok(handle)
    }

    /// NtReadFile - Read from a file (internal implementation)
    fn nt_read_file_impl(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize> {
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(file.read(buffer)?)
    }

    /// NtWriteFile - Write to a file (internal implementation)
    fn nt_write_file_impl(&mut self, handle: u64, buffer: &[u8]) -> Result<usize> {
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(file.write(buffer)?)
    }

    /// NtClose - Close a handle (internal implementation)
    fn nt_close_impl(&mut self, handle: u64) -> Result<()> {
        self.handles
            .remove(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(())
    }

    /// Get standard output handle (internal implementation)
    fn get_std_output_impl(&self) -> u64 {
        // Use a special handle value for stdout
        0xFFFF_FFFF_0001
    }

    /// Write to console (internal implementation)
    fn write_console_impl(&mut self, handle: u64, text: &str) -> Result<usize> {
        if handle == 0xFFFF_FFFF_0001 {
            print!("{text}");
            std::io::stdout().flush()?;
            Ok(text.len())
        } else {
            Err(PlatformError::InvalidHandle(handle))
        }
    }

    /// NtAllocateVirtualMemory - Allocate virtual memory (internal implementation)
    fn nt_allocate_virtual_memory_impl(&mut self, size: usize, protect: u32) -> Result<u64> {
        use std::ptr;

        // Translate Windows protection flags to Linux PROT_ flags
        let mut prot = 0;
        if protect & 0x04 != 0 || protect & 0x40 != 0 {
            // PAGE_READWRITE or PAGE_EXECUTE_READWRITE
            prot |= libc::PROT_READ | libc::PROT_WRITE;
        } else if protect & 0x02 != 0 || protect & 0x20 != 0 {
            // PAGE_READONLY or PAGE_EXECUTE_READ
            prot |= libc::PROT_READ;
        }
        if protect & 0x10 != 0 || protect & 0x20 != 0 || protect & 0x40 != 0 {
            // Any EXECUTE flag
            prot |= libc::PROT_EXEC;
        }

        // SAFETY: mmap is called with valid parameters
        let addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if addr == libc::MAP_FAILED {
            return Err(PlatformError::MemoryError("mmap failed".to_string()));
        }

        Ok(addr as u64)
    }

    /// NtFreeVirtualMemory - Free virtual memory (internal implementation)
    fn nt_free_virtual_memory_impl(&mut self, address: u64, size: usize) -> Result<()> {
        // SAFETY: munmap is called with valid parameters
        let result = unsafe { libc::munmap(address as *mut libc::c_void, size) };

        if result != 0 {
            return Err(PlatformError::MemoryError("munmap failed".to_string()));
        }

        Ok(())
    }

    // Phase 4: Threading implementation

    /// NtCreateThread - Create a new thread (internal implementation)
    fn nt_create_thread_impl(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        _stack_size: usize,
    ) -> Result<u64> {
        let exit_code = Arc::new(Mutex::new(None));
        let exit_code_clone = Arc::clone(&exit_code);

        // Convert pointer to usize for Send across threads
        let param_addr = parameter as usize;

        // SAFETY: We're spawning a thread with a valid entry point function.
        // The caller is responsible for ensuring the parameter pointer is valid
        // for the lifetime of the thread.
        let join_handle = thread::spawn(move || {
            let param_ptr = param_addr as *mut core::ffi::c_void;
            let result = entry_point(param_ptr);
            *exit_code_clone.lock().unwrap() = Some(result);
            result
        });

        let handle = self.allocate_handle();
        self.threads.insert(
            handle,
            ThreadInfo {
                join_handle: Some(join_handle),
                exit_code,
            },
        );

        Ok(handle)
    }

    /// NtTerminateThread - Terminate a thread (internal implementation)
    fn nt_terminate_thread_impl(&mut self, handle: u64, exit_code: u32) -> Result<()> {
        let thread_info = self
            .threads
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        // Set the exit code
        *thread_info.exit_code.lock().unwrap() = Some(exit_code);

        // Note: Rust doesn't support forcefully terminating threads safely
        // The thread will exit when it reaches a natural exit point
        // For now, we just mark it as terminated
        Ok(())
    }

    /// NtWaitForSingleObject - Wait for a thread (internal implementation)
    fn nt_wait_for_single_object_impl(&mut self, handle: u64, timeout_ms: u32) -> Result<u32> {
        let thread_info = self
            .threads
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        if let Some(join_handle) = thread_info.join_handle.take() {
            if timeout_ms == u32::MAX {
                // Infinite wait
                join_handle
                    .join()
                    .map_err(|_| PlatformError::ThreadError("Thread join failed".to_string()))?;
                Ok(0) // WAIT_OBJECT_0
            } else {
                // Timed wait - spawn a timeout checker
                use std::time::Duration;
                let start = std::time::Instant::now();
                let timeout = Duration::from_millis(u64::from(timeout_ms));
                let exit_code = Arc::clone(&thread_info.exit_code);

                loop {
                    if let Some(_code) = *exit_code.lock().unwrap() {
                        // Thread completed
                        join_handle.join().map_err(|_| {
                            PlatformError::ThreadError("Thread join failed".to_string())
                        })?;
                        return Ok(0); // WAIT_OBJECT_0
                    }

                    if start.elapsed() >= timeout {
                        // Store the join handle back for later
                        thread_info.join_handle = Some(join_handle);
                        return Ok(0x00000102); // WAIT_TIMEOUT
                    }

                    thread::sleep(Duration::from_millis(10));
                }
            }
        } else {
            // Thread already waited on
            Ok(0) // WAIT_OBJECT_0
        }
    }

    /// NtCreateEvent - Create an event object (internal implementation)
    fn nt_create_event_impl(&mut self, manual_reset: bool, initial_state: bool) -> u64 {
        let handle = self.allocate_handle();
        let event = EventObject {
            manual_reset,
            state: Arc::new((Mutex::new(initial_state), Condvar::new())),
        };
        self.events.insert(handle, event);
        handle
    }

    /// NtSetEvent - Signal an event (internal implementation)
    fn nt_set_event_impl(&mut self, handle: u64) -> Result<()> {
        let event = self
            .events
            .get(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        let (lock, cvar) = &*event.state;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
        Ok(())
    }

    /// NtResetEvent - Reset an event (internal implementation)
    fn nt_reset_event_impl(&mut self, handle: u64) -> Result<()> {
        let event = self
            .events
            .get(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        let (lock, _cvar) = &*event.state;
        *lock.lock().unwrap() = false;
        Ok(())
    }

    /// NtWaitForEvent - Wait for an event (internal implementation)
    fn nt_wait_for_event_impl(&mut self, handle: u64, timeout_ms: u32) -> Result<u32> {
        let event = self
            .events
            .get(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;

        let (lock, cvar) = &*event.state;
        let mut signaled = lock.lock().unwrap();

        if timeout_ms == u32::MAX {
            // Infinite wait
            while !*signaled {
                signaled = cvar.wait(signaled).unwrap();
            }
            // Auto-reset for non-manual reset events
            if !event.manual_reset {
                *signaled = false;
            }
            Ok(0) // WAIT_OBJECT_0
        } else {
            // Timed wait
            use std::time::Duration;
            let timeout = Duration::from_millis(u64::from(timeout_ms));
            let result = cvar.wait_timeout(signaled, timeout).unwrap();
            signaled = result.0;

            if *signaled {
                // Auto-reset for non-manual reset events
                if !event.manual_reset {
                    *signaled = false;
                }
                Ok(0) // WAIT_OBJECT_0
            } else {
                Ok(0x00000102) // WAIT_TIMEOUT
            }
        }
    }

    /// NtCloseHandle - Close thread or event handle (internal implementation)
    fn nt_close_handle_impl(&mut self, handle: u64) -> Result<()> {
        // Try to remove from threads or events
        if self.threads.remove(&handle).is_some() || self.events.remove(&handle).is_some() {
            Ok(())
        } else {
            Err(PlatformError::InvalidHandle(handle))
        }
    }
}

impl Default for LinuxPlatformForWindows {
    fn default() -> Self {
        Self::new()
    }
}

/// Translate Windows path to Linux path
///
/// Converts Windows-style paths (C:\path\to\file.txt) to Linux paths (/path/to/file.txt)
fn translate_windows_path_to_linux(windows_path: &str) -> String {
    let mut path = windows_path.to_string();

    // Remove drive letter if present (C:, D:, etc.)
    if path.len() >= 2 && path.chars().nth(1) == Some(':') {
        path = path[2..].to_string();
    }

    // Replace backslashes with forward slashes
    path = path.replace('\\', "/");

    // Ensure it starts with /
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    path
}

/// Implement the NtdllApi trait from litebox_shim_windows
impl NtdllApi for LinuxPlatformForWindows {
    fn nt_create_file(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> litebox_shim_windows::Result<FileHandle> {
        let handle = self
            .nt_create_file_impl(path, access, create_disposition)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(FileHandle(handle))
    }

    fn nt_read_file(
        &mut self,
        handle: FileHandle,
        buffer: &mut [u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_read_file_impl(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_write_file(
        &mut self,
        handle: FileHandle,
        buffer: &[u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_write_file_impl(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_close(&mut self, handle: FileHandle) -> litebox_shim_windows::Result<()> {
        self.nt_close_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn get_std_output(&self) -> ConsoleHandle {
        ConsoleHandle(self.get_std_output_impl())
    }

    fn write_console(
        &mut self,
        handle: ConsoleHandle,
        text: &str,
    ) -> litebox_shim_windows::Result<usize> {
        self.write_console_impl(handle.0, text)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_allocate_virtual_memory(
        &mut self,
        size: usize,
        protect: u32,
    ) -> litebox_shim_windows::Result<u64> {
        self.nt_allocate_virtual_memory_impl(size, protect)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_free_virtual_memory(
        &mut self,
        address: u64,
        size: usize,
    ) -> litebox_shim_windows::Result<()> {
        self.nt_free_virtual_memory_impl(address, size)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 4: Threading APIs

    fn nt_create_thread(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        stack_size: usize,
    ) -> litebox_shim_windows::Result<ThreadHandle> {
        let handle = self
            .nt_create_thread_impl(entry_point, parameter, stack_size)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(ThreadHandle(handle))
    }

    fn nt_terminate_thread(
        &mut self,
        handle: ThreadHandle,
        exit_code: u32,
    ) -> litebox_shim_windows::Result<()> {
        self.nt_terminate_thread_impl(handle.0, exit_code)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_wait_for_single_object(
        &mut self,
        handle: ThreadHandle,
        timeout_ms: u32,
    ) -> litebox_shim_windows::Result<u32> {
        self.nt_wait_for_single_object_impl(handle.0, timeout_ms)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    // Phase 4: Synchronization APIs

    fn nt_create_event(
        &mut self,
        manual_reset: bool,
        initial_state: bool,
    ) -> litebox_shim_windows::Result<EventHandle> {
        let handle = self.nt_create_event_impl(manual_reset, initial_state);
        Ok(EventHandle(handle))
    }

    fn nt_set_event(&mut self, handle: EventHandle) -> litebox_shim_windows::Result<()> {
        self.nt_set_event_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_reset_event(&mut self, handle: EventHandle) -> litebox_shim_windows::Result<()> {
        self.nt_reset_event_impl(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_wait_for_event(
        &mut self,
        handle: EventHandle,
        timeout_ms: u32,
    ) -> litebox_shim_windows::Result<u32> {
        self.nt_wait_for_event_impl(handle.0, timeout_ms)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_close_handle(&mut self, handle: u64) -> litebox_shim_windows::Result<()> {
        self.nt_close_handle_impl(handle)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_translation() {
        assert_eq!(
            translate_windows_path_to_linux("C:\\test\\file.txt"),
            "/test/file.txt"
        );
        assert_eq!(
            translate_windows_path_to_linux("\\test\\file.txt"),
            "/test/file.txt"
        );
        assert_eq!(
            translate_windows_path_to_linux("/test/file.txt"),
            "/test/file.txt"
        );
    }

    #[test]
    fn test_handle_allocation() {
        let mut platform = LinuxPlatformForWindows::new();
        let h1 = platform.allocate_handle();
        let h2 = platform.allocate_handle();
        assert_ne!(h1, h2);
    }

    // Phase 4: Threading tests

    extern "C" fn simple_thread_func(_param: *mut core::ffi::c_void) -> u32 {
        42
    }

    #[test]
    fn test_thread_creation() {
        let mut platform = LinuxPlatformForWindows::new();
        
        let result = platform.nt_create_thread(
            simple_thread_func,
            std::ptr::null_mut(),
            1024 * 1024,
        );
        
        assert!(result.is_ok());
        let handle = result.unwrap();
        
        // Wait for thread to complete
        let wait_result = platform.nt_wait_for_single_object(handle, u32::MAX);
        assert!(wait_result.is_ok());
        assert_eq!(wait_result.unwrap(), 0); // WAIT_OBJECT_0
    }

    extern "C" fn incrementing_thread_func(param: *mut core::ffi::c_void) -> u32 {
        // SAFETY: Test code controls the pointer validity
        unsafe {
            let counter = param as *mut u32;
            *counter += 1;
        }
        0
    }

    #[test]
    fn test_thread_with_parameter() {
        let mut platform = LinuxPlatformForWindows::new();
        let mut counter: u32 = 0;
        let counter_ptr = &mut counter as *mut u32 as *mut core::ffi::c_void;
        
        let handle = platform
            .nt_create_thread(incrementing_thread_func, counter_ptr, 1024 * 1024)
            .unwrap();
        
        // Wait for thread
        platform.nt_wait_for_single_object(handle, u32::MAX).unwrap();
        
        assert_eq!(counter, 1);
    }

    #[test]
    fn test_event_creation_and_signal() {
        let mut platform = LinuxPlatformForWindows::new();
        
        // Create an event in non-signaled state
        let event = platform.nt_create_event(false, false).unwrap();
        
        // Set the event
        let result = platform.nt_set_event(event);
        assert!(result.is_ok());
        
        // Wait should succeed immediately
        let wait_result = platform.nt_wait_for_event(event, 100);
        assert!(wait_result.is_ok());
        assert_eq!(wait_result.unwrap(), 0); // WAIT_OBJECT_0
    }

    #[test]
    fn test_event_manual_reset() {
        let mut platform = LinuxPlatformForWindows::new();
        
        // Create a manual reset event in signaled state
        let event = platform.nt_create_event(true, true).unwrap();
        
        // Wait should succeed
        platform.nt_wait_for_event(event, 100).unwrap();
        
        // Wait again should still succeed (manual reset stays signaled)
        platform.nt_wait_for_event(event, 100).unwrap();
        
        // Reset the event
        platform.nt_reset_event(event).unwrap();
        
        // Now wait should timeout
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0x00000102); // WAIT_TIMEOUT
    }

    #[test]
    fn test_event_auto_reset() {
        let mut platform = LinuxPlatformForWindows::new();
        
        // Create an auto-reset event in signaled state
        let event = platform.nt_create_event(false, true).unwrap();
        
        // First wait should succeed and auto-reset
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0); // WAIT_OBJECT_0
        
        // Second wait should timeout (auto-reset)
        let result = platform.nt_wait_for_event(event, 100).unwrap();
        assert_eq!(result, 0x00000102); // WAIT_TIMEOUT
    }

    #[test]
    fn test_close_handles() {
        let mut platform = LinuxPlatformForWindows::new();
        
        // Create thread handle
        let thread_handle = platform
            .nt_create_thread(simple_thread_func, std::ptr::null_mut(), 1024 * 1024)
            .unwrap();
        
        // Create event handle
        let event_handle = platform.nt_create_event(false, false).unwrap();
        
        // Close both handles
        assert!(platform.nt_close_handle(thread_handle.0).is_ok());
        assert!(platform.nt_close_handle(event_handle.0).is_ok());
        
        // Trying to close again should fail
        assert!(platform.nt_close_handle(thread_handle.0).is_err());
        assert!(platform.nt_close_handle(event_handle.0).is_err());
    }
}
