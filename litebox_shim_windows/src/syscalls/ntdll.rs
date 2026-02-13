// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NTDLL API interface
//!
//! This module defines the Windows NTDLL API interface:
//! - Phase 2: File I/O, Console I/O, Memory management
//! - Phase 4: Threading and Synchronization
//! - Phase 5: Environment variables, Process information, Registry emulation

use crate::Result;

/// Windows file handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle(pub u64);

/// Windows console handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleHandle(pub u64);

/// Windows thread handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadHandle(pub u64);

/// Windows event handle (for synchronization)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventHandle(pub u64);

/// Windows registry key handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegKeyHandle(pub u64);

/// Thread entry point function type
pub type ThreadEntryPoint = extern "C" fn(*mut core::ffi::c_void) -> u32;

/// NTDLL API interface
///
/// This trait defines the Windows NTDLL APIs that need to be implemented
/// by the platform layer (litebox_platform_linux_for_windows)
pub trait NtdllApi {
    /// NtCreateFile - Create or open a file
    ///
    /// Maps to Linux `open()` syscall
    fn nt_create_file(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> Result<FileHandle>;

    /// NtReadFile - Read from a file
    ///
    /// Maps to Linux `read()` syscall
    fn nt_read_file(&mut self, handle: FileHandle, buffer: &mut [u8]) -> Result<usize>;

    /// NtWriteFile - Write to a file
    ///
    /// Maps to Linux `write()` syscall
    fn nt_write_file(&mut self, handle: FileHandle, buffer: &[u8]) -> Result<usize>;

    /// NtClose - Close a handle
    ///
    /// Maps to Linux `close()` syscall
    fn nt_close(&mut self, handle: FileHandle) -> Result<()>;

    /// Get standard output handle for console I/O
    fn get_std_output(&self) -> ConsoleHandle;

    /// Write to console
    fn write_console(&mut self, handle: ConsoleHandle, text: &str) -> Result<usize>;

    /// NtAllocateVirtualMemory - Allocate virtual memory
    ///
    /// Maps to Linux `mmap()` syscall
    fn nt_allocate_virtual_memory(&mut self, size: usize, protect: u32) -> Result<u64>;

    /// NtFreeVirtualMemory - Free virtual memory
    ///
    /// Maps to Linux `munmap()` syscall
    fn nt_free_virtual_memory(&mut self, address: u64, size: usize) -> Result<()>;

    // Phase 4: Threading APIs

    /// NtCreateThread - Create a new thread
    ///
    /// Creates a thread with the specified entry point and parameter.
    /// Maps to Linux `clone()` syscall with CLONE_VM | CLONE_THREAD flags.
    fn nt_create_thread(
        &mut self,
        entry_point: ThreadEntryPoint,
        parameter: *mut core::ffi::c_void,
        stack_size: usize,
    ) -> Result<ThreadHandle>;

    /// NtTerminateThread - Terminate a thread
    ///
    /// Terminates the specified thread with the given exit code.
    /// If handle is current thread, exits immediately.
    fn nt_terminate_thread(&mut self, handle: ThreadHandle, exit_code: u32) -> Result<()>;

    /// NtWaitForSingleObject - Wait for an object to be signaled
    ///
    /// Waits for the specified object (thread or event) to be signaled.
    /// timeout_ms: milliseconds to wait, or u32::MAX for infinite.
    fn nt_wait_for_single_object(&mut self, handle: ThreadHandle, timeout_ms: u32) -> Result<u32>;

    // Phase 4: Synchronization APIs

    /// NtCreateEvent - Create an event object
    ///
    /// Creates a synchronization event (manual or auto-reset).
    /// Maps to Linux eventfd or condition variable.
    fn nt_create_event(&mut self, manual_reset: bool, initial_state: bool) -> Result<EventHandle>;

    /// NtSetEvent - Signal an event
    ///
    /// Sets the event to signaled state, waking waiting threads.
    fn nt_set_event(&mut self, handle: EventHandle) -> Result<()>;

    /// NtResetEvent - Reset an event
    ///
    /// Sets the event to non-signaled state.
    fn nt_reset_event(&mut self, handle: EventHandle) -> Result<()>;

    /// NtWaitForEvent - Wait for an event to be signaled
    ///
    /// Waits for the specified event to be signaled.
    /// timeout_ms: milliseconds to wait, or u32::MAX for infinite.
    fn nt_wait_for_event(&mut self, handle: EventHandle, timeout_ms: u32) -> Result<u32>;

    /// NtCloseHandle - Close a thread or event handle
    ///
    /// Generic handle close for thread and event handles.
    fn nt_close_handle(&mut self, handle: u64) -> Result<()>;

    // Phase 5: Environment Variables

    /// Get environment variable value
    ///
    /// Returns the value of the specified environment variable.
    /// Returns None if the variable doesn't exist.
    fn get_environment_variable(&self, name: &str) -> Option<String>;

    /// Set environment variable
    ///
    /// Sets the value of the specified environment variable.
    fn set_environment_variable(&mut self, name: &str, value: &str) -> Result<()>;

    // Phase 5: Process Information

    /// Get current process ID
    fn get_current_process_id(&self) -> u32;

    /// Get current thread ID
    fn get_current_thread_id(&self) -> u32;

    // Phase 5: Registry Emulation

    /// Open registry key
    ///
    /// Opens a registry key for read access.
    /// Returns a handle to the key.
    fn reg_open_key_ex(&mut self, key: &str, subkey: &str) -> Result<RegKeyHandle>;

    /// Query registry value
    ///
    /// Queries a value from a registry key.
    /// Returns None if the value doesn't exist.
    fn reg_query_value_ex(&self, handle: RegKeyHandle, value_name: &str) -> Option<String>;

    /// Close registry key
    fn reg_close_key(&mut self, handle: RegKeyHandle) -> Result<()>;

    // Phase 6: DLL Loading APIs

    /// LoadLibrary - Load a DLL
    ///
    /// Loads a DLL by name and returns a handle.
    /// Case-insensitive name matching.
    fn load_library(&mut self, name: &str) -> Result<u64>;

    /// GetProcAddress - Get address of a function in a DLL
    ///
    /// Returns the address of the specified exported function.
    fn get_proc_address(&self, dll_handle: u64, name: &str) -> Result<u64>;

    /// FreeLibrary - Unload a DLL
    ///
    /// Frees a previously loaded DLL.
    fn free_library(&mut self, dll_handle: u64) -> Result<()>;
}

/// Windows file access flags (simplified)
pub mod file_access {
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
}

/// Windows file creation disposition (simplified)
pub mod create_disposition {
    pub const CREATE_NEW: u32 = 1;
    pub const CREATE_ALWAYS: u32 = 2;
    pub const OPEN_EXISTING: u32 = 3;
    pub const OPEN_ALWAYS: u32 = 4;
}

/// Windows memory protection flags (simplified)
pub mod memory_protection {
    pub const PAGE_NOACCESS: u32 = 0x01;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const PAGE_EXECUTE: u32 = 0x10;
    pub const PAGE_EXECUTE_READ: u32 = 0x20;
    pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
}

/// Windows wait return codes
pub mod wait_result {
    /// The specified object is in the signaled state
    pub const WAIT_OBJECT_0: u32 = 0x00000000;
    /// The time-out interval elapsed, and the object's state is nonsignaled
    pub const WAIT_TIMEOUT: u32 = 0x00000102;
    /// The wait failed
    pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
}

/// Thread creation flags
pub mod thread_flags {
    /// Thread is created in a suspended state
    pub const CREATE_SUSPENDED: u32 = 0x00000004;
    /// Default stack size
    pub const DEFAULT_STACK_SIZE: usize = 1024 * 1024; // 1 MB
}

/// Registry root keys (simplified)
pub mod registry_keys {
    /// HKEY_LOCAL_MACHINE
    pub const HKEY_LOCAL_MACHINE: &str = "HKEY_LOCAL_MACHINE";
    /// HKEY_CURRENT_USER
    pub const HKEY_CURRENT_USER: &str = "HKEY_CURRENT_USER";
    /// HKEY_CLASSES_ROOT
    pub const HKEY_CLASSES_ROOT: &str = "HKEY_CLASSES_ROOT";
}

/// Registry value types (simplified)
pub mod registry_types {
    /// String value
    pub const REG_SZ: u32 = 1;
    /// DWORD value
    pub const REG_DWORD: u32 = 4;
}
