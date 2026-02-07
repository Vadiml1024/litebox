// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NTDLL API interface
//!
//! This module defines the Windows NTDLL API interface for Phase 2:
//! - File I/O (NtCreateFile, NtReadFile, NtWriteFile, NtClose)
//! - Console I/O
//! - Memory management (NtAllocateVirtualMemory, NtFreeVirtualMemory)

use crate::Result;

/// Windows file handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHandle(pub u64);

/// Windows console handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleHandle(pub u64);

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
