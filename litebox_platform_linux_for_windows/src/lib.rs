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

use thiserror::Error;

use litebox_shim_windows::syscalls::ntdll::{ConsoleHandle, FileHandle, NtdllApi};

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
}

pub type Result<T> = core::result::Result<T, PlatformError>;

/// Windows file handle (maps to Linux FD)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WinHandle(u64);

/// Linux platform for Windows API implementation
pub struct LinuxPlatformForWindows {
    /// Handle to file descriptor mapping
    handles: HashMap<u64, File>,
    /// Next handle ID
    next_handle: u64,
}

impl LinuxPlatformForWindows {
    /// Create a new platform instance
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle: 0x1000, // Start at a high value to avoid conflicts
        }
    }

    /// Allocate a new handle ID
    fn allocate_handle(&mut self) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    /// NtCreateFile - Create or open a file
    pub fn nt_create_file(
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

    /// NtReadFile - Read from a file
    pub fn nt_read_file(&mut self, handle: u64, buffer: &mut [u8]) -> Result<usize> {
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(file.read(buffer)?)
    }

    /// NtWriteFile - Write to a file
    pub fn nt_write_file(&mut self, handle: u64, buffer: &[u8]) -> Result<usize> {
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(file.write(buffer)?)
    }

    /// NtClose - Close a handle
    pub fn nt_close(&mut self, handle: u64) -> Result<()> {
        self.handles
            .remove(&handle)
            .ok_or(PlatformError::InvalidHandle(handle))?;
        Ok(())
    }

    /// Get standard output handle
    pub fn get_std_output(&self) -> u64 {
        // Use a special handle value for stdout
        0xFFFF_FFFF_0001
    }

    /// Write to console
    pub fn write_console(&mut self, handle: u64, text: &str) -> Result<usize> {
        if handle == 0xFFFF_FFFF_0001 {
            print!("{text}");
            std::io::stdout().flush()?;
            Ok(text.len())
        } else {
            Err(PlatformError::InvalidHandle(handle))
        }
    }

    /// NtAllocateVirtualMemory - Allocate virtual memory
    pub fn nt_allocate_virtual_memory(&mut self, size: usize, protect: u32) -> Result<u64> {
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

    /// NtFreeVirtualMemory - Free virtual memory
    pub fn nt_free_virtual_memory(&mut self, address: u64, size: usize) -> Result<()> {
        // SAFETY: munmap is called with valid parameters
        let result = unsafe { libc::munmap(address as *mut libc::c_void, size) };

        if result != 0 {
            return Err(PlatformError::MemoryError("munmap failed".to_string()));
        }

        Ok(())
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
            .nt_create_file(path, access, create_disposition)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))?;
        Ok(FileHandle(handle))
    }

    fn nt_read_file(
        &mut self,
        handle: FileHandle,
        buffer: &mut [u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_read_file(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_write_file(
        &mut self,
        handle: FileHandle,
        buffer: &[u8],
    ) -> litebox_shim_windows::Result<usize> {
        self.nt_write_file(handle.0, buffer)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_close(&mut self, handle: FileHandle) -> litebox_shim_windows::Result<()> {
        self.nt_close(handle.0)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn get_std_output(&self) -> ConsoleHandle {
        ConsoleHandle(self.get_std_output())
    }

    fn write_console(
        &mut self,
        handle: ConsoleHandle,
        text: &str,
    ) -> litebox_shim_windows::Result<usize> {
        self.write_console(handle.0, text)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_allocate_virtual_memory(
        &mut self,
        size: usize,
        protect: u32,
    ) -> litebox_shim_windows::Result<u64> {
        self.nt_allocate_virtual_memory(size, protect)
            .map_err(|e| litebox_shim_windows::WindowsShimError::IoError(e.to_string()))
    }

    fn nt_free_virtual_memory(
        &mut self,
        address: u64,
        size: usize,
    ) -> litebox_shim_windows::Result<()> {
        self.nt_free_virtual_memory(address, size)
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
}
