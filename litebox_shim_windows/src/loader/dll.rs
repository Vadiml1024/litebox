// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! DLL loading and management
//!
//! This module provides:
//! - DLL handle management
//! - Function export lookups
//! - Stub DLL implementations for common Windows DLLs

use crate::{Result, WindowsShimError};
extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Type for a DLL function pointer
pub type DllFunction = usize;

/// Type for a function implementation callback
///
/// This is called when a Windows API function needs to be executed.
/// The callback receives the function name and can dispatch to the appropriate implementation.
pub type FunctionCallback = fn(dll_name: &str, function_name: &str) -> Option<DllFunction>;

/// Handle to a loaded DLL
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DllHandle(u64);

impl DllHandle {
    /// Create a new DLL handle from a raw value
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Get the raw handle value
    pub const fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Information about a single exported function
#[derive(Debug, Clone)]
pub struct ExportedFunction {
    /// Function name
    pub name: String,
    /// Function address (stub implementation)
    pub address: DllFunction,
}

/// Information about a loaded or stub DLL
#[derive(Debug, Clone)]
pub struct DllInfo {
    /// DLL name (e.g., "KERNEL32.dll")
    pub name: String,
    /// DLL handle
    pub handle: DllHandle,
    /// Exported functions
    pub exports: BTreeMap<String, DllFunction>,
}

/// DLL manager for loading and managing Windows DLLs
pub struct DllManager {
    /// Next DLL handle to allocate
    next_handle: u64,
    /// Loaded DLLs by handle
    dlls: BTreeMap<DllHandle, DllInfo>,
    /// DLL lookup by name (case-insensitive)
    dll_by_name: BTreeMap<String, DllHandle>,
}

impl DllManager {
    /// Create a new DLL manager with common stub DLLs pre-loaded
    pub fn new() -> Self {
        let mut manager = Self {
            next_handle: 1,
            dlls: BTreeMap::new(),
            dll_by_name: BTreeMap::new(),
        };

        // Pre-load common stub DLLs
        manager.load_stub_kernel32();
        manager.load_stub_ntdll();
        manager.load_stub_msvcrt();

        manager
    }

    /// Load a DLL by name (or return existing handle if already loaded)
    pub fn load_library(&mut self, name: &str) -> Result<DllHandle> {
        // Normalize name to uppercase for case-insensitive lookup
        let normalized_name = name.to_uppercase();

        // Check if already loaded
        if let Some(&handle) = self.dll_by_name.get(&normalized_name) {
            return Ok(handle);
        }

        // For now, we only support stub DLLs
        // Real DLL loading would be implemented here
        Err(WindowsShimError::UnsupportedFeature(format!(
            "DLL not found: {name}"
        )))
    }

    /// Get the address of a function in a loaded DLL
    pub fn get_proc_address(&self, handle: DllHandle, name: &str) -> Result<DllFunction> {
        let dll = self.dlls.get(&handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        dll.exports.get(name).copied().ok_or_else(|| {
            WindowsShimError::UnsupportedFeature(format!(
                "Function {name} not found in {}",
                dll.name
            ))
        })
    }

    /// Free a loaded DLL
    pub fn free_library(&mut self, handle: DllHandle) -> Result<()> {
        let dll = self.dlls.remove(&handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        let normalized_name = dll.name.to_uppercase();
        self.dll_by_name.remove(&normalized_name);

        Ok(())
    }

    /// Register a stub DLL with the manager
    fn register_stub_dll(&mut self, name: &str, exports: Vec<(&str, DllFunction)>) -> DllHandle {
        let handle = DllHandle::new(self.next_handle);
        self.next_handle += 1;

        let normalized_name = name.to_uppercase();

        let mut export_map: BTreeMap<String, DllFunction> = BTreeMap::new();
        for (export_name, address) in exports {
            export_map.insert(export_name.to_string(), address);
        }

        let dll_info = DllInfo {
            name: name.to_string(),
            handle,
            exports: export_map,
        };

        self.dlls.insert(handle, dll_info);
        self.dll_by_name.insert(normalized_name, handle);

        handle
    }

    /// Load stub KERNEL32.dll
    fn load_stub_kernel32(&mut self) {
        // For now, use stub addresses (will be replaced with actual implementations)
        let exports = vec![
            ("LoadLibraryA", 0x1000 as DllFunction),
            ("LoadLibraryW", 0x1001 as DllFunction),
            ("GetProcAddress", 0x1002 as DllFunction),
            ("FreeLibrary", 0x1003 as DllFunction),
            ("GetStdHandle", 0x1004 as DllFunction),
            ("WriteConsoleW", 0x1005 as DllFunction),
            ("CreateFileW", 0x1006 as DllFunction),
            ("ReadFile", 0x1007 as DllFunction),
            ("WriteFile", 0x1008 as DllFunction),
            ("CloseHandle", 0x1009 as DllFunction),
        ];

        self.register_stub_dll("KERNEL32.dll", exports);
    }

    /// Load stub NTDLL.dll
    fn load_stub_ntdll(&mut self) {
        let exports = vec![
            ("NtCreateFile", 0x2000 as DllFunction),
            ("NtReadFile", 0x2001 as DllFunction),
            ("NtWriteFile", 0x2002 as DllFunction),
            ("NtClose", 0x2003 as DllFunction),
            ("NtAllocateVirtualMemory", 0x2004 as DllFunction),
            ("NtFreeVirtualMemory", 0x2005 as DllFunction),
        ];

        self.register_stub_dll("NTDLL.dll", exports);
    }

    /// Load stub MSVCRT.dll
    fn load_stub_msvcrt(&mut self) {
        let exports = vec![
            ("printf", 0x3000 as DllFunction),
            ("malloc", 0x3001 as DllFunction),
            ("free", 0x3002 as DllFunction),
            ("exit", 0x3003 as DllFunction),
        ];

        self.register_stub_dll("MSVCRT.dll", exports);
    }
}

impl Default for DllManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dll_manager_creation() {
        let manager = DllManager::new();
        // Should have 3 pre-loaded stub DLLs
        assert_eq!(manager.dlls.len(), 3);
    }

    #[test]
    fn test_load_library_existing() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        assert!(handle.as_raw() > 0);
    }

    #[test]
    fn test_load_library_case_insensitive() {
        let mut manager = DllManager::new();
        let handle1 = manager.load_library("kernel32.dll").unwrap();
        let handle2 = manager.load_library("KERNEL32.DLL").unwrap();
        assert_eq!(handle1, handle2);
    }

    #[test]
    fn test_get_proc_address() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        let func = manager.get_proc_address(handle, "LoadLibraryA");
        assert!(func.is_ok());
    }

    #[test]
    fn test_get_proc_address_not_found() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("KERNEL32.dll").unwrap();
        let result = manager.get_proc_address(handle, "NonExistentFunction");
        assert!(result.is_err());
    }

    #[test]
    fn test_free_library() {
        let mut manager = DllManager::new();
        let handle = manager.load_library("MSVCRT.dll").unwrap();
        let result = manager.free_library(handle);
        assert!(result.is_ok());

        // Should not be able to get proc address after freeing
        let result = manager.get_proc_address(handle, "printf");
        assert!(result.is_err());
    }
}
