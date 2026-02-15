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

/// Base addresses for stub DLL function pointers
/// Each DLL gets its own address range to avoid collisions
mod stub_addresses {
    /// KERNEL32.dll function address range: 0x1000-0x1FFF
    pub const KERNEL32_BASE: usize = 0x1000;

    /// NTDLL.dll function address range: 0x2000-0x2FFF
    pub const NTDLL_BASE: usize = 0x2000;

    /// MSVCRT.dll function address range: 0x3000-0x3FFF
    pub const MSVCRT_BASE: usize = 0x3000;

    /// bcryptprimitives.dll function address range: 0x4000-0x4FFF
    pub const BCRYPT_BASE: usize = 0x4000;

    /// USERENV.dll function address range: 0x5000-0x5FFF
    pub const USERENV_BASE: usize = 0x5000;

    /// WS2_32.dll function address range: 0x6000-0x6FFF
    pub const WS2_32_BASE: usize = 0x6000;

    /// api-ms-win-core-synch-l1-2-0.dll function address range: 0x7000-0x7FFF
    pub const APIMS_SYNCH_BASE: usize = 0x7000;
}

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
        manager.load_stub_bcryptprimitives();
        manager.load_stub_userenv();
        manager.load_stub_ws2_32();
        manager.load_stub_apims_synch();

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

        // Handle API Set DLLs - these are forwarder DLLs that redirect to real implementations
        // API sets were introduced in Windows 7 and use the naming pattern "api-ms-win-*"
        if normalized_name.starts_with("API-MS-WIN-") || normalized_name.starts_with("EXT-MS-WIN-")
        {
            // Map API set DLLs to their real implementation DLL
            let impl_dll = map_api_set_to_implementation(&normalized_name);

            // Check if we have the implementation DLL loaded
            if let Some(&handle) = self.dll_by_name.get(&impl_dll.to_uppercase()) {
                // Alias the API set name to the same handle
                self.dll_by_name.insert(normalized_name, handle);
                return Ok(handle);
            }

            // If implementation isn't loaded, return error
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "API Set DLL {name} maps to {impl_dll}, which is not loaded"
            )));
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

    /// Update the address of an exported function
    ///
    /// This is used to replace stub addresses with actual trampoline addresses
    /// after initialization.
    ///
    /// # Panics
    /// Panics if attempting to update a function in a DLL that doesn't exist or
    /// if the function doesn't exist in that DLL's export table.
    pub fn update_export_address(
        &mut self,
        dll_name: &str,
        function_name: &str,
        new_address: DllFunction,
    ) -> Result<()> {
        let normalized_name = dll_name.to_uppercase();
        let handle = self.dll_by_name.get(&normalized_name).ok_or_else(|| {
            WindowsShimError::UnsupportedFeature(format!("DLL not found: {dll_name}"))
        })?;

        let dll = self.dlls.get_mut(handle).ok_or_else(|| {
            WindowsShimError::InvalidParameter(format!("Invalid DLL handle: {handle:?}"))
        })?;

        if !dll.exports.contains_key(function_name) {
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "Function {function_name} not found in {dll_name}"
            )));
        }

        dll.exports.insert(function_name.to_string(), new_address);
        Ok(())
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
        use stub_addresses::KERNEL32_BASE;

        // For now, use stub addresses (will be replaced with actual implementations)
        let exports = vec![
            ("LoadLibraryA", KERNEL32_BASE),
            ("LoadLibraryW", KERNEL32_BASE + 1),
            ("GetProcAddress", KERNEL32_BASE + 2),
            ("FreeLibrary", KERNEL32_BASE + 3),
            ("GetStdHandle", KERNEL32_BASE + 4),
            ("WriteConsoleW", KERNEL32_BASE + 5),
            ("CreateFileW", KERNEL32_BASE + 6),
            ("ReadFile", KERNEL32_BASE + 7),
            ("WriteFile", KERNEL32_BASE + 8),
            ("CloseHandle", KERNEL32_BASE + 9),
            // Synchronization functions (from API set api-ms-win-core-synch-l1-2-0.dll)
            ("WaitOnAddress", KERNEL32_BASE + 0xA),
            ("WakeByAddressAll", KERNEL32_BASE + 0xB),
            ("WakeByAddressSingle", KERNEL32_BASE + 0xC),
            // Phase 7: Command-line and file operations
            ("GetCommandLineW", KERNEL32_BASE + 0xD),
            ("FindFirstFileExW", KERNEL32_BASE + 0xE),
            ("FindNextFileW", KERNEL32_BASE + 0xF),
            ("FindClose", KERNEL32_BASE + 0x10),
            // Phase 7: Process and thread information
            ("GetCurrentProcessId", KERNEL32_BASE + 0x11),
            ("GetCurrentThreadId", KERNEL32_BASE + 0x12),
            ("GetCurrentProcess", KERNEL32_BASE + 0x13),
            ("GetCurrentThread", KERNEL32_BASE + 0x14),
            // Phase 7: Error handling
            ("GetLastError", KERNEL32_BASE + 0x15),
            ("SetLastError", KERNEL32_BASE + 0x16),
            // Phase 7: Memory operations
            ("VirtualProtect", KERNEL32_BASE + 0x17),
            ("VirtualQuery", KERNEL32_BASE + 0x18),
            ("HeapAlloc", KERNEL32_BASE + 0x19),
            ("HeapFree", KERNEL32_BASE + 0x1A),
            ("HeapReAlloc", KERNEL32_BASE + 0x1B),
            ("GetProcessHeap", KERNEL32_BASE + 0x1C),
            // Phase 7: Environment and system info
            ("GetEnvironmentVariableW", KERNEL32_BASE + 0x1D),
            ("SetEnvironmentVariableW", KERNEL32_BASE + 0x1E),
            ("GetEnvironmentStringsW", KERNEL32_BASE + 0x1F),
            ("FreeEnvironmentStringsW", KERNEL32_BASE + 0x20),
            ("GetSystemInfo", KERNEL32_BASE + 0x21),
            // Phase 7: Module handling
            ("GetModuleHandleW", KERNEL32_BASE + 0x22),
            ("GetModuleHandleA", KERNEL32_BASE + 0x23),
            ("GetModuleFileNameW", KERNEL32_BASE + 0x24),
            // Phase 7: Console
            ("GetConsoleMode", KERNEL32_BASE + 0x25),
            ("ReadConsoleW", KERNEL32_BASE + 0x26),
            ("GetConsoleOutputCP", KERNEL32_BASE + 0x27),
            // Phase 7: Threading and timing
            ("Sleep", KERNEL32_BASE + 0x28),
            // Phase 7: Exit
            ("ExitProcess", KERNEL32_BASE + 0x29),
            // Phase 7: Thread Local Storage (TLS)
            ("TlsAlloc", KERNEL32_BASE + 0x2A),
            ("TlsFree", KERNEL32_BASE + 0x2B),
            ("TlsGetValue", KERNEL32_BASE + 0x2C),
            ("TlsSetValue", KERNEL32_BASE + 0x2D),
        ];

        self.register_stub_dll("KERNEL32.dll", exports);
    }

    /// Load stub NTDLL.dll
    fn load_stub_ntdll(&mut self) {
        use stub_addresses::NTDLL_BASE;

        let exports = vec![
            ("NtCreateFile", NTDLL_BASE),
            ("NtReadFile", NTDLL_BASE + 1),
            ("NtWriteFile", NTDLL_BASE + 2),
            ("NtClose", NTDLL_BASE + 3),
            ("NtAllocateVirtualMemory", NTDLL_BASE + 4),
            ("NtFreeVirtualMemory", NTDLL_BASE + 5),
            // Additional NTDLL functions
            ("NtOpenFile", NTDLL_BASE + 6),
            ("NtCreateNamedPipeFile", NTDLL_BASE + 7),
            ("RtlNtStatusToDosError", NTDLL_BASE + 8),
        ];

        self.register_stub_dll("NTDLL.dll", exports);
    }

    /// Load stub MSVCRT.dll
    fn load_stub_msvcrt(&mut self) {
        use stub_addresses::MSVCRT_BASE;

        let exports = vec![
            ("printf", MSVCRT_BASE),
            ("malloc", MSVCRT_BASE + 1),
            ("free", MSVCRT_BASE + 2),
            ("exit", MSVCRT_BASE + 3),
            // Additional CRT functions needed by Rust binaries
            ("calloc", MSVCRT_BASE + 4),
            ("memcmp", MSVCRT_BASE + 5),
            ("memcpy", MSVCRT_BASE + 6),
            ("memmove", MSVCRT_BASE + 7),
            ("memset", MSVCRT_BASE + 8),
            ("strlen", MSVCRT_BASE + 9),
            ("strncmp", MSVCRT_BASE + 0xA),
            ("fprintf", MSVCRT_BASE + 0xB),
            ("vfprintf", MSVCRT_BASE + 0xC),
            ("fwrite", MSVCRT_BASE + 0xD),
            ("signal", MSVCRT_BASE + 0xE),
            ("abort", MSVCRT_BASE + 0xF),
            // MinGW-specific CRT initialization functions
            ("__getmainargs", MSVCRT_BASE + 0x10),
            ("__initenv", MSVCRT_BASE + 0x11),
            ("__iob_func", MSVCRT_BASE + 0x12),
            ("__set_app_type", MSVCRT_BASE + 0x13),
            ("__setusermatherr", MSVCRT_BASE + 0x14),
            ("_amsg_exit", MSVCRT_BASE + 0x15),
            ("_cexit", MSVCRT_BASE + 0x16),
            ("_commode", MSVCRT_BASE + 0x17),
            ("_fmode", MSVCRT_BASE + 0x18),
            ("_fpreset", MSVCRT_BASE + 0x19),
            ("_initterm", MSVCRT_BASE + 0x1A),
            ("_onexit", MSVCRT_BASE + 0x1B),
        ];

        self.register_stub_dll("MSVCRT.dll", exports);
    }

    /// Load stub bcryptprimitives.dll
    fn load_stub_bcryptprimitives(&mut self) {
        use stub_addresses::BCRYPT_BASE;

        let exports = vec![
            // Cryptographic PRNG function
            ("ProcessPrng", BCRYPT_BASE),
        ];

        self.register_stub_dll("bcryptprimitives.dll", exports);
    }

    /// Load stub USERENV.dll
    fn load_stub_userenv(&mut self) {
        use stub_addresses::USERENV_BASE;

        let exports = vec![
            // User profile directory function
            ("GetUserProfileDirectoryW", USERENV_BASE),
        ];

        self.register_stub_dll("USERENV.dll", exports);
    }

    /// Load stub WS2_32.dll (Windows Sockets 2)
    fn load_stub_ws2_32(&mut self) {
        use stub_addresses::WS2_32_BASE;

        let exports = vec![
            // Winsock initialization and cleanup
            ("WSAStartup", WS2_32_BASE),
            ("WSACleanup", WS2_32_BASE + 1),
            ("WSAGetLastError", WS2_32_BASE + 2),
            // Socket operations
            ("WSASocketW", WS2_32_BASE + 3),
            ("socket", WS2_32_BASE + 4),
            ("closesocket", WS2_32_BASE + 5),
            // Connection operations
            ("bind", WS2_32_BASE + 6),
            ("listen", WS2_32_BASE + 7),
            ("accept", WS2_32_BASE + 8),
            ("connect", WS2_32_BASE + 9),
            // Data transfer
            ("send", WS2_32_BASE + 0xA),
            ("recv", WS2_32_BASE + 0xB),
            ("sendto", WS2_32_BASE + 0xC),
            ("recvfrom", WS2_32_BASE + 0xD),
            ("WSASend", WS2_32_BASE + 0xE),
            ("WSARecv", WS2_32_BASE + 0xF),
            // Socket information and control
            ("getsockname", WS2_32_BASE + 0x10),
            ("getpeername", WS2_32_BASE + 0x11),
            ("getsockopt", WS2_32_BASE + 0x12),
            ("setsockopt", WS2_32_BASE + 0x13),
            ("ioctlsocket", WS2_32_BASE + 0x14),
            // Name resolution
            ("getaddrinfo", WS2_32_BASE + 0x15),
            ("freeaddrinfo", WS2_32_BASE + 0x16),
            ("GetHostNameW", WS2_32_BASE + 0x17),
            // Misc
            ("select", WS2_32_BASE + 0x18),
            ("shutdown", WS2_32_BASE + 0x19),
            ("WSADuplicateSocketW", WS2_32_BASE + 0x1A),
        ];

        self.register_stub_dll("WS2_32.dll", exports);
    }

    /// Load stub api-ms-win-core-synch-l1-2-0.dll
    fn load_stub_apims_synch(&mut self) {
        use stub_addresses::APIMS_SYNCH_BASE;

        let exports = vec![
            // Modern synchronization primitives
            ("WaitOnAddress", APIMS_SYNCH_BASE),
            ("WakeByAddressAll", APIMS_SYNCH_BASE + 1),
            ("WakeByAddressSingle", APIMS_SYNCH_BASE + 2),
        ];

        self.register_stub_dll("api-ms-win-core-synch-l1-2-0.dll", exports);
    }
}

/// Map Windows API Set DLL names to their real implementation DLLs
///
/// Windows uses API Sets as a layer of indirection between applications and
/// the actual DLL implementations. This allows Microsoft to refactor their
/// implementation without breaking compatibility.
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets>
fn map_api_set_to_implementation(api_set_name: &str) -> &'static str {
    let name_upper = api_set_name.to_uppercase();

    // Core Process/Thread APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-PROCESSTHREADS-") {
        return "KERNEL32.dll";
    }

    // Synchronization APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-SYNCH-") {
        return "KERNEL32.dll";
    }

    // Memory APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-MEMORY-") {
        return "KERNEL32.dll";
    }

    // File I/O APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-FILE-") {
        return "KERNEL32.dll";
    }

    // Console APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-CONSOLE-") {
        return "KERNEL32.dll";
    }

    // Handle APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-HANDLE-") {
        return "KERNEL32.dll";
    }

    // Library Loader APIs -> KERNEL32.dll
    if name_upper.starts_with("API-MS-WIN-CORE-LIBRARYLOADER-") {
        return "KERNEL32.dll";
    }

    // NT DLL APIs -> NTDLL.dll
    if name_upper.starts_with("API-MS-WIN-CORE-RTLSUPPORT-") {
        return "NTDLL.dll";
    }

    // C Runtime APIs -> MSVCRT.dll or UCRTBASE.dll
    if name_upper.starts_with("API-MS-WIN-CRT-") {
        return "UCRTBASE.dll";
    }

    // Default to KERNEL32.dll for unknown API sets
    // Most API sets forward to KERNEL32
    "KERNEL32.dll"
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
        // Should have 7 pre-loaded stub DLLs (KERNEL32, NTDLL, MSVCRT, bcryptprimitives, USERENV, WS2_32, api-ms-win-core-synch-l1-2-0)
        assert_eq!(manager.dlls.len(), 7);
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
