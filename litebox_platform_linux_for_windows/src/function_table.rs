// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Function implementation table and trampoline linking
//!
//! This module provides the infrastructure to link DLL stub exports
//! to actual platform implementations via trampolines.

use crate::{LinuxPlatformForWindows, Result};
use litebox_shim_windows::loader::dispatch::generate_trampoline;

/// Function implementation entry
pub struct FunctionImpl {
    /// Function name (e.g., "NtCreateFile")
    pub name: &'static str,
    /// DLL name (e.g., "KERNEL32.dll", "NTDLL.dll")
    pub dll_name: &'static str,
    /// Number of parameters
    pub num_params: usize,
    /// Implementation function address
    pub impl_address: usize,
}

/// Get the table of all function implementations
///
/// This table maps Windows API functions to their Linux platform implementations.
/// Each entry specifies:
/// - The function name
/// - The DLL it belongs to
/// - The number of parameters (for trampoline generation)
/// - The address of the implementation function
///
/// The implementation functions are external C functions defined in the
/// MSVCRT module and platform layer.
pub fn get_function_table() -> Vec<FunctionImpl> {
    vec![
        // MSVCRT.dll functions - these are defined in msvcrt.rs
        FunctionImpl {
            name: "malloc",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_malloc as *const () as usize,
        },
        FunctionImpl {
            name: "free",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_free as *const () as usize,
        },
        FunctionImpl {
            name: "calloc",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_calloc as *const () as usize,
        },
        FunctionImpl {
            name: "memcpy",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memcpy as *const () as usize,
        },
        FunctionImpl {
            name: "memmove",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memmove as *const () as usize,
        },
        FunctionImpl {
            name: "memset",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memset as *const () as usize,
        },
        FunctionImpl {
            name: "memcmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_memcmp as *const () as usize,
        },
        FunctionImpl {
            name: "strlen",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_strlen as *const () as usize,
        },
        FunctionImpl {
            name: "strncmp",
            dll_name: "MSVCRT.dll",
            num_params: 3,
            impl_address: crate::msvcrt::msvcrt_strncmp as *const () as usize,
        },
        FunctionImpl {
            name: "printf",
            dll_name: "MSVCRT.dll",
            num_params: 1, // Variadic, but at least 1
            impl_address: crate::msvcrt::msvcrt_printf as *const () as usize,
        },
        FunctionImpl {
            name: "fprintf",
            dll_name: "MSVCRT.dll",
            num_params: 2, // Variadic, but at least 2
            impl_address: crate::msvcrt::msvcrt_fprintf as *const () as usize,
        },
        FunctionImpl {
            name: "fwrite",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt_fwrite as *const () as usize,
        },
        FunctionImpl {
            name: "__getmainargs",
            dll_name: "MSVCRT.dll",
            num_params: 5,
            impl_address: crate::msvcrt::msvcrt___getmainargs as *const () as usize,
        },
        FunctionImpl {
            name: "__set_app_type",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt___set_app_type as *const () as usize,
        },
        FunctionImpl {
            name: "_initterm",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt__initterm as *const () as usize,
        },
        FunctionImpl {
            name: "signal",
            dll_name: "MSVCRT.dll",
            num_params: 2,
            impl_address: crate::msvcrt::msvcrt_signal as *const () as usize,
        },
        FunctionImpl {
            name: "abort",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt_abort as *const () as usize,
        },
        FunctionImpl {
            name: "exit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt_exit as *const () as usize,
        },
    ]
}

impl LinuxPlatformForWindows {
    /// Initialize function trampolines for all supported functions
    ///
    /// This generates trampolines that bridge the Windows x64 calling convention
    /// to the System V AMD64 calling convention used by our platform implementations.
    ///
    /// # Safety
    /// This function allocates executable memory and writes machine code to it.
    /// The generated trampolines must only be called from Windows x64 calling
    /// convention code.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub unsafe fn initialize_trampolines(&self) -> Result<()> {
        let function_table = get_function_table();
        let state = self.state.lock().unwrap();

        for func in function_table {
            // Generate trampoline code
            let trampoline_code = generate_trampoline(func.num_params, func.impl_address as u64);

            // Allocate and write the trampoline
            #[cfg_attr(not(debug_assertions), allow(unused_variables))]
            let trampoline_addr = unsafe {
                state.trampoline_manager.allocate_trampoline(
                    format!("{}::{}", func.dll_name, func.name),
                    &trampoline_code,
                )?
            };

            // Log successful initialization (in debug builds)
            #[cfg(debug_assertions)]
            eprintln!(
                "Initialized trampoline for {}::{} at 0x{:X}",
                func.dll_name, func.name, trampoline_addr
            );
        }

        Ok(())
    }

    /// Link trampolines to DLL manager
    ///
    /// This updates the DLL export addresses to use actual trampoline addresses
    /// instead of stub addresses. Must be called after `initialize_trampolines()`.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn link_trampolines_to_dll_manager(&self) -> Result<()> {
        let function_table = get_function_table();
        let mut state = self.state.lock().unwrap();

        for func in function_table {
            // Get the trampoline address
            if let Some(trampoline_addr) = state
                .trampoline_manager
                .get_trampoline(&format!("{}::{}", func.dll_name, func.name))
            {
                // Update the DLL manager with the real address
                state
                    .dll_manager
                    .update_export_address(func.dll_name, func.name, trampoline_addr)
                    .ok(); // Ignore errors - function may not be in DLL exports yet

                // Log successful linking (in debug builds)
                #[cfg(debug_assertions)]
                eprintln!(
                    "Linked trampoline for {}::{} at 0x{:X}",
                    func.dll_name, func.name, trampoline_addr
                );
            }
        }

        Ok(())
    }

    /// Get the trampoline address for a specific function
    ///
    /// Returns the address of the trampoline that can be called from Windows
    /// x64 calling convention code.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn get_trampoline_address(&self, dll_name: &str, function_name: &str) -> Option<usize> {
        let state = self.state.lock().unwrap();
        state
            .trampoline_manager
            .get_trampoline(&format!("{dll_name}::{function_name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_table() {
        let table = get_function_table();
        assert!(!table.is_empty());

        // Verify all entries have valid data
        for func in &table {
            assert!(!func.name.is_empty());
            assert!(!func.dll_name.is_empty());
            assert_ne!(func.impl_address, 0);
        }
    }

    #[test]
    fn test_initialize_trampolines() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization
        let result = unsafe { platform.initialize_trampolines() };
        assert!(result.is_ok());

        // Verify we can retrieve trampoline addresses
        let malloc_addr = platform.get_trampoline_address("MSVCRT.dll", "malloc");
        assert!(malloc_addr.is_some());
        assert_ne!(malloc_addr.unwrap(), 0);

        let free_addr = platform.get_trampoline_address("MSVCRT.dll", "free");
        assert!(free_addr.is_some());
        assert_ne!(free_addr.unwrap(), 0);

        // Addresses should be different
        assert_ne!(malloc_addr, free_addr);
    }

    #[test]
    fn test_get_nonexistent_trampoline() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization
        let _ = unsafe { platform.initialize_trampolines() };

        let addr = platform.get_trampoline_address("KERNEL32.dll", "NonExistentFunction");
        assert!(addr.is_none());
    }

    #[test]
    fn test_link_trampolines_to_dll_manager() {
        let platform = LinuxPlatformForWindows::new();

        // SAFETY: We're testing trampoline initialization and linking
        unsafe {
            platform.initialize_trampolines().unwrap();
        }
        platform.link_trampolines_to_dll_manager().unwrap();

        // Verify that MSVCRT exports now have trampoline addresses
        let mut state = platform.state.lock().unwrap();

        // Load MSVCRT.dll handle
        let msvcrt_handle = state.dll_manager.load_library("MSVCRT.dll").unwrap();

        // Check that malloc has a trampoline address
        let malloc_addr = state
            .dll_manager
            .get_proc_address(msvcrt_handle, "malloc")
            .unwrap();

        // The address should not be a stub address (< 0x1000 is too low for real code)
        assert!(malloc_addr > 0x1000);

        // Verify it matches the trampoline manager's address
        let trampoline_addr = state
            .trampoline_manager
            .get_trampoline("MSVCRT.dll::malloc");
        assert_eq!(Some(malloc_addr), trampoline_addr);
    }
}
