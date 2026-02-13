// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows execution context structures and entry point invocation
//!
//! This module implements stub versions of Windows Thread Environment Block (TEB)
//! and Process Environment Block (PEB) structures, along with the machinery to
//! invoke PE entry points with proper ABI translation.

use crate::{Result, WindowsShimError};

/// Thread Environment Block (TEB) - Minimal stub version
///
/// The TEB is a Windows-internal structure that contains thread-specific information.
/// Windows programs access it via the GS segment register (offset 0x30 for PEB pointer).
/// This is a minimal stub that provides only the essential fields.
///
/// Reference: Windows Internals, Part 1, 7th Edition
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ThreadEnvironmentBlock {
    /// Pointer to the exception list (not implemented)
    pub exception_list: u64,
    /// Stack base address
    pub stack_base: u64,
    /// Stack limit address
    pub stack_limit: u64,
    /// SubSystem TIB (not used in our stub)
    pub sub_system_tib: u64,
    /// Fiber data or version (not used)
    pub fiber_data: u64,
    /// Arbitrary data slot (not used)
    pub arbitrary_user_pointer: u64,
    /// Pointer to self (this TEB)
    pub self_pointer: u64,
    /// Environment pointer (not used)
    pub environment_pointer: u64,
    /// Client ID (process ID and thread ID)
    pub client_id: [u64; 2],
    /// Reserved fields
    _reserved: [u64; 10],
    /// Pointer to PEB at offset 0x60
    pub peb_pointer: u64,
    /// Additional reserved fields
    _reserved2: [u64; 100],
}

impl ThreadEnvironmentBlock {
    /// Create a new TEB with the given stack range and PEB pointer
    pub fn new(stack_base: u64, stack_size: u64, peb_pointer: u64) -> Self {
        Self {
            exception_list: 0,
            stack_base,
            stack_limit: stack_base.saturating_sub(stack_size),
            sub_system_tib: 0,
            fiber_data: 0,
            arbitrary_user_pointer: 0,
            self_pointer: 0, // Will be set after allocation
            environment_pointer: 0,
            client_id: [0; 2], // [process_id, thread_id]
            _reserved: [0; 10],
            peb_pointer,
            _reserved2: [0; 100],
        }
    }

    /// Get the size of the TEB structure in bytes
    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Process Environment Block (PEB) - Minimal stub version
///
/// The PEB is a Windows-internal structure that contains process-wide information.
/// Windows programs access it via the TEB (at offset 0x60).
///
/// Reference: Windows Internals, Part 1, 7th Edition
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessEnvironmentBlock {
    /// Inherited address space (not used)
    pub inherited_address_space: u8,
    /// Read image file exec options (not used)
    pub read_image_file_exec_options: u8,
    /// Being debugged flag
    pub being_debugged: u8,
    /// Bit field flags
    pub bit_field: u8,
    /// Reserved padding
    _padding: [u8; 4],
    /// Mutant (not used)
    pub mutant: u64,
    /// Image base address
    pub image_base_address: u64,
    /// Loader data pointer (not implemented)
    pub ldr: u64,
    /// Process parameters pointer (not implemented)
    pub process_parameters: u64,
    /// Additional reserved fields
    _reserved: [u64; 50],
}

impl ProcessEnvironmentBlock {
    /// Create a new PEB with the given image base address
    pub fn new(image_base_address: u64) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding: [0; 4],
            mutant: 0,
            image_base_address,
            ldr: 0,
            process_parameters: 0,
            _reserved: [0; 50],
        }
    }

    /// Get the size of the PEB structure in bytes
    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }
}

/// Windows entry point function signature
///
/// DLL entry points have the signature:
/// ```c
/// BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
/// ```
///
/// EXE entry points have various signatures, but typically:
/// ```c
/// int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
/// int wmain(int argc, wchar_t *argv[]);
/// int main(int argc, char *argv[]);
/// ```
///
/// For simplicity, we'll treat the entry point as a function that takes no arguments
/// and returns an integer exit code.
pub type EntryPointFn = unsafe extern "C" fn() -> i32;

/// Execution context for a Windows program
///
/// This structure holds all the state needed to execute a Windows PE binary,
/// including the TEB, PEB, and stack information.
#[derive(Debug)]
pub struct ExecutionContext {
    /// Thread Environment Block
    pub teb: Box<ThreadEnvironmentBlock>,
    /// Process Environment Block
    pub peb: Box<ProcessEnvironmentBlock>,
    /// TEB address in memory (for self-pointer)
    pub teb_address: u64,
    /// Stack base address
    pub stack_base: u64,
    /// Stack size in bytes
    pub stack_size: u64,
}

impl ExecutionContext {
    /// Create a new execution context with the given parameters
    ///
    /// # Arguments
    /// * `image_base` - Base address where the PE image is loaded
    /// * `stack_size` - Size of the stack to allocate (default 1MB if 0)
    ///
    /// # Returns
    /// A new ExecutionContext with allocated TEB and PEB
    pub fn new(image_base: u64, stack_size: u64) -> Result<Self> {
        let stack_size = if stack_size == 0 {
            1024 * 1024 // Default 1MB stack
        } else {
            stack_size
        };

        // For now, use a placeholder stack address
        // In a real implementation, we would allocate actual stack memory
        let stack_base = 0x0000_7FFF_FFFF_0000u64;

        // Create PEB first
        let peb = Box::new(ProcessEnvironmentBlock::new(image_base));
        let peb_address = &raw const *peb as u64;

        // Create TEB with pointer to PEB
        let mut teb = Box::new(ThreadEnvironmentBlock::new(
            stack_base,
            stack_size,
            peb_address,
        ));

        // Set TEB self-pointer
        let teb_address = &raw const *teb as u64;
        teb.self_pointer = teb_address;

        Ok(Self {
            teb,
            peb,
            teb_address,
            stack_base,
            stack_size,
        })
    }

    /// Get a pointer to the TEB
    pub fn teb_ptr(&self) -> *const ThreadEnvironmentBlock {
        &raw const *self.teb
    }

    /// Get a pointer to the PEB
    pub fn peb_ptr(&self) -> *const ProcessEnvironmentBlock {
        &raw const *self.peb
    }
}

/// Call a Windows PE entry point with proper ABI setup
///
/// This function handles the ABI translation between Linux (System V AMD64) and
/// Windows (Microsoft x64 calling convention).
///
/// # Safety
/// This function is unsafe because:
/// - It calls a function pointer at an arbitrary memory address
/// - It assumes the entry point is valid code
/// - It assumes the memory is executable
/// - No validation is performed on the entry point
///
/// The caller must ensure:
/// - The entry point address points to valid, executable code
/// - The PE binary has been properly loaded and relocated
/// - All imports have been resolved
/// - The execution context is properly initialized
///
/// # Arguments
/// * `entry_point_address` - Address of the entry point to call (base + RVA)
/// * `_context` - Execution context (TEB/PEB) - currently unused but needed for future
///
/// # Returns
/// The exit code returned by the entry point, or an error if execution fails
pub unsafe fn call_entry_point(
    entry_point_address: u64,
    _context: &ExecutionContext,
) -> Result<i32> {
    // Validate entry point is not null
    if entry_point_address == 0 {
        return Err(WindowsShimError::InvalidParameter(
            "Entry point address is null".to_string(),
        ));
    }

    // NOTE: In a full implementation, we would:
    // 1. Set up the GS segment register to point to the TEB
    // 2. Set up the stack pointer to the allocated stack
    // 3. Ensure 16-byte stack alignment
    // 4. Set up initial register state (RCX, RDX, R8, R9 for parameters)
    // 5. Handle any exceptions that occur during execution
    //
    // For now, this is a simplified version that demonstrates the concept.
    // Calling arbitrary code is extremely dangerous and would likely crash.

    // Cast the address to a function pointer
    // This is the core of the ABI translation issue - we're assuming the
    // entry point can be called with no arguments and returns an int.
    // Real Windows entry points have different signatures.
    //
    // SAFETY: We're transmuting a u64 to a function pointer, which is inherently unsafe.
    // The caller must ensure the address points to valid, executable code.
    let entry_fn = unsafe { std::mem::transmute::<u64, EntryPointFn>(entry_point_address) };

    // Call the entry point
    // NOTE: This will almost certainly crash in practice because:
    // - The TEB is not accessible via GS register
    // - The stack is not properly set up
    // - We're not handling the actual Windows calling convention
    // This is a placeholder for demonstration purposes.
    //
    // SAFETY: We're calling a function pointer created from an arbitrary address.
    // The caller must ensure this points to valid code that can be safely executed.
    let exit_code = unsafe { entry_fn() };

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_teb_creation() {
        let stack_base = 0x7FFF_FFFF_0000u64;
        let stack_size = 1024 * 1024; // 1MB
        let peb_ptr = 0x1234_5678u64;

        let teb = ThreadEnvironmentBlock::new(stack_base, stack_size, peb_ptr);

        assert_eq!(teb.stack_base, stack_base);
        assert_eq!(teb.stack_limit, stack_base - stack_size);
        assert_eq!(teb.peb_pointer, peb_ptr);
    }

    #[test]
    fn test_peb_creation() {
        let image_base = 0x0000_0001_4000_0000u64;
        let peb = ProcessEnvironmentBlock::new(image_base);

        assert_eq!(peb.image_base_address, image_base);
        assert_eq!(peb.being_debugged, 0);
    }

    #[test]
    fn test_execution_context_creation() {
        let image_base = 0x0000_0001_4000_0000u64;
        let stack_size = 2 * 1024 * 1024; // 2MB

        let context = ExecutionContext::new(image_base, stack_size).unwrap();

        assert_eq!(context.peb.image_base_address, image_base);
        assert_eq!(context.stack_size, stack_size);
        assert_ne!(context.teb_address, 0);
    }

    #[test]
    fn test_execution_context_default_stack() {
        let image_base = 0x0000_0001_4000_0000u64;

        let context = ExecutionContext::new(image_base, 0).unwrap();

        assert_eq!(context.stack_size, 1024 * 1024); // Default 1MB
    }
}
