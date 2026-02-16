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
    /// Pointer to allocated stack memory (for cleanup)
    stack_ptr: Option<*mut u8>,
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
    ///
    /// # Safety
    /// This function uses mmap to allocate stack memory. The caller must ensure
    /// the ExecutionContext is properly dropped to free the allocated memory.
    pub fn new(image_base: u64, stack_size: u64) -> Result<Self> {
        let stack_size = if stack_size == 0 {
            1024 * 1024 // Default 1MB stack
        } else {
            stack_size
        };

        // Allocate actual stack memory using mmap
        // SAFETY: We're calling mmap with valid parameters to allocate memory
        // for the stack. The memory will be freed in the Drop implementation.
        #[allow(clippy::cast_possible_truncation)]
        let stack_ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                stack_size as libc::size_t,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if stack_ptr == libc::MAP_FAILED {
            return Err(WindowsShimError::MemoryAllocationFailed(
                "Failed to allocate stack memory".to_string(),
            ));
        }

        // Stack grows downward, so stack_base is at the top of the allocated region
        // SAFETY: We just allocated this memory successfully, so it's a valid pointer
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let stack_base = unsafe { stack_ptr.add(stack_size as usize) }.addr() as u64;

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
            stack_ptr: Some(stack_ptr.cast::<u8>()),
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

impl Drop for ExecutionContext {
    fn drop(&mut self) {
        // Clean up allocated stack memory
        if let Some(stack_ptr) = self.stack_ptr {
            // SAFETY: This memory was allocated by mmap in the constructor,
            // so it's safe to unmap it here. We use the original stack_ptr
            // (not stack_base) because munmap expects the address returned by mmap.
            #[allow(clippy::cast_possible_truncation)]
            unsafe {
                libc::munmap(stack_ptr.cast::<libc::c_void>(), self.stack_size as libc::size_t);
            }
        }
    }
}

/// Call a Windows PE entry point with proper ABI setup
///
/// This function handles the ABI translation between Linux (System V AMD64) and
/// Windows (Microsoft x64 calling convention). It sets up a proper stack and
/// calls the entry point with the Windows ABI.
///
/// # Safety
/// This function is unsafe because:
/// - It calls a function pointer at an arbitrary memory address
/// - It assumes the entry point is valid code
/// - It assumes the memory is executable
/// - It switches to a different stack during execution
/// - No validation is performed on the entry point
///
/// The caller must ensure:
/// - The entry point address points to valid, executable code
/// - The PE binary has been properly loaded and relocated
/// - All imports have been resolved
/// - The execution context is properly initialized
/// - The GS register has been set to point to the TEB
///
/// # Arguments
/// * `entry_point_address` - Address of the entry point to call (base + RVA)
/// * `context` - Execution context with TEB/PEB and allocated stack
///
/// # Returns
/// The exit code returned by the entry point, or an error if execution fails
pub unsafe fn call_entry_point(
    entry_point_address: usize,
    context: &ExecutionContext,
) -> Result<i32> {
    // Validate entry point is not null
    if entry_point_address == 0 {
        return Err(WindowsShimError::InvalidParameter(
            "Entry point address is null".to_string(),
        ));
    }

    // Windows x64 calling convention requires the stack to be 16-byte aligned
    // before the call instruction. Since call pushes an 8-byte return address,
    // we need to ensure RSP is 16-byte aligned + 8 before we make the call.
    //
    // The stack grows downward, so stack_base is the highest address.
    // We need to leave some space at the top for the "shadow space" (32 bytes)
    // required by the Windows x64 calling convention for the first 4 parameters.

    let stack_top = context.stack_base;

    // Align to 16 bytes and subtract 8 (so after call pushes return address, it's aligned)
    let aligned_stack = (stack_top & !0xF) - 8;

    // Reserve shadow space (32 bytes) - required by Windows x64 ABI
    let stack_with_shadow = aligned_stack - 32;

    // Call the entry point with proper stack setup
    // We use inline assembly to:
    // 1. Save current RSP
    // 2. Switch to the new stack
    // 3. Call the entry point
    // 4. Restore the original RSP
    // 5. Return the result
    //
    // SAFETY: We're switching stacks and calling arbitrary code. The caller must
    // ensure the entry point is valid code and all imports are resolved.
    let exit_code: i32;
    unsafe {
        core::arch::asm!(
            // Save the current stack pointer
            "push rbp",
            "mov rbp, rsp",

            // Switch to the new stack
            "mov rsp, {new_stack}",

            // Ensure 16-byte alignment (stack should already be aligned from our calculation)
            "and rsp, -16",

            // Call the entry point
            // Note: The entry point might be mainCRTStartup or similar, which
            // expects no parameters. Windows x64 ABI requires shadow space to be
            // allocated by caller even if no parameters are passed.
            "call {entry_point}",

            // Restore the original stack
            "mov rsp, rbp",
            "pop rbp",

            entry_point = in(reg) entry_point_address,
            new_stack = in(reg) stack_with_shadow,
            lateout("rax") exit_code,

            // Clobber list - these registers may be modified by the callee
            clobber_abi("C"),
        );
    }

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
