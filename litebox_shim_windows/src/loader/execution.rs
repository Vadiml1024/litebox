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
/// Windows programs access it via the GS segment register.
/// The PEB pointer MUST be at offset 0x60 for x64 Windows compatibility.
///
/// Reference: Windows Internals, Part 1, 7th Edition
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ThreadEnvironmentBlock {
    /// Pointer to the exception list (offset 0x00)
    pub exception_list: u64,
    /// Stack base address (offset 0x08)
    pub stack_base: u64,
    /// Stack limit address (offset 0x10)
    pub stack_limit: u64,
    /// SubSystem TIB (offset 0x18)
    pub sub_system_tib: u64,
    /// Fiber data or version (offset 0x20)
    pub fiber_data: u64,
    /// Arbitrary data slot (offset 0x28)
    pub arbitrary_user_pointer: u64,
    /// Pointer to self - this TEB (offset 0x30)
    pub self_pointer: u64,
    /// Environment pointer (offset 0x38)
    pub environment_pointer: u64,
    /// Client ID - [process ID, thread ID] (offset 0x40)
    pub client_id: [u64; 2],
    /// Reserved fields to reach offset 0x60 (offset 0x50-0x58)
    _reserved: [u64; 2],
    /// Pointer to PEB - MUST be at offset 0x60 for x64 Windows
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
            _reserved: [0; 2], // Fixed to 2 u64s to reach offset 0x60
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
    /// Inherited address space (offset 0x00)
    pub inherited_address_space: u8,
    /// Read image file exec options (offset 0x01)
    pub read_image_file_exec_options: u8,
    /// Being debugged flag (offset 0x02)
    pub being_debugged: u8,
    /// Bit field flags (offset 0x03)
    pub bit_field: u8,
    /// Reserved padding (offset 0x04-0x07)
    _padding: [u8; 4],
    /// Mutant (offset 0x08)
    pub mutant: u64,
    /// Image base address (offset 0x10)
    pub image_base_address: u64,
    /// Loader data pointer (offset 0x18) - initialized to non-null to prevent crashes
    pub ldr: u64,
    /// Process parameters pointer (offset 0x20) - initialized to non-null
    pub process_parameters: u64,
    /// Additional reserved fields
    _reserved: [u64; 50],
}

/// PEB_LDR_DATA - Minimal stub for module loader information
///
/// This structure contains information about loaded modules.
/// We provide a minimal stub to prevent crashes when CRT accesses it.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PebLdrData {
    /// Length of this structure
    pub length: u32,
    /// Initialized flag
    pub initialized: u32,
    /// SS handle (not used)
    pub ss_handle: u64,
    /// In load order module list (LIST_ENTRY)
    pub in_load_order_module_list: [u64; 2],
    /// In memory order module list (LIST_ENTRY)
    pub in_memory_order_module_list: [u64; 2],
    /// In initialization order module list (LIST_ENTRY) 
    pub in_initialization_order_module_list: [u64; 2],
    /// Entry in progress (not used)
    pub entry_in_progress: u64,
}

impl PebLdrData {
    /// Create a new minimal PEB_LDR_DATA structure
    ///
    /// # Arguments
    /// * `self_address` - Address where this structure will be stored (for LIST_ENTRY)
    pub fn new_with_address(self_address: u64) -> Self {
        // Calculate offsets for the list heads
        // in_load_order_module_list starts at offset 0x10 (16)
        let load_order_offset = 0x10u64;
        let memory_order_offset = 0x20u64;
        let init_order_offset = 0x30u64;

        Self {
            length: std::mem::size_of::<Self>() as u32,
            initialized: 1, // Mark as initialized
            ss_handle: 0,
            // Initialize list heads to point to themselves (empty circular list)
            // Format: [Flink, Blink] where both point to the list head itself
            in_load_order_module_list: [
                self_address + load_order_offset,
                self_address + load_order_offset,
            ],
            in_memory_order_module_list: [
                self_address + memory_order_offset,
                self_address + memory_order_offset,
            ],
            in_initialization_order_module_list: [
                self_address + init_order_offset,
                self_address + init_order_offset,
            ],
            entry_in_progress: 0,
        }
    }

    /// Create a new minimal PEB_LDR_DATA structure with null lists
    /// 
    /// Use this when the address is not yet known
    pub fn new() -> Self {
        Self {
            length: std::mem::size_of::<Self>() as u32,
            initialized: 1, // Mark as initialized
            ss_handle: 0,
            // Initialize list heads to zero (will be updated later if needed)
            in_load_order_module_list: [0, 0],
            in_memory_order_module_list: [0, 0],
            in_initialization_order_module_list: [0, 0],
            entry_in_progress: 0,
        }
    }
}

/// RTL_USER_PROCESS_PARAMETERS - Minimal stub for process parameters
///
/// Contains command line, environment, and other process startup information.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RtlUserProcessParameters {
    /// Maximum length
    pub maximum_length: u32,
    /// Length
    pub length: u32,
    /// Flags
    pub flags: u32,
    /// Debug flags
    pub debug_flags: u32,
    /// Console handle
    pub console_handle: u64,
    /// Console flags
    pub console_flags: u32,
    /// Padding
    _padding: u32,
    /// Standard input handle
    pub standard_input: u64,
    /// Standard output handle
    pub standard_output: u64,
    /// Standard error handle  
    pub standard_error: u64,
    /// Additional fields (simplified)
    _reserved: [u64; 20],
}

impl RtlUserProcessParameters {
    /// Create a new minimal RTL_USER_PROCESS_PARAMETERS structure
    pub fn new() -> Self {
        Self {
            maximum_length: std::mem::size_of::<Self>() as u32,
            length: std::mem::size_of::<Self>() as u32,
            flags: 0,
            debug_flags: 0,
            console_handle: 0,
            console_flags: 0,
            _padding: 0,
            standard_input: 0,
            standard_output: 0,
            standard_error: 0,
            _reserved: [0; 20],
        }
    }
}

impl ProcessEnvironmentBlock {
    /// Create a new PEB with the given image base address
    ///
    /// Initializes PEB with minimal stubs for Ldr and ProcessParameters
    /// to prevent crashes when CRT code accesses these fields.
    pub fn new(image_base_address: u64, ldr: u64, process_parameters: u64) -> Self {
        Self {
            inherited_address_space: 0,
            read_image_file_exec_options: 0,
            being_debugged: 0,
            bit_field: 0,
            _padding: [0; 4],
            mutant: 0,
            image_base_address,
            ldr,
            process_parameters,
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
    /// PEB Loader Data
    pub ldr: Box<PebLdrData>,
    /// Process Parameters
    pub process_parameters: Box<RtlUserProcessParameters>,
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

        // Create PEB Loader Data - first without address
        let mut ldr = Box::new(PebLdrData::new());
        let ldr_address = &raw const *ldr as u64;
        
        // Now update with proper circular list pointers
        *ldr = PebLdrData::new_with_address(ldr_address);

        // Create Process Parameters
        let process_parameters = Box::new(RtlUserProcessParameters::new());
        let process_parameters_address = &raw const *process_parameters as u64;

        // Create PEB with pointers to Ldr and ProcessParameters
        let peb = Box::new(ProcessEnvironmentBlock::new(
            image_base,
            ldr_address,
            process_parameters_address,
        ));
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
            ldr,
            process_parameters,
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
                libc::munmap(
                    stack_ptr.cast::<libc::c_void>(),
                    self.stack_size as libc::size_t,
                );
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

    // Windows x64 calling convention requires RSP to be 16-byte aligned
    // BEFORE the call instruction executes. The call instruction then pushes
    // an 8-byte return address, resulting in RSP being misaligned by 8 bytes
    // at function entry (this is correct per the ABI).
    //
    // The stack grows downward, so stack_base is the highest address.
    // We need to reserve "shadow space" (32 bytes minimum) required by the
    // Windows x64 calling convention for the first 4 register parameters.

    let stack_top = context.stack_base;

    // Align to 16 bytes (BEFORE call instruction)
    let aligned_stack = stack_top & !0xF;

    // Reserve shadow space (32 bytes) - required by Windows x64 ABI
    // After subtracting 32, RSP is still 16-byte aligned (32 is multiple of 16)
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

            // Switch to the new stack (already properly aligned)
            "mov rsp, {new_stack}",

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

            // Explicitly list clobbered registers instead of using clobber_abi
            // The Windows x64 calling convention can clobber: rax, rcx, rdx, r8-r11, xmm0-xmm5
            // We preserve: rbx, rbp, rdi, rsi, rsp, r12-r15, xmm6-xmm15
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
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
        let ldr_address = 0x7FFF_0000_0000u64;
        let process_params_address = 0x7FFF_0001_0000u64;
        let peb = ProcessEnvironmentBlock::new(image_base, ldr_address, process_params_address);

        assert_eq!(peb.image_base_address, image_base);
        assert_eq!(peb.ldr, ldr_address);
        assert_eq!(peb.process_parameters, process_params_address);
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
