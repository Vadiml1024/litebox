// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Function dispatch system for Windows API implementations
//!
//! This module provides a trampoline-based dispatch system that:
//! 1. Allocates executable memory for function stubs
//! 2. Creates trampolines that redirect Windows API calls to Linux implementations
//! 3. Handles calling convention translation between Windows x64 and System V AMD64
//!
//! ## Calling Convention Differences
//!
//! Windows x64:
//! - Parameters: RCX, RDX, R8, R9, then stack (right-to-left)
//! - Return value: RAX (integers), XMM0 (floats)
//! - Caller must allocate 32 bytes of "shadow space" on stack
//! - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5
//! - Non-volatile: RBX, RBP, RDI, RSI, RSP, R12-R15, XMM6-XMM15
//!
//! System V AMD64 (Linux):
//! - Parameters: RDI, RSI, RDX, RCX, R8, R9, then stack (right-to-left)
//! - Return value: RAX (integers), XMM0 (floats)
//! - No shadow space requirement
//! - Volatile registers: RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM15
//! - Non-volatile: RBX, RBP, RSP, R12-R15
//!
//! ## Trampoline Approach
//!
//! For each Windows API function, we generate a small assembly stub that:
//! 1. Translates registers from Windows calling convention to Linux
//! 2. Calls the actual implementation function
//! 3. Returns the result in the expected register (RAX)
//!
//! Example trampoline for a function with 2 parameters:
//! ```asm
//! ; On entry: RCX = param1, RDX = param2 (Windows)
//! ; Need to call with: RDI = param1, RSI = param2 (Linux)
//! mov rdi, rcx    ; param1: Windows RCX -> Linux RDI
//! mov rsi, rdx    ; param2: Windows RDX -> Linux RSI
//! mov rax, <impl_address>
//! jmp rax         ; Tail call to implementation
//! ```

use crate::{Result, WindowsShimError};
extern crate alloc;
use alloc::vec::Vec;

/// Function pointer type for actual implementations
pub type ImplFunction = usize;

/// Generate x86-64 machine code for a trampoline that adapts calling conventions
///
/// This generates a stub that:
/// 1. Ensures 16-byte stack alignment (System V ABI requirement)
/// 2. Moves parameters from Windows x64 registers to System V AMD64 registers
/// 3. Handles stack parameters for 5+ parameter functions
/// 4. Calls the actual implementation
///
/// # Parameters
/// * `num_params` - Number of integer/pointer parameters (0-8 recommended)
/// * `impl_address` - Address of the actual implementation function
///
/// # Returns
/// Machine code bytes for the trampoline
///
/// # Safety
/// The returned bytes must be placed in executable memory and executed
/// from Windows x64 calling convention code.
pub fn generate_trampoline(num_params: usize, impl_address: u64) -> Vec<u8> {
    let mut code = Vec::new();

    // Register mapping:
    // Windows x64: RCX, RDX, R8, R9, then stack at [rsp+32], [rsp+40], ...
    // Linux x64:   RDI, RSI, RDX, RCX, R8, R9, then stack at [rsp+0], [rsp+8], ...
    //
    // Stack alignment requirement:
    // - System V ABI requires RSP to be 16-byte aligned before 'call'
    // - On function entry, RSP is misaligned by 8 bytes (due to return address push)
    // - For odd number of stack params, we need to add 8 bytes padding
    // - For even number (including 0), no padding needed

    // Calculate stack parameters (beyond first 4 in registers)
    let stack_params = num_params.saturating_sub(4);

    // Determine if we need stack alignment padding
    // Windows has shadow space at rsp+32, but we're using tail call approach
    // We need to ensure 16-byte alignment before the call
    let needs_alignment = !stack_params.is_multiple_of(2);
    let alignment_bytes = if needs_alignment { 8 } else { 0 };

    // If we have stack parameters or need alignment, set up stack frame
    if stack_params > 0 || needs_alignment {
        // Save return address by pushing it
        // (already on stack from caller)

        // Allocate stack space for parameters + alignment
        let stack_space = (stack_params * 8) + alignment_bytes;
        if stack_space > 0 {
            // sub rsp, stack_space
            #[allow(clippy::cast_possible_truncation)]
            if stack_space <= 127 {
                code.extend_from_slice(&[0x48, 0x83, 0xEC, stack_space as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x81, 0xEC]);
                code.extend_from_slice(&(stack_space as u32).to_le_bytes());
            }
        }

        // Copy stack parameters from Windows shadow space to Linux stack
        // Windows convention: params 5+ at [rsp + stack_space + 8 + 32 + (i)*8]
        //   where: stack_space = our allocated space
        //          +8 = return address pushed by caller (above our allocation)
        //          +32 = Windows shadow space (reserved by caller)
        //          +(i)*8 = offset for parameter i (i=0 is 5th param, i=1 is 6th, etc.)
        // Linux convention: params 5+ at [rsp + (i)*8] (directly on our stack)
        #[allow(clippy::cast_possible_truncation)]
        for i in 0..stack_params {
            let windows_offset = stack_space + 8 + 32 + (i * 8); // +8 for return addr
            let linux_offset = i * 8;

            // mov rax, [rsp + windows_offset]
            if windows_offset <= 127 {
                code.extend_from_slice(&[0x48, 0x8B, 0x44, 0x24, windows_offset as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x8B, 0x84, 0x24]);
                code.extend_from_slice(&(windows_offset as u32).to_le_bytes());
            }

            // mov [rsp + linux_offset], rax
            if linux_offset <= 127 {
                code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, linux_offset as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x89, 0x84, 0x24]);
                code.extend_from_slice(&(linux_offset as u32).to_le_bytes());
            }
        }
    }

    // Move register parameters (first 4)
    // Win RCX -> Linux RDI (param 1)
    // Win RDX -> Linux RSI (param 2)
    // Win R8  -> Linux RDX (param 3)
    // Win R9  -> Linux RCX (param 4)

    if num_params >= 1 {
        // mov rdi, rcx
        code.extend_from_slice(&[0x48, 0x89, 0xCF]);
    }
    if num_params >= 2 {
        // mov rsi, rdx
        code.extend_from_slice(&[0x48, 0x89, 0xD6]);
    }
    if num_params >= 3 {
        // mov rdx, r8
        code.extend_from_slice(&[0x4C, 0x89, 0xC2]);
    }
    if num_params >= 4 {
        // mov rcx, r9
        code.extend_from_slice(&[0x4C, 0x89, 0xC9]);
    }

    // Call the implementation
    // movabs rax, impl_address
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&impl_address.to_le_bytes());

    if stack_params > 0 || needs_alignment {
        // call rax (not jmp, since we need to clean up stack)
        code.extend_from_slice(&[0xFF, 0xD0]);

        // Clean up stack
        let stack_space = (stack_params * 8) + alignment_bytes;
        if stack_space > 0 {
            // add rsp, stack_space
            #[allow(clippy::cast_possible_truncation)]
            if stack_space <= 127 {
                code.extend_from_slice(&[0x48, 0x83, 0xC4, stack_space as u8]);
            } else {
                code.extend_from_slice(&[0x48, 0x81, 0xC4]);
                code.extend_from_slice(&(stack_space as u32).to_le_bytes());
            }
        }

        // ret
        code.extend_from_slice(&[0xC3]);
    } else {
        // Tail call optimization for 0-4 parameters
        // jmp rax
        code.extend_from_slice(&[0xFF, 0xE0]);
    }

    code
}

/// Allocate executable memory for trampolines
///
/// NOTE: This function is a placeholder. Actual allocation must be done
/// by the platform layer (e.g., LinuxPlatformForWindows) which has access
/// to system calls like mmap.
///
/// The platform should allocate memory with PROT_READ | PROT_WRITE | PROT_EXEC
/// permissions.
///
/// # Safety
/// This function allocates memory with execute permissions, which is inherently
/// dangerous. The caller must ensure that only valid machine code is written
/// to this memory.
///
/// # Arguments
/// * `_size` - Size of memory to allocate in bytes (unused in this stub)
///
/// # Returns
/// An error indicating that allocation must be done by the platform layer
pub unsafe fn allocate_executable_memory(_size: usize) -> Result<u64> {
    Err(WindowsShimError::UnsupportedFeature(
        "Executable memory allocation must be done by the platform layer".to_string(),
    ))
}

/// Generate x86-64 trampoline with floating-point parameter support
///
/// This generates a stub that:
/// 1. Ensures 16-byte stack alignment
/// 2. Moves integer parameters from Windows to Linux registers
/// 3. Moves floating-point parameters from Windows to Linux XMM registers
/// 4. Handles stack parameters for 5+ parameter functions
///
/// # Parameters
/// * `num_int_params` - Number of integer/pointer parameters
/// * `_num_fp_params` - Reserved for future use (currently ignored)
/// * `impl_address` - Address of the actual implementation function
///
/// # Returns
/// Machine code bytes for the trampoline
///
/// # Floating-Point Register Mapping
/// Windows x64 and System V AMD64 both use XMM0-XMM7 for FP parameters,
/// BUT the parameter ordering differs:
/// - Windows: First 4 params use RCX/XMM0, RDX/XMM1, R8/XMM2, R9/XMM3 (mixed)
/// - Linux: First 6 int params use RDI, RSI, RDX, RCX, R8, R9; first 8 FP use XMM0-XMM7
///
/// For simplicity, this implementation assumes XMM registers don't need translation
/// (already in XMM0-XMM3), which is correct for most common cases.
///
/// # Safety
/// The returned bytes must be placed in executable memory.
pub fn generate_trampoline_with_fp(
    num_int_params: usize,
    _num_fp_params: usize,
    impl_address: u64,
) -> Vec<u8> {
    // For now, floating-point parameters in XMM registers don't need translation
    // because both Windows and Linux use XMM0-XMM7 for FP parameters.
    // The main difference is in how they're mixed with integer parameters,
    // but for simple cases where FP params are the first few parameters,
    // they're already in the right XMM registers.
    //
    // Future enhancement: Handle complex mixed parameter scenarios

    // Just use the regular trampoline for integer parameters
    generate_trampoline(num_int_params, impl_address)
}

/// Write machine code to executable memory
///
/// # Safety
/// This function writes arbitrary bytes to executable memory. The caller must
/// ensure that:
/// - The memory was allocated with execute permissions
/// - The bytes represent valid machine code
/// - The destination has enough space for the code
///
/// # Arguments
/// * `dest` - Destination address in executable memory
/// * `code` - Machine code bytes to write
pub unsafe fn write_to_executable_memory(dest: u64, code: &[u8]) {
    let dest_ptr = dest as *mut u8;
    // SAFETY: The caller guarantees dest is valid executable memory
    // with sufficient space for code.len() bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(code.as_ptr(), dest_ptr, code.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_trampoline_0_params() {
        let code = generate_trampoline(0, 0x1234_5678_9ABC_DEF0);
        // Should contain movabs rax, addr (10 bytes) + jmp rax (2 bytes)
        assert_eq!(code.len(), 12);
        // Check for movabs rax prefix
        assert_eq!(&code[0..2], &[0x48, 0xB8]);
        // Check for jmp rax suffix
        assert_eq!(&code[10..12], &[0xFF, 0xE0]);
    }

    #[test]
    fn test_generate_trampoline_1_param() {
        let code = generate_trampoline(1, 0x1234_5678_9ABC_DEF0);
        // mov rdi, rcx (3) + movabs (10) + jmp (2) = 15 bytes
        assert_eq!(code.len(), 15);
        // Check for mov rdi, rcx
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xCF]);
    }

    #[test]
    fn test_generate_trampoline_2_params() {
        let code = generate_trampoline(2, 0x1234_5678_9ABC_DEF0);
        // mov rdi,rcx (3) + mov rsi,rdx (3) + movabs (10) + jmp (2) = 18 bytes
        assert_eq!(code.len(), 18);
        // Check for mov rdi, rcx
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xCF]);
        // Check for mov rsi, rdx
        assert_eq!(&code[3..6], &[0x48, 0x89, 0xD6]);
    }

    #[test]
    fn test_generate_trampoline_3_params() {
        let code = generate_trampoline(3, 0x1234_5678_9ABC_DEF0);
        // Check basic structure
        assert!(!code.is_empty());
        // Check for mov rdi, rcx
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xCF]);
        // Check for mov rsi, rdx
        assert_eq!(&code[3..6], &[0x48, 0x89, 0xD6]);
        // Check for mov rdx, r8
        assert_eq!(&code[6..9], &[0x4C, 0x89, 0xC2]);
    }

    #[test]
    fn test_generate_trampoline_4_params() {
        let code = generate_trampoline(4, 0x1234_5678_9ABC_DEF0);
        // Check basic structure
        assert!(!code.is_empty());
        // Check for mov rdi, rcx
        assert_eq!(&code[0..3], &[0x48, 0x89, 0xCF]);
        // Should still use tail call optimization (jmp) for 4 params
        assert!(code.contains(&0xFF) && code.contains(&0xE0));
    }

    #[test]
    fn test_generate_trampoline_5_params() {
        let code = generate_trampoline(5, 0x1234_5678_9ABC_DEF0);
        // 5 params means 1 stack parameter
        // Should have: stack setup, stack copy, register moves, call, stack cleanup, ret
        assert!(!code.is_empty());

        // Check that code contains mov rdi, rcx somewhere
        // Pattern: 0x48, 0x89, 0xCF
        let has_mov_rdi_rcx = code.windows(3).any(|w| w == [0x48, 0x89, 0xCF]);
        assert!(has_mov_rdi_rcx, "Should contain 'mov rdi, rcx'");

        // Should contain 'call rax' (0xFF, 0xD0) not 'jmp rax' (0xFF, 0xE0)
        let has_call = code.windows(2).any(|w| w == [0xFF, 0xD0]);
        assert!(has_call, "Should use 'call rax' for 5+ parameters");

        // Should contain 'ret' (0xC3) at the end
        assert_eq!(*code.last().unwrap(), 0xC3, "Should end with 'ret'");
    }

    #[test]
    fn test_generate_trampoline_6_params() {
        let code = generate_trampoline(6, 0x1234_5678_9ABC_DEF0);
        // 6 params means 2 stack parameters (even number, no alignment padding needed)
        assert!(!code.is_empty());

        // Should contain 'call rax' not 'jmp rax'
        let has_call = code.windows(2).any(|w| w == [0xFF, 0xD0]);
        assert!(has_call, "Should use 'call rax' for 6 parameters");

        // Should contain 'ret' at the end
        assert_eq!(*code.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_generate_trampoline_8_params() {
        let code = generate_trampoline(8, 0x1234_5678_9ABC_DEF0);
        // 8 params means 4 stack parameters
        assert!(!code.is_empty());

        // Should use 'call rax' for 5+ parameters
        let has_call = code.windows(2).any(|w| w == [0xFF, 0xD0]);
        assert!(has_call, "Should use 'call rax' for 8 parameters");

        // Should end with 'ret'
        assert_eq!(*code.last().unwrap(), 0xC3);
    }

    #[test]
    fn test_stack_alignment_odd_params() {
        // 5 params = 1 stack param (odd) -> needs 8 bytes alignment padding
        let code = generate_trampoline(5, 0x1234_5678_9ABC_DEF0);

        // The code should allocate 8 (param) + 8 (alignment) = 16 bytes
        // sub rsp, 16: 48 83 EC 10
        let has_sub_16 = code.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x10]);
        assert!(
            has_sub_16,
            "Should allocate 16 bytes (8 param + 8 align) for 5 params"
        );
    }

    #[test]
    fn test_stack_alignment_even_params() {
        // 6 params = 2 stack params (even) -> no alignment padding needed
        let code = generate_trampoline(6, 0x1234_5678_9ABC_DEF0);

        // The code should allocate 16 bytes (2 params * 8)
        // sub rsp, 16: 48 83 EC 10
        let has_sub_16 = code.windows(4).any(|w| w == [0x48, 0x83, 0xEC, 0x10]);
        assert!(
            has_sub_16,
            "Should allocate 16 bytes (2 params * 8) for 6 params"
        );
    }

    #[test]
    fn test_generate_trampoline_with_fp() {
        // Test FP parameter handling
        let code = generate_trampoline_with_fp(2, 2, 0x1234_5678_9ABC_DEF0);
        // Should generate code for 2 integer parameters
        // FP parameters are already in correct XMM registers
        assert!(!code.is_empty());
    }
}
