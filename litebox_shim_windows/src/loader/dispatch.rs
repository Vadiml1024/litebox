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
/// This generates a minimal stub that:
/// 1. Moves parameters from Windows x64 registers to System V AMD64 registers
/// 2. Tail-calls the actual implementation
///
/// # Parameters
/// * `num_params` - Number of parameters (0-4 supported)
/// * `impl_address` - Address of the actual implementation function
///
/// # Returns
/// Machine code bytes for the trampoline
///
/// # Safety
/// The returned bytes must be placed in executable memory and executed
/// with proper stack alignment.
#[allow(clippy::cast_possible_truncation)]
pub fn generate_trampoline(num_params: usize, impl_address: u64) -> Vec<u8> {
    let mut code = Vec::new();

    // Register mapping:
    // Windows x64: RCX, RDX, R8, R9
    // Linux x64:   RDI, RSI, RDX, RCX, R8, R9
    //
    // For 0-4 parameters, we need to move:
    // Win RCX -> Linux RDI (param 1)
    // Win RDX -> Linux RSI (param 2)
    // Win R8  -> Linux RDX (param 3)
    // Win R9  -> Linux RCX (param 4)

    match num_params {
        0 => {
            // No parameters, just tail call
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
        1 => {
            // mov rdi, rcx ; param1
            code.extend_from_slice(&[0x48, 0x89, 0xCF]);
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
        2 => {
            // mov rdi, rcx ; param1
            code.extend_from_slice(&[0x48, 0x89, 0xCF]);
            // mov rsi, rdx ; param2
            code.extend_from_slice(&[0x48, 0x89, 0xD6]);
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
        3 => {
            // mov rdi, rcx ; param1
            code.extend_from_slice(&[0x48, 0x89, 0xCF]);
            // mov rsi, rdx ; param2
            code.extend_from_slice(&[0x48, 0x89, 0xD6]);
            // mov rdx, r8  ; param3
            code.extend_from_slice(&[0x4C, 0x89, 0xC2]);
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
        4 => {
            // mov rdi, rcx ; param1
            code.extend_from_slice(&[0x48, 0x89, 0xCF]);
            // mov rsi, rdx ; param2
            code.extend_from_slice(&[0x48, 0x89, 0xD6]);
            // mov rdx, r8  ; param3
            code.extend_from_slice(&[0x4C, 0x89, 0xC2]);
            // mov rcx, r9  ; param4
            code.extend_from_slice(&[0x4C, 0x89, 0xC9]);
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
        _ => {
            // For more than 4 parameters, we would need to handle stack parameters
            // This is more complex and not implemented yet
            // For now, just tail call and hope the implementation handles it
            // movabs rax, impl_address
            code.extend_from_slice(&[0x48, 0xB8]);
            code.extend_from_slice(&impl_address.to_le_bytes());
            // jmp rax
            code.extend_from_slice(&[0xFF, 0xE0]);
        }
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
    }
}
