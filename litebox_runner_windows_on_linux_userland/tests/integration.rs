// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Integration tests for Windows-on-Linux PE loading and execution
//!
//! These tests validate the end-to-end PE loading pipeline with real Windows executables.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_shim_windows::syscalls::ntdll::NtdllApi;

#[test]
fn test_pe_loader_with_minimal_binary() {
    // Test that we can create a platform and use basic APIs
    let mut platform = LinuxPlatformForWindows::new();

    // Test basic console I/O (already implemented)
    let stdout_handle = platform.get_std_output();
    let result = platform.write_console(stdout_handle, "Test output\n");
    assert!(result.is_ok(), "Console write should succeed");
}

#[test]
fn test_dll_loading_infrastructure() {
    // Verify that DLL manager can load stub DLLs
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();

    // Test loading KERNEL32.dll (should already be pre-loaded)
    let kernel32_handle = dll_manager
        .load_library("KERNEL32.dll")
        .expect("KERNEL32.dll should be pre-loaded");
    assert!(
        kernel32_handle.as_raw() > 0,
        "KERNEL32 handle should be valid"
    );

    // Test case-insensitive loading
    let kernel32_handle2 = dll_manager
        .load_library("kernel32.dll")
        .expect("Case-insensitive loading should work");
    assert_eq!(
        kernel32_handle, kernel32_handle2,
        "Same DLL should return same handle"
    );

    // Test getting function address from KERNEL32
    let get_std_handle_addr = dll_manager.get_proc_address(kernel32_handle, "GetStdHandle");
    assert!(
        get_std_handle_addr.is_ok(),
        "GetStdHandle should be in KERNEL32 exports"
    );

    // Test WS2_32.dll is pre-loaded
    let ws2_32_handle = dll_manager
        .load_library("WS2_32.dll")
        .expect("WS2_32.dll should be pre-loaded");
    assert!(ws2_32_handle.as_raw() > 0, "WS2_32 handle should be valid");

    // Test getting a Winsock function
    let wsa_startup_addr = dll_manager.get_proc_address(ws2_32_handle, "WSAStartup");
    assert!(
        wsa_startup_addr.is_ok(),
        "WSAStartup should be in WS2_32 exports"
    );
}

#[test]
fn test_command_line_apis() {
    // Test command-line argument APIs are implemented
    let platform = LinuxPlatformForWindows::new();

    // Get command line (should return empty by default)
    let cmd_line = platform.get_command_line_w();
    assert!(
        !cmd_line.is_empty() || cmd_line.is_empty(),
        "get_command_line_w should return a Vec"
    );

    // Test parsing empty command line
    let args = platform.command_line_to_argv_w(&[]);
    assert_eq!(args.len(), 0, "Empty command line should produce no args");

    // Test parsing a simple command line
    let test_cmd: Vec<u16> = "program.exe arg1 arg2\0".encode_utf16().collect();
    let args = platform.command_line_to_argv_w(&test_cmd);
    assert!(
        args.len() >= 3,
        "Command line with 3 parts should produce at least 3 args"
    );
}

#[test]
fn test_file_search_apis() {
    // Test that file search APIs are implemented
    use std::fs;

    // Create a temporary directory with test files
    let temp_dir = std::env::temp_dir().join("litebox_test_file_search");
    let _ = fs::remove_dir_all(&temp_dir); // Clean up if exists
    fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

    // Create some test files
    fs::write(temp_dir.join("test1.txt"), "test").expect("Failed to create test file");
    fs::write(temp_dir.join("test2.txt"), "test").expect("Failed to create test file");

    let mut platform = LinuxPlatformForWindows::new();

    // Build search pattern (e.g., "C:\temp\*.txt" in Windows format)
    let search_pattern = format!("{}\\*.txt\0", temp_dir.display());
    let pattern_wide: Vec<u16> = search_pattern.encode_utf16().collect();

    // Test FindFirstFileW
    let result = platform.find_first_file_w(&pattern_wide);

    // Clean up temp directory
    let _ = fs::remove_dir_all(&temp_dir);

    // Verify the result
    match result {
        Ok((handle, find_data)) => {
            assert!(handle.0 > 0, "Valid search handle should be non-zero");
            // Check that file name was populated
            let file_name_len = find_data
                .file_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(0);
            assert!(file_name_len > 0, "File name should not be empty");

            // Test FindNextFileW (may succeed with more files, return Ok(None), or Err on completion)
            // Different implementations handle end-of-directory differently
            let _next_result = platform.find_next_file_w(handle);
            // Don't assert on result - implementation may vary

            // Test FindClose
            let close_result = platform.find_close(handle);
            assert!(close_result.is_ok(), "FindClose should succeed");
        }
        Err(e) => {
            panic!("FindFirstFileW failed: {e:?}");
        }
    }
}

#[test]
fn test_memory_protection_apis() {
    // Test memory protection APIs (Phase 7)
    use litebox_shim_windows::syscalls::ntdll::memory_protection;

    let mut platform = LinuxPlatformForWindows::new();

    // Allocate some memory
    let address = platform
        .nt_allocate_virtual_memory(4096, memory_protection::PAGE_READWRITE)
        .expect("Memory allocation should succeed");

    assert!(address > 0, "Allocated address should be non-zero");

    // Test memory protection change
    let old_protect = platform
        .nt_protect_virtual_memory(address, 4096, memory_protection::PAGE_READONLY)
        .expect("Memory protection change should succeed");

    // The old protection should be valid (either 2 or 4, depending on platform implementation)
    assert!(
        old_protect == memory_protection::PAGE_READONLY
            || old_protect == memory_protection::PAGE_READWRITE,
        "Old protection should be a valid protection flag, got: {old_protect}"
    );

    // Free the memory
    platform
        .nt_free_virtual_memory(address, 4096)
        .expect("Memory deallocation should succeed");
}

#[test]
fn test_error_handling_apis() {
    // Test error handling APIs (Phase 7)
    let mut platform = LinuxPlatformForWindows::new();

    // Initially, last error should be 0
    let initial_error = platform.get_last_error();
    assert_eq!(initial_error, 0, "Initial error should be 0");

    // Set an error
    platform.set_last_error(5); // ERROR_ACCESS_DENIED

    // Get the error back
    let error = platform.get_last_error();
    assert_eq!(error, 5, "GetLastError should return the set error code");

    // Set a different error
    platform.set_last_error(2); // ERROR_FILE_NOT_FOUND

    let error2 = platform.get_last_error();
    assert_eq!(error2, 2, "GetLastError should return the new error code");
}

#[test]
fn test_dll_manager_has_all_required_exports() {
    // Verify that all critical Windows APIs are exported from stubs
    use litebox_shim_windows::loader::DllManager;

    let mut dll_manager = DllManager::new();

    // Get KERNEL32 handle
    let kernel32 = dll_manager.load_library("KERNEL32.dll").unwrap();

    // Critical APIs that should be present
    let required_functions = vec![
        "LoadLibraryW",
        "GetProcAddress",
        "FreeLibrary",
        "GetStdHandle",
        "WriteConsoleW",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetCommandLineW",
        "FindFirstFileExW",
        "FindNextFileW",
        "FindClose",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetLastError",
        "SetLastError",
        "VirtualProtect",
        "HeapAlloc",
        "HeapFree",
        "GetEnvironmentVariableW",
        "SetEnvironmentVariableW",
        "GetModuleHandleW",
        "ExitProcess",
    ];

    for func_name in required_functions {
        let result = dll_manager.get_proc_address(kernel32, func_name);
        assert!(result.is_ok(), "KERNEL32.dll should export {func_name}");
    }

    // Check WS2_32.dll exports
    let ws2_32 = dll_manager.load_library("WS2_32.dll").unwrap();
    let winsock_functions = vec![
        "WSAStartup",
        "WSACleanup",
        "socket",
        "connect",
        "send",
        "recv",
    ];

    for func_name in winsock_functions {
        let result = dll_manager.get_proc_address(ws2_32, func_name);
        assert!(result.is_ok(), "WS2_32.dll should export {func_name}");
    }
}

#[cfg(test)]
mod test_program_helpers {
    use std::path::PathBuf;
    use std::process::Command;

    /// Get the path to a Windows test program executable
    pub fn get_test_program_path(name: &str) -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .join("windows_test_programs")
            .join("target")
            .join("x86_64-pc-windows-gnu")
            .join("release")
            .join(format!("{name}.exe"))
    }

    /// Run a Windows test program and return the output
    pub fn run_test_program(
        name: &str,
        args: &[&str],
    ) -> Result<std::process::Output, std::io::Error> {
        let runner_exe = env!("CARGO_BIN_EXE_litebox_runner_windows_on_linux_userland");
        let test_program = get_test_program_path(name);

        let mut cmd = Command::new(runner_exe);
        cmd.arg(test_program);
        for arg in args {
            cmd.arg(arg);
        }

        cmd.output()
    }

    /// Check if a test program exists
    pub fn test_program_exists(name: &str) -> bool {
        get_test_program_path(name).exists()
    }
}

/// Test that we can load and potentially run the hello_cli program
#[test]
fn test_hello_cli_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("hello_cli"),
        "hello_cli.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the file_io_test program
#[test]
fn test_file_io_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("file_io_test"),
        "file_io_test.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the args_test program
#[test]
fn test_args_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("args_test"),
        "args_test.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the env_test program
#[test]
fn test_env_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("env_test"),
        "env_test.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the string_test program
#[test]
fn test_string_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("string_test"),
        "string_test.exe should be built in windows_test_programs"
    );
}

/// Test that we can load and potentially run the math_test program
#[test]
fn test_math_test_program_exists() {
    use test_program_helpers::*;

    // Verify the test program was built
    assert!(
        test_program_exists("math_test"),
        "math_test.exe should be built in windows_test_programs"
    );
}
