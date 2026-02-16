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
        FunctionImpl {
            name: "__iob_func",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt___iob_func as *const () as usize,
        },
        FunctionImpl {
            name: "vfprintf",
            dll_name: "MSVCRT.dll",
            num_params: 3, // Variadic, but at least 3
            impl_address: crate::msvcrt::msvcrt_vfprintf as *const () as usize,
        },
        FunctionImpl {
            name: "_onexit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__onexit as *const () as usize,
        },
        FunctionImpl {
            name: "_amsg_exit",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__amsg_exit as *const () as usize,
        },
        FunctionImpl {
            name: "_cexit",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__cexit as *const () as usize,
        },
        FunctionImpl {
            name: "_fpreset",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__fpreset as *const () as usize,
        },
        FunctionImpl {
            name: "__setusermatherr",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt___setusermatherr as *const () as usize,
        },
        // KERNEL32.dll functions - these are defined in kernel32.rs
        FunctionImpl {
            name: "Sleep",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_Sleep as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentThreadId",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentThreadId as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentProcessId",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetCurrentProcessId as *const () as usize,
        },
        FunctionImpl {
            name: "TlsAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_TlsAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "TlsFree",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TlsFree as *const () as usize,
        },
        FunctionImpl {
            name: "TlsGetValue",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TlsGetValue as *const () as usize,
        },
        FunctionImpl {
            name: "TlsSetValue",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_TlsSetValue as *const () as usize,
        },
        // Phase 8: Exception Handling (stubs for CRT compatibility)
        FunctionImpl {
            name: "__C_specific_handler",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32___C_specific_handler as *const () as usize,
        },
        FunctionImpl {
            name: "SetUnhandledExceptionFilter",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetUnhandledExceptionFilter as *const ()
                as usize,
        },
        FunctionImpl {
            name: "RaiseException",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_RaiseException as *const () as usize,
        },
        FunctionImpl {
            name: "RtlCaptureContext",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_RtlCaptureContext as *const () as usize,
        },
        FunctionImpl {
            name: "RtlLookupFunctionEntry",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_RtlLookupFunctionEntry as *const () as usize,
        },
        FunctionImpl {
            name: "RtlUnwindEx",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_RtlUnwindEx as *const () as usize,
        },
        FunctionImpl {
            name: "RtlVirtualUnwind",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_RtlVirtualUnwind as *const () as usize,
        },
        FunctionImpl {
            name: "AddVectoredExceptionHandler",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_AddVectoredExceptionHandler as *const ()
                as usize,
        },
        // Phase 8.2: Critical Sections
        FunctionImpl {
            name: "InitializeCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_InitializeCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "EnterCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_EnterCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "LeaveCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LeaveCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "TryEnterCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_TryEnterCriticalSection as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteCriticalSection",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteCriticalSection as *const () as usize,
        },
        // Phase 8.3: String Operations
        FunctionImpl {
            name: "MultiByteToWideChar",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_MultiByteToWideChar as *const () as usize,
        },
        FunctionImpl {
            name: "WideCharToMultiByte",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_WideCharToMultiByte as *const () as usize,
        },
        FunctionImpl {
            name: "lstrlenW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_lstrlenW as *const () as usize,
        },
        FunctionImpl {
            name: "CompareStringOrdinal",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_CompareStringOrdinal as *const () as usize,
        },
        // Phase 8.4: Performance Counters
        FunctionImpl {
            name: "QueryPerformanceCounter",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_QueryPerformanceCounter as *const () as usize,
        },
        FunctionImpl {
            name: "QueryPerformanceFrequency",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_QueryPerformanceFrequency as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemTimePreciseAsFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetSystemTimePreciseAsFileTime as *const ()
                as usize,
        },
        // Phase 8.5: File I/O Trampolines
        FunctionImpl {
            name: "CreateFileW",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_CreateFileW as *const () as usize,
        },
        FunctionImpl {
            name: "ReadFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadFile as *const () as usize,
        },
        FunctionImpl {
            name: "WriteFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteFile as *const () as usize,
        },
        FunctionImpl {
            name: "CloseHandle",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_CloseHandle as *const () as usize,
        },
        // Phase 8.6: Heap Management Trampolines
        FunctionImpl {
            name: "GetProcessHeap",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetProcessHeap as *const () as usize,
        },
        FunctionImpl {
            name: "HeapAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_HeapAlloc as *const () as usize,
        },
        FunctionImpl {
            name: "HeapFree",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_HeapFree as *const () as usize,
        },
        FunctionImpl {
            name: "HeapReAlloc",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_HeapReAlloc as *const () as usize,
        },
        // Phase 8.7: Additional startup and CRT functions
        FunctionImpl {
            name: "GetStartupInfoA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStartupInfoA as *const () as usize,
        },
        FunctionImpl {
            name: "GetStartupInfoW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStartupInfoW as *const () as usize,
        },
        FunctionImpl {
            name: "_acmdln",
            dll_name: "MSVCRT.dll",
            num_params: 0,
            impl_address: crate::msvcrt::msvcrt__acmdln as *const () as usize,
        },
        FunctionImpl {
            name: "_ismbblead",
            dll_name: "MSVCRT.dll",
            num_params: 1,
            impl_address: crate::msvcrt::msvcrt__ismbblead as *const () as usize,
        },
        FunctionImpl {
            name: "__C_specific_handler",
            dll_name: "MSVCRT.dll",
            num_params: 4,
            impl_address: crate::msvcrt::msvcrt___C_specific_handler as *const () as usize,
        },
        // Additional KERNEL32 stub functions
        FunctionImpl {
            name: "CancelIo",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_CancelIo as *const () as usize,
        },
        FunctionImpl {
            name: "CopyFileExW",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CopyFileExW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CreateDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateEventW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateEventW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateFileMappingA",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CreateFileMappingA as *const () as usize,
        },
        FunctionImpl {
            name: "CreateHardLinkW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateHardLinkW as *const () as usize,
        },
        FunctionImpl {
            name: "CreatePipe",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreatePipe as *const () as usize,
        },
        FunctionImpl {
            name: "CreateProcessW",
            dll_name: "KERNEL32.dll",
            num_params: 10,
            impl_address: crate::kernel32::kernel32_CreateProcessW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateSymbolicLinkW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_CreateSymbolicLinkW as *const () as usize,
        },
        FunctionImpl {
            name: "CreateThread",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_CreateThread as *const () as usize,
        },
        FunctionImpl {
            name: "CreateToolhelp32Snapshot",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_CreateToolhelp32Snapshot as *const () as usize,
        },
        FunctionImpl {
            name: "CreateWaitableTimerExW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_CreateWaitableTimerExW as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteFileW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteFileW as *const () as usize,
        },
        FunctionImpl {
            name: "DeleteProcThreadAttributeList",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_DeleteProcThreadAttributeList as *const ()
                as usize,
        },
        FunctionImpl {
            name: "DeviceIoControl",
            dll_name: "KERNEL32.dll",
            num_params: 8,
            impl_address: crate::kernel32::kernel32_DeviceIoControl as *const () as usize,
        },
        FunctionImpl {
            name: "DuplicateHandle",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_DuplicateHandle as *const () as usize,
        },
        FunctionImpl {
            name: "FlushFileBuffers",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_FlushFileBuffers as *const () as usize,
        },
        FunctionImpl {
            name: "FormatMessageW",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_FormatMessageW as *const () as usize,
        },
        FunctionImpl {
            name: "GetCurrentDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetCurrentDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "GetExitCodeProcess",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetExitCodeProcess as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileAttributesW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetFileAttributesW as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileInformationByHandle",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetFileInformationByHandle as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetFileType",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetFileType as *const () as usize,
        },
        FunctionImpl {
            name: "GetFullPathNameW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFullPathNameW as *const () as usize,
        },
        FunctionImpl {
            name: "GetLastError",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_GetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "GetModuleHandleW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetModuleHandleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcAddress",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetProcAddress as *const () as usize,
        },
        FunctionImpl {
            name: "GetStdHandle",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetStdHandle as *const () as usize,
        },
        FunctionImpl {
            name: "LoadLibraryA",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LoadLibraryA as *const () as usize,
        },
        FunctionImpl {
            name: "LoadLibraryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_LoadLibraryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetConsoleCtrlHandler",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetConsoleCtrlHandler as *const () as usize,
        },
        FunctionImpl {
            name: "SetFilePointerEx",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFilePointerEx as *const () as usize,
        },
        FunctionImpl {
            name: "SetLastError",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetLastError as *const () as usize,
        },
        FunctionImpl {
            name: "WaitForSingleObject",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_WaitForSingleObject as *const () as usize,
        },
        FunctionImpl {
            name: "WriteConsoleW",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteConsoleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetFileInformationByHandleEx",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFileInformationByHandleEx as *const ()
                as usize,
        },
        FunctionImpl {
            name: "GetFileSizeEx",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetFileSizeEx as *const () as usize,
        },
        FunctionImpl {
            name: "GetFinalPathNameByHandleW",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetFinalPathNameByHandleW as *const () as usize,
        },
        FunctionImpl {
            name: "GetOverlappedResult",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_GetOverlappedResult as *const () as usize,
        },
        FunctionImpl {
            name: "GetProcessId",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_GetProcessId as *const () as usize,
        },
        FunctionImpl {
            name: "GetSystemDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetSystemDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "GetTempPathW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetTempPathW as *const () as usize,
        },
        FunctionImpl {
            name: "GetWindowsDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_GetWindowsDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "InitOnceBeginInitialize",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_InitOnceBeginInitialize as *const () as usize,
        },
        FunctionImpl {
            name: "InitOnceComplete",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_InitOnceComplete as *const () as usize,
        },
        FunctionImpl {
            name: "InitializeProcThreadAttributeList",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_InitializeProcThreadAttributeList as *const ()
                as usize,
        },
        FunctionImpl {
            name: "LockFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_LockFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "MapViewOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_MapViewOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "Module32FirstW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_Module32FirstW as *const () as usize,
        },
        FunctionImpl {
            name: "Module32NextW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_Module32NextW as *const () as usize,
        },
        FunctionImpl {
            name: "MoveFileExW",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_MoveFileExW as *const () as usize,
        },
        FunctionImpl {
            name: "ReadFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_ReadFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "RemoveDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_RemoveDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetCurrentDirectoryW",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetCurrentDirectoryW as *const () as usize,
        },
        FunctionImpl {
            name: "SetFileAttributesW",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SetFileAttributesW as *const () as usize,
        },
        FunctionImpl {
            name: "SetFileInformationByHandle",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFileInformationByHandle as *const ()
                as usize,
        },
        FunctionImpl {
            name: "SetFileTime",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_SetFileTime as *const () as usize,
        },
        FunctionImpl {
            name: "SetHandleInformation",
            dll_name: "KERNEL32.dll",
            num_params: 3,
            impl_address: crate::kernel32::kernel32_SetHandleInformation as *const () as usize,
        },
        FunctionImpl {
            name: "UnlockFile",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_UnlockFile as *const () as usize,
        },
        FunctionImpl {
            name: "UnmapViewOfFile",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_UnmapViewOfFile as *const () as usize,
        },
        FunctionImpl {
            name: "UpdateProcThreadAttribute",
            dll_name: "KERNEL32.dll",
            num_params: 7,
            impl_address: crate::kernel32::kernel32_UpdateProcThreadAttribute as *const () as usize,
        },
        FunctionImpl {
            name: "WriteFileEx",
            dll_name: "KERNEL32.dll",
            num_params: 5,
            impl_address: crate::kernel32::kernel32_WriteFileEx as *const () as usize,
        },
        FunctionImpl {
            name: "SetThreadStackGuarantee",
            dll_name: "KERNEL32.dll",
            num_params: 1,
            impl_address: crate::kernel32::kernel32_SetThreadStackGuarantee as *const () as usize,
        },
        FunctionImpl {
            name: "SetWaitableTimer",
            dll_name: "KERNEL32.dll",
            num_params: 6,
            impl_address: crate::kernel32::kernel32_SetWaitableTimer as *const () as usize,
        },
        FunctionImpl {
            name: "SleepEx",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_SleepEx as *const () as usize,
        },
        FunctionImpl {
            name: "SwitchToThread",
            dll_name: "KERNEL32.dll",
            num_params: 0,
            impl_address: crate::kernel32::kernel32_SwitchToThread as *const () as usize,
        },
        FunctionImpl {
            name: "TerminateProcess",
            dll_name: "KERNEL32.dll",
            num_params: 2,
            impl_address: crate::kernel32::kernel32_TerminateProcess as *const () as usize,
        },
        FunctionImpl {
            name: "WaitForMultipleObjects",
            dll_name: "KERNEL32.dll",
            num_params: 4,
            impl_address: crate::kernel32::kernel32_WaitForMultipleObjects as *const () as usize,
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

    /// Link data exports to their actual memory addresses
    ///
    /// This updates the DLL manager to point data imports to real memory locations
    /// instead of stub addresses. Must be called after `link_trampolines_to_dll_manager()`.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    ///
    /// # Safety
    /// This function accesses mutable static variables to get their addresses.
    /// It's safe because we only take addresses, not modify the values.
    pub unsafe fn link_data_exports_to_dll_manager(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        // MSVCRT.dll data exports
        // SAFETY: We're only taking the address of the static, not modifying it.
        // These are global variables that C code expects to access directly.
        let data_exports = vec![
            (
                "MSVCRT.dll",
                "_fmode",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt__fmode) as usize,
            ),
            (
                "MSVCRT.dll",
                "_commode",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt__commode) as usize,
            ),
            (
                "MSVCRT.dll",
                "__initenv",
                core::ptr::addr_of_mut!(crate::msvcrt::msvcrt___initenv) as usize,
            ),
        ];

        for (dll_name, export_name, address) in data_exports {
            state
                .dll_manager
                .update_export_address(dll_name, export_name, address)
                .ok(); // Ignore errors - export may not be in DLL yet
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
