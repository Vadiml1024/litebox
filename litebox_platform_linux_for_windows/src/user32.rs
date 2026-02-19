// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! USER32.dll function implementations
//!
//! This module provides minimal stub implementations of the Windows USER32 GUI
//! API. These stubs allow programs that link against USER32 to run in a headless
//! Linux environment without crashing. GUI operations print diagnostic messages
//! to stderr and return values that indicate "no window / no messages", enabling
//! programs with optional GUI code paths to continue executing their non-GUI
//! logic.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings as we're implementing Windows API which requires specific integer types
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

use core::ffi::c_void;

// ── Return-value constants ────────────────────────────────────────────────────

/// IDOK — returned by `MessageBoxW` when the user clicks OK (or when headless)
const IDOK: i32 = 1;

/// Fake non-null HWND returned by `CreateWindowExW`
const FAKE_HWND: usize = 0x0000_BEEF;

/// Fake non-zero ATOM returned by `RegisterClassExW`
const FAKE_ATOM: u16 = 1;

// ── Wide-string helper ────────────────────────────────────────────────────────

/// Convert a null-terminated UTF-16 pointer to a `String`, or return an empty
/// string if the pointer is null.
fn wide_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    // SAFETY: Caller guarantees `ptr` is a valid null-terminated UTF-16 string.
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

// ── USER32 stub implementations ───────────────────────────────────────────────

/// `MessageBoxW` — display a modal dialog box.
///
/// In headless mode (no display), the message and caption are printed to stderr
/// and IDOK (1) is returned, as if the user clicked OK.
///
/// # Safety
/// `text` and `caption` must be null-terminated UTF-16 strings or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_MessageBoxW(
    _hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    _msg_type: u32,
) -> i32 {
    let text_str = wide_to_string(text);
    let caption_str = wide_to_string(caption);
    eprintln!("[USER32] MessageBoxW: [{caption_str}] {text_str}");
    IDOK
}

/// `RegisterClassExW` — register a window class.
///
/// Returns a fake non-zero ATOM so that the caller believes the class was
/// registered successfully.
///
/// # Safety
/// `wndclassex` must be a valid pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_RegisterClassExW(_wndclassex: *const c_void) -> u16 {
    FAKE_ATOM
}

/// `CreateWindowExW` — create an overlapped, pop-up, or child window.
///
/// Returns a fake non-null HWND.
///
/// # Safety
/// All pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_CreateWindowExW(
    _ex_style: u32,
    _class_name: *const u16,
    _window_name: *const u16,
    _style: u32,
    _x: i32,
    _y: i32,
    _width: i32,
    _height: i32,
    _parent: *mut c_void,
    _menu: *mut c_void,
    _instance: *mut c_void,
    _param: *mut c_void,
) -> *mut c_void {
    FAKE_HWND as *mut c_void
}

/// `ShowWindow` — set the show state of the specified window.
///
/// Returns 1 (non-zero), indicating the window was previously visible.
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_ShowWindow(_hwnd: *mut c_void, _cmd_show: i32) -> i32 {
    1
}

/// `UpdateWindow` — update the client area of the specified window.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_UpdateWindow(_hwnd: *mut c_void) -> i32 {
    1
}

/// `GetMessageW` — retrieve a message from the thread's message queue.
///
/// Returns 0, indicating a `WM_QUIT` message was received, so that message
/// loops in headless programs terminate immediately.
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_GetMessageW(
    _msg: *mut c_void,
    _hwnd: *mut c_void,
    _msg_filter_min: u32,
    _msg_filter_max: u32,
) -> i32 {
    0
}

/// `TranslateMessage` — translate virtual-key messages into character messages.
///
/// Returns 0 (no translation performed).
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_TranslateMessage(_msg: *const c_void) -> i32 {
    0
}

/// `DispatchMessageW` — dispatch a message to a window procedure.
///
/// Returns 0.
///
/// # Safety
/// `msg` must be a valid pointer to a MSG structure or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DispatchMessageW(_msg: *const c_void) -> isize {
    0
}

/// `DestroyWindow` — destroy the specified window.
///
/// Returns 1 (TRUE).
///
/// # Safety
/// `hwnd` must be a valid HWND or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn user32_DestroyWindow(_hwnd: *mut c_void) -> i32 {
    1
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_box_null_returns_idok() {
        // SAFETY: null pointers are handled gracefully by wide_to_string
        let result = unsafe {
            user32_MessageBoxW(std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), 0)
        };
        assert_eq!(result, IDOK);
    }

    #[test]
    fn test_message_box_with_text() {
        let text: Vec<u16> = "Hello\0".encode_utf16().collect();
        let caption: Vec<u16> = "Title\0".encode_utf16().collect();
        // SAFETY: text and caption are valid null-terminated UTF-16 strings
        let result =
            unsafe { user32_MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0) };
        assert_eq!(result, IDOK);
    }

    #[test]
    fn test_register_class_ex_returns_nonzero() {
        // SAFETY: null pointer is passed; the stub does not dereference it
        let atom = unsafe { user32_RegisterClassExW(std::ptr::null()) };
        assert_ne!(atom, 0);
    }

    #[test]
    fn test_create_window_returns_nonnull() {
        // SAFETY: all null pointers; stub does not dereference any of them
        let hwnd = unsafe {
            user32_CreateWindowExW(
                0,
                std::ptr::null(),
                std::ptr::null(),
                0,
                0,
                0,
                800,
                600,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert!(!hwnd.is_null());
    }

    #[test]
    fn test_show_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_ShowWindow(std::ptr::null_mut(), 1) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_update_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_UpdateWindow(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_get_message_returns_zero() {
        // SAFETY: all null pointers; stub does not dereference any of them
        let result =
            unsafe { user32_GetMessageW(std::ptr::null_mut(), std::ptr::null_mut(), 0, 0) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_translate_message_returns_zero() {
        // SAFETY: null pointer; stub does not dereference it
        let result = unsafe { user32_TranslateMessage(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_dispatch_message_returns_zero() {
        // SAFETY: null pointer; stub does not dereference it
        let result = unsafe { user32_DispatchMessageW(std::ptr::null()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_destroy_window_returns_one() {
        // SAFETY: null HWND; stub does not dereference it
        let result = unsafe { user32_DestroyWindow(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }
}
