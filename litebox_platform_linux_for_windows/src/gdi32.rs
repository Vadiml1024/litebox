// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! GDI32.dll function implementations
//!
//! This module provides minimal stub implementations of the Windows GDI
//! (Graphics Device Interface) API.  These stubs allow programs that link
//! against GDI32 to run in a headless Linux environment without crashing.
//! All drawing operations are silently discarded; functions return values
//! that indicate success so that callers can continue without error-checking.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]

use core::ffi::c_void;

// ── Return-value constants ────────────────────────────────────────────────────

/// Fake non-null HGDIOBJ returned by `GetStockObject`
const FAKE_HGDIOBJ: usize = 0x0000_6D01;

/// Fake non-null HBRUSH returned by `CreateSolidBrush`
const FAKE_HBRUSH: usize = 0x0000_B001;

/// Fake non-null HGDIOBJ returned as the previous object by `SelectObject`
const FAKE_PREV_OBJ: usize = 0x0000_6D02;

/// Fake non-null HDC returned by `CreateCompatibleDC`
const FAKE_COMPAT_HDC: usize = 0x0000_0DC1;

/// Fake non-null HFONT returned by `CreateFontW`
const FAKE_HFONT: usize = 0x0000_F001;

// ── GDI32 stub implementations ────────────────────────────────────────────────

/// `GetStockObject` — retrieve a handle to one of the stock pens, brushes,
/// fonts, or palettes.
///
/// Returns a fake non-null HGDIOBJ in headless mode.
///
/// # Safety
/// `object` is a plain integer; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetStockObject(_object: i32) -> *mut c_void {
    FAKE_HGDIOBJ as *mut c_void
}

/// `CreateSolidBrush` — create a logical brush with the specified solid color.
///
/// Returns a fake non-null HBRUSH in headless mode.
///
/// # Safety
/// `color` is a plain integer (COLORREF); always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateSolidBrush(_color: u32) -> *mut c_void {
    FAKE_HBRUSH as *mut c_void
}

/// `DeleteObject` — delete a logical pen, brush, font, bitmap, region, or palette.
///
/// Returns 1 (TRUE); there are no real GDI objects to delete in headless mode.
///
/// # Safety
/// `object` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_DeleteObject(_object: *mut c_void) -> i32 {
    1
}

/// `SelectObject` — select an object into the specified device context.
///
/// Returns a fake previous HGDIOBJ so that callers can restore it.
///
/// # Safety
/// Parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SelectObject(
    _hdc: *mut c_void,
    _object: *mut c_void,
) -> *mut c_void {
    FAKE_PREV_OBJ as *mut c_void
}

/// `CreateCompatibleDC` — create a memory device context compatible with the
/// specified device.
///
/// Returns a fake non-null HDC in headless mode.
///
/// # Safety
/// `hdc` is not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateCompatibleDC(_hdc: *mut c_void) -> *mut c_void {
    FAKE_COMPAT_HDC as *mut c_void
}

/// `DeleteDC` — delete the specified device context.
///
/// Returns 1 (TRUE); there are no real DCs to delete in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_DeleteDC(_hdc: *mut c_void) -> i32 {
    1
}

/// `SetBkColor` — set the current background color of the specified device context.
///
/// Returns the previous background color (0 = black) in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetBkColor(_hdc: *mut c_void, _color: u32) -> u32 {
    0 // CLR_INVALID would be 0xFFFF_FFFF; 0 means "previous was black"
}

/// `SetTextColor` — set the text color for the specified device context.
///
/// Returns the previous text color (0 = black) in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_SetTextColor(_hdc: *mut c_void, _color: u32) -> u32 {
    0
}

/// `TextOutW` — write a character string at the specified location.
///
/// Returns 1 (TRUE); the text is silently discarded in headless mode.
///
/// # Safety
/// `string` and `hdc` are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_TextOutW(
    _hdc: *mut c_void,
    _x: i32,
    _y: i32,
    _string: *const u16,
    _c: i32,
) -> i32 {
    1
}

/// `Rectangle` — draw a rectangle.
///
/// Returns 1 (TRUE); the drawing is silently discarded in headless mode.
///
/// # Safety
/// `hdc` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_Rectangle(
    _hdc: *mut c_void,
    _left: i32,
    _top: i32,
    _right: i32,
    _bottom: i32,
) -> i32 {
    1
}

/// `FillRect` — fill a rectangle using the specified brush.
///
/// Returns 1 (non-zero = success); the fill is silently discarded in headless mode.
///
/// # Safety
/// `rect` and `brush` are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_FillRect(
    _hdc: *mut c_void,
    _rect: *const c_void,
    _brush: *mut c_void,
) -> i32 {
    1
}

/// `CreateFontW` — create a logical font with the specified characteristics.
///
/// Returns a fake non-null HFONT in headless mode.
///
/// # Safety
/// Pointer parameters are not dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_CreateFontW(
    _height: i32,
    _width: i32,
    _escapement: i32,
    _orientation: i32,
    _weight: i32,
    _italic: u32,
    _underline: u32,
    _strike_out: u32,
    _char_set: u32,
    _out_precision: u32,
    _clip_precision: u32,
    _quality: u32,
    _pitch_and_family: u32,
    _face_name: *const u16,
) -> *mut c_void {
    FAKE_HFONT as *mut c_void
}

/// `GetTextExtentPoint32W` — compute the width and height of the specified string
/// of text.
///
/// Writes a fake SIZE of (8, 16) — 8 pixels wide per character × 16 pixels tall —
/// and returns 1 (TRUE).
///
/// # Safety
/// `size` must be either null or a valid writable buffer of ≥ 8 bytes (2 × i32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gdi32_GetTextExtentPoint32W(
    _hdc: *mut c_void,
    _string: *const u16,
    c: i32,
    size: *mut i32,
) -> i32 {
    if !size.is_null() {
        // SAFETY: caller guarantees `size` points to a SIZE (2 × i32).
        size.write(c * 8); // cx: 8 pixels per character
        size.add(1).write(16); // cy: 16 pixels tall
    }
    1
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_stock_object_returns_nonnull() {
        // SAFETY: plain integer argument; always safe.
        let obj = unsafe { gdi32_GetStockObject(0) }; // WHITE_BRUSH = 0
        assert!(!obj.is_null());
    }

    #[test]
    fn test_create_solid_brush_returns_nonnull() {
        // SAFETY: color is a plain u32; always safe.
        let brush = unsafe { gdi32_CreateSolidBrush(0x00FF_0000) }; // red
        assert!(!brush.is_null());
    }

    #[test]
    fn test_delete_object_returns_one() {
        // SAFETY: null GDI object; stub does not dereference it.
        let result = unsafe { gdi32_DeleteObject(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_select_object_returns_fake_prev() {
        // SAFETY: null HDC and null object; stub does not dereference them.
        let prev = unsafe { gdi32_SelectObject(std::ptr::null_mut(), std::ptr::null_mut()) };
        assert!(!prev.is_null());
    }

    #[test]
    fn test_create_compatible_dc_returns_nonnull() {
        // SAFETY: null HDC; stub does not dereference it.
        let hdc = unsafe { gdi32_CreateCompatibleDC(std::ptr::null_mut()) };
        assert!(!hdc.is_null());
    }

    #[test]
    fn test_delete_dc_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_DeleteDC(std::ptr::null_mut()) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_set_bk_color_returns_previous() {
        // SAFETY: null HDC; stub does not dereference it.
        let prev = unsafe { gdi32_SetBkColor(std::ptr::null_mut(), 0x00FF_0000) };
        assert_eq!(prev, 0);
    }

    #[test]
    fn test_set_text_color_returns_previous() {
        // SAFETY: null HDC; stub does not dereference it.
        let prev = unsafe { gdi32_SetTextColor(std::ptr::null_mut(), 0x0000_00FF) };
        assert_eq!(prev, 0);
    }

    #[test]
    fn test_text_out_returns_one() {
        // SAFETY: all null/integer parameters; stub does not dereference them.
        let result = unsafe { gdi32_TextOutW(std::ptr::null_mut(), 0, 0, std::ptr::null(), 0) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_rectangle_returns_one() {
        // SAFETY: null HDC; stub does not dereference it.
        let result = unsafe { gdi32_Rectangle(std::ptr::null_mut(), 0, 0, 100, 100) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_fill_rect_returns_nonzero() {
        // SAFETY: all null parameters; stub does not dereference them.
        let result =
            unsafe { gdi32_FillRect(std::ptr::null_mut(), std::ptr::null(), std::ptr::null_mut()) };
        assert_ne!(result, 0);
    }

    #[test]
    fn test_create_font_returns_nonnull() {
        // SAFETY: all integer/null parameters; stub does not dereference them.
        let hfont = unsafe {
            gdi32_CreateFontW(16, 0, 0, 0, 400, 0, 0, 0, 0, 0, 0, 0, 0, std::ptr::null())
        };
        assert!(!hfont.is_null());
    }

    #[test]
    fn test_get_text_extent_returns_one_and_fills_size() {
        // SAFETY: size is a valid 2-i32 buffer; string pointer is null (c=0).
        let mut size = [0i32; 2];
        let result = unsafe {
            gdi32_GetTextExtentPoint32W(
                std::ptr::null_mut(),
                std::ptr::null(),
                5,
                size.as_mut_ptr(),
            )
        };
        assert_eq!(result, 1);
        assert_eq!(size[0], 40); // 5 chars × 8 px
        assert_eq!(size[1], 16);
    }

    #[test]
    fn test_get_text_extent_null_size() {
        // SAFETY: null size; GetTextExtentPoint32W guards with null check.
        let result = unsafe {
            gdi32_GetTextExtentPoint32W(
                std::ptr::null_mut(),
                std::ptr::null(),
                3,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1);
    }
}
