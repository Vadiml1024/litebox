// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Simple GUI "Hello World" program for testing Windows-on-Linux platform

#![windows_subsystem = "windows"]

use windows::{
    core::*, Win32::System::LibraryLoader::GetModuleHandleW, Win32::UI::WindowsAndMessaging::*,
};

fn main() -> Result<()> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        debug_assert!(!instance.is_invalid());

        let message = w!("Hello LiteBox!\n\nThis is a Windows GUI program running on Linux.");
        let title = w!("LiteBox Test");

        MessageBoxW(None, message, title, MB_OK | MB_ICONINFORMATION);
    }

    Ok(())
}
