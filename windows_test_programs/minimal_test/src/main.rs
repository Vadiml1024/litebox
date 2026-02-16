// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Windows test program with no CRT dependencies
//! 
//! This program has a simple entry point that returns immediately.
//! It's designed to test the PE loader without CRT initialization complexity.

#![no_std]
#![no_main]
#![allow(unsafe_code)]

// Entry point - just return 42
#[unsafe(no_mangle)]
pub extern "C" fn mainCRTStartup() -> i32 {
    42
}

// Panic handler required for no_std
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
