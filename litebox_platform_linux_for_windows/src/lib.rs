// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux platform implementation for Windows API translation.
//!
//! This crate provides Linux-based implementations of Windows platform APIs,
//! enabling Windows binaries to run on Linux through syscall translation.
//!
//! # Phase 1 Status
//!
//! This crate currently contains placeholder stubs. Full implementation will
//! be added in Phase 2 and beyond:
//! - File I/O operations (Phase 2)
//! - Memory management (Phase 2)
//! - Threading support (Phase 4)
//! - Synchronization primitives (Phase 4)
//! - Registry emulation (Phase 5)
//! - Path translation (Phase 2)

/// Placeholder module for future platform implementation.
pub struct WindowsOnLinuxPlatform;

impl WindowsOnLinuxPlatform {
    /// Create a new platform instance.
    pub fn new() -> Self {
        Self
    }
}

impl Default for WindowsOnLinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}
