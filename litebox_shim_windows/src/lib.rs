// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows shim for running Windows PE binaries on Linux
//!
//! This crate provides a Windows PE binary loader and syscall interface
//! for running unmodified Windows programs on Linux through LiteBox.

pub mod loader;
pub mod syscalls;

use thiserror::Error;

/// Errors that can occur when loading or running Windows binaries
#[derive(Debug, Error)]
pub enum WindowsShimError {
    #[error("Invalid PE binary: {0}")]
    InvalidPeBinary(String),

    #[error("Unsupported PE feature: {0}")]
    UnsupportedFeature(String),

    #[error("Syscall error: {0}")]
    SyscallError(String),

    #[error("I/O error: {0}")]
    IoError(String),
}

pub type Result<T> = core::result::Result<T, WindowsShimError>;
