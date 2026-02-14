// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE (Portable Executable) binary loader
//!
//! This module provides a minimal PE loader for loading Windows executables
//! into memory. This is Phase 1 of the Windows on Linux implementation.

pub mod dispatch;
pub mod dll;
pub mod execution;
pub mod pe;

pub use dll::{DllFunction, DllHandle, DllManager};
pub use execution::{
    call_entry_point, ExecutionContext, ProcessEnvironmentBlock, ThreadEnvironmentBlock,
};
pub use pe::PeLoader;
