// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A shim that provides Windows PE binary support and Windows syscall handling.
//!
//! This crate enables LiteBox to load and run Windows PE (Portable Executable)
//! binaries on Linux. It provides PE binary parsing, loading, and relocation
//! handling.
//!
//! # Phase 1 Implementation
//!
//! This is the Phase 1 implementation focusing on the foundation and PE loader:
//! - PE binary parsing (DOS header, NT headers, sections)
//! - Section loading with proper alignment
//! - Relocation handling for ASLR support
//! - Entry point extraction
//!
//! Future phases will add syscall handling, API tracing, and runtime support.

#![no_std]

extern crate alloc;

pub mod loader;
pub mod syscalls;
pub mod tracing;

// Re-export commonly used types
pub use loader::pe::{PeBinary, PeError};
