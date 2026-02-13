// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! API tracing framework for Windows syscalls
//!
//! This module provides configurable tracing of Windows API calls for
//! debugging and security analysis.

pub mod config;
pub mod event;
pub mod filter;
pub mod formatter;
pub mod tracer;

pub use config::{TraceConfig, TraceFormat, TraceOutput};
pub use event::TraceEvent;
pub use filter::{TraceFilter, FilterRule};
pub use formatter::{TraceFormatter, TextFormatter, JsonFormatter};
pub use tracer::Tracer;
