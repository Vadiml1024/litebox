// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tracing wrapper for NTDLL APIs
//!
//! This module provides a wrapper that intercepts NTDLL API calls
//! for tracing purposes.

use crate::Result;
use crate::syscalls::ntdll::{ConsoleHandle, FileHandle, NtdllApi};
use crate::tracing::{ApiCategory, TraceEvent, Tracer};
use std::sync::Arc;

/// Wrapper for NtdllApi that adds tracing
pub struct TracedNtdllApi<T: NtdllApi> {
    inner: T,
    tracer: Arc<Tracer>,
}

impl<T: NtdllApi> TracedNtdllApi<T> {
    /// Create a new traced API wrapper
    pub fn new(inner: T, tracer: Arc<Tracer>) -> Self {
        Self { inner, tracer }
    }

    /// Get a reference to the inner API implementation
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner API implementation
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: NtdllApi> NtdllApi for TracedNtdllApi<T> {
    fn nt_create_file(
        &mut self,
        path: &str,
        access: u32,
        create_disposition: u32,
    ) -> Result<FileHandle> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!(
                "path=\"{}\", access=0x{:08X}, disposition={}",
                path, access, create_disposition
            );
            let event = TraceEvent::call("NtCreateFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_create_file(path, access, create_disposition);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(handle) => format!("Ok(handle=0x{:X})", handle.0),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("NtCreateFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_read_file(&mut self, handle: FileHandle, buffer: &mut [u8]) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, buffer_size={}", handle.0, buffer.len());
            let event = TraceEvent::call("NtReadFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_read_file(handle, buffer);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_read) => format!("Ok(bytes_read={})", bytes_read),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("NtReadFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_write_file(&mut self, handle: FileHandle, buffer: &[u8]) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, buffer_size={}", handle.0, buffer.len());
            let event = TraceEvent::call("NtWriteFile", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_write_file(handle, buffer);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_written) => format!("Ok(bytes_written={})", bytes_written),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("NtWriteFile", ApiCategory::FileIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_close(&mut self, handle: FileHandle) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}", handle.0);
            let event = TraceEvent::call("NtClose", ApiCategory::FileIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_close(handle);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({})", e),
            };
            let event =
                TraceEvent::return_event("NtClose", ApiCategory::FileIo).with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn get_std_output(&self) -> ConsoleHandle {
        // Note: get_std_output doesn't modify state, so we don't trace it by default
        // as it would create noise. If needed, this can be enabled.
        self.inner.get_std_output()
    }

    fn write_console(&mut self, handle: ConsoleHandle, text: &str) -> Result<usize> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("handle=0x{:X}, text=\"{}\"", handle.0, text.escape_debug());
            let event = TraceEvent::call("WriteConsole", ApiCategory::ConsoleIo).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.write_console(handle, text);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(bytes_written) => format!("Ok(bytes_written={})", bytes_written),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("WriteConsole", ApiCategory::ConsoleIo)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_allocate_virtual_memory(&mut self, size: usize, protect: u32) -> Result<u64> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("size={}, protect=0x{:08X}", size, protect);
            let event =
                TraceEvent::call("NtAllocateVirtualMemory", ApiCategory::Memory).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_allocate_virtual_memory(size, protect);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(addr) => format!("Ok(address=0x{:X})", addr),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("NtAllocateVirtualMemory", ApiCategory::Memory)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }

    fn nt_free_virtual_memory(&mut self, address: u64, size: usize) -> Result<()> {
        // Trace call
        if self.tracer.is_enabled() {
            let args = format!("address=0x{:X}, size={}", address, size);
            let event =
                TraceEvent::call("NtFreeVirtualMemory", ApiCategory::Memory).with_args(args);
            self.tracer.trace(event);
        }

        // Call the inner implementation
        let result = self.inner.nt_free_virtual_memory(address, size);

        // Trace return
        if self.tracer.is_enabled() {
            let ret_str = match &result {
                Ok(()) => "Ok(())".to_string(),
                Err(e) => format!("Err({})", e),
            };
            let event = TraceEvent::return_event("NtFreeVirtualMemory", ApiCategory::Memory)
                .with_return_value(ret_str);
            self.tracer.trace(event);
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::ntdll::{create_disposition, file_access, memory_protection};
    use crate::tracing::{TraceConfig, TraceFilter};

    // Mock implementation for testing
    struct MockNtdllApi;

    impl NtdllApi for MockNtdllApi {
        fn nt_create_file(
            &mut self,
            _path: &str,
            _access: u32,
            _create_disposition: u32,
        ) -> Result<FileHandle> {
            Ok(FileHandle(42))
        }

        fn nt_read_file(&mut self, _handle: FileHandle, buffer: &mut [u8]) -> Result<usize> {
            Ok(buffer.len())
        }

        fn nt_write_file(&mut self, _handle: FileHandle, buffer: &[u8]) -> Result<usize> {
            Ok(buffer.len())
        }

        fn nt_close(&mut self, _handle: FileHandle) -> Result<()> {
            Ok(())
        }

        fn get_std_output(&self) -> ConsoleHandle {
            ConsoleHandle(1)
        }

        fn write_console(&mut self, _handle: ConsoleHandle, text: &str) -> Result<usize> {
            Ok(text.len())
        }

        fn nt_allocate_virtual_memory(&mut self, _size: usize, _protect: u32) -> Result<u64> {
            Ok(0x1000000)
        }

        fn nt_free_virtual_memory(&mut self, _address: u64, _size: usize) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_traced_api_disabled() {
        let mock = MockNtdllApi;
        let config = TraceConfig::default(); // disabled
        let tracer = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, tracer);

        let result = traced.nt_create_file(
            "test.txt",
            file_access::GENERIC_READ,
            create_disposition::OPEN_EXISTING,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_traced_api_enabled() {
        let mock = MockNtdllApi;
        let config = TraceConfig::enabled();
        let tracer = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, tracer);

        let result = traced.nt_create_file(
            "test.txt",
            file_access::GENERIC_READ,
            create_disposition::OPEN_EXISTING,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_traced_memory_operations() {
        let mock = MockNtdllApi;
        let config = TraceConfig::enabled();
        let tracer = Arc::new(Tracer::new(config, TraceFilter::default()).unwrap());
        let mut traced = TracedNtdllApi::new(mock, tracer);

        let alloc_result =
            traced.nt_allocate_virtual_memory(4096, memory_protection::PAGE_READWRITE);
        assert!(alloc_result.is_ok());

        let free_result = traced.nt_free_virtual_memory(0x1000000, 4096);
        assert!(free_result.is_ok());
    }
}
