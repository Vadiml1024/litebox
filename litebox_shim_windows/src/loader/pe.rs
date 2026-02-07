// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE binary parser and loader
//!
//! This implements a minimal PE (Portable Executable) loader that can:
//! - Parse PE headers (DOS header, NT headers, optional headers)
//! - Load sections into memory
//! - Handle basic relocations
//! - Set up the initial execution context

use crate::{Result, WindowsShimError};

/// DOS header magic number "MZ"
const DOS_SIGNATURE: u16 = 0x5A4D;

/// PE signature "PE\0\0"
const PE_SIGNATURE: u32 = 0x00004550;

/// IMAGE_FILE_MACHINE_AMD64
const MACHINE_AMD64: u16 = 0x8664;

/// Minimal PE DOS header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DosHeader {
    e_magic: u16, // Magic number "MZ"
    _reserved1: [u8; 58],
    e_lfanew: u32, // Offset to PE header
}

/// PE file header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FileHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

/// Optional header (64-bit)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    _reserved: [u8; 64], // Simplified - rest of optional header
}

/// PE section header
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    _reserved: [u32; 3],
    characteristics: u32,
}

/// PE binary loader
pub struct PeLoader {
    /// Raw binary data
    data: Vec<u8>,
    /// Entry point offset
    entry_point: u64,
    /// Image base address
    image_base: u64,
    /// Number of sections
    section_count: u16,
}

impl PeLoader {
    /// Create a new PE loader from binary data
    ///
    /// This performs minimal validation and header parsing
    pub fn new(data: Vec<u8>) -> Result<Self> {
        if data.len() < core::mem::size_of::<DosHeader>() {
            return Err(WindowsShimError::InvalidPeBinary(
                "File too small to contain DOS header".to_string(),
            ));
        }

        // SAFETY: We just checked the size is sufficient for DosHeader
        let dos_header = unsafe { &*(data.as_ptr() as *const DosHeader) };

        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(WindowsShimError::InvalidPeBinary(format!(
                "Invalid DOS signature: expected 0x{:04X}, found 0x{:04X}",
                DOS_SIGNATURE, dos_header.e_magic
            )));
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "PE offset out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above
        let pe_signature = unsafe { *(data.as_ptr().add(pe_offset) as *const u32) };

        if pe_signature != PE_SIGNATURE {
            return Err(WindowsShimError::InvalidPeBinary(format!(
                "Invalid PE signature: expected 0x{:08X}, found 0x{:08X}",
                PE_SIGNATURE, pe_signature
            )));
        }

        let file_header_offset = pe_offset + 4;
        if file_header_offset + core::mem::size_of::<FileHeader>() > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "File header out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above
        let file_header = unsafe { &*(data.as_ptr().add(file_header_offset) as *const FileHeader) };

        if file_header.machine != MACHINE_AMD64 {
            return Err(WindowsShimError::UnsupportedFeature(format!(
                "Unsupported machine type: 0x{:04X} (only x64 is supported)",
                file_header.machine
            )));
        }

        let optional_header_offset = file_header_offset + core::mem::size_of::<FileHeader>();
        if optional_header_offset + core::mem::size_of::<OptionalHeader64>() > data.len() {
            return Err(WindowsShimError::InvalidPeBinary(
                "Optional header out of bounds".to_string(),
            ));
        }

        // SAFETY: We checked bounds above
        let optional_header =
            unsafe { &*(data.as_ptr().add(optional_header_offset) as *const OptionalHeader64) };

        Ok(Self {
            data,
            entry_point: optional_header.address_of_entry_point as u64,
            image_base: optional_header.image_base,
            section_count: file_header.number_of_sections,
        })
    }

    /// Get the entry point address
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Get the preferred image base
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Get the number of sections
    pub fn section_count(&self) -> u16 {
        self.section_count
    }

    /// Get the raw binary data
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_too_small() {
        let data = vec![0; 10];
        let result = PeLoader::new(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_dos_signature() {
        let mut data = vec![0; 64];
        data[0] = 0x00; // Wrong signature
        data[1] = 0x00;
        let result = PeLoader::new(data);
        assert!(result.is_err());
    }
}
