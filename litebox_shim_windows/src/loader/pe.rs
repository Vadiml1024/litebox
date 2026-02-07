// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PE (Portable Executable) binary parser and loader.
//!
//! This module provides functionality to parse Windows PE/COFF binaries,
//! validate their structure, and load them into memory.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem::size_of;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Errors that can occur during PE parsing and loading.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    /// The file is too small to contain a valid PE header.
    #[error("File too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    /// Invalid DOS signature (expected "MZ").
    #[error("Invalid DOS signature: expected 0x5A4D, got {0:#06x}")]
    InvalidDosSignature(u16),

    /// Invalid PE signature (expected "PE\0\0").
    #[error("Invalid PE signature: expected 0x00004550, got {0:#010x}")]
    InvalidPeSignature(u32),

    /// Unsupported machine type (only x64 is supported).
    #[error("Unsupported machine type: {0:#06x} (only x86-64 is supported)")]
    UnsupportedMachine(u16),

    /// Invalid optional header magic (expected PE32+ for x64).
    #[error("Invalid optional header magic: {0:#06x} (expected PE32+ for x64)")]
    InvalidOptionalHeaderMagic(u16),

    /// Section data extends beyond file bounds.
    #[error("Section {name} extends beyond file bounds")]
    SectionOutOfBounds { name: String },

    /// Invalid relocation data.
    #[error("Invalid relocation data: {0}")]
    InvalidRelocation(String),

    /// Memory allocation error.
    #[error("Memory allocation failed: {0}")]
    MemoryAllocation(String),

    /// Invalid offset in the PE file.
    #[error("Invalid offset: {0}")]
    InvalidOffset(String),
}

/// DOS header structure (IMAGE_DOS_HEADER).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DosHeader {
    /// Magic number "MZ" (0x5A4D).
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial (relative) SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial (relative) CS value.
    pub e_cs: u16,
    /// File address of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File address of new exe header.
    pub e_lfanew: u32,
}

const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const PE_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664; // x64
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b; // PE32+

/// COFF file header (IMAGE_FILE_HEADER).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct CoffHeader {
    /// Machine type (0x8664 for x64).
    pub machine: u16,
    /// Number of sections.
    pub number_of_sections: u16,
    /// Time and date stamp.
    pub time_date_stamp: u32,
    /// File offset of symbol table.
    pub pointer_to_symbol_table: u32,
    /// Number of symbols.
    pub number_of_symbols: u32,
    /// Size of optional header.
    pub size_of_optional_header: u16,
    /// Characteristics flags.
    pub characteristics: u16,
}

/// Data directory entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct DataDirectory {
    /// RVA of the data.
    pub virtual_address: u32,
    /// Size of the data.
    pub size: u32,
}

/// Optional header for PE32+ (64-bit).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct OptionalHeader64 {
    /// Magic number (0x20b for PE32+).
    pub magic: u16,
    /// Linker major version.
    pub major_linker_version: u8,
    /// Linker minor version.
    pub minor_linker_version: u8,
    /// Size of code sections.
    pub size_of_code: u32,
    /// Size of initialized data.
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data.
    pub size_of_uninitialized_data: u32,
    /// Address of entry point.
    pub address_of_entry_point: u32,
    /// Base of code.
    pub base_of_code: u32,
    /// Image base address.
    pub image_base: u64,
    /// Section alignment.
    pub section_alignment: u32,
    /// File alignment.
    pub file_alignment: u32,
    /// OS major version.
    pub major_operating_system_version: u16,
    /// OS minor version.
    pub minor_operating_system_version: u16,
    /// Image major version.
    pub major_image_version: u16,
    /// Image minor version.
    pub minor_image_version: u16,
    /// Subsystem major version.
    pub major_subsystem_version: u16,
    /// Subsystem minor version.
    pub minor_subsystem_version: u16,
    /// Win32 version value.
    pub win32_version_value: u32,
    /// Size of image.
    pub size_of_image: u32,
    /// Size of headers.
    pub size_of_headers: u32,
    /// Checksum.
    pub check_sum: u32,
    /// Subsystem.
    pub subsystem: u16,
    /// DLL characteristics.
    pub dll_characteristics: u16,
    /// Size of stack reserve.
    pub size_of_stack_reserve: u64,
    /// Size of stack commit.
    pub size_of_stack_commit: u64,
    /// Size of heap reserve.
    pub size_of_heap_reserve: u64,
    /// Size of heap commit.
    pub size_of_heap_commit: u64,
    /// Loader flags.
    pub loader_flags: u32,
    /// Number of data directories.
    pub number_of_rva_and_sizes: u32,
}

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

/// Section header (IMAGE_SECTION_HEADER).
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct SectionHeader {
    /// Section name (8 bytes, null-padded).
    pub name: [u8; 8],
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Size of raw data.
    pub size_of_raw_data: u32,
    /// File pointer to raw data.
    pub pointer_to_raw_data: u32,
    /// File pointer to relocations.
    pub pointer_to_relocations: u32,
    /// File pointer to line numbers.
    pub pointer_to_linenumbers: u32,
    /// Number of relocations.
    pub number_of_relocations: u16,
    /// Number of line numbers.
    pub number_of_linenumbers: u16,
    /// Section characteristics.
    pub characteristics: u32,
}

impl SectionHeader {
    /// Get the section name as a string.
    pub fn name_str(&self) -> &str {
        let len = self
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..len]).unwrap_or("<invalid>")
    }
}

/// Base relocation block header.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BaseRelocation {
    /// Page RVA.
    pub virtual_address: u32,
    /// Block size (including this header).
    pub size_of_block: u32,
}

/// Relocation entry type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// Absolute, no relocation needed.
    Absolute = 0,
    /// 64-bit address relocation (x64).
    Dir64 = 10,
}

/// A relocation entry.
#[derive(Debug, Clone, Copy)]
pub struct RelocationEntry {
    /// Type of relocation.
    pub reloc_type: RelocationType,
    /// Offset within the page.
    pub offset: u16,
}

impl RelocationEntry {
    /// Parse a relocation entry from a u16.
    pub fn from_u16(value: u16) -> Self {
        let reloc_type = match value >> 12 {
            10 => RelocationType::Dir64,
            _ => RelocationType::Absolute, // 0 and unknown types treated as absolute
        };
        let offset = value & 0x0FFF;
        Self { reloc_type, offset }
    }
}

/// Parsed PE binary information.
#[derive(Debug)]
pub struct PeBinary<'a> {
    /// Raw PE file data.
    data: &'a [u8],
    /// DOS header.
    pub dos_header: DosHeader,
    /// COFF header.
    pub coff_header: CoffHeader,
    /// Optional header.
    pub optional_header: OptionalHeader64,
    /// Data directories.
    pub data_directories: &'a [DataDirectory],
    /// Section headers.
    pub sections: &'a [SectionHeader],
}

impl<'a> PeBinary<'a> {
    /// Parse a PE binary from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary is invalid or not a supported PE format.
    ///
    /// # Panics
    ///
    /// Will panic if zerocopy parsing fails unexpectedly (should not happen
    /// since all sizes are validated before parsing).
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        // Parse DOS header
        if data.len() < size_of::<DosHeader>() {
            return Err(PeError::FileTooSmall {
                expected: size_of::<DosHeader>(),
                actual: data.len(),
            });
        }

        let dos_header = DosHeader::read_from_bytes(&data[..size_of::<DosHeader>()])
            .expect("size checked above");

        // Validate DOS signature
        if dos_header.e_magic != DOS_SIGNATURE {
            return Err(PeError::InvalidDosSignature(dos_header.e_magic));
        }

        // Check PE header offset
        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + size_of::<u32>() > data.len() {
            return Err(PeError::InvalidOffset(
                "PE signature offset beyond file".to_string(),
            ));
        }

        // Validate PE signature
        let pe_signature = u32::read_from_bytes(&data[pe_offset..pe_offset + size_of::<u32>()])
            .expect("bounds checked");
        if pe_signature != PE_SIGNATURE {
            return Err(PeError::InvalidPeSignature(pe_signature));
        }

        // Parse COFF header
        let coff_offset = pe_offset + size_of::<u32>();
        if coff_offset + size_of::<CoffHeader>() > data.len() {
            return Err(PeError::FileTooSmall {
                expected: coff_offset + size_of::<CoffHeader>(),
                actual: data.len(),
            });
        }

        let coff_header =
            CoffHeader::read_from_bytes(&data[coff_offset..coff_offset + size_of::<CoffHeader>()])
                .expect("bounds checked");

        // Validate machine type (only x64 supported)
        if coff_header.machine != IMAGE_FILE_MACHINE_AMD64 {
            return Err(PeError::UnsupportedMachine(coff_header.machine));
        }

        // Parse optional header
        let opt_offset = coff_offset + size_of::<CoffHeader>();
        if opt_offset + size_of::<OptionalHeader64>() > data.len() {
            return Err(PeError::FileTooSmall {
                expected: opt_offset + size_of::<OptionalHeader64>(),
                actual: data.len(),
            });
        }

        let optional_header = OptionalHeader64::read_from_bytes(
            &data[opt_offset..opt_offset + size_of::<OptionalHeader64>()],
        )
        .expect("bounds checked");

        // Validate optional header magic (PE32+ for x64)
        if optional_header.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            return Err(PeError::InvalidOptionalHeaderMagic(optional_header.magic));
        }

        // Parse data directories
        let dd_offset = opt_offset + size_of::<OptionalHeader64>();
        let dd_count = optional_header.number_of_rva_and_sizes as usize;
        let dd_size = dd_count * size_of::<DataDirectory>();

        if dd_offset + dd_size > data.len() {
            return Err(PeError::FileTooSmall {
                expected: dd_offset + dd_size,
                actual: data.len(),
            });
        }

        let data_directories = <[DataDirectory]>::ref_from_bytes(
            &data[dd_offset..dd_offset + dd_size],
        )
        .map_err(|_| PeError::FileTooSmall {
            expected: dd_offset + dd_size,
            actual: data.len(),
        })?;

        // Parse section headers
        let section_offset = opt_offset + coff_header.size_of_optional_header as usize;
        let section_count = coff_header.number_of_sections as usize;
        let section_size = section_count * size_of::<SectionHeader>();

        if section_offset + section_size > data.len() {
            return Err(PeError::FileTooSmall {
                expected: section_offset + section_size,
                actual: data.len(),
            });
        }

        let sections =
            <[SectionHeader]>::ref_from_bytes(&data[section_offset..section_offset + section_size])
                .map_err(|_| PeError::FileTooSmall {
                    expected: section_offset + section_size,
                    actual: data.len(),
                })?;

        Ok(Self {
            data,
            dos_header,
            coff_header,
            optional_header,
            data_directories,
            sections,
        })
    }

    /// Get the entry point address (RVA).
    pub fn entry_point(&self) -> u32 {
        self.optional_header.address_of_entry_point
    }

    /// Get the preferred image base address.
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base
    }

    /// Get the size of the loaded image in memory.
    pub fn image_size(&self) -> u32 {
        self.optional_header.size_of_image
    }

    /// Get section data from the file.
    ///
    /// # Errors
    ///
    /// Returns an error if the section extends beyond file bounds.
    pub fn section_data(&self, section: &SectionHeader) -> Result<&'a [u8], PeError> {
        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        if start + size > self.data.len() {
            return Err(PeError::SectionOutOfBounds {
                name: section.name_str().to_string(),
            });
        }

        Ok(&self.data[start..start + size])
    }

    /// Get the base relocation directory if present.
    pub fn relocation_directory(&self) -> Option<&DataDirectory> {
        self.data_directories
            .get(IMAGE_DIRECTORY_ENTRY_BASERELOC)
            .filter(|dd| dd.virtual_address != 0 && dd.size != 0)
    }

    /// Parse relocations from the relocation directory.
    ///
    /// # Errors
    ///
    /// Returns an error if relocation data is invalid.
    ///
    /// # Panics
    ///
    /// Will panic if zerocopy parsing fails unexpectedly (should not happen
    /// since all sizes are validated before parsing).
    pub fn parse_relocations(&self) -> Result<Vec<(u32, RelocationEntry)>, PeError> {
        let mut relocations = Vec::new();

        let Some(reloc_dir) = self.relocation_directory() else {
            return Ok(relocations);
        };

        // Find the section containing relocations
        let reloc_rva = reloc_dir.virtual_address;
        let reloc_size = reloc_dir.size as usize;

        let reloc_data = self.get_data_at_rva(reloc_rva, reloc_size)?;

        let mut offset = 0;
        while offset + size_of::<BaseRelocation>() <= reloc_data.len() {
            let block =
                BaseRelocation::read_from_bytes(&reloc_data[offset..]).expect("bounds checked");

            let block_size = block.size_of_block as usize;
            if block_size < size_of::<BaseRelocation>() || offset + block_size > reloc_data.len() {
                break;
            }

            // Parse relocation entries
            let entries_start = offset + size_of::<BaseRelocation>();
            let entries_end = offset + block_size;
            let entries_data = &reloc_data[entries_start..entries_end];

            for chunk in entries_data.chunks_exact(2) {
                let value = u16::from_le_bytes([chunk[0], chunk[1]]);
                let entry = RelocationEntry::from_u16(value);

                if entry.reloc_type != RelocationType::Absolute {
                    let reloc_rva = block.virtual_address + u32::from(entry.offset);
                    relocations.push((reloc_rva, entry));
                }
            }

            offset += block_size;
        }

        Ok(relocations)
    }

    /// Get data at a given RVA (Relative Virtual Address).
    fn get_data_at_rva(&self, rva: u32, size: usize) -> Result<&'a [u8], PeError> {
        // Find the section containing this RVA
        for section in self.sections {
            let section_start = section.virtual_address;
            let section_end = section_start + section.virtual_size;

            if rva >= section_start && rva < section_end {
                let offset_in_section = (rva - section_start) as usize;
                let file_offset = section.pointer_to_raw_data as usize + offset_in_section;

                if file_offset + size > self.data.len() {
                    return Err(PeError::InvalidOffset(format!(
                        "Data at RVA {rva:#x} extends beyond file"
                    )));
                }

                return Ok(&self.data[file_offset..file_offset + size]);
            }
        }

        Err(PeError::InvalidOffset(format!(
            "RVA {rva:#x} not found in any section"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relocation_entry_parsing() {
        let entry = RelocationEntry::from_u16(0xA123); // Type 10 (DIR64), offset 0x123
        assert_eq!(entry.reloc_type, RelocationType::Dir64);
        assert_eq!(entry.offset, 0x123);

        let entry = RelocationEntry::from_u16(0x0456); // Type 0 (Absolute), offset 0x456
        assert_eq!(entry.reloc_type, RelocationType::Absolute);
        assert_eq!(entry.offset, 0x456);
    }

    #[test]
    fn test_section_name() {
        let mut section = SectionHeader {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            size_of_raw_data: 0,
            pointer_to_raw_data: 0,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0,
        };

        section.name[..5].copy_from_slice(b".text");
        assert_eq!(section.name_str(), ".text");
    }
}
