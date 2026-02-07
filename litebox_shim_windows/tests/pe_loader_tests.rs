// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Tests for PE loader functionality.

extern crate alloc;

use alloc::vec;
use litebox_shim_windows::loader::pe::{
    CoffHeader, DataDirectory, DosHeader, OptionalHeader64, PeBinary, PeError, RelocationEntry,
    RelocationType, SectionHeader,
};

/// Create a minimal valid PE file for testing.
#[allow(clippy::items_after_statements, clippy::cast_possible_truncation)]
fn create_minimal_pe() -> Vec<u8> {
    let mut data = vec![0u8; 4096];

    // DOS Header
    let dos_header = DosHeader {
        e_magic: 0x5A4D, // "MZ"
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: 128, // Offset to PE header
    };

    // Write DOS header
    use zerocopy::IntoBytes;
    data[..core::mem::size_of::<DosHeader>()].copy_from_slice(dos_header.as_bytes());

    // PE Signature at offset 128
    let pe_sig: u32 = 0x0000_4550; // "PE\0\0"
    data[128..132].copy_from_slice(&pe_sig.to_le_bytes());

    // COFF Header
    let coff_header = CoffHeader {
        machine: 0x8664,       // AMD64
        number_of_sections: 1, // One section
        time_date_stamp: 0,
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: core::mem::size_of::<OptionalHeader64>() as u16 + 16 * 8, // Include data directories
        characteristics: 0x0022, // Executable, large address aware
    };

    let coff_offset = 132;
    data[coff_offset..coff_offset + core::mem::size_of::<CoffHeader>()]
        .copy_from_slice(coff_header.as_bytes());

    // Optional Header
    let opt_offset = coff_offset + core::mem::size_of::<CoffHeader>();
    let optional_header = OptionalHeader64 {
        magic: 0x20b, // PE32+
        major_linker_version: 14,
        minor_linker_version: 0,
        size_of_code: 0x1000,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: 0x1000,
        base_of_code: 0x1000,
        image_base: 0x0001_4000_0000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        major_operating_system_version: 6,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image: 0x3000,
        size_of_headers: 0x400,
        check_sum: 0,
        subsystem: 3, // Console
        dll_characteristics: 0x8160,
        size_of_stack_reserve: 0x10_0000,
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x10_0000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
    };

    data[opt_offset..opt_offset + core::mem::size_of::<OptionalHeader64>()]
        .copy_from_slice(optional_header.as_bytes());

    // Data directories (16 entries, all zeros for now)
    let dd_offset = opt_offset + core::mem::size_of::<OptionalHeader64>();
    for i in 0..16 {
        let dd = DataDirectory {
            virtual_address: 0,
            size: 0,
        };
        let offset = dd_offset + i * core::mem::size_of::<DataDirectory>();
        data[offset..offset + core::mem::size_of::<DataDirectory>()].copy_from_slice(dd.as_bytes());
    }

    // Section header
    let section_offset = dd_offset + 16 * core::mem::size_of::<DataDirectory>();
    let mut section = SectionHeader {
        name: [0; 8],
        virtual_size: 0x1000,
        virtual_address: 0x1000,
        size_of_raw_data: 0x200,
        pointer_to_raw_data: 0x400,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics: 0x6000_0020, // Code, Execute, Read
    };
    section.name[..5].copy_from_slice(b".text");

    data[section_offset..section_offset + core::mem::size_of::<SectionHeader>()]
        .copy_from_slice(section.as_bytes());

    data
}

#[test]
fn test_parse_valid_pe() {
    let data = create_minimal_pe();
    let pe = PeBinary::parse(&data).expect("Should parse valid PE");

    assert_eq!(pe.entry_point(), 0x1000);
    assert_eq!(pe.image_base(), 0x0001_4000_0000);
    assert_eq!(pe.sections.len(), 1);
    assert_eq!(pe.sections[0].name_str(), ".text");
}

#[test]
fn test_invalid_dos_signature() {
    let mut data = create_minimal_pe();
    data[0] = 0xFF; // Invalid DOS signature

    let result = PeBinary::parse(&data);
    assert!(matches!(result, Err(PeError::InvalidDosSignature(_))));
}

#[test]
fn test_invalid_pe_signature() {
    let mut data = create_minimal_pe();
    data[128] = 0xFF; // Invalid PE signature

    let result = PeBinary::parse(&data);
    assert!(matches!(result, Err(PeError::InvalidPeSignature(_))));
}

#[test]
fn test_unsupported_machine() {
    let mut data = create_minimal_pe();
    // Change machine type to x86 (0x014c)
    data[132] = 0x4c;
    data[133] = 0x01;

    let result = PeBinary::parse(&data);
    assert!(matches!(result, Err(PeError::UnsupportedMachine(_))));
}

#[test]
fn test_file_too_small() {
    let data = vec![0u8; 10]; // Too small for DOS header
    let result = PeBinary::parse(&data);
    assert!(matches!(result, Err(PeError::FileTooSmall { .. })));
}

#[test]
fn test_section_data() {
    let data = create_minimal_pe();
    let pe = PeBinary::parse(&data).expect("Should parse valid PE");

    let section_data = pe
        .section_data(&pe.sections[0])
        .expect("Should get section data");
    assert_eq!(section_data.len(), 0x200);
}

#[test]
fn test_relocation_entry_parsing() {
    // Type 10 (DIR64), offset 0x123
    let entry = RelocationEntry::from_u16(0xA123);
    assert_eq!(entry.reloc_type, RelocationType::Dir64);
    assert_eq!(entry.offset, 0x123);

    // Type 0 (Absolute), offset 0x456
    let entry = RelocationEntry::from_u16(0x0456);
    assert_eq!(entry.reloc_type, RelocationType::Absolute);
    assert_eq!(entry.offset, 0x456);
}

#[test]
fn test_no_relocations() {
    let data = create_minimal_pe();
    let pe = PeBinary::parse(&data).expect("Should parse valid PE");

    assert!(pe.relocation_directory().is_none());
    let relocations = pe
        .parse_relocations()
        .expect("Should handle no relocations");
    assert_eq!(relocations.len(), 0);
}
