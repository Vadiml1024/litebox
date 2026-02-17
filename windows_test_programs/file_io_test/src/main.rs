// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File I/O test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Creating files
//! - Writing to files
//! - Reading from files
//! - Deleting files
//! - File existence checks

use std::fs;
use std::io::{Read, Write};

fn main() {
    println!("=== File I/O Test Suite ===\n");
    
    let test_file = "test_file.txt";
    let test_content = "Hello from LiteBox file I/O test!";
    
    // Test 1: Create and write file
    println!("Test 1: Creating file '{}'...", test_file);
    match fs::File::create(test_file) {
        Ok(mut file) => {
            println!("  ✓ File created successfully");
            
            print!("  Writing content...");
            match file.write_all(test_content.as_bytes()) {
                Ok(_) => println!(" ✓"),
                Err(e) => {
                    println!(" ✗ Failed: {}", e);
                    return;
                }
            }
        }
        Err(e) => {
            println!("  ✗ Failed to create file: {}", e);
            return;
        }
    }
    
    // Test 2: Read file
    println!("\nTest 2: Reading file...");
    match fs::File::open(test_file) {
        Ok(mut file) => {
            let mut contents = String::new();
            match file.read_to_string(&mut contents) {
                Ok(_) => {
                    println!("  ✓ Read {} bytes", contents.len());
                    if contents == test_content {
                        println!("  ✓ Content matches expected");
                    } else {
                        println!("  ✗ Content mismatch!");
                        println!("    Expected: {}", test_content);
                        println!("    Got: {}", contents);
                    }
                }
                Err(e) => println!("  ✗ Failed to read: {}", e),
            }
        }
        Err(e) => println!("  ✗ Failed to open file: {}", e),
    }
    
    // Test 3: File metadata
    println!("\nTest 3: Checking file metadata...");
    match fs::metadata(test_file) {
        Ok(metadata) => {
            println!("  ✓ File size: {} bytes", metadata.len());
            println!("  ✓ Is file: {}", metadata.is_file());
            println!("  ✓ Is directory: {}", metadata.is_dir());
        }
        Err(e) => println!("  ✗ Failed to get metadata: {}", e),
    }
    
    // Test 4: Delete file
    println!("\nTest 4: Deleting file...");
    match fs::remove_file(test_file) {
        Ok(_) => {
            println!("  ✓ File deleted successfully");
            
            // Verify deletion
            if !std::path::Path::new(test_file).exists() {
                println!("  ✓ File no longer exists");
            } else {
                println!("  ✗ File still exists after deletion!");
            }
        }
        Err(e) => println!("  ✗ Failed to delete file: {}", e),
    }
    
    // Test 5: Directory operations
    println!("\nTest 5: Directory operations...");
    let test_dir = "test_directory";
    
    print!("  Creating directory '{}'...", test_dir);
    match fs::create_dir(test_dir) {
        Ok(_) => {
            println!(" ✓");
            
            // Create a file in the directory
            let nested_file = format!("{}/nested.txt", test_dir);
            if let Ok(mut file) = fs::File::create(&nested_file) {
                let _ = file.write_all(b"nested file content");
                println!("  ✓ Created nested file");
            }
            
            // List directory contents
            print!("  Listing directory contents...");
            match fs::read_dir(test_dir) {
                Ok(entries) => {
                    let count = entries.count();
                    println!(" ✓ ({} entries)", count);
                }
                Err(e) => println!(" ✗ Failed: {}", e),
            }
            
            // Clean up
            print!("  Cleaning up...");
            let _ = fs::remove_file(&nested_file);
            match fs::remove_dir(test_dir) {
                Ok(_) => println!(" ✓"),
                Err(e) => println!(" ✗ Failed: {}", e),
            }
        }
        Err(e) => println!(" ✗ Failed: {}", e),
    }
    
    println!("\n=== File I/O Test Complete ===");
}
