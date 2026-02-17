// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! String operations test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - String allocation and manipulation
//! - CRT string functions
//! - Unicode string handling

fn main() {
    println!("=== String Operations Test ===\n");
    
    // Test 1: Basic string operations
    println!("Test 1: Basic string operations");
    let s1 = String::from("Hello");
    let s2 = String::from("World");
    let s3 = format!("{} {}", s1, s2);
    println!("  Concatenation: '{}' + '{}' = '{}'", s1, s2, s3);
    
    // Test 2: String comparison
    println!("\nTest 2: String comparison");
    let str_a = "litebox";
    let str_b = "litebox";
    let str_c = "LiteBox";
    println!("  '{}' == '{}': {}", str_a, str_b, str_a == str_b);
    println!("  '{}' == '{}': {}", str_a, str_c, str_a == str_c);
    println!("  '{}' (case-insensitive) == '{}': {}", 
             str_a, str_c, str_a.eq_ignore_ascii_case(str_c));
    
    // Test 3: String searching
    println!("\nTest 3: String searching");
    let haystack = "The quick brown fox jumps over the lazy dog";
    let needle = "fox";
    match haystack.find(needle) {
        Some(pos) => println!("  Found '{}' at position {} in '{}'", needle, pos, haystack),
        None => println!("  '{}' not found in '{}'", needle, haystack),
    }
    
    // Test 4: String splitting
    println!("\nTest 4: String splitting");
    let csv = "apple,banana,cherry,date";
    println!("  Splitting '{}' by ',':", csv);
    for (i, part) in csv.split(',').enumerate() {
        println!("    Part {}: '{}'", i + 1, part);
    }
    
    // Test 5: String trimming
    println!("\nTest 5: String trimming");
    let spaced = "   Hello World   ";
    println!("  Original: '{}'", spaced);
    println!("  Trimmed: '{}'", spaced.trim());
    println!("  Trim start: '{}'", spaced.trim_start());
    println!("  Trim end: '{}'", spaced.trim_end());
    
    // Test 6: Unicode strings
    println!("\nTest 6: Unicode string handling");
    let unicode = "Hello 世界 🦀";
    println!("  Unicode string: '{}'", unicode);
    println!("  Length in bytes: {}", unicode.len());
    println!("  Length in chars: {}", unicode.chars().count());
    
    // Test 7: Case conversion
    println!("\nTest 7: Case conversion");
    let text = "LiteBox Sandbox";
    println!("  Original: '{}'", text);
    println!("  Uppercase: '{}'", text.to_uppercase());
    println!("  Lowercase: '{}'", text.to_lowercase());
    
    println!("\n=== String Operations Test Complete ===");
}
