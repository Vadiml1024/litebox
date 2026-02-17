// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Math operations test program for Windows-on-Linux platform
//! 
//! This program tests:
//! - Floating-point arithmetic
//! - Integer arithmetic
//! - Math library functions

fn main() {
    println!("=== Math Operations Test ===\n");
    
    // Test 1: Integer arithmetic
    println!("Test 1: Integer arithmetic");
    let a = 42;
    let b = 17;
    println!("  {} + {} = {}", a, b, a + b);
    println!("  {} - {} = {}", a, b, a - b);
    println!("  {} * {} = {}", a, b, a * b);
    println!("  {} / {} = {}", a, b, a / b);
    println!("  {} % {} = {}", a, b, a % b);
    
    // Test 2: Floating-point arithmetic
    println!("\nTest 2: Floating-point arithmetic");
    let x = std::f64::consts::PI;
    let y = std::f64::consts::E;
    println!("  {:.5} + {:.5} = {:.5}", x, y, x + y);
    println!("  {:.5} - {:.5} = {:.5}", x, y, x - y);
    println!("  {:.5} * {:.5} = {:.5}", x, y, x * y);
    println!("  {:.5} / {:.5} = {:.5}", x, y, x / y);
    
    // Test 3: Math functions
    println!("\nTest 3: Math library functions");
    let angle = 45.0_f64.to_radians();
    println!("  sqrt(16.0) = {:.5}", 16.0_f64.sqrt());
    println!("  pow(2.0, 8.0) = {:.5}", 2.0_f64.powf(8.0));
    println!("  sin(45°) = {:.5}", angle.sin());
    println!("  cos(45°) = {:.5}", angle.cos());
    println!("  tan(45°) = {:.5}", angle.tan());
    println!("  exp(1.0) = {:.5}", 1.0_f64.exp());
    println!("  ln(e) = {:.5}", std::f64::consts::E.ln());
    
    // Test 4: Special values
    println!("\nTest 4: Special floating-point values");
    println!("  Infinity: {}", f64::INFINITY);
    println!("  Negative infinity: {}", f64::NEG_INFINITY);
    println!("  NaN: {}", f64::NAN);
    println!("  Is {} finite? {}", 42.0, 42.0_f64.is_finite());
    println!("  Is {} NaN? {}", f64::NAN, f64::NAN.is_nan());
    
    // Test 5: Rounding
    println!("\nTest 5: Rounding operations");
    let value = 3.7_f64;
    println!("  {:.1} -> floor: {}", value, value.floor());
    println!("  {:.1} -> ceil: {}", value, value.ceil());
    println!("  {:.1} -> round: {}", value, value.round());
    println!("  {:.1} -> trunc: {}", value, value.trunc());
    
    // Test 6: Bitwise operations
    println!("\nTest 6: Bitwise operations");
    let bits_a = 0b1010;
    let bits_b = 0b1100;
    println!("  {:04b} & {:04b} = {:04b}", bits_a, bits_b, bits_a & bits_b);
    println!("  {:04b} | {:04b} = {:04b}", bits_a, bits_b, bits_a | bits_b);
    println!("  {:04b} ^ {:04b} = {:04b}", bits_a, bits_b, bits_a ^ bits_b);
    println!("  !{:04b} = {:04b}", bits_a, !bits_a & 0b1111);
    println!("  {:04b} << 1 = {:04b}", bits_a, bits_a << 1);
    println!("  {:04b} >> 1 = {:04b}", bits_a, bits_a >> 1);
    
    println!("\n=== Math Operations Test Complete ===");
}
