# Windows Test Programs

This directory contains simple Windows programs used to test the Windows-on-Linux platform in LiteBox.

# Windows Test Programs

This directory contains Windows programs used to test the Windows-on-Linux platform in LiteBox.

## Test Programs

### hello_cli

A simple command-line "Hello World" program that:
- Prints "Hello World from LiteBox!" to the console
- Demonstrates basic Windows console I/O
- Tests standard output in the Windows-on-Linux environment

### hello_gui

A simple GUI program that:
- Shows a message box with "Hello LiteBox!"
- Demonstrates basic Windows GUI functionality
- Tests Windows API calls (MessageBoxW) in the Windows-on-Linux environment

### file_io_test

Comprehensive file I/O operations test that validates:
- Creating and writing files
- Reading file contents
- File metadata queries
- Deleting files
- Directory creation and listing
- Nested file operations

This test creates temporary files and directories, performs operations on them, and cleans up afterward.

### args_test

Command-line argument parsing test that validates:
- Accessing the program name (argv[0])
- Parsing command-line arguments
- Handling arguments with spaces
- Getting the current executable path

Run with various arguments to test: `args_test.exe arg1 "arg with spaces" arg3`

### env_test

Environment variable operations test that validates:
- Reading common environment variables (PATH, HOME, USER, etc.)
- Setting custom environment variables
- Removing environment variables
- Listing all environment variables

### string_test

String operations test that validates:
- String concatenation and manipulation
- String comparison (case-sensitive and case-insensitive)
- String searching (finding substrings)
- String splitting and trimming
- Unicode string handling
- Case conversion (uppercase/lowercase)

### math_test

Mathematical operations test that validates:
- Integer arithmetic (addition, subtraction, multiplication, division, modulo)
- Floating-point arithmetic
- Math library functions (sqrt, pow, sin, cos, tan, exp, ln)
- Special floating-point values (infinity, NaN)
- Rounding operations (floor, ceil, round, trunc)
- Bitwise operations (AND, OR, XOR, NOT, shifts)

## Building

These programs are automatically built for Windows (x86_64-pc-windows-gnu) by the GitHub Actions workflow.

To build locally with cross-compilation:

```bash
# Install the Windows target
rustup target add x86_64-pc-windows-gnu

# Install MinGW cross-compiler
sudo apt install -y mingw-w64

# Build the programs
cd windows_test_programs
cargo build --release --target x86_64-pc-windows-gnu
```

The resulting executables will be in:
- `target/x86_64-pc-windows-gnu/release/hello_cli.exe`
- `target/x86_64-pc-windows-gnu/release/hello_gui.exe`
- `target/x86_64-pc-windows-gnu/release/file_io_test.exe`
- `target/x86_64-pc-windows-gnu/release/args_test.exe`
- `target/x86_64-pc-windows-gnu/release/env_test.exe`
- `target/x86_64-pc-windows-gnu/release/string_test.exe`
- `target/x86_64-pc-windows-gnu/release/math_test.exe`

## Testing

These programs can be used to test the Windows-on-Linux runner:

```bash
# Build the runner
cargo build -p litebox_runner_windows_on_linux_userland

# Run the test programs
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/file_io_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/args_test.exe arg1 arg2
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/env_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/string_test.exe
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/math_test.exe
```

### Current Status

As of the last update, the Windows-on-Linux platform can:
- ✅ Load and parse PE executables
- ✅ Apply relocations
- ⚠️ Import resolution requires Windows DLLs to be available

When running the test programs, you'll see output like:
```
Loaded PE binary: ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe
  Entry point: 0x1410
  Image base: 0x140000000
  Sections: 10
```

This confirms the PE loader is working correctly. Full execution will be possible once DLL loading is implemented.

## Purpose

These test programs serve as a comprehensive test suite to verify that:
1. Windows executables can be loaded and executed correctly
2. File I/O operations work properly (create, read, write, delete, directory ops)
3. Command-line argument parsing is functional
4. Environment variable operations work correctly
5. String manipulation and CRT functions are implemented
6. Mathematical operations and floating-point handling work correctly
7. Console I/O works correctly
8. Memory allocation and management are functional
9. The Windows-on-Linux platform is working as expected

Each test program is self-contained and performs a series of tests, reporting success (✓) or failure (✗) for each operation. This makes it easy to identify which parts of the platform are working and which need attention.
