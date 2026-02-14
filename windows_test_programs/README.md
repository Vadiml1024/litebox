# Windows Test Programs

This directory contains simple Windows programs used to test the Windows-on-Linux platform in LiteBox.

## Programs

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

## Testing

These programs can be used to test the Windows-on-Linux runner once the DLL loading and API implementation is complete:

```bash
# Build the runner
cd /home/runner/work/litebox/litebox
cargo build -p litebox_runner_windows_on_linux_userland

# Run the CLI program (requires Windows API implementation to be complete)
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_cli.exe

# Run the GUI program (if GUI support is implemented)
./target/debug/litebox_runner_windows_on_linux_userland ./windows_test_programs/target/x86_64-pc-windows-gnu/release/hello_gui.exe
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

These minimal test programs serve as basic smoke tests to verify that:
1. Windows executables can be loaded and executed
2. Console I/O works correctly
3. Basic Windows API calls are functional
4. The Windows-on-Linux platform is working as expected
