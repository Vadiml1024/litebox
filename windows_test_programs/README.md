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

These programs can be used to test the Windows-on-Linux runner:

```bash
# Run the CLI program
./litebox_runner_windows_on_linux_userland hello_cli.exe

# Run the GUI program (if GUI support is implemented)
./litebox_runner_windows_on_linux_userland hello_gui.exe
```

## Purpose

These minimal test programs serve as basic smoke tests to verify that:
1. Windows executables can be loaded and executed
2. Console I/O works correctly
3. Basic Windows API calls are functional
4. The Windows-on-Linux platform is working as expected
