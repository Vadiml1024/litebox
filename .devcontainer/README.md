# LiteBox Development Container

This directory contains the configuration for a development container that provides a pre-configured environment for working on the LiteBox project.

## What's Included

The devcontainer provides:

- **Rust Toolchain**: Pre-installed Rust nightly-2026-01-15 (as specified in `rust-toolchain.toml`)
- **Build Tools**: 
  - `build-essential`, `pkg-config`, `libssl-dev` for compiling Rust projects
  - `mingw-w64` for cross-compiling Windows PE binaries
  - `gdb` for debugging
- **Rust Targets**: `x86_64-pc-windows-gnu` for Windows cross-compilation
- **Cargo Tools**: `cargo-nextest` for faster test execution
- **Cached Dependencies**: All Cargo dependencies are pre-downloaded in the container image
- **VS Code Extensions**:
  - `rust-analyzer` - Rust language server
  - `vscode-lldb` - Debugger
  - `even-better-toml` - TOML syntax support

## Benefits

- **Fast Startup**: Dependencies are cached in the container image, so you don't need to download them every time
- **Consistent Environment**: Everyone uses the same toolchain and dependencies
- **No Local Setup**: No need to install Rust, MinGW, or other tools on your local machine

## Using the Devcontainer

### GitHub Codespaces

1. Go to the repository on GitHub
2. Click the "Code" button
3. Select "Codespaces" tab
4. Click "Create codespace on [branch]"

The devcontainer will automatically build and start.

### VS Code with Docker

1. Install [Docker](https://www.docker.com/products/docker-desktop)
2. Install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
3. Open the repository in VS Code
4. When prompted, click "Reopen in Container" (or run "Dev Containers: Reopen in Container" from the command palette)

The container will build the first time (this may take 10-15 minutes), but subsequent starts will be much faster.

## Building the Container Manually

If you want to build the container image manually:

```bash
cd .devcontainer
docker build -t litebox-dev .
```

## Customization

To customize the devcontainer:

- **Dockerfile**: Modify system packages, Rust components, or add new tools
- **devcontainer.json**: Adjust VS Code settings, extensions, or environment variables

## Caching

The devcontainer uses Docker volume mounts to cache:
- Cargo registry (`litebox-cargo-registry` volume)
- Cargo git repositories (`litebox-cargo-git` volume)

This means dependencies persist across container rebuilds, making subsequent builds faster.

## Troubleshooting

**Container build fails:**
- Ensure Docker has enough disk space (at least 10GB free)
- Try building with `docker build --no-cache` to force a clean build

**Slow first build:**
- The first build downloads and compiles all dependencies, which can take 10-15 minutes
- Subsequent builds will be much faster due to Docker layer caching

**VS Code can't connect to container:**
- Check that Docker is running
- Try rebuilding the container: "Dev Containers: Rebuild Container"
