This repository contains a Rust-based, security-focused sandboxing library OS. To maintain high code quality and consistency, please adhere to the following guidelines when contributing.

## Code Standards

### Required Before Each Commit
- Run `cargo fmt` to format all Rust files using `rustfmt`.
  - This ensures consistent code style across the codebase.

### Development Workflow
The recommended sequence during development is:
1. **Format**: `cargo fmt`
2. **Build**: `cargo build`
3. **Lint**: `cargo clippy --all-targets --all-features`
4. **Test**: `cargo nextest run`
5. **Ratchet Tests**: `cargo test -p dev_tests` - Verify ratchet constraints are met

- Full CI checks are defined in `.github/workflows/ci.yml`.

### Ratchet Tests
The repository uses "ratchet tests" in `dev_tests/src/ratchet.rs` to track and reduce usage of certain features:
- **Globals** (`static` declarations) - We aim to minimize global state
- **Transmutes** - We aim to minimize unsafe transmutes  
- **MaybeUninit** - We aim to minimize uninitialized memory usage

**Important**: If your changes add new instances of these features:
1. First, try to avoid using the feature if possible
2. If unavoidable, update the count in `dev_tests/src/ratchet.rs` for the affected module
3. Justify why the feature is necessary in your PR description

**Note**: The ratchet heuristic for globals detects lines that start with `static ` or `pub static ` (after trimming whitespace). Struct field type annotations like `pub name: &'static str` do NOT count as globals.

## Key Guidelines

1. Follow Rust best practices and idiomatic patterns.
2. Preserve the existing code structure and organization.
3. Minimize use of `unsafe` code. Every `unsafe` block **must** include a clear safety comment explaining why it's sound. Always prefer safe abstractions and code where possible.
4. Write unit tests for new functionality, especially if it affects public interfaces.
   - Extremely simple changes do not require explicit unit tests.
5. Document all public APIs and non-trivial implementation details.
6. Avoid introducing new dependencies unless strictly necessary. If a dependency is added:
   - It must be justified.
   - Prefer `default-features = false` in `Cargo.toml`.
7. Favor `no_std` compatibility wherever feasible.
   - Some crates in the workspace may use `std`, but this should be deliberate and justified.
8. **Prefer modern `let...else` syntax** over manual if-let-else patterns:
   - Prefer: `let Some(x) = opt else { return Err(...); };`
   - Avoid: `let x = if let Some(v) = opt { v } else { return Err(...); };`
   - The modern syntax is more concise and idiomatic in Rust.
