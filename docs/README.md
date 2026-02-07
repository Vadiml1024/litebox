# LiteBox Documentation

This directory contains design documents and implementation plans for LiteBox features.

## Documents

### [Windows on Linux Implementation Plan](./windows_on_linux_implementation_plan.md)

Comprehensive plan for running unmodified Windows programs on Linux while tracing Windows API usage.

**Key Features:**
- PE binary loader
- Windows API translation layer (NTDLL → Linux syscalls)
- Comprehensive API tracing with filtering
- Support for multi-threaded Windows programs

**Status:** Phase 1 & 2 complete (foundation and core APIs)

**Quick Links:**
- [Architecture Overview](./windows_on_linux_implementation_plan.md#architecture-overview)
- [Implementation Phases](./windows_on_linux_implementation_plan.md#implementation-phases)
- [Technical Challenges](./windows_on_linux_implementation_plan.md#technical-challenges--solutions)
- [Phase 2 Implementation Summary](./PHASE2_IMPLEMENTATION.md)

### [Phase 2 Implementation Summary](./PHASE2_IMPLEMENTATION.md)

Summary of the completed Phase 1 (Foundation & PE Loader) and Phase 2 (Core NTDLL APIs) implementation.

**Completed:**
- litebox_shim_windows - PE loader and Windows syscall interface
- litebox_platform_linux_for_windows - Linux implementation of Windows APIs
- litebox_runner_windows_on_linux_userland - CLI runner for Windows programs

**Next:** Phase 3 - API Tracing Framework

