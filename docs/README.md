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

**Status:** Phases 1-6 complete (100%), Phase 7 in progress (15%)

**Quick Links:**
- [Architecture Overview](./windows_on_linux_implementation_plan.md#architecture-overview)
- [Implementation Phases](./windows_on_linux_implementation_plan.md#implementation-phases)
- [Technical Challenges](./windows_on_linux_implementation_plan.md#technical-challenges--solutions)
- [Current Status](./windows_on_linux_status.md)

### [Windows on Linux Current Status](./windows_on_linux_status.md)

Complete status of the Windows-on-Linux implementation with test coverage and capabilities.

**Current Status:**
- ✅ Phase 1-6: Complete (PE loading, APIs, tracing, threading, environment, DLL loading)
- 🚧 Phase 7: In Progress (Real API implementations, memory protection, error handling)

### Implementation Phase Documents

- [Phase 2 Implementation](./PHASE2_IMPLEMENTATION.md) - Foundation and Core NTDLL APIs
- [Phase 3 Complete](./PHASE3_COMPLETE.md) - API Tracing Framework
- [Phase 4 Complete](./PHASE4_COMPLETE.md) - Threading & Synchronization
- [Phase 5 Complete](./PHASE5_COMPLETE.md) - Extended API Support
- [Phase 6 Complete](./PHASE6_100_PERCENT_COMPLETE.md) - DLL Loading & Execution Framework
- [Phase 7 Implementation](./PHASE7_IMPLEMENTATION.md) - Real Windows API Implementation (IN PROGRESS)

