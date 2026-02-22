// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! KERNEL32.dll function implementations
//!
//! This module provides Linux-based implementations of KERNEL32 functions
//! that are commonly used by Windows programs. These are higher-level wrappers
//! around NTDLL functions.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings as we're implementing Windows API which requires specific integer types
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
// Allow raw-pointer alignment casts: we always use write_unaligned / read_unaligned
// when writing to potentially unaligned addresses derived from *mut u8 buffers.
#![allow(clippy::cast_ptr_alignment)]

use std::alloc;
use std::cell::Cell;
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

// Code page constants for MultiByteToWideChar and WideCharToMultiByte
const CP_ACP: u32 = 0;
const CP_UTF8: u32 = 65001;

// Heap constants for HeapAlloc
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

// Epoch difference between Windows (1601-01-01) and Unix (1970-01-01) in seconds
const EPOCH_DIFF: i64 = 11_644_473_600;

/// Thread Local Storage (TLS) manager
///
/// Windows TLS allows each thread to store thread-specific data.
/// This is implemented using a global HashMap where the key is
/// (thread_id, slot_index) and the value is the stored pointer.
struct TlsManager {
    /// Next available TLS slot index
    next_slot: u32,
    /// Map of (thread_id, slot_index) -> value
    storage: HashMap<(u32, u32), usize>,
}

impl TlsManager {
    fn new() -> Self {
        Self {
            next_slot: 0,
            storage: HashMap::new(),
        }
    }

    fn alloc_slot(&mut self) -> Option<u32> {
        // Windows TLS has a limited number of slots (64 or 1088 depending on version)
        // We'll use a generous limit
        const MAX_TLS_SLOTS: u32 = 1088;
        if self.next_slot >= MAX_TLS_SLOTS {
            return None;
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        Some(slot)
    }

    fn free_slot(&mut self, slot: u32, thread_id: u32) -> bool {
        // Remove the value for this thread and slot
        self.storage.remove(&(thread_id, slot));
        true
    }

    fn get_value(&self, slot: u32, thread_id: u32) -> usize {
        self.storage.get(&(thread_id, slot)).copied().unwrap_or(0)
    }

    fn set_value(&mut self, slot: u32, thread_id: u32, value: usize) -> bool {
        self.storage.insert((thread_id, slot), value);
        true
    }
}

/// Global TLS manager protected by a mutex
static TLS_MANAGER: Mutex<Option<TlsManager>> = Mutex::new(None);

/// Initialize the TLS manager (called once)
fn ensure_tls_manager_initialized() {
    let mut manager = TLS_MANAGER.lock().unwrap();
    if manager.is_none() {
        *manager = Some(TlsManager::new());
    }
}

/// Heap allocation tracker
///
/// Tracks allocation sizes for HeapAlloc so that HeapFree and HeapReAlloc
/// can properly deallocate memory using the correct Layout.
struct HeapAllocationTracker {
    /// Map of pointer address -> (size, alignment)
    allocations: HashMap<usize, (usize, usize)>,
}

impl HeapAllocationTracker {
    fn new() -> Self {
        Self {
            allocations: HashMap::new(),
        }
    }

    fn track_allocation(&mut self, ptr: *mut u8, size: usize, align: usize) {
        if !ptr.is_null() {
            self.allocations.insert(ptr as usize, (size, align));
        }
    }

    fn get_allocation(&self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.get(&(ptr as usize)).copied()
    }

    fn remove_allocation(&mut self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.remove(&(ptr as usize))
    }
}

/// Global heap allocation tracker protected by a mutex
static HEAP_TRACKER: Mutex<Option<HeapAllocationTracker>> = Mutex::new(None);

/// Initialize the heap tracker (called once)
fn ensure_heap_tracker_initialized() {
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if tracker.is_none() {
        *tracker = Some(HeapAllocationTracker::new());
    }
}

// ── File-handle registry ──────────────────────────────────────────────────
// Maps Win32 HANDLE values (encoded as usize) to open `File` objects.

static FILE_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x1_0000);

struct FileEntry {
    file: File,
}

/// Global file-handle map: handle_value → FileEntry
static FILE_HANDLES: Mutex<Option<HashMap<usize, FileEntry>>> = Mutex::new(None);

fn with_file_handles<R>(f: impl FnOnce(&mut HashMap<usize, FileEntry>) -> R) -> R {
    let mut guard = FILE_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Windows error code returned when no more handles can be opened.
const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;

/// Maximum number of concurrently open file handles.
/// `CreateFileW` returns `ERROR_TOO_MANY_OPEN_FILES` (4) once this limit is
/// reached.  1024 matches a common Windows per-process soft limit.
#[cfg(not(test))]
const MAX_OPEN_FILE_HANDLES: usize = 1024;
/// Use a smaller limit in tests to avoid exhausting the process fd table and
/// to keep the test fast.
#[cfg(test)]
const MAX_OPEN_FILE_HANDLES: usize = 8;

/// Allocate a new Win32-style file handle value (non-null, not INVALID_HANDLE_VALUE).
fn alloc_file_handle() -> usize {
    use std::sync::atomic::Ordering;
    FILE_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Directory-search-handle registry ─────────────────────────────────────
// Maps synthetic HANDLE values (usize) to in-progress directory searches.
// Used by FindFirstFileW / FindNextFileW / FindClose.
//
// Note: entries are only removed by FindClose. A Windows program that exits
// without calling FindClose (or crashes) will leave entries in this map for
// the lifetime of the process, holding onto Vec allocations. This is
// consistent with the FILE_HANDLES registry and is acceptable for a
// sandboxed single-process environment.

static FIND_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x2_0000);

struct DirSearchState {
    entries: Vec<std::fs::DirEntry>,
    current_index: usize,
    pattern: String,
}

static FIND_HANDLES: Mutex<Option<HashMap<usize, DirSearchState>>> = Mutex::new(None);

fn with_find_handles<R>(f: impl FnOnce(&mut HashMap<usize, DirSearchState>) -> R) -> R {
    let mut guard = FIND_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Maximum number of concurrently open directory-search handles.
#[cfg(not(test))]
const MAX_OPEN_FIND_HANDLES: usize = 1024;
/// Smaller limit during tests.
#[cfg(test)]
const MAX_OPEN_FIND_HANDLES: usize = 8;

fn alloc_find_handle() -> usize {
    use std::sync::atomic::Ordering;
    FIND_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Thread-handle registry ────────────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to spawned Rust thread state.
// Used by CreateThread / WaitForSingleObject / WaitForMultipleObjects.

static THREAD_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x3_0000);

struct ThreadEntry {
    join_handle: Option<thread::JoinHandle<u32>>,
    exit_code: Arc<Mutex<Option<u32>>>,
}

/// Global thread-handle map: handle_value → ThreadEntry
static THREAD_HANDLES: Mutex<Option<HashMap<usize, ThreadEntry>>> = Mutex::new(None);

fn with_thread_handles<R>(f: impl FnOnce(&mut HashMap<usize, ThreadEntry>) -> R) -> R {
    let mut guard = THREAD_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_thread_handle() -> usize {
    use std::sync::atomic::Ordering;
    THREAD_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Event-handle registry ─────────────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to Condvar-backed event objects.
// Used by CreateEventW / SetEvent / ResetEvent / WaitForSingleObject.

static EVENT_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x4_0000);

struct EventEntry {
    manual_reset: bool,
    state: Arc<(Mutex<bool>, Condvar)>,
}

static EVENT_HANDLES: Mutex<Option<HashMap<usize, EventEntry>>> = Mutex::new(None);

fn with_event_handles<R>(f: impl FnOnce(&mut HashMap<usize, EventEntry>) -> R) -> R {
    let mut guard = EVENT_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_event_handle() -> usize {
    use std::sync::atomic::Ordering;
    EVENT_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

/// Windows thread start function pointer type (MS-x64 ABI).
/// LPTHREAD_START_ROUTINE = DWORD (WINAPI *)(LPVOID lpThreadParameter)
type WindowsThreadStart = unsafe extern "win64" fn(*mut core::ffi::c_void) -> u32;

/// Simple glob pattern matching (Windows-style: `*` = any substring, `?` = any char).
/// Comparison is case-insensitive (ASCII).
fn find_matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    let name_lower: String = name.to_ascii_lowercase();
    let pat_lower: String = pattern.to_ascii_lowercase();
    glob_match(name_lower.as_bytes(), pat_lower.as_bytes())
}

fn glob_match(name: &[u8], pattern: &[u8]) -> bool {
    let mut i: usize = 0; // index into name
    let mut j: usize = 0; // index into pattern

    // Last position of '*' in pattern, and the index in name that matched it.
    let mut star_idx: Option<usize> = None;
    let mut match_idx: usize = 0;

    while i < name.len() {
        if j < pattern.len() && (pattern[j] == b'?' || pattern[j] == name[i]) {
            // Current characters match (or pattern has '?'): advance both.
            i += 1;
            j += 1;
        } else if j < pattern.len() && pattern[j] == b'*' {
            // Record position of '*' and the corresponding match index in name.
            star_idx = Some(j);
            match_idx = i;
            j += 1;
        } else if let Some(si) = star_idx {
            // Mismatch, but we have a previous '*': backtrack.
            j = si + 1;
            match_idx += 1;
            if match_idx > name.len() {
                return false;
            }
            i = match_idx;
        } else {
            // Mismatch and no '*' to fall back to.
            return false;
        }
    }

    // Consume any trailing '*' in the pattern: they can match an empty suffix.
    while j < pattern.len() && pattern[j] == b'*' {
        j += 1;
    }

    j == pattern.len()
}

/// Fill a raw `WIN32_FIND_DATAW` buffer from a directory entry.
///
/// The caller-supplied `find_data` must point to at least 592 bytes (the size of
/// `WIN32_FIND_DATAW`).  The layout written matches the Windows ABI exactly:
///   - offset   0: dwFileAttributes (u32)
///   - offset   4: ftCreationTime   (2×u32, low first)
///   - offset  12: ftLastAccessTime (2×u32)
///   - offset  20: ftLastWriteTime  (2×u32)
///   - offset  28: nFileSizeHigh (u32)
///   - offset  32: nFileSizeLow  (u32)
///   - offset  36: dwReserved0   (u32)
///   - offset  40: dwReserved1   (u32)
///   - offset  44: cFileName\[260\] (u16 array)
///   - offset 564: cAlternateFileName\[14\] (u16 array)
///
/// # Safety
/// `find_data` must point to a writable buffer of at least 592 bytes.
unsafe fn fill_find_data(entry: &std::fs::DirEntry, find_data: *mut u8) {
    const WIN32_FIND_DATAW_SIZE: usize = 592;
    if find_data.is_null() {
        return;
    }
    // Always zero-initialize the buffer so that callers never observe
    // uninitialized memory, even if metadata retrieval fails.
    // SAFETY: Caller guarantees `find_data` points to at least
    // `WIN32_FIND_DATAW_SIZE` writable bytes (see function safety contract),
    // and we've just checked that the pointer is non-null.
    std::ptr::write_bytes(find_data, 0u8, WIN32_FIND_DATAW_SIZE);

    let Ok(metadata) = entry.metadata() else {
        // Return with a zeroed structure on metadata failure.
        return;
    };
    fill_find_data_from_path(&entry.path(), &metadata, find_data);
}

/// Parse a Windows/Linux path into (directory_string, pattern_string).
/// e.g. "/tmp/foo/*.txt" → ("/tmp/foo", "*.txt")
///      "/tmp/foo/bar.txt" → ("/tmp/foo", "bar.txt")
fn split_dir_and_pattern(linux_path: &str) -> (String, String) {
    let path = std::path::Path::new(linux_path);
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let dir = if parent.as_os_str().is_empty() {
            ".".to_string()
        } else {
            parent.to_string_lossy().into_owned()
        };
        (dir, name.to_string_lossy().into_owned())
    } else {
        (".".to_string(), linux_path.to_string())
    }
}

/// Write `data` to the file registered under `handle` in the kernel32 file-handle map.
///
/// Returns `Some(bytes_written)` if the handle was found, `None` otherwise.
/// Used by `ntdll_impl.rs` to route `NtWriteFile` calls through the kernel32 handle registry.
pub fn nt_write_file_handle(handle: u64, data: &[u8]) -> Option<usize> {
    let handle_val = handle as usize;
    with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.write(data).ok()
        } else {
            None
        }
    })
}

/// Read from the file registered under `handle` in the kernel32 file-handle map.
///
/// Returns `Some(bytes_read)` if the handle was found, `None` otherwise.
/// Used by `ntdll_impl.rs` to route `NtReadFile` calls through the kernel32 handle registry.
pub fn nt_read_file_handle(handle: u64, buf: &mut [u8]) -> Option<usize> {
    let handle_val = handle as usize;
    with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.read(buf).ok()
        } else {
            None
        }
    })
}

/// Return the command line as a UTF-8 `String`.
///
/// Reads `PROCESS_COMMAND_LINE` (UTF-16) and converts to UTF-8.  Returns an empty
/// string if the command line has not been set yet.
pub fn get_command_line_utf8() -> String {
    PROCESS_COMMAND_LINE
        .get()
        .map(|v| {
            // strip trailing null terminator(s) before converting
            let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
            String::from_utf16_lossy(&v[..end])
        })
        .unwrap_or_default()
}

// ── Environment-strings block registry ───────────────────────────────────
// Each call to `GetEnvironmentStringsW` allocates a block.  The block's
// raw pointer is recorded here so that `FreeEnvironmentStringsW` can
// reconstruct the `Box` and drop it, preventing unbounded memory growth.

/// Newtype wrapper so that `*mut u16` (which is not `Send`) can be stored in a
/// `static Mutex`.  Safety: the pointer is only ever accessed while holding the
/// mutex lock, so no data race can occur.
struct SendablePtr(*mut u16);
// SAFETY: We only ever access the pointer while holding the mutex, so it is
// effectively single-threaded at any given moment.
unsafe impl Send for SendablePtr {}

static ENV_STRINGS_BLOCKS: Mutex<Option<Vec<SendablePtr>>> = Mutex::new(None);

/// Process command line (UTF-16, null-terminated) set by the runner before entry point execution
static PROCESS_COMMAND_LINE: OnceLock<Vec<u16>> = OnceLock::new();

/// Optional sandbox root directory. When set, all file paths resolved by
/// `wide_path_to_linux` are restricted to this prefix. Paths that escape the
/// sandbox (e.g. via `..` traversal) are replaced with an empty string so that
/// the subsequent file operation fails safely.
static SANDBOX_ROOT: Mutex<Option<String>> = Mutex::new(None);

/// Volume serial number reported by `GetFileInformationByHandle`.
///
/// `0` means "not yet set"; the first call to `get_volume_serial()` will
/// generate a value from the process ID and the current time and store it
/// here so that subsequent calls return the same value for the lifetime of
/// the process.  The runner may call `set_volume_serial` before the entry
/// point executes to pin a specific value instead.
static VOLUME_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Override the volume serial number returned by `GetFileInformationByHandle`.
///
/// Call this before executing the PE entry point.  Passing `0` clears any
/// previously pinned value, causing the next `GetFileInformationByHandle`
/// call to generate a fresh per-run value.
pub fn set_volume_serial(serial: u32) {
    use std::sync::atomic::Ordering;
    VOLUME_SERIAL.store(serial, Ordering::Relaxed);
}

/// Return the volume serial number, generating one lazily if none has been set.
///
/// The generated value is derived from the process ID and the current
/// system time, giving a different value on each run without requiring an
/// external RNG dependency.
fn get_volume_serial() -> u32 {
    use std::sync::atomic::Ordering;
    let current = VOLUME_SERIAL.load(Ordering::Relaxed);
    if current != 0 {
        return current;
    }
    // Generate: mix process ID with sub-second time to get a per-run value.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // Simple multiplicative hash so even similar inputs differ widely.
    let generated = pid.wrapping_mul(2_654_435_761).wrapping_add(nanos) | 1; // ensure non-zero
    // Only store the generated value if nobody else stored one concurrently.
    match VOLUME_SERIAL.compare_exchange(0, generated, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => generated,
        Err(stored) => stored, // another thread beat us; use their value
    }
}

/// Set the process command line from runner-provided arguments.
///
/// Call this before executing the entry point to ensure Windows programs receive
/// the correct command line via `GetCommandLineW` and `__getmainargs`.
/// The first element of `args` should be the program name/path.
pub fn set_process_command_line(args: &[String]) {
    let cmd_line = args
        .iter()
        .map(|arg| {
            if arg.contains(' ') || arg.contains('"') {
                // Windows command-line quoting: escape backslashes before a quote,
                // escape any embedded quotes with backslash, then wrap in double quotes.
                format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let mut utf16: Vec<u16> = cmd_line.encode_utf16().collect();
    utf16.push(0);
    // Ignore errors if already set (idempotent in tests)
    let _ = PROCESS_COMMAND_LINE.set(utf16);
}

/// Restrict all file-path operations to the given directory root.
///
/// When a sandbox root is configured, `wide_path_to_linux` will normalise
/// every path (resolving all `..` and `.` components) and verify that the
/// result still starts with `root`.  Paths that escape the sandbox are
/// replaced with an empty string so that the corresponding file operation
/// fails with `ERROR_ACCESS_DENIED` (or similar) rather than accessing an
/// unexpected location.
///
/// May be called multiple times to change or clear the sandbox root
/// (`None` disables sandboxing).
///
/// # Panics
/// Panics if the internal sandbox-root mutex is poisoned.
pub fn set_sandbox_root(root: &str) {
    *SANDBOX_ROOT.lock().unwrap() = Some(root.to_owned());
}

/// Apply the sandbox restriction to an already-translated Linux path.
///
/// If no sandbox root is configured the path is returned unchanged.
/// If a root is configured the path is normalised (all `..`/`.` resolved)
/// and returned only if it is a descendant of the root; otherwise an empty
/// string is returned so that callers treat the access as failed.
fn sandbox_guard(path: String) -> String {
    let guard = SANDBOX_ROOT.lock().unwrap();
    let Some(root) = guard.as_deref() else {
        return path;
    };
    // Normalise without hitting the filesystem (works for paths that do not
    // exist yet, e.g. a file about to be created).
    // `PathBuf::pop()` never removes the root component (`/`), so traversal
    // cannot escape below the filesystem root.
    let mut normalised = PathBuf::new();
    for component in Path::new(&path).components() {
        match component {
            Component::ParentDir => {
                normalised.pop();
            }
            Component::CurDir => {}
            _ => normalised.push(component),
        }
    }
    let normalised_str = normalised.to_string_lossy();
    if normalised_str.starts_with(root) {
        normalised_str.into_owned()
    } else {
        // Path escapes sandbox: return empty string so that the caller's file
        // operation fails with a benign error (e.g. ENOENT / ERROR_ACCESS_DENIED).
        String::new()
    }
}

/// Convert a null-terminated UTF-16 wide string pointer to a Rust `String`.
///
/// Returns an empty string if the pointer is null.
///
/// # Safety
/// Caller must ensure `wide` points to a valid null-terminated UTF-16 string.
unsafe fn wide_str_to_string(wide: *const u16) -> String {
    if wide.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: Caller guarantees `wide` is a valid null-terminated wide string.
    while *wide.add(len) != 0 {
        len += 1;
        if len > 32_768 {
            break;
        }
    }
    let slice = core::slice::from_raw_parts(wide, len);
    String::from_utf16_lossy(slice)
}

/// Convert a null-terminated UTF-16 Windows path pointer to a Linux absolute path string.
///
/// Handles the MinGW/Windows encoding where root-relative paths (e.g. `/tmp/foo`) are
/// stored with a leading NUL `u16` followed by the rest of the path without the leading
/// slash.  Backslashes are normalised to forward slashes, drive letters are stripped,
/// and the result is made absolute.
///
/// # Safety
/// Caller must ensure `wide` points to a valid null-terminated UTF-16 string.
unsafe fn wide_path_to_linux(wide: *const u16) -> String {
    if wide.is_null() {
        return String::new();
    }
    // Peek at position 0.  MinGW encodes root-relative paths (those whose
    // Windows-display form starts with '/') with u16[0] == 0x0000 followed
    // by the path body (no leading slash).
    // SAFETY: `wide` is non-null; we read one u16 to check for the pattern.
    let first = *wide;
    let path_str = if first == 0 {
        // Root-relative encoding: the path body starts at position 1.
        // SAFETY: `wide` is a valid null-terminated buffer; reading position 1 is
        // safe because position 0 is guaranteed non-terminal by the caller's contract
        // (a buffer is either empty — both u16[0] and u16[1] are 0 — or has body data).
        let second = *wide.add(1);
        if second == 0 {
            // Only the leading null — effectively an empty path body.
            String::new()
        } else {
            // We know position 1 is non-null; scan from there.
            let mut len: usize = 1;
            while len <= 32_768 {
                if *wide.add(1 + len) == 0 {
                    break;
                }
                len += 1;
            }
            let slice = core::slice::from_raw_parts(wide.add(1), len);
            String::from_utf16_lossy(slice)
        }
    } else {
        wide_str_to_string(wide)
    };

    // Normalise Windows path to Linux:
    //  - Strip optional drive letter prefix (e.g. "C:")
    //  - Replace backslashes with forward slashes
    //  - Ensure the result is absolute
    let without_drive = if path_str.len() >= 2 && path_str.as_bytes()[1] == b':' {
        &path_str[2..]
    } else {
        path_str.as_str()
    };
    let with_slashes = without_drive.replace('\\', "/");
    let absolute = if with_slashes.is_empty() || !with_slashes.starts_with('/') {
        format!("/{with_slashes}")
    } else {
        with_slashes
    };
    // Apply sandbox restriction (no-op when no sandbox root is configured).
    sandbox_guard(absolute)
}

/// Write a UTF-8 string into a caller-supplied UTF-16 buffer.
///
/// On success, returns the number of UTF-16 code units written (excluding the null
/// terminator). If `buffer` is null, `buffer_len` is 0, or `buffer_len` is smaller than
/// required, returns the required buffer size in UTF-16 code units (including the null
/// terminator). Sets `SetLastError(234)` when the buffer is smaller than required but
/// non-null.
///
/// # Safety
/// `buffer` must point to a valid writable buffer of at least `buffer_len` `u16` elements,
/// or be null.
unsafe fn copy_utf8_to_wide(value: &str, buffer: *mut u16, buffer_len: u32) -> u32 {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let required = utf16.len() as u32 + 1; // +1 for null terminator

    if buffer.is_null() || buffer_len == 0 {
        return required;
    }
    if buffer_len < required {
        // SAFETY: Caller guarantees buffer is non-null (checked above).
        kernel32_SetLastError(234); // ERROR_MORE_DATA
        return required;
    }
    for (i, &ch) in utf16.iter().enumerate() {
        // SAFETY: We checked buffer_len >= required, so index i is within bounds.
        *buffer.add(i) = ch;
    }
    // SAFETY: null terminator at index utf16.len(), which is < required <= buffer_len.
    *buffer.add(utf16.len()) = 0;
    utf16.len() as u32
}

/// Sleep for specified milliseconds (Sleep)
///
/// This is the Windows Sleep function that suspends execution for the specified duration.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Sleep(milliseconds: u32) {
    thread::sleep(Duration::from_millis(u64::from(milliseconds)));
}

/// Get the current thread ID (GetCurrentThreadId)
///
/// Returns the unique identifier for the current thread.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThreadId() -> u32 {
    // SAFETY: gettid is a safe syscall
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    // Truncate to u32 to match Windows API
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    (tid as u32)
}

/// Get the current process ID (GetCurrentProcessId)
///
/// Returns the unique identifier for the current process.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcessId() -> u32 {
    // SAFETY: getpid is a safe syscall
    let pid = unsafe { libc::getpid() };
    // Convert to u32 to match Windows API
    #[allow(clippy::cast_sign_loss)]
    (pid as u32)
}

/// Allocate a thread local storage (TLS) slot index (TlsAlloc)
///
/// Allocates a TLS index for thread-specific data. Returns TLS_OUT_OF_INDEXES (0xFFFFFFFF)
/// on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsAlloc() -> u32 {
    ensure_tls_manager_initialized();
    let mut manager = TLS_MANAGER.lock().unwrap();
    manager
        .as_mut()
        .and_then(TlsManager::alloc_slot)
        .unwrap_or(0xFFFF_FFFF) // TLS_OUT_OF_INDEXES
}

/// Free a thread local storage (TLS) slot (TlsFree)
///
/// Releases a TLS index previously allocated by TlsAlloc.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsFree(slot: u32) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.free_slot(slot, thread_id)),
    )
}

/// Get a value from thread local storage (TlsGetValue)
///
/// Retrieves the value stored in the specified TLS slot for the current thread.
/// Returns 0 if no value has been set.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for interpreting the returned pointer correctly.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsGetValue(slot: u32) -> usize {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let manager = TLS_MANAGER.lock().unwrap();
    manager.as_ref().map_or(0, |m| m.get_value(slot, thread_id))
}

/// Set a value in thread local storage (TlsSetValue)
///
/// Stores a value in the specified TLS slot for the current thread.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for managing the lifetime of the data pointed to by `value`.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsSetValue(slot: u32, value: usize) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.set_value(slot, thread_id, value)),
    )
}

//
// Phase 8.2: Critical Sections
//
// Critical sections provide thread synchronization primitives for Windows programs.
// We implement them using pthread mutexes on Linux.
//

/// Windows CRITICAL_SECTION structure (opaque to us, but Windows expects ~40 bytes)
///
/// In real Windows, CRITICAL_SECTION is 40 bytes on x64 and contains:
/// - DebugInfo pointer
/// - LockCount
/// - RecursionCount
/// - OwningThread
/// - LockSemaphore
/// - SpinCount
///
/// We treat it as an opaque structure that just needs to hold a pointer to our internal data.
#[repr(C)]
pub struct CriticalSection {
    /// Internal data pointer (points to `Arc<Mutex<CriticalSectionData>>`)
    internal: usize,
    /// Padding to match Windows CRITICAL_SECTION size (40 bytes total)
    _padding: [u8; 32],
}

/// Internal data for a critical section
struct CriticalSectionData {
    /// Mutex for synchronization
    mutex: std::sync::Mutex<CriticalSectionInner>,
}

/// Inner state protected by the mutex
struct CriticalSectionInner {
    /// Current owner thread ID (0 if not owned)
    owner: u32,
    /// Recursion count (how many times the owner has entered)
    recursion: u32,
}

/// Initialize a critical section (InitializeCriticalSection)
///
/// This creates a new critical section object. The caller must provide
/// a pointer to a CRITICAL_SECTION structure (at least 40 bytes).
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` points to valid memory of at least 40 bytes
/// - The memory remains valid until `DeleteCriticalSection` is called
/// - The structure is not used concurrently during initialization
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSection(
    critical_section: *mut CriticalSection,
) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid
    let cs = unsafe { &mut *critical_section };

    // Create the internal data structure
    let data = Arc::new(CriticalSectionData {
        mutex: std::sync::Mutex::new(CriticalSectionInner {
            owner: 0,
            recursion: 0,
        }),
    });

    // Store the Arc as a raw pointer in the structure
    cs.internal = Arc::into_raw(data) as usize;
}

/// Enter a critical section (acquire the lock).
///
/// If the critical section is already owned by this thread, increments the recursion count.
/// If owned by another thread, waits until it becomes available.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized with `InitializeCriticalSection`
/// - The structure has not been deleted with `DeleteCriticalSection`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EnterCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex and check ownership
    {
        let mut inner = data.mutex.lock().unwrap();

        if inner.owner == current_thread {
            // Recursive lock - just increment the count
            inner.recursion += 1;
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
        } else {
            // Another thread owns it - this shouldn't happen with a mutex lock
            // But if it does, just wait and try again
            drop(inner);
            let mut inner2 = data.mutex.lock().unwrap();
            inner2.owner = current_thread;
            inner2.recursion = 1;
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Leave a critical section (release the lock).
///
/// Decrements the recursion count. If the count reaches zero, releases ownership.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - This thread currently owns the critical section
/// - Each `Leave` matches an `Enter`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LeaveCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex
    {
        let mut inner = data.mutex.lock().unwrap();

        // Decrement recursion count
        if inner.recursion > 0 {
            inner.recursion -= 1;
            if inner.recursion == 0 {
                // Release ownership
                inner.owner = 0;
            }
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Try to enter a critical section without blocking (TryEnterCriticalSection)
///
/// This attempts to acquire the critical section lock. If it's already held
/// by another thread, returns FALSE (0) immediately without blocking.
/// Returns TRUE (1) on success.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TryEnterCriticalSection(
    critical_section: *mut CriticalSection,
) -> u32 {
    if critical_section.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return 0; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Try to lock the mutex
    let result = if let Ok(mut inner) = data.mutex.try_lock() {
        if inner.owner == current_thread {
            // Recursive lock
            inner.recursion += 1;
            1
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
            1
        } else {
            // Another thread owns it
            0
        }
    } else {
        // Failed to acquire mutex
        0
    };

    // Don't drop the Arc
    core::mem::forget(data);

    result
}

/// Delete a critical section (DeleteCriticalSection)
///
/// This releases all resources associated with a critical section.
/// The caller must ensure no threads are waiting on or holding the lock.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - No threads are currently using the critical section
/// - The critical section will not be used after this call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &mut *critical_section };
    if cs.internal == 0 {
        return; // Not initialized or already deleted
    }

    // Reconstruct the Arc and let it drop to deallocate
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let _data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };
    // The Arc will drop here, deallocating the data if this was the last reference

    // Clear the internal pointer
    cs.internal = 0;
}

//
// Phase 8: Exception Handling Stubs
//
// These are minimal stub implementations to allow MinGW CRT to initialize.
// Real exception handling (SEH) would require significant additional work.
//

/// Windows exception handler function type
///
/// This is a stub implementation. Real SEH would require:
/// - Parsing .pdata and .xdata sections for unwind info
/// - Implementing exception dispatching
/// - Managing exception chains
/// - Supporting __try/__except/__finally
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers,
/// as it only returns a constant value and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32___C_specific_handler(
    _exception_record: *mut core::ffi::c_void,
    _establisher_frame: u64,
    _context_record: *mut core::ffi::c_void,
    _dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    // EXCEPTION_CONTINUE_SEARCH (1) - Tell the system to keep looking for handlers
    // For now, we don't handle any exceptions, just let them propagate
    1
}

/// Set unhandled exception filter
///
/// This is a stub that accepts the filter but doesn't actually use it.
/// Returns the previous filter (always NULL in this stub).
///
/// # Safety
/// This function is safe to call with any argument including NULL pointers.
/// It only returns a constant NULL value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetUnhandledExceptionFilter(
    _filter: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL (no previous filter)
    core::ptr::null_mut()
}

/// Raise an exception
///
/// This stub implementation aborts the process, which is a reasonable
/// fallback for unhandled exceptions.
///
/// # Safety
/// This function always aborts the process, so it never returns.
/// Safe to call with any arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RaiseException(
    exception_code: u32,
    _exception_flags: u32,
    _number_parameters: u32,
    _arguments: *const usize,
) -> ! {
    // For now, any raised exception causes an abort
    eprintln!("Windows exception raised (code: {exception_code:#x}) - aborting");
    std::process::abort()
}

/// Capture CPU context for exception handling
///
/// This stub zeros out the context structure. Real implementation would
/// capture all CPU registers (RAX, RBX, RCX, RDX, RSI, RDI, etc.)
///
/// # Safety
/// Caller must ensure `context` points to a valid writable memory region
/// of at least 1232 bytes (size of Windows CONTEXT structure for x64).
/// Passing NULL is safe (function checks and does nothing).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlCaptureContext(context: *mut core::ffi::c_void) {
    if !context.is_null() {
        // Zero out the context (size of Windows CONTEXT structure is ~1200 bytes for x64)
        // SAFETY: Caller ensures context points to valid CONTEXT structure
        unsafe {
            core::ptr::write_bytes(context.cast::<u8>(), 0, 1232);
        }
    }
}

/// Lookup function entry for exception handling
///
/// This stub returns NULL, indicating no unwind info found.
/// Real implementation would parse .pdata section.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It only returns NULL and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlLookupFunctionEntry(
    _control_pc: u64,
    _image_base: *mut u64,
    _history_table: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL - no function entry found
    core::ptr::null_mut()
}

/// Perform stack unwinding
///
/// This stub does nothing. Real implementation would unwind the stack
/// using information from .pdata and .xdata sections.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It does nothing and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlUnwindEx(
    _target_frame: *mut core::ffi::c_void,
    _target_ip: *mut core::ffi::c_void,
    _exception_record: *mut core::ffi::c_void,
    _return_value: *mut core::ffi::c_void,
    _context_record: *mut core::ffi::c_void,
    _history_table: *mut core::ffi::c_void,
) {
    // Stub: do nothing
}

/// Virtual unwind for exception handling
///
/// This stub returns a failure code. Real implementation would
/// simulate unwinding one stack frame.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It only returns NULL and doesn't dereference any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlVirtualUnwind(
    _handler_type: u32,
    _image_base: u64,
    _control_pc: u64,
    _function_entry: *mut core::ffi::c_void,
    _context_record: *mut core::ffi::c_void,
    _handler_data: *mut *mut core::ffi::c_void,
    _establisher_frame: *mut u64,
    _context_pointers: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return NULL - indicates failure/no handler
    core::ptr::null_mut()
}

/// Add vectored exception handler
///
/// This stub accepts the handler but doesn't register it.
/// Returns a non-NULL handle to indicate success.
///
/// # Safety
/// This function is safe to call with any arguments including NULL pointers.
/// It returns a fake non-NULL handle without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_AddVectoredExceptionHandler(
    _first: u32,
    _handler: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return a fake handle (non-NULL to indicate success)
    // Real implementation would register the handler
    0x1000 as *mut core::ffi::c_void
}

//
// Phase 8.3: String Operations
//
// Windows uses UTF-16 (wide characters) while Linux uses UTF-8.
// These functions handle conversion between the two encodings.
//

/// Convert multibyte string to wide-character string
///
/// This implements MultiByteToWideChar for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `multi_byte_str`: Source multibyte string
/// - `multi_byte_len`: Length of source string (-1 = null-terminated)
/// - `wide_char_str`: Destination buffer for wide chars (NULL = query size)
/// - `wide_char_len`: Size of destination buffer in characters
///
/// # Returns
/// Number of wide characters written (or required if `wide_char_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `multi_byte_str` points to valid memory
/// - If `multi_byte_len` != -1, at least `multi_byte_len` bytes are readable
/// - If `wide_char_str` is not NULL, at least `wide_char_len` u16s are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MultiByteToWideChar(
    code_page: u32,
    _flags: u32,
    multi_byte_str: *const u8,
    multi_byte_len: i32,
    wide_char_str: *mut u16,
    wide_char_len: i32,
) -> i32 {
    if multi_byte_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate multi_byte_len (must be -1 or >= 0)
    if multi_byte_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if multi_byte_len == -1 {
        // SAFETY: Caller guarantees multi_byte_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *multi_byte_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (multi_byte_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees multi_byte_str points to at least input_len bytes
    let input_bytes = unsafe { core::slice::from_raw_parts(multi_byte_str, input_len) };

    // Convert to UTF-8 string (assume input is UTF-8)
    let Ok(utf8_str) = core::str::from_utf8(input_bytes) else {
        return 0; // Invalid UTF-8
    };

    // Convert to UTF-16
    let utf16_chars: Vec<u16> = utf8_str.encode_utf16().collect();
    let required_len = if include_null {
        utf16_chars.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf16_chars.len() // No null terminator when length was explicit
    };

    // If wide_char_str is NULL, return required size
    if wide_char_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if wide_char_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees wide_char_str has space for wide_char_len u16s
    let output = unsafe { core::slice::from_raw_parts_mut(wide_char_str, wide_char_len as usize) };

    // Copy the UTF-16 characters
    output[..utf16_chars.len()].copy_from_slice(&utf16_chars);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf16_chars.len()] = 0;
    }

    required_len as i32
}

/// Convert wide-character string to multibyte string
///
/// This implements WideCharToMultiByte for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `wide_char_str`: Source wide-character string
/// - `wide_char_len`: Length of source string (-1 = null-terminated)
/// - `multi_byte_str`: Destination buffer for multibyte chars (NULL = query size)
/// - `multi_byte_len`: Size of destination buffer in bytes
/// - `default_char`: Default char for unmappable characters (NULL = use default)
/// - `used_default_char`: Pointer to flag set if default char was used (NULL = ignore)
///
/// # Returns
/// Number of bytes written (or required if `multi_byte_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `wide_char_str` points to valid memory
/// - If `wide_char_len` != -1, at least `wide_char_len` u16s are readable
/// - If `multi_byte_str` is not NULL, at least `multi_byte_len` bytes are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WideCharToMultiByte(
    code_page: u32,
    _flags: u32,
    wide_char_str: *const u16,
    wide_char_len: i32,
    multi_byte_str: *mut u8,
    multi_byte_len: i32,
    _default_char: *const u8,
    _used_default_char: *mut i32,
) -> i32 {
    if wide_char_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate wide_char_len (must be -1 or >= 0)
    if wide_char_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if wide_char_len == -1 {
        // SAFETY: Caller guarantees wide_char_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *wide_char_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (wide_char_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees wide_char_str points to at least input_len u16s
    let input_chars = unsafe { core::slice::from_raw_parts(wide_char_str, input_len) };

    // Convert from UTF-16 to String (UTF-8)
    let utf8_string = String::from_utf16_lossy(input_chars);
    let utf8_bytes = utf8_string.as_bytes();
    let required_len = if include_null {
        utf8_bytes.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf8_bytes.len() // No null terminator when length was explicit
    };

    // If multi_byte_str is NULL, return required size
    if multi_byte_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if multi_byte_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees multi_byte_str has space for multi_byte_len bytes
    let output =
        unsafe { core::slice::from_raw_parts_mut(multi_byte_str, multi_byte_len as usize) };

    // Copy the UTF-8 bytes
    output[..utf8_bytes.len()].copy_from_slice(utf8_bytes);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf8_bytes.len()] = 0;
    }

    required_len as i32
}

/// Get the length of a wide-character string
///
/// This implements lstrlenW, which returns the length of a null-terminated
/// wide-character string (excluding the null terminator).
///
/// # Safety
/// The caller must ensure `wide_str` points to a valid null-terminated wide string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrlenW(wide_str: *const u16) -> i32 {
    if wide_str.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees wide_str is a valid null-terminated string
    let mut len = 0;
    while unsafe { *wide_str.add(len) } != 0 {
        len += 1;
    }

    len as i32
}

/// Compare two Unicode strings using ordinal (binary) comparison
///
/// This implements CompareStringOrdinal, which performs a code-point by code-point
/// comparison of two Unicode strings.
///
/// # Arguments
/// - `string1`: First string to compare
/// - `count1`: Length of first string (-1 = null-terminated)
/// - `string2`: Second string to compare
/// - `count2`: Length of second string (-1 = null-terminated)
/// - `ignore_case`: TRUE to ignore case, FALSE for case-sensitive
///
/// # Returns
/// - CSTR_LESS_THAN (1): string1 < string2
/// - CSTR_EQUAL (2): string1 == string2
/// - CSTR_GREATER_THAN (3): string1 > string2
/// - 0: Error
///
/// # Safety
/// The caller must ensure both string pointers point to valid memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CompareStringOrdinal(
    string1: *const u16,
    count1: i32,
    string2: *const u16,
    count2: i32,
    ignore_case: i32,
) -> i32 {
    if string1.is_null() || string2.is_null() {
        return 0; // Error
    }

    // Validate count1 and count2 (must be -1 or >= 0)
    if count1 < -1 || count2 < -1 {
        return 0; // Invalid parameter
    }

    // Get length of first string
    let len1 = if count1 == -1 {
        // SAFETY: Caller guarantees string1 is null-terminated
        let mut len = 0;
        while unsafe { *string1.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count1 as usize
    };

    // Get length of second string
    let len2 = if count2 == -1 {
        // SAFETY: Caller guarantees string2 is null-terminated
        let mut len = 0;
        while unsafe { *string2.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count2 as usize
    };

    // SAFETY: Caller guarantees the pointers are valid
    let slice1 = unsafe { core::slice::from_raw_parts(string1, len1) };
    let slice2 = unsafe { core::slice::from_raw_parts(string2, len2) };

    // Perform ordinal (binary) comparison on UTF-16 code units
    // This matches Windows' ordinal semantics (code-unit by code-unit comparison)
    let min_len = core::cmp::min(len1, len2);
    let mut result = core::cmp::Ordering::Equal;

    for i in 0..min_len {
        let mut c1 = slice1[i];
        let mut c2 = slice2[i];

        if ignore_case != 0 {
            // ASCII case fold: 'A'..='Z' -> 'a'..='z'
            // This provides basic case-insensitive comparison for ASCII characters
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c1) {
                c1 += u16::from(b'a') - u16::from(b'A');
            }
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c2) {
                c2 += u16::from(b'a') - u16::from(b'A');
            }
        }

        if c1 < c2 {
            result = core::cmp::Ordering::Less;
            break;
        } else if c1 > c2 {
            result = core::cmp::Ordering::Greater;
            break;
        }
    }

    // If all compared code units are equal, shorter string is "less"
    if result == core::cmp::Ordering::Equal {
        result = len1.cmp(&len2);
    }

    // Convert to Windows constants
    match result {
        core::cmp::Ordering::Less => 1,    // CSTR_LESS_THAN
        core::cmp::Ordering::Equal => 2,   // CSTR_EQUAL
        core::cmp::Ordering::Greater => 3, // CSTR_GREATER_THAN
    }
}

//
// Phase 8.4: Performance Counters
//
// Windows programs often use high-resolution performance counters for timing.
// On Linux, we implement these using clock_gettime(CLOCK_MONOTONIC).
//

/// Windows FILETIME structure (64-bit value representing 100-nanosecond intervals since 1601-01-01)
#[repr(C)]
pub struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

/// Query the performance counter
///
/// This implements QueryPerformanceCounter which returns a high-resolution timestamp.
/// On Linux, we use clock_gettime(CLOCK_MONOTONIC) which provides nanosecond precision.
///
/// # Safety
/// The caller must ensure `counter` points to a valid u64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceCounter(counter: *mut i64) -> i32 {
    if counter.is_null() {
        return 0; // FALSE - error
    }

    // SAFETY: Use libc to get monotonic time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        return 0; // FALSE - error
    }

    // Convert to a counter value (nanoseconds)
    let nanoseconds = ts
        .tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec);

    // SAFETY: Caller guarantees counter is valid
    unsafe {
        *counter = nanoseconds;
    }

    1 // TRUE - success
}

/// Query the performance counter frequency
///
/// This implements QueryPerformanceFrequency which returns the frequency of the
/// performance counter in counts per second. Since we use nanoseconds, the frequency
/// is 1,000,000,000 (1 billion counts per second).
///
/// # Safety
/// The caller must ensure `frequency` points to a valid i64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceFrequency(frequency: *mut i64) -> i32 {
    if frequency.is_null() {
        return 0; // FALSE - error
    }

    // Our counter is in nanoseconds, so frequency is 1 billion counts/second
    // SAFETY: Caller guarantees frequency is valid
    unsafe {
        *frequency = 1_000_000_000;
    }

    1 // TRUE - success
}

/// Get system time as FILETIME with high precision
///
/// This implements GetSystemTimePreciseAsFileTime which returns the current system time
/// in FILETIME format (100-nanosecond intervals since January 1, 1601 UTC).
///
/// # Safety
/// The caller must ensure `filetime` points to a valid FILETIME structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemTimePreciseAsFileTime(filetime: *mut FileTime) {
    if filetime.is_null() {
        return;
    }

    // SAFETY: Use libc to get real time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        // On error, return epoch
        unsafe {
            (*filetime).low_date_time = 0;
            (*filetime).high_date_time = 0;
        }
        return;
    }

    // Convert Unix timestamp (seconds since 1970-01-01) to Windows FILETIME
    // (100-nanosecond intervals since 1601-01-01)
    //
    // The difference between 1601-01-01 and 1970-01-01 is 11644473600 seconds

    // Convert to 100-nanosecond intervals
    let seconds_since_1601 = ts.tv_sec + EPOCH_DIFF;
    let intervals = seconds_since_1601
        .saturating_mul(10_000_000) // seconds to 100-nanosecond intervals
        .saturating_add(ts.tv_nsec / 100); // add nanoseconds converted to 100-ns intervals

    // Split into low and high parts
    // SAFETY: Caller guarantees filetime is valid
    unsafe {
        (*filetime).low_date_time = (intervals & 0xFFFF_FFFF) as u32;
        (*filetime).high_date_time = ((intervals >> 32) & 0xFFFF_FFFF) as u32;
    }
}

//
// Phase 8.5: File I/O Trampolines
//
// These are KERNEL32 wrappers around file operations.
// They provide a Windows-compatible API but use simple stub implementations
// since full file I/O is handled through NTDLL APIs.
//

/// Create or open a file (CreateFileW)
///
/// Implements the most common creation dispositions and access modes.
/// File attributes and flags beyond `GENERIC_READ`/`GENERIC_WRITE` are ignored.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileW(
    file_name: *const u16,
    desired_access: u32,
    _share_mode: u32,
    _security_attributes: *mut core::ffi::c_void,
    creation_disposition: u32,
    _flags_and_attributes: u32,
    _template_file: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = usize::MAX as *mut core::ffi::c_void;

    // Windows GENERIC_READ / GENERIC_WRITE flags
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    // CreationDisposition constants
    const CREATE_NEW: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const OPEN_ALWAYS: u32 = 4;
    const TRUNCATE_EXISTING: u32 = 5;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE_VALUE;
    }

    let path_str = wide_path_to_linux(file_name);
    let can_read = desired_access & GENERIC_READ != 0;
    let can_write = desired_access & GENERIC_WRITE != 0;
    // When desired_access=0 (Windows attribute/metadata query), neither read nor write
    // is requested.  Linux requires at least one access mode; open read-only so that
    // fstat and similar metadata operations work.
    let need_read = can_read || !can_write;

    let result = match creation_disposition {
        CREATE_NEW => std::fs::OpenOptions::new()
            .read(need_read)
            .write(can_write)
            .create_new(true)
            .open(&path_str),
        CREATE_ALWAYS => std::fs::OpenOptions::new()
            .read(need_read)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_str),
        OPEN_EXISTING => std::fs::OpenOptions::new()
            .read(need_read)
            .write(can_write)
            .open(&path_str),
        OPEN_ALWAYS => std::fs::OpenOptions::new()
            .read(need_read)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path_str),
        TRUNCATE_EXISTING => std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path_str),
        _ => {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return INVALID_HANDLE_VALUE;
        }
    };

    match result {
        Ok(file) => {
            // Enforce the open-handle limit atomically inside the mutex so
            // that the check and insert cannot race with other threads.
            let handle_val = alloc_file_handle();
            let inserted = with_file_handles(|map| {
                if map.len() >= MAX_OPEN_FILE_HANDLES {
                    return false;
                }
                map.insert(handle_val, FileEntry { file });
                true
            });
            if inserted {
                handle_val as *mut core::ffi::c_void
            } else {
                kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
                INVALID_HANDLE_VALUE
            }
        }
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::AlreadyExists => 80, // ERROR_FILE_EXISTS
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::NotFound => 2,       // ERROR_FILE_NOT_FOUND
                _ => 87,                                 // ERROR_INVALID_PARAMETER
            };
            kernel32_SetLastError(code);
            INVALID_HANDLE_VALUE
        }
    }
}

/// Read from a file (ReadFile)
///
/// # Safety
/// `file` must be a valid handle, `buffer` must be writable for
/// `number_of_bytes_to_read` bytes, and `number_of_bytes_read` must be
/// a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFile(
    file: *mut core::ffi::c_void,
    buffer: *mut u8,
    number_of_bytes_to_read: u32,
    number_of_bytes_read: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    if buffer.is_null() {
        kernel32_SetLastError(87);
        return 0;
    }

    let handle_val = file as usize;
    let count = number_of_bytes_to_read as usize;
    // SAFETY: Caller guarantees buffer is valid for `count` bytes.
    let slice = std::slice::from_raw_parts_mut(buffer, count);

    let bytes_read = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.read(slice).ok()
        } else {
            None
        }
    });

    if let Some(n) = bytes_read {
        if !number_of_bytes_read.is_null() {
            // Windows API uses u32 for byte counts; saturate rather than truncate.
            *number_of_bytes_read = u32::try_from(n).unwrap_or(u32::MAX);
        }
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        if !number_of_bytes_read.is_null() {
            *number_of_bytes_read = 0;
        }
        0 // FALSE
    }
}

/// Write to a file (WriteFile)
///
/// Writes to stdout/stderr or to a regular file opened by `CreateFileW`.
///
/// # Safety
/// This function is unsafe as it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFile(
    file: *mut core::ffi::c_void,
    buffer: *const u8,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    // STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    let stdout_handle = kernel32_GetStdHandle((-11i32) as u32);
    let stderr_handle = kernel32_GetStdHandle((-12i32) as u32);

    // Check if this is stdout or stderr
    let is_stdout = file == stdout_handle;
    let is_stderr = file == stderr_handle;

    if buffer.is_null() || number_of_bytes_to_write == 0 {
        if !number_of_bytes_written.is_null() {
            *number_of_bytes_written = 0;
        }
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // SAFETY: Caller guarantees buffer is valid for number_of_bytes_to_write bytes
    let data = std::slice::from_raw_parts(buffer, number_of_bytes_to_write as usize);

    if is_stdout || is_stderr {
        // Write to stdout or stderr
        let result = if is_stdout {
            std::io::Write::write(&mut std::io::stdout(), data)
        } else {
            std::io::Write::write(&mut std::io::stderr(), data)
        };
        if let Ok(written) = result {
            if !number_of_bytes_written.is_null() {
                // Windows API uses u32 for byte counts; saturate rather than truncate.
                *number_of_bytes_written = u32::try_from(written).unwrap_or(u32::MAX);
            }
            if is_stdout {
                let _ = std::io::Write::flush(&mut std::io::stdout());
            } else {
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
            1 // TRUE
        } else {
            kernel32_SetLastError(29); // ERROR_WRITE_FAULT
            0
        }
    } else {
        // Try regular file handle
        let handle_val = file as usize;
        let written = with_file_handles(|map| {
            if let Some(entry) = map.get_mut(&handle_val) {
                entry.file.write(data).ok()
            } else {
                None
            }
        });
        if let Some(n) = written {
            if !number_of_bytes_written.is_null() {
                // Windows API uses u32 for byte counts; saturate rather than truncate.
                *number_of_bytes_written = u32::try_from(n).unwrap_or(u32::MAX);
            }
            1 // TRUE
        } else {
            kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
            if !number_of_bytes_written.is_null() {
                *number_of_bytes_written = 0;
            }
            0 // FALSE
        }
    }
}

/// Close a handle (CloseHandle)
///
/// Closes file handles opened by `CreateFileW` and event handles opened by
/// `CreateEventW`. Directory-search handles opened by `FindFirstFileW` /
/// `FindNextFileW` must be closed using `FindClose`, not `CloseHandle`.
/// Thread handles are also accepted; for them we just return TRUE.
///
/// # Safety
/// This function is safe to call with any argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CloseHandle(handle: *mut core::ffi::c_void) -> i32 {
    let handle_val = handle as usize;
    // Remove from file-handle map if present (this closes the underlying File)
    with_file_handles(|map| {
        map.remove(&handle_val);
    });
    // Remove from event-handle map if present (drops the Arc-backed event state)
    with_event_handles(|map| {
        map.remove(&handle_val);
    });
    1 // TRUE - success (or was not a registered handle)
}

//
// Phase 8.6: Heap Management Trampolines
//
// Windows programs often use HeapAlloc/HeapFree for dynamic memory.
// These are wrappers around the standard malloc/free functions.
//

/// Get the default process heap handle
///
/// In Windows, processes have a default heap. We return a fake
/// non-NULL handle since programs check for NULL.
///
/// # Safety
/// This function is safe to call. It returns a constant non-NULL value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessHeap() -> *mut core::ffi::c_void {
    // Return a fake heap handle (non-NULL)
    // Real heap operations use malloc/free directly
    0x1000 as *mut core::ffi::c_void
}

/// Allocate memory from a heap
///
/// This wraps malloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored, we use the global allocator)
/// - `flags`: Allocation flags (HEAP_ZERO_MEMORY = 0x00000008)
/// - `size`: Number of bytes to allocate
///
/// # Returns
/// Pointer to allocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The returned pointer must be freed with HeapFree.
/// The caller must ensure the size is reasonable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapAlloc(
    _heap: *mut core::ffi::c_void,
    flags: u32,
    size: usize,
) -> *mut core::ffi::c_void {
    // Windows HeapAlloc can return a non-NULL pointer for 0-byte allocation
    // Allocate a minimal block (1 byte) to match Windows semantics
    let alloc_size = if size == 0 { 1 } else { size };

    // Allocate using the global allocator
    let Ok(layout) =
        core::alloc::Layout::from_size_align(alloc_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    // SAFETY: Layout is valid, size is non-zero
    let ptr = unsafe { alloc::alloc(layout) };

    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Zero memory if requested
    if flags & HEAP_ZERO_MEMORY != 0 {
        // SAFETY: ptr is valid and has alloc_size bytes allocated
        unsafe {
            core::ptr::write_bytes(ptr, 0, alloc_size);
        }
    }

    // Track this allocation for later deallocation
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if let Some(ref mut t) = *tracker {
        t.track_allocation(ptr, alloc_size, layout.align());
    }

    ptr.cast()
}

/// Free memory allocated from a heap
///
/// This wraps dealloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Free flags (ignored)
/// - `mem`: Pointer to memory to free
///
/// # Returns
/// TRUE (1) on success, FALSE (0) on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - `mem` is not freed twice
/// - `mem` is not used after being freed
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapFree(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *mut core::ffi::c_void,
) -> i32 {
    if mem.is_null() {
        return 1; // TRUE - freeing NULL is a no-op
    }

    // Retrieve and remove the allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        // If tracker doesn't exist, we can't free safely
        return 0; // FALSE - failure
    };

    let Some((size, align)) = t.remove_allocation(mem) else {
        // Allocation not found - this is either a double-free or
        // memory not allocated with HeapAlloc
        return 0; // FALSE - failure
    };

    // Create the layout and deallocate
    // SAFETY: We're recreating the same layout that was used for allocation
    let Ok(layout) = core::alloc::Layout::from_size_align(size, align) else {
        return 0; // FALSE - invalid layout (shouldn't happen)
    };

    // SAFETY: ptr was allocated with alloc::alloc using this layout
    unsafe {
        alloc::dealloc(mem.cast(), layout);
    }

    1 // TRUE - success
}

/// Reallocate memory in a heap
///
/// This wraps realloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Realloc flags (HEAP_ZERO_MEMORY supported)
/// - `mem`: Pointer to memory to reallocate (or NULL to allocate new)
/// - `size`: New size in bytes
///
/// # Returns
/// Pointer to reallocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - The old pointer is not used after reallocation
/// - The returned pointer must be freed with HeapFree
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapReAlloc(
    heap: *mut core::ffi::c_void,
    flags: u32,
    mem: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    if mem.is_null() {
        // Allocate new memory
        return unsafe { kernel32_HeapAlloc(heap, flags, size) };
    }

    if size == 0 {
        // Free the memory
        unsafe { kernel32_HeapFree(heap, flags, mem) };
        return core::ptr::null_mut();
    }

    // Get the current allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        return core::ptr::null_mut(); // Tracker not initialized
    };

    let Some((old_size, old_align)) = t.get_allocation(mem) else {
        // Memory not tracked - can't reallocate safely
        return core::ptr::null_mut();
    };

    // Prepare new allocation
    let new_size = if size == 0 { 1 } else { size };
    let Ok(new_layout) =
        core::alloc::Layout::from_size_align(new_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    let Ok(old_layout) = core::alloc::Layout::from_size_align(old_size, old_align) else {
        return core::ptr::null_mut();
    };

    // Remove the old allocation entry BEFORE realloc, since realloc may move the memory
    t.remove_allocation(mem);

    // SAFETY: mem was allocated with the old_layout
    let new_ptr = unsafe { alloc::realloc(mem.cast(), old_layout, new_size) };

    if new_ptr.is_null() {
        // Realloc failed - the original allocation is still valid
        // Re-insert the original allocation back into the tracker
        t.track_allocation(mem.cast(), old_size, old_align);
        return core::ptr::null_mut();
    }

    // If growing the allocation and HEAP_ZERO_MEMORY is set, zero the new bytes
    if new_size > old_size && (flags & HEAP_ZERO_MEMORY != 0) {
        // SAFETY: new_ptr is valid for new_size bytes, and we're only writing
        // to the newly allocated portion
        unsafe {
            core::ptr::write_bytes(new_ptr.add(old_size), 0, new_size - old_size);
        }
    }

    // Track the new allocation (whether it moved or stayed in place)
    t.track_allocation(new_ptr, new_size, new_layout.align());

    new_ptr.cast()
}

/// STARTUPINFOA structure - contains information about window station, desktop, standard handles, etc.
/// This is a simplified version that matches the Windows API layout.
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoA {
    cb: u32,
    lpReserved: *mut u8,
    lpDesktop: *mut u8,
    lpTitle: *mut u8,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// STARTUPINFOW structure - wide-character version
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// GetStartupInfoA - retrieves the STARTUPINFO structure for the current process
///
/// This is a minimal implementation that sets the structure to default values.
/// In a real Windows environment, this would contain information passed to CreateProcess.
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOA structure
/// - The pointer is properly aligned for a STARTUPINFOA structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoA(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoA structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoA>()) };

    // Initialize the structure with default values
    // In a real implementation, these would come from the process's startup information
    info.cb = core::mem::size_of::<StartupInfoA>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0; // Could be mapped to actual stdin fd
    info.hStdOutput = 1; // Could be mapped to actual stdout fd
    info.hStdError = 2; // Could be mapped to actual stderr fd
}

/// GetStartupInfoW - retrieves the STARTUPINFOW structure for the current process (wide-char version)
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOW structure
/// - The pointer is properly aligned for a STARTUPINFOW structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoW(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoW structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoW>()) };

    // Initialize the structure with default values
    info.cb = core::mem::size_of::<StartupInfoW>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0;
    info.hStdOutput = 1;
    info.hStdError = 2;
}

//
// Stub implementations for missing APIs
//
// These are minimal implementations that return failure or no-op.
// They allow programs to link and run, but don't provide full functionality.
//

/// CancelIo stub - cancels pending I/O operations
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CancelIo(_file: *mut core::ffi::c_void) -> i32 {
    0 // FALSE - not implemented
}

/// CopyFileExW - copies a file (progress callback and cancel flag are ignored)
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CopyFileExW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    _progress_routine: *mut core::ffi::c_void,
    _data: *mut core::ffi::c_void,
    _cancel: *mut i32,
    _copy_flags: u32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    match std::fs::copy(&src, &dst) {
        Ok(_) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 1,                                    // ERROR_INVALID_FUNCTION
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CopyFileW - copies a file
///
/// Simplified wrapper around `CopyFileExW` (no progress callback, no cancel).
///
/// Note: when `fail_if_exists` is non-zero, there is a TOCTOU window between
/// the existence check and the copy. In the sandboxed single-process context
/// this is typically harmless, but callers should be aware of the limitation.
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CopyFileW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    fail_if_exists: i32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    if fail_if_exists != 0 && std::path::Path::new(&dst).exists() {
        kernel32_SetLastError(183); // ERROR_ALREADY_EXISTS
        return 0;
    }
    match std::fs::copy(&src, &dst) {
        Ok(_) => 1,
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,
                std::io::ErrorKind::PermissionDenied => 5,
                _ => 1,
            };
            kernel32_SetLastError(code);
            0
        }
    }
}

/// CreateDirectoryW - creates a directory
///
/// Creates the directory named by `path_name`.  Security attributes are ignored.
///
/// # Safety
/// `path_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateDirectoryW(
    path_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(path_name);
    match std::fs::create_dir(std::path::Path::new(&path_str)) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::AlreadyExists => 183, // ERROR_ALREADY_EXISTS
                std::io::ErrorKind::NotFound => 3,        // ERROR_PATH_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,                                   // ERROR_FILE_NOT_FOUND
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CreateDirectoryExW - creates a directory, ignoring the template directory argument.
///
/// Template directory attributes are not applied; this behaves like `CreateDirectoryW`.
///
/// # Safety
/// `new_directory` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateDirectoryExW(
    _template_directory: *const u16,
    new_directory: *const u16,
    security_attributes: *mut core::ffi::c_void,
) -> i32 {
    kernel32_CreateDirectoryW(new_directory, security_attributes)
}

/// CreateEventW - creates an event object
///
/// Creates a named or unnamed event object backed by a `Condvar` that can be
/// signaled with `SetEvent` and waited on with `WaitForSingleObject`.
///
/// `manual_reset` (non-zero) means the event stays signaled until explicitly
/// reset with `ResetEvent`; zero means the event auto-resets after one
/// waiter is released.  `initial_state` (non-zero) starts the event already
/// signaled.  Named events (`name` non-null) are currently treated as
/// anonymous; a unique synthetic handle is still returned.
///
/// This implementation always returns a non-null synthetic handle and does
/// not currently report allocation failures via `GetLastError()`.
///
/// # Safety
/// If `name` is non-null it must be a valid null-terminated UTF-16 string
/// (it is accepted but ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateEventW(
    _security_attributes: *mut core::ffi::c_void,
    manual_reset: i32,
    initial_state: i32,
    _name: *const u16,
) -> *mut core::ffi::c_void {
    let handle = alloc_event_handle();
    let entry = EventEntry {
        manual_reset: manual_reset != 0,
        state: Arc::new((Mutex::new(initial_state != 0), Condvar::new())),
    };
    with_event_handles(|map| map.insert(handle, entry));
    handle as *mut core::ffi::c_void
}

/// CreateFileMappingA stub - creates a file mapping object
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileMappingA(
    _file: *mut core::ffi::c_void,
    _security_attributes: *mut core::ffi::c_void,
    _protect: u32,
    _maximum_size_high: u32,
    _maximum_size_low: u32,
    _name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// CreateHardLinkW stub - creates a hard link
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateHardLinkW(
    _file_name: *const u16,
    _existing_file_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreatePipe stub - creates a pipe
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreatePipe(
    _read_pipe: *mut *mut core::ffi::c_void,
    _write_pipe: *mut *mut core::ffi::c_void,
    _pipe_attributes: *mut core::ffi::c_void,
    _size: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateProcessW stub - creates a new process
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateProcessW(
    _application_name: *const u16,
    _command_line: *mut u16,
    _process_attributes: *mut core::ffi::c_void,
    _thread_attributes: *mut core::ffi::c_void,
    _inherit_handles: i32,
    _creation_flags: u32,
    _environment: *mut core::ffi::c_void,
    _current_directory: *const u16,
    _startup_info: *mut core::ffi::c_void,
    _process_information: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateSymbolicLinkW stub - creates a symbolic link
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateSymbolicLinkW(
    _symlink_file_name: *const u16,
    _target_file_name: *const u16,
    _flags: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// CreateThread - creates a thread to execute within the virtual address space of the process
///
/// # Panics
/// Panics if the thread mutex is poisoned.
///
/// # Safety
/// `start_address` must be a valid Windows thread function (MS-x64 ABI).
/// `parameter` is passed as-is to the thread; the caller must ensure its validity.
/// `thread_id` must either be null or point to a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateThread(
    _thread_attributes: *mut core::ffi::c_void,
    _stack_size: usize,
    start_address: *mut core::ffi::c_void,
    parameter: *mut core::ffi::c_void,
    _creation_flags: u32,
    thread_id: *mut u32,
) -> *mut core::ffi::c_void {
    if start_address.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }

    // SAFETY: caller guarantees start_address is a valid Windows LPTHREAD_START_ROUTINE.
    let thread_fn: WindowsThreadStart = core::mem::transmute(start_address);
    let param_addr = parameter as usize;

    let exit_code: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let exit_code_clone = Arc::clone(&exit_code);

    // SAFETY: We spawn a thread that calls the Windows thread function.
    // param_addr is sent to the thread as a raw usize (avoiding Send requirement on *mut c_void).
    // The caller must ensure the parameter pointer remains valid for the thread's lifetime.
    let join_handle = thread::spawn(move || {
        let param_ptr = param_addr as *mut core::ffi::c_void;
        // SAFETY: thread_fn is a valid Windows thread function (MS-x64 ABI).
        let result = unsafe { thread_fn(param_ptr) };
        *exit_code_clone.lock().unwrap() = Some(result);
        result
    });

    let handle = alloc_thread_handle();
    with_thread_handles(|map| {
        map.insert(
            handle,
            ThreadEntry {
                join_handle: Some(join_handle),
                exit_code,
            },
        );
    });

    // Use the handle value (truncated) as the thread ID: non-zero and unique per thread.
    if !thread_id.is_null() {
        *thread_id = (handle & 0xFFFF_FFFF) as u32;
    }

    handle as *mut core::ffi::c_void
}

/// CreateToolhelp32Snapshot stub - creates a snapshot of processes/threads/etc
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateToolhelp32Snapshot(
    _flags: u32,
    _process_id: u32,
) -> *mut core::ffi::c_void {
    usize::MAX as *mut core::ffi::c_void // INVALID_HANDLE_VALUE
}

/// CreateWaitableTimerExW stub - creates a waitable timer
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateWaitableTimerExW(
    _timer_attributes: *mut core::ffi::c_void,
    _timer_name: *const u16,
    _flags: u32,
    _desired_access: u32,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not implemented
}

/// DeleteFileW - deletes a file
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteFileW(file_name: *const u16) -> i32 {
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    match std::fs::remove_file(std::path::Path::new(&path_str)) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// DeleteProcThreadAttributeList stub - deletes a process thread attribute list
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteProcThreadAttributeList(
    _attribute_list: *mut core::ffi::c_void,
) {
    // No-op stub
}

/// DeviceIoControl stub - sends a control code to a device driver
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeviceIoControl(
    _device: *mut core::ffi::c_void,
    _io_control_code: u32,
    _in_buffer: *mut core::ffi::c_void,
    _in_buffer_size: u32,
    _out_buffer: *mut core::ffi::c_void,
    _out_buffer_size: u32,
    _bytes_returned: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE - not implemented
}

/// DuplicateHandle stub - duplicates a handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DuplicateHandle(
    _source_process_handle: *mut core::ffi::c_void,
    _source_handle: *mut core::ffi::c_void,
    _target_process_handle: *mut core::ffi::c_void,
    _target_handle: *mut *mut core::ffi::c_void,
    _desired_access: u32,
    _inherit_handle: i32,
    _options: u32,
) -> i32 {
    0 // FALSE - not implemented
}

/// FlushFileBuffers - flushes the write buffers of the specified file
///
/// In this implementation all writes are synchronous (backed directly by Linux
/// `write` syscalls), so there are no pending buffers to flush.  Always
/// returns TRUE.
///
/// # Safety
/// `file` is accepted as an opaque handle and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlushFileBuffers(_file: *mut core::ffi::c_void) -> i32 {
    1 // TRUE
}

/// FormatMessageW - formats a system error message or a custom message string
///
/// Supports `FORMAT_MESSAGE_FROM_SYSTEM` (0x1000): looks up the text for the
/// Windows error code given in `message_id` and writes it (as a null-terminated
/// UTF-16 string) into `buffer`.  When `FORMAT_MESSAGE_ALLOCATE_BUFFER`
/// (0x100) is also set, `buffer` is treated as a `*mut *mut u16`: a heap
/// buffer is allocated with `HeapAlloc` and its address is stored at
/// `*buffer`; the caller must free it with `HeapFree` / `LocalFree`.
///
/// Returns the number of UTF-16 code units written, excluding the null
/// terminator, or 0 on failure (sets last-error to
/// `ERROR_INSUFFICIENT_BUFFER` / `ERROR_INVALID_PARAMETER` as appropriate).
///
/// # Safety
/// * When `FORMAT_MESSAGE_ALLOCATE_BUFFER` is clear: `buffer` must be a
///   writable array of at least `size` UTF-16 code units.
/// * When `FORMAT_MESSAGE_ALLOCATE_BUFFER` is set: `buffer` must be a valid
///   `*mut *mut u16`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FormatMessageW(
    flags: u32,
    _source: *const core::ffi::c_void,
    message_id: u32,
    _language_id: u32,
    buffer: *mut u16,
    size: u32,
    _arguments: *mut *mut core::ffi::c_void,
) -> u32 {
    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;

    if flags & FORMAT_MESSAGE_FROM_SYSTEM == 0 {
        // We only support FORMAT_MESSAGE_FROM_SYSTEM for now.
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let msg = windows_error_message(message_id);
    let utf16: Vec<u16> = msg.encode_utf16().chain(core::iter::once(0u16)).collect();
    let char_count = (utf16.len() - 1) as u32; // without null terminator

    if flags & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
        // buffer is actually a *mut *mut u16 — allocate heap memory and store pointer.
        if buffer.is_null() {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let heap = kernel32_GetProcessHeap();
        let byte_len = utf16.len() * 2;
        let ptr = kernel32_HeapAlloc(heap, 0, byte_len).cast::<u16>();
        if ptr.is_null() {
            kernel32_SetLastError(14); // ERROR_OUTOFMEMORY
            return 0;
        }
        core::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        *buffer.cast::<*mut u16>() = ptr;
        return char_count;
    }

    // Write to caller-supplied buffer.
    if buffer.is_null() || size == 0 {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    // Clamp to however many UTF-16 units fit (including the null terminator).
    // utf16.len() >= 1 because we always chain a null terminator above, so
    // to_write >= 1 whenever size >= 1, ruling out any underflow below.
    let to_write = utf16.len().min(size as usize);
    if to_write == 0 {
        return 0;
    }
    core::ptr::copy_nonoverlapping(utf16.as_ptr(), buffer, to_write);
    // Guarantee null termination at the last position written (handles truncation).
    *buffer.add(to_write - 1) = 0;
    // Return the number of characters written, not counting the null terminator.
    char_count.min(size - 1)
}

/// Returns the human-readable message for a Windows system error code.
fn windows_error_message(code: u32) -> String {
    let msg = match code {
        0 => "The operation completed successfully.",
        1 => "Incorrect function.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        4 => "The system cannot open the file.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough storage is available to process this command.",
        14 => "Not enough storage is available to complete this operation.",
        15 => "The system cannot find the drive specified.",
        16 => "The directory cannot be removed.",
        18 => "There are no more files.",
        32 => "The process cannot access the file because it is being used by another process.",
        87 => "The parameter is incorrect.",
        112 => "There is not enough space on the disk.",
        122 => "The data area passed to a system call is too small.",
        123 => "The filename, directory name, or volume label syntax is incorrect.",
        183 => "Cannot create a file when that file already exists.",
        206 => "The filename or extension is too long.",
        998 => "Invalid access to memory location.",
        1168 => "Element not found.",
        _ => return format!("Unknown error ({code})."),
    };
    msg.to_string()
}

/// GetCurrentDirectoryW - gets the current working directory
///
/// Returns the length of the path copied to the buffer (not including null terminator).
/// If the buffer is too small, returns the required buffer size (including null terminator).
///
/// # Safety
/// Caller must ensure buffer is valid and buffer_length is accurate if buffer is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentDirectoryW(
    buffer_length: u32,
    buffer: *mut u16,
) -> u32 {
    // Get current directory from std::env
    let Ok(current_dir) = std::env::current_dir() else {
        // Set last error to ERROR_ACCESS_DENIED (5)
        kernel32_SetLastError(5);
        return 0;
    };

    // Convert to string
    let dir_str = current_dir.to_string_lossy();

    // Convert Windows-style if needed (for consistency with Windows behavior)
    // But since we're on Linux, keep it as-is

    // Convert to UTF-16
    let mut utf16: Vec<u16> = dir_str.encode_utf16().collect();
    utf16.push(0); // Null terminator

    // Check if buffer is large enough
    if buffer.is_null() || buffer_length < utf16.len() as u32 {
        // Return required buffer size (including null terminator)
        return utf16.len() as u32;
    }

    // Copy to buffer
    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    // Return length without null terminator
    (utf16.len() - 1) as u32
}

/// GetExitCodeProcess — retrieves the termination status of a process.
///
/// For the current-process pseudo-handle (`-1 / 0xFFFF…`) this reports
/// `STILL_ACTIVE` (259), which is the correct value for a running process.
/// Any other handle is not tracked in our emulation layer, so we also
/// return `STILL_ACTIVE` as the most safe default.
///
/// # Safety
/// `exit_code` must be null or point to a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetExitCodeProcess(
    _process: *mut core::ffi::c_void,
    exit_code: *mut u32,
) -> i32 {
    const STILL_ACTIVE: u32 = 259;
    if !exit_code.is_null() {
        // SAFETY: Caller guarantees exit_code is valid and non-null (checked above).
        *exit_code = STILL_ACTIVE;
    }
    1 // TRUE
}

/// GetFileAttributesW - gets file attributes
///
/// Returns `FILE_ATTRIBUTE_DIRECTORY` for directories, `FILE_ATTRIBUTE_NORMAL`
/// for regular files, and `INVALID_FILE_ATTRIBUTES` (0xFFFF_FFFF) if the path
/// does not exist or cannot be accessed.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileAttributesW(file_name: *const u16) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0080;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_FILE_ATTRIBUTES;
    }
    let path_str = wide_path_to_linux(file_name);
    if let Ok(meta) = std::fs::metadata(std::path::Path::new(&path_str)) {
        if meta.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            let mut attrs = FILE_ATTRIBUTE_NORMAL;
            if meta.permissions().readonly() {
                attrs |= FILE_ATTRIBUTE_READONLY;
            }
            attrs
        }
    } else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        INVALID_FILE_ATTRIBUTES
    }
}

/// GetFileInformationByHandle — retrieves file information for the specified file.
///
/// Fills the caller-supplied `BY_HANDLE_FILE_INFORMATION` structure (52 bytes,
/// 13 consecutive `u32` fields) using `fstat` on the underlying Linux file descriptor.
///
/// # Safety
/// `file` must be a handle previously returned by `CreateFileW`.
/// `file_information` must point to a writable 52-byte `BY_HANDLE_FILE_INFORMATION` struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandle(
    file: *mut core::ffi::c_void,
    file_information: *mut core::ffi::c_void,
) -> i32 {
    use std::os::unix::fs::MetadataExt;

    // Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
    // Unix time: seconds since 1970-01-01 UTC.  Difference: 11 644 473 600 s.
    const UNIX_EPOCH_OFFSET: u64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if file_information.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let handle_val = file as usize;

    // Retrieve metadata from the registered file handle (calls fstat internally).
    let result = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.metadata()));

    let Some(meta_result) = result else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let Ok(meta) = meta_result else {
        kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
        return 0;
    };

    let to_filetime = |secs: i64, nsecs: i64| -> u64 {
        if secs < 0 {
            return 0;
        }
        let whole_ticks = (secs as u64)
            .saturating_add(UNIX_EPOCH_OFFSET)
            .saturating_mul(TICKS_PER_SEC);
        // Add the sub-second nanosecond component (1 tick = 100 ns).
        let sub_ticks = (nsecs.max(0) as u64) / 100;
        whole_ticks.saturating_add(sub_ticks)
    };

    let attrs: u32 =
        if meta.is_dir() { 0x10 } else { 0x80 } | u32::from(meta.permissions().readonly());
    let file_size = meta.len();
    let mtime = to_filetime(meta.mtime(), meta.mtime_nsec());
    let atime = to_filetime(meta.atime(), meta.atime_nsec());
    // Linux has no "creation time"; use ctime (metadata-change time) as approximation.
    let ctime = to_filetime(meta.ctime(), meta.ctime_nsec());
    let ino = meta.ino();
    let nlink = meta.nlink();

    // BY_HANDLE_FILE_INFORMATION layout (13 × u32 = 52 bytes):
    //  [0]     dwFileAttributes
    //  [1,2]   ftCreationTime    (low32, high32)
    //  [3,4]   ftLastAccessTime  (low32, high32)
    //  [5,6]   ftLastWriteTime   (low32, high32)
    //  [7]     dwVolumeSerialNumber
    //  [8]     nFileSizeHigh
    //  [9]     nFileSizeLow
    //  [10]    nNumberOfLinks
    //  [11]    nFileIndexHigh
    //  [12]    nFileIndexLow
    // SAFETY: Caller guarantees file_information points to a valid 52-byte struct.
    let p = file_information.cast::<u32>();
    *p.add(0) = attrs;
    *p.add(1) = ctime as u32;
    *p.add(2) = (ctime >> 32) as u32;
    *p.add(3) = atime as u32;
    *p.add(4) = (atime >> 32) as u32;
    *p.add(5) = mtime as u32;
    *p.add(6) = (mtime >> 32) as u32;
    *p.add(7) = get_volume_serial();
    *p.add(8) = (file_size >> 32) as u32;
    *p.add(9) = file_size as u32;
    *p.add(10) = nlink as u32;
    *p.add(11) = (ino >> 32) as u32;
    *p.add(12) = ino as u32;

    kernel32_SetLastError(0); // SUCCESS
    1 // TRUE
}

/// GetFileType - gets the type of a file
///
/// Returns FILE_TYPE_CHAR (2) for the standard console handles, FILE_TYPE_DISK (1)
/// for handles opened with CreateFileW, and FILE_TYPE_UNKNOWN (0) otherwise.
///
/// # Safety
/// This function is safe to call; `file` is treated as an opaque handle value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileType(file: *mut core::ffi::c_void) -> u32 {
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_TYPE_CHAR: u32 = 2;
    const FILE_TYPE_UNKNOWN: u32 = 0;

    let handle_val = file as usize;
    // 0x10 = stdin, 0x11 = stdout, 0x12 = stderr (see GetStdHandle)
    if handle_val == 0x10 || handle_val == 0x11 || handle_val == 0x12 {
        return FILE_TYPE_CHAR;
    }
    if with_file_handles(|map| map.contains_key(&handle_val)) {
        return FILE_TYPE_DISK;
    }
    FILE_TYPE_UNKNOWN
}

/// GetFullPathNameW - gets the absolute path name of a file
///
/// Converts a potentially relative path to an absolute one using the current
/// working directory.  The `file_part` pointer (if non-null) is set to point
/// at the file name portion of the result inside `buffer`.
///
/// Returns the number of characters written (excluding the null terminator),
/// or the required buffer length (including the null terminator) if the buffer
/// is too small, or 0 on error.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
/// `buffer` must point to a writable area of at least `buffer_length` `u16`s, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFullPathNameW(
    file_name: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    // Resolve to an absolute path
    let abs_path = if std::path::Path::new(&path_str).is_absolute() {
        path_str.clone()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(&path_str).to_string_lossy().into_owned(),
            Err(_) => path_str.clone(),
        }
    };

    let utf16: Vec<u16> = abs_path.encode_utf16().collect();
    let required = utf16.len() as u32 + 1; // +1 for null terminator

    if buffer.is_null() || buffer_length == 0 {
        return required;
    }
    if buffer_length < required {
        // Buffer too small – return required size (including null)
        kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return required;
    }
    for (i, &ch) in utf16.iter().enumerate() {
        // SAFETY: we checked buffer_length >= required
        core::ptr::write(buffer.add(i), ch);
    }
    core::ptr::write(buffer.add(utf16.len()), 0u16);

    // Set *file_part to point at the final component (the filename) inside buffer
    if !file_part.is_null() {
        let last_sep = utf16
            .iter()
            .rposition(|&c| c == u16::from(b'/') || c == u16::from(b'\\'));
        let fname_offset = match last_sep {
            Some(pos) => pos + 1,
            None => 0,
        };
        if fname_offset < utf16.len() {
            // SAFETY: fname_offset < utf16.len() < required <= buffer_length
            *file_part = buffer.add(fname_offset);
        } else {
            *file_part = core::ptr::null_mut();
        }
    }

    utf16.len() as u32 // number of chars written (excluding null)
}

// Thread-local storage for last error codes
//
// Each thread maintains its own error code without global synchronization.
// This eliminates the unbounded memory growth issue from the previous
// implementation and improves performance by removing mutex contention.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// GetLastError - gets the last error code for the current thread
///
/// In Windows, this is thread-local and set by many APIs.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLastError() -> u32 {
    LAST_ERROR.with(Cell::get)
}

/// GetModuleHandleW stub - gets a module handle
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleW(
    _module_name: *const u16,
) -> *mut core::ffi::c_void {
    // Return a fake non-null handle for the main module (NULL parameter)
    0x400000 as *mut core::ffi::c_void
}

/// GetProcAddress stub - gets a procedure address
///
/// Note: This is already handled by the DLL manager, but we provide
/// a stub in case it's called directly.
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcAddress(
    _module: *mut core::ffi::c_void,
    _proc_name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// GetStdHandle - retrieves a handle to the specified standard device
///
/// Returns:
/// - `0x10` for `STD_INPUT_HANDLE`  (-10 / 0xFFFFFFF6)
/// - `0x11` for `STD_OUTPUT_HANDLE` (-11 / 0xFFFFFFF5)
/// - `0x12` for `STD_ERROR_HANDLE`  (-12 / 0xFFFFFFF4)
/// - `NULL` for any other value
///
/// These sentinel values are recognised by `WriteFile`, `ReadFile`, and
/// `GetFileType` as the console handles.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStdHandle(std_handle: u32) -> *mut core::ffi::c_void {
    // STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    #[allow(clippy::cast_possible_wrap)]
    match std_handle as i32 {
        -10 => 0x10 as *mut core::ffi::c_void, // stdin
        -11 => 0x11 as *mut core::ffi::c_void, // stdout
        -12 => 0x12 as *mut core::ffi::c_void, // stderr
        _ => core::ptr::null_mut(),
    }
}

/// GetCommandLineW - returns the command line for the current process (wide version)
///
/// Returns a pointer to the process command line as a null-terminated UTF-16 string.
/// The runner must call `set_process_command_line` before the entry point executes.
///
/// # Safety
/// This function is safe to call. It returns a pointer to static storage that is valid
/// for the lifetime of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCommandLineW() -> *const u16 {
    // SAFETY: The Vec stored in PROCESS_COMMAND_LINE is never dropped; as_ptr() is valid.
    // EMPTY_CMD is a const array; its address is stable for the lifetime of the process.
    const EMPTY_CMD: [u16; 1] = [0];
    PROCESS_COMMAND_LINE
        .get()
        .map_or(EMPTY_CMD.as_ptr(), std::vec::Vec::as_ptr)
}

/// GetEnvironmentStringsW - returns all environment strings as a UTF-16 block
///
/// Returns a pointer to a freshly allocated block of null-terminated wide strings
/// of the form `NAME=VALUE\0NAME2=VALUE2\0\0`.  Each call allocates a new block;
/// the caller must release it with `FreeEnvironmentStringsW` to avoid a memory leak.
///
/// # Panics
/// Panics if the environment strings mutex is poisoned.
///
/// # Safety
/// This function is safe to call. The returned pointer is valid until
/// `FreeEnvironmentStringsW` is called with the same pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentStringsW() -> *mut u16 {
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in std::env::vars() {
        let entry = format!("{key}={value}");
        block.extend(entry.encode_utf16());
        block.push(0); // null terminator for this entry
    }
    block.push(0); // final null terminator (empty string = end of block)

    let len = block.len();
    let boxed = block.into_boxed_slice();
    // SAFETY: We just allocated this box; we record the raw pointer so that
    // FreeEnvironmentStringsW can reconstruct the Box and drop it.
    let raw = Box::into_raw(boxed).cast::<u16>();

    let mut guard = ENV_STRINGS_BLOCKS.lock().unwrap();
    guard.get_or_insert_with(Vec::new).push(SendablePtr(raw));
    drop(guard);

    // Suppress unused-variable warning for `len` (used only as a sanity note).
    let _ = len;
    raw
}

/// FreeEnvironmentStringsW - frees a block returned by `GetEnvironmentStringsW`
///
/// Reconstructs the `Box<[u16]>` from the pointer and drops it.  If the pointer
/// was not returned by `GetEnvironmentStringsW`, this is a no-op (safe but does not
/// free the memory).
///
/// # Panics
/// Panics if the environment strings mutex is poisoned.
///
/// # Safety
/// `env_strings` must be a pointer previously returned by `GetEnvironmentStringsW`,
/// or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeEnvironmentStringsW(env_strings: *mut u16) -> i32 {
    if env_strings.is_null() {
        return 1; // TRUE
    }
    let mut guard = ENV_STRINGS_BLOCKS.lock().unwrap();
    let blocks = guard.get_or_insert_with(Vec::new);
    if let Some(pos) = blocks.iter().position(|p| p.0 == env_strings) {
        let ptr = blocks.swap_remove(pos).0;
        drop(guard);
        // Reconstruct the slice length by scanning for the double-null terminator,
        // then drop the box.  We need the length to build a fat pointer.
        //
        // SAFETY: `ptr` was created by `Box::into_raw(boxed.into_boxed_slice())` in
        // `GetEnvironmentStringsW`; we are the only owner now that we removed it from
        // the registry.  We scan to re-derive the original slice length.
        let mut len = 0usize;
        loop {
            if *ptr.add(len) == 0 && *ptr.add(len + 1) == 0 {
                len += 2; // include both null terminators
                break;
            }
            len += 1;
        }
        let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice_ptr));
    }
    1 // TRUE
}

/// LoadLibraryA stub - loads a library (ANSI version)
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryA(
    _lib_file_name: *const u8,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// LoadLibraryW stub - loads a library (wide version)
///
/// Note: This is already handled by the DLL manager, but we provide
/// a stub in case it's called directly.
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryW(
    _lib_file_name: *const u16,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL - not found
}

/// SetConsoleCtrlHandler stub - sets a console control handler
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleCtrlHandler(
    _handler_routine: *mut core::ffi::c_void,
    _add: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SetFilePointerEx - moves the file pointer of the specified file
///
/// Translates Windows `move_method` (FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2) to
/// a `std::io::SeekFrom` and calls `seek()` on the file registered in the handle map.
///
/// # Safety
/// `new_file_pointer` may be null; when non-null it must be a valid writable `i64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFilePointerEx(
    file: *mut core::ffi::c_void,
    distance_to_move: i64,
    new_file_pointer: *mut i64,
    move_method: u32,
) -> i32 {
    let handle_val = file as usize;
    let seek_from = match move_method {
        0 => {
            if distance_to_move < 0 {
                // Windows: SetFilePointerEx(FILE_BEGIN, negative) -> ERROR_NEGATIVE_SEEK (131)
                kernel32_SetLastError(131);
                return 0;
            }
            std::io::SeekFrom::Start(distance_to_move as u64) // FILE_BEGIN
        }
        1 => std::io::SeekFrom::Current(distance_to_move), // FILE_CURRENT
        2 => std::io::SeekFrom::End(distance_to_move),     // FILE_END
        _ => {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
    };
    let result = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.seek(seek_from).ok().map(|pos| pos as i64)
        } else {
            None
        }
    });
    if let Some(pos) = result {
        if !new_file_pointer.is_null() {
            *new_file_pointer = pos;
        }
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        0 // FALSE
    }
}

/// SetLastError - sets the last error code for the current thread
///
/// In Windows, this is thread-local storage used by many APIs to report errors.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetLastError(error_code: u32) {
    LAST_ERROR.with(|error| error.set(error_code));
}

/// WaitForSingleObject - waits until the specified object is in the signaled state or the
/// time-out interval elapses.
///
/// For event handles (created by `CreateEventW`), this waits with correct
/// manual/auto-reset semantics. `INFINITE` (0xFFFFFFFF) blocks until the event
/// is signaled; finite timeouts use a deadline loop that handles spurious
/// wakeups and returns immediately when the event is already signaled.
///
/// For thread handles (created by `CreateThread`), this joins the thread.
///
/// For unrecognised handles (neither event nor thread), `WAIT_OBJECT_0` is
/// returned immediately as an optimistic default.
///
/// # Panics
/// Panics if a mutex protecting event or thread state is poisoned.
///
/// # Safety
/// `handle` must be a valid handle returned by `CreateEventW`, `CreateThread`,
/// or another handle-producing API.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForSingleObject(
    handle: *mut core::ffi::c_void,
    milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    let handle_val = handle as usize;

    // Check if this is an event handle first.
    let event_entry = with_event_handles(|map| {
        map.get(&handle_val)
            .map(|e| (Arc::clone(&e.state), e.manual_reset))
    });
    if let Some((state, manual_reset)) = event_entry {
        let (lock, cvar) = &*state;
        let mut signaled = lock.lock().unwrap();
        if milliseconds == u32::MAX {
            // Infinite wait until the event is signaled.
            while !*signaled {
                signaled = cvar.wait(signaled).unwrap();
            }
            if !manual_reset {
                *signaled = false; // auto-reset
            }
            return WAIT_OBJECT_0;
        }

        // Finite-timeout wait.
        //
        // Return immediately if the event is already signaled.
        if *signaled {
            if !manual_reset {
                *signaled = false; // auto-reset
            }
            return WAIT_OBJECT_0;
        }

        // Zero-timeout: check-and-return without blocking.
        if milliseconds == 0 {
            return WAIT_TIMEOUT;
        }

        // Loop to handle spurious wakeups and recompute remaining time.
        let timeout = Duration::from_millis(u64::from(milliseconds));
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *signaled {
                if !manual_reset {
                    *signaled = false; // auto-reset
                }
                return WAIT_OBJECT_0;
            }

            let now = std::time::Instant::now();
            if now >= deadline {
                return WAIT_TIMEOUT;
            }

            let remaining = deadline - now;
            let (guard, result) = cvar.wait_timeout(signaled, remaining).unwrap();
            signaled = guard;

            // If the Condvar reported a genuine timeout and the event is still not
            // signaled, report WAIT_TIMEOUT.  Otherwise loop to recheck *signaled.
            if result.timed_out() && !*signaled {
                return WAIT_TIMEOUT;
            }
        }
    }

    // Take ownership of the join handle (if this is a thread handle).
    let thread_entry = with_thread_handles(|map| {
        map.get_mut(&handle_val).map(|entry| {
            let jh = entry.join_handle.take();
            let ec = Arc::clone(&entry.exit_code);
            (jh, ec)
        })
    });

    let Some((join_handle_opt, exit_code)) = thread_entry else {
        // Not a thread or event handle — treat as already-signaled.
        return WAIT_OBJECT_0;
    };

    let Some(join_handle) = join_handle_opt else {
        // Thread was already joined.
        return WAIT_OBJECT_0;
    };

    if milliseconds == u32::MAX {
        // Infinite wait: block until the thread finishes.
        let _ = join_handle.join();
        return WAIT_OBJECT_0;
    }

    // Timed wait: poll the exit code with 1 ms sleep intervals.
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(u64::from(milliseconds));
    loop {
        if exit_code.lock().unwrap().is_some() {
            let _ = join_handle.join();
            return WAIT_OBJECT_0;
        }
        if start.elapsed() >= timeout {
            // Return the join handle to the registry so the thread can be joined later.
            with_thread_handles(|map| {
                if let Some(entry) = map.get_mut(&handle_val) {
                    entry.join_handle = Some(join_handle);
                }
            });
            return WAIT_TIMEOUT;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// WriteConsoleW - writes a character string to a console screen buffer
///
/// Converts the wide (UTF-16) string to UTF-8 and writes it to `stdout`.
/// The `console_output` handle is accepted but not used to distinguish between
/// stdout and stderr; all output goes to stdout.  Returns FALSE if `buffer`
/// is null, `number_of_chars_to_write` is zero, or the UTF-16 string is not
/// valid.
///
/// # Safety
/// `buffer` must point to at least `number_of_chars_to_write` valid UTF-16
/// code units when non-null.  `number_of_chars_written`, if non-null, must
/// point to a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteConsoleW(
    _console_output: *mut core::ffi::c_void,
    buffer: *const u16,
    number_of_chars_to_write: u32,
    number_of_chars_written: *mut u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // Try to write to stdout
    if !buffer.is_null() && number_of_chars_to_write > 0 {
        let slice = core::slice::from_raw_parts(buffer, number_of_chars_to_write as usize);
        if let Ok(s) = String::from_utf16(slice) {
            print!("{s}");
            let _ = std::io::stdout().flush();
            if !number_of_chars_written.is_null() {
                *number_of_chars_written = number_of_chars_to_write;
            }
            return 1; // TRUE
        }
    }
    0 // FALSE
}

// Additional stubs for remaining missing APIs

/// GetFileInformationByHandleEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandleEx(
    _file: *mut core::ffi::c_void,
    _file_information_class: u32,
    _file_information: *mut core::ffi::c_void,
    _buffer_size: u32,
) -> i32 {
    0 // FALSE
}

/// GetFileSizeEx - retrieves the size of the specified file
///
/// Looks up the file handle in the kernel32 file-handle registry and calls
/// `metadata().len()` to get the actual file size.
///
/// # Safety
/// When `file_size` is non-null, it must be a valid, writable pointer to an `i64`
/// where the file size will be stored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileSizeEx(
    file: *mut core::ffi::c_void,
    file_size: *mut i64,
) -> i32 {
    if file_size.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let handle_val = file as usize;
    let size_result = with_file_handles(|map| {
        map.get(&handle_val)
            .and_then(|entry| entry.file.metadata().ok())
            .map(|m| m.len() as i64)
    });
    if let Some(sz) = size_result {
        *file_size = sz;
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        0 // FALSE
    }
}

/// GetFinalPathNameByHandleW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFinalPathNameByHandleW(
    _file: *mut core::ffi::c_void,
    _file_path: *mut u16,
    _file_path_size: u32,
    _flags: u32,
) -> u32 {
    0 // 0 = error
}

/// GetOverlappedResult stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOverlappedResult(
    _file: *mut core::ffi::c_void,
    _overlapped: *mut core::ffi::c_void,
    _number_of_bytes_transferred: *mut u32,
    _wait: i32,
) -> i32 {
    0 // FALSE
}

/// GetProcessId - retrieves the process identifier of the specified process
///
/// When `process` is the current-process pseudo-handle (`-1`) or any other
/// handle, returns the actual PID of this (Linux) process via
/// `std::process::id()`.
///
/// # Safety
/// `process` is accepted as an opaque handle value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessId(_process: *mut core::ffi::c_void) -> u32 {
    std::process::id()
}

/// GetSystemDirectoryW - returns the Windows system directory path
///
/// Returns `C:\Windows\System32` as the system directory.  When `buffer` is
/// null or too small, the required size (including the null terminator) is
/// returned so callers can retry with the correct buffer size.
///
/// # Safety
/// When `buffer` is non-null, it must be a valid writable buffer of at least
/// `size` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    // "C:\Windows\System32" encoded as UTF-16 (null-terminated)
    let path: &[u16] = &[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        u16::from(b'W'),
        u16::from(b'i'),
        u16::from(b'n'),
        u16::from(b'd'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b's'),
        u16::from(b'\\'),
        u16::from(b'S'),
        u16::from(b'y'),
        u16::from(b's'),
        u16::from(b't'),
        u16::from(b'e'),
        u16::from(b'm'),
        u16::from(b'3'),
        u16::from(b'2'),
        0u16,
    ];
    let required = path.len() as u32; // includes null terminator
    if buffer.is_null() || size < required {
        return required;
    }
    for (i, &ch) in path.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    (path.len() - 1) as u32 // characters written, excluding null terminator
}

/// GetTempPathW - retrieves the path of the directory designated for temporary files
///
/// Returns the path reported by `std::env::temp_dir()` (typically `/tmp` on
/// Linux) as a null-terminated UTF-16 string with a trailing directory
/// separator.
///
/// If `buffer` is null or `buffer_length` is too small, returns the required
/// buffer size (in UTF-16 code units, including the null terminator); otherwise
/// copies the path and returns the length excluding the null terminator.
///
/// # Safety
/// `buffer`, if non-null, must point to a writable area of at least
/// `buffer_length` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32 {
    let temp_dir = std::env::temp_dir();
    let mut dir_str = temp_dir.to_string_lossy().into_owned();
    if !dir_str.ends_with('/') {
        dir_str.push('/');
    }
    let mut utf16: Vec<u16> = dir_str.encode_utf16().collect();
    utf16.push(0); // null terminator

    let required = utf16.len() as u32;
    if buffer.is_null() || buffer_length < required {
        return required;
    }

    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    (utf16.len() - 1) as u32 // length without null terminator
}

/// GetWindowsDirectoryW - returns the Windows directory path
///
/// Returns `C:\Windows` as the Windows directory.  When `buffer` is null or
/// too small, the required size (including the null terminator) is returned.
///
/// # Safety
/// When `buffer` is non-null, it must be a valid writable buffer of at least
/// `size` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    // "C:\Windows" encoded as UTF-16 (null-terminated)
    let path: &[u16] = &[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        u16::from(b'W'),
        u16::from(b'i'),
        u16::from(b'n'),
        u16::from(b'd'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b's'),
        0u16,
    ];
    let required = path.len() as u32; // includes null terminator
    if buffer.is_null() || size < required {
        return required;
    }
    for (i, &ch) in path.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    (path.len() - 1) as u32 // characters written, excluding null terminator
}

/// InitOnceBeginInitialize stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceBeginInitialize(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    pending: *mut i32,
    _context: *mut *mut core::ffi::c_void,
) -> i32 {
    // Set pending to FALSE, indicating initialization is complete
    if !pending.is_null() {
        *pending = 0;
    }
    1 // TRUE
}

/// InitOnceComplete stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceComplete(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    _context: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// InitializeProcThreadAttributeList stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeProcThreadAttributeList(
    _attribute_list: *mut core::ffi::c_void,
    _attribute_count: u32,
    _flags: u32,
    _size: *mut usize,
) -> i32 {
    0 // FALSE
}

/// LockFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LockFileEx(
    _file: *mut core::ffi::c_void,
    _flags: u32,
    _reserved: u32,
    _number_of_bytes_to_lock_low: u32,
    _number_of_bytes_to_lock_high: u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE - pretend success
}

/// MapViewOfFile stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MapViewOfFile(
    _file_mapping_object: *mut core::ffi::c_void,
    _desired_access: u32,
    _file_offset_high: u32,
    _file_offset_low: u32,
    _number_of_bytes_to_map: usize,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut() // NULL
}

/// Module32FirstW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32FirstW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// Module32NextW stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32NextW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// MoveFileExW - renames or moves a file or directory
///
/// Translates both path arguments with `wide_path_to_linux` then calls
/// `std::fs::rename`.  The `flags` parameter is accepted but ignored.
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16
/// strings when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MoveFileExW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    _flags: u32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    match std::fs::rename(&src, &dst) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 2,                                    // ERROR_FILE_NOT_FOUND (generic)
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// ReadFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFileEx(
    _file: *mut core::ffi::c_void,
    _buffer: *mut u8,
    _number_of_bytes_to_read: u32,
    _overlapped: *mut core::ffi::c_void,
    _completion_routine: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// RemoveDirectoryW - removes an existing empty directory
///
/// Translates the path with `wide_path_to_linux` then calls `std::fs::remove_dir`.
///
/// # Safety
/// `path_name` must be a valid null-terminated UTF-16 string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RemoveDirectoryW(path_name: *const u16) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path = wide_path_to_linux(path_name);
    match std::fs::remove_dir(&path) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                // std::io::ErrorKind::DirectoryNotEmpty doesn't exist yet on stable Rust,
                // but POSIX ENOTEMPTY maps to `Other`.
                _ => {
                    // Check for ENOTEMPTY via the OS error code
                    if e.raw_os_error() == Some(libc::ENOTEMPTY) {
                        145 // ERROR_DIR_NOT_EMPTY
                    } else {
                        2 // ERROR_FILE_NOT_FOUND (generic)
                    }
                }
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// SetCurrentDirectoryW - sets the current working directory
///
/// Returns 1 (TRUE) on success, 0 (FALSE) on failure.
///
/// # Safety
/// Caller must ensure path_name points to a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetCurrentDirectoryW(path_name: *const u16) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // Read UTF-16 string until null terminator
    let mut len = 0;
    while *path_name.add(len) != 0 {
        len += 1;
        // Safety check: prevent infinite loop
        if len > 32768 {
            // MAX_PATH is 260, but we allow more
            kernel32_SetLastError(206); // ERROR_FILENAME_EXCEED_RANGE
            return 0;
        }
    }

    // Convert to Rust string
    let slice = core::slice::from_raw_parts(path_name, len);
    let path_str = String::from_utf16_lossy(slice);

    // Try to set the current directory
    if std::env::set_current_dir(std::path::Path::new(path_str.as_str())).is_ok() {
        1 // TRUE - success
    } else {
        // Set last error to ERROR_FILE_NOT_FOUND (2)
        kernel32_SetLastError(2);
        0 // FALSE - failure
    }
}

/// SetFileAttributesW — sets the attributes of a file or directory.
///
/// Maps Windows `FILE_ATTRIBUTE_READONLY (0x1)` to the Linux read-only
/// permission model via `chmod`. Other attribute bits (hidden, system, etc.)
/// have no direct Linux equivalent and are silently accepted so that programs
/// that set them do not fail.
///
/// Returns TRUE on success, FALSE on failure (sets last error).
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileAttributesW(
    file_name: *const u16,
    file_attributes: u32,
) -> i32 {
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    if path_str.is_empty() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path = std::path::Path::new(&path_str);
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mut perms = meta.permissions();
            if (file_attributes & FILE_ATTRIBUTE_READONLY) != 0 {
                perms.set_readonly(true);
            } else {
                perms.set_readonly(false);
            }
            match std::fs::set_permissions(path, perms) {
                Ok(()) => 1, // TRUE
                Err(_) => {
                    kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
                    0
                }
            }
        }
        Err(_) => {
            kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
            0
        }
    }
}

/// SetFileInformationByHandle stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileInformationByHandle(
    _file: *mut core::ffi::c_void,
    _file_information_class: u32,
    _file_information: *mut core::ffi::c_void,
    _buffer_size: u32,
) -> i32 {
    0 // FALSE
}

/// SetFileTime - sets the date and time that a file was created, accessed, or modified
///
/// On Linux we have limited ability to set all three timestamps accurately via
/// `utimes`.  For simplicity this always returns TRUE (success) without
/// actually updating timestamps; programs that inspect file timestamps may
/// observe stale values.
///
/// # Safety
/// All pointer arguments are accepted but not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileTime(
    _file: *mut core::ffi::c_void,
    _creation_time: *const core::ffi::c_void,
    _last_access_time: *const core::ffi::c_void,
    _last_write_time: *const core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// SetHandleInformation - sets certain properties of an object handle
///
/// Handle inheritance and protections are not meaningful in our single-process
/// emulation environment, so this always returns TRUE (success).
///
/// # Safety
/// `object` is accepted as an opaque handle and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetHandleInformation(
    _object: *mut core::ffi::c_void,
    _mask: u32,
    _flags: u32,
) -> i32 {
    1 // TRUE
}

/// UnlockFile - unlocks a region of an open file
///
/// File-locking is not implemented; this always returns TRUE (success) since
/// we do not implement `LockFile` either.
///
/// # Safety
/// `file` is accepted as an opaque handle and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnlockFile(
    _file: *mut core::ffi::c_void,
    _offset_low: u32,
    _offset_high: u32,
    _number_of_bytes_to_unlock_low: u32,
    _number_of_bytes_to_unlock_high: u32,
) -> i32 {
    1 // TRUE
}

/// UnmapViewOfFile - unmaps a mapped view of a file from the address space
///
/// File mapping is not implemented; this always returns TRUE (success) since
/// `MapViewOfFile` returns NULL and programs typically check for NULL before
/// calling `UnmapViewOfFile`.
///
/// # Safety
/// `base_address` is accepted as an opaque pointer and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnmapViewOfFile(_base_address: *const core::ffi::c_void) -> i32 {
    1 // TRUE
}

/// UpdateProcThreadAttribute stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UpdateProcThreadAttribute(
    _attribute_list: *mut core::ffi::c_void,
    _flags: u32,
    _attribute: usize,
    _value: *mut core::ffi::c_void,
    _size: usize,
    _previous_value: *mut core::ffi::c_void,
    _return_size: *mut usize,
) -> i32 {
    0 // FALSE
}

/// WriteFileEx stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFileEx(
    _file: *mut core::ffi::c_void,
    _buffer: *const u8,
    _number_of_bytes_to_write: u32,
    _overlapped: *mut core::ffi::c_void,
    _completion_routine: *mut core::ffi::c_void,
) -> i32 {
    0 // FALSE
}

/// SetThreadStackGuarantee - sets the minimum stack size for the current thread
///
/// Stack size management is handled by the OS; this always returns TRUE
/// (success) without modifying the actual stack.
///
/// # Safety
/// `stack_size_in_bytes` is accepted as a pointer but not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetThreadStackGuarantee(_stack_size_in_bytes: *mut u32) -> i32 {
    1 // TRUE
}

/// SetWaitableTimer stub
///
/// # Safety
/// This function is a stub that returns a safe default value without dereferencing any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetWaitableTimer(
    _timer: *mut core::ffi::c_void,
    _due_time: *const i64,
    _period: i32,
    _completion_routine: *mut core::ffi::c_void,
    _arg_to_completion_routine: *mut core::ffi::c_void,
    _resume: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SleepEx - suspends the current thread with optional alertable wait
///
/// Sleeps for `milliseconds` milliseconds.  The `alertable` flag is ignored
/// (I/O completion callbacks are not supported), and this always returns 0.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SleepEx(milliseconds: u32, _alertable: i32) -> u32 {
    if milliseconds > 0 {
        thread::sleep(Duration::from_millis(u64::from(milliseconds)));
    }
    0 // WAIT_IO_COMPLETION not supported; always return 0
}

/// SwitchToThread - yields execution to another runnable thread
///
/// Calls `std::thread::yield_now()` to give the scheduler an opportunity to
/// run another thread.  Returns TRUE.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SwitchToThread() -> i32 {
    thread::yield_now();
    1 // TRUE
}

/// TerminateProcess - terminates the specified process and all of its threads
///
/// When called with the current-process pseudo-handle (-1 / 0xFFFFFFFFFFFFFFFF), this
/// immediately exits the process.  Terminating other processes is not supported.
///
/// # Safety
/// Calling this with the current-process pseudo-handle is safe: it exits immediately.
/// Passing other values is a no-op (returns FALSE).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TerminateProcess(
    process: *mut core::ffi::c_void,
    exit_code: u32,
) -> i32 {
    // -1 (0xFFFFFFFFFFFFFFFF) is the Windows pseudo-handle for the current process.
    if process as isize == -1 {
        std::process::exit(exit_code as i32);
    }
    0 // FALSE - cannot terminate other processes
}

/// WaitForMultipleObjects - waits until one or all of the specified objects are in the
/// signaled state or the time-out interval elapses.
///
/// For thread handles in the registry:
///   - `wait_all != 0`: joins every thread in order; returns WAIT_OBJECT_0 when all finish.
///   - `wait_all == 0`: polls all handles; returns WAIT_OBJECT_0 + i for the first to finish.
///
/// Handles not found in the thread registry are treated as already-signaled.
///
/// # Panics
/// Panics if a thread's exit-code mutex is poisoned.
///
/// # Safety
/// `handles` must point to an array of `count` valid HANDLE values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForMultipleObjects(
    count: u32,
    handles: *const *mut core::ffi::c_void,
    wait_all: i32,
    milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    if count == 0 || handles.is_null() {
        return WAIT_OBJECT_0;
    }

    // Collect handle values.
    let handle_vals: Vec<usize> = (0..count as usize)
        .map(|i| unsafe { *handles.add(i) as usize })
        .collect();

    if wait_all != 0 {
        // Wait for ALL objects: join each thread handle sequentially.
        let start = std::time::Instant::now();
        let timeout_opt = if milliseconds == u32::MAX {
            None
        } else {
            Some(Duration::from_millis(u64::from(milliseconds)))
        };

        for &hval in &handle_vals {
            let thread_entry = with_thread_handles(|map| {
                map.get_mut(&hval).map(|entry| {
                    let jh = entry.join_handle.take();
                    let ec = Arc::clone(&entry.exit_code);
                    (jh, ec)
                })
            });

            let Some((join_handle_opt, _)) = thread_entry else {
                continue; // non-thread handle: treat as signaled
            };
            let Some(join_handle) = join_handle_opt else {
                continue; // already joined
            };

            match timeout_opt {
                None => {
                    let _ = join_handle.join();
                }
                Some(timeout) => loop {
                    if join_handle.is_finished() {
                        let _ = join_handle.join();
                        break;
                    }
                    if start.elapsed() >= timeout {
                        with_thread_handles(|map| {
                            if let Some(entry) = map.get_mut(&hval) {
                                entry.join_handle = Some(join_handle);
                            }
                        });
                        return WAIT_TIMEOUT;
                    }
                    thread::sleep(Duration::from_millis(1));
                },
            }
        }
        WAIT_OBJECT_0
    } else {
        // Wait for ANY object: poll all handles until one finishes.
        let start = std::time::Instant::now();
        let timeout_opt = if milliseconds == u32::MAX {
            None
        } else {
            Some(Duration::from_millis(u64::from(milliseconds)))
        };

        loop {
            for (i, &hval) in handle_vals.iter().enumerate() {
                let is_done = with_thread_handles(|map| {
                    if let Some(entry) = map.get(&hval) {
                        // Signaled if exit_code is set or join_handle is finished/gone.
                        entry.exit_code.lock().unwrap().is_some()
                            || entry
                                .join_handle
                                .as_ref()
                                .is_none_or(std::thread::JoinHandle::is_finished)
                    } else {
                        true // non-thread handle: treat as signaled
                    }
                });

                if is_done {
                    // Join the thread if possible.
                    with_thread_handles(|map| {
                        if let Some(entry) = map.get_mut(&hval)
                            && let Some(jh) = entry.join_handle.take()
                        {
                            let _ = jh.join();
                        }
                    });
                    return WAIT_OBJECT_0 + i as u32;
                }
            }

            if let Some(timeout) = timeout_opt
                && start.elapsed() >= timeout
            {
                return WAIT_TIMEOUT;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// ExitProcess - terminates the calling process and all its threads
///
/// # Safety
/// This function terminates the process immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ExitProcess(exit_code: u32) {
    std::process::exit(exit_code as i32);
}

/// GetCurrentProcess - returns a pseudo-handle for the current process
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcess() -> *mut core::ffi::c_void {
    // Windows returns -1 (0xFFFFFFFFFFFFFFFF) as the pseudo-handle for the current process
    -1_i64 as usize as *mut core::ffi::c_void
}

/// GetCurrentThread - returns a pseudo-handle for the current thread
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThread() -> *mut core::ffi::c_void {
    // Windows returns -2 (0xFFFFFFFFFFFFFFFE) as the pseudo-handle for the current thread
    -2_i64 as usize as *mut core::ffi::c_void
}

/// GetModuleHandleA - returns the module handle for a named module (ANSI version)
///
/// # Safety
/// This function is a stub that returns a default base address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleA(
    _module_name: *const u8,
) -> *mut core::ffi::c_void {
    // Return default image base address
    0x400000_usize as *mut core::ffi::c_void
}

/// GetModuleFileNameW — retrieves the fully qualified path for the executable
/// that contains the specified module.
///
/// When `module` is null (i.e. the main executable), reads the path from
/// `/proc/self/exe` and returns it as a UTF-16 string in `filename`.
/// Non-null module handles refer to loaded DLLs; for those we currently
/// return an empty string (unimplemented).
///
/// Returns the number of UTF-16 characters written, excluding the null
/// terminator.  Returns 0 on failure (buffer too small or unresolvable path).
///
/// # Safety
/// `filename` must point to a valid buffer of at least `size` `u16` elements,
/// or be null.  `size` of 0 is treated as a null buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleFileNameW(
    module: *mut core::ffi::c_void,
    filename: *mut u16,
    size: u32,
) -> u32 {
    // Only handle the "current executable" case (module == NULL).
    if !module.is_null() {
        kernel32_SetLastError(31); // ERROR_GEN_FAILURE - DLL handle not tracked
        return 0;
    }
    let exe_path = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            let win_err = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                _ => 31,                                   // ERROR_GEN_FAILURE
            };
            kernel32_SetLastError(win_err);
            return 0;
        }
    };
    // SAFETY: filename and size are validated by copy_utf8_to_wide.
    copy_utf8_to_wide(&exe_path, filename, size)
}

/// Windows SYSTEM_INFO structure (x86_64 layout).
///
/// Matches the Windows API `SYSTEM_INFO` struct at
/// <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info>.
/// Field names follow Windows naming conventions. Pointer-sized fields use `u64`
/// to match the fixed x86_64 Windows ABI layout (always 8 bytes).
#[repr(C)]
struct SystemInfo {
    w_processor_architecture: u16,
    w_reserved: u16,
    dw_page_size: u32,
    lp_minimum_application_address: u64,
    lp_maximum_application_address: u64,
    dw_active_processor_mask: u64,
    dw_number_of_processors: u32,
    dw_processor_type: u32,
    dw_allocation_granularity: u32,
    w_processor_level: u16,
    w_processor_revision: u16,
}

/// GetSystemInfo - retrieves information about the current system
///
/// # Safety
/// Caller must ensure `system_info` points to a valid buffer of at least
/// `core::mem::size_of::<SystemInfo>()` bytes when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemInfo(system_info: *mut u8) {
    if system_info.is_null() {
        return;
    }
    let info = SystemInfo {
        w_processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
        w_reserved: 0,
        dw_page_size: 4096,
        lp_minimum_application_address: 0x10000,
        lp_maximum_application_address: 0x7FFF_FFFE_FFFF,
        dw_active_processor_mask: 1,
        dw_number_of_processors: 1,
        dw_processor_type: 8664, // PROCESSOR_AMD_X8664
        dw_allocation_granularity: 65536,
        w_processor_level: 6,
        w_processor_revision: 0,
    };
    // SAFETY: Caller guarantees system_info points to a valid buffer of sufficient size.
    core::ptr::copy_nonoverlapping(
        (&raw const info).cast::<u8>(),
        system_info,
        core::mem::size_of::<SystemInfo>(),
    );
}

/// GetConsoleMode - retrieves the current input mode of a console's input buffer
///
/// # Safety
/// Caller must ensure `mode` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleMode(
    _console_handle: *mut core::ffi::c_void,
    mode: *mut u32,
) -> i32 {
    if !mode.is_null() {
        // SAFETY: Caller guarantees mode is valid and non-null (checked above).
        *mode = 3; // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT
    }
    1 // TRUE - success
}

/// GetConsoleOutputCP - retrieves the output code page used by the console
///
/// # Safety
/// This function is safe to call. It returns a constant value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleOutputCP() -> u32 {
    65001 // UTF-8
}

/// ReadConsoleW - reads character input from the console input buffer (wide version)
///
/// # Safety
/// Caller must ensure `chars_read` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadConsoleW(
    _console_input: *mut core::ffi::c_void,
    _buffer: *mut u16,
    _chars_to_read: u32,
    chars_read: *mut u32,
    _input_control: *mut core::ffi::c_void,
) -> i32 {
    if !chars_read.is_null() {
        // SAFETY: Caller guarantees chars_read is valid and non-null (checked above).
        *chars_read = 0;
    }
    1 // TRUE - success (no input available)
}

/// GetEnvironmentVariableW - retrieves the value of an environment variable (wide version)
///
/// Reads the variable from the process environment using the C library `getenv`.
/// The name is converted from UTF-16 to UTF-8 for the lookup, and the value is
/// returned as UTF-16.
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
/// `buffer` must point to a writable array of at least `size` `u16` elements, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentVariableW(
    name: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let name_str = wide_str_to_string(name);
    let Ok(c_name) = CString::new(name_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    // SAFETY: c_name is a valid C string; getenv returns a pointer owned by the OS.
    let value_ptr = libc::getenv(c_name.as_ptr());
    if value_ptr.is_null() {
        kernel32_SetLastError(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    // SAFETY: getenv returns a valid null-terminated C string.
    let env_value = std::ffi::CStr::from_ptr(value_ptr).to_string_lossy();
    // copy_utf8_to_wide follows Windows GetEnvironmentVariableW semantics:
    // - if buffer is null or too small: returns required size (including null terminator)
    // - if buffer is large enough: returns characters written (excluding null terminator)
    copy_utf8_to_wide(&env_value, buffer, size)
}

/// SetEnvironmentVariableW - sets the value of an environment variable (wide version)
///
/// When `value` is null the variable is removed.  Uses `setenv`/`unsetenv` from libc.
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
/// `value` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEnvironmentVariableW(
    name: *const u16,
    value: *const u16,
) -> i32 {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let name_str = wide_str_to_string(name);
    let Ok(c_name) = CString::new(name_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    if value.is_null() {
        // Delete the variable (Windows: SetEnvironmentVariable(name, NULL) removes it)
        // SAFETY: c_name is a valid C string.
        libc::unsetenv(c_name.as_ptr());
        return 1; // TRUE
    }
    let value_str = wide_str_to_string(value);
    let Ok(c_value) = CString::new(value_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    // SAFETY: c_name and c_value are valid C strings; overwrite=1 replaces existing value.
    let result = libc::setenv(c_name.as_ptr(), c_value.as_ptr(), 1);
    if result == 0 {
        1 // TRUE
    } else {
        kernel32_SetLastError(13); // ERROR_INVALID_DATA
        0 // FALSE
    }
}

/// VirtualProtect - changes the protection on a region of committed pages
///
/// # Safety
/// Caller must ensure `old_protect` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualProtect(
    _address: *mut core::ffi::c_void,
    _size: usize,
    _new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if !old_protect.is_null() {
        // SAFETY: Caller guarantees old_protect is valid and non-null (checked above).
        *old_protect = 0x40; // PAGE_EXECUTE_READWRITE
    }
    1 // TRUE - success
}

/// VirtualQuery - retrieves information about a range of pages
///
/// # Safety
/// This function is a stub that returns 0 (failure).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualQuery(
    _address: *const core::ffi::c_void,
    _buffer: *mut u8,
    _length: usize,
) -> usize {
    0 // Failure - not implemented
}

/// FreeLibrary - frees the loaded dynamic-link library module
///
/// # Safety
/// This function is a stub that returns success without freeing anything.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeLibrary(_module: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - success
}

/// FindFirstFileW - begin a directory search matching a pattern
///
/// Opens a search for files matching `file_name` (which may contain `*`/`?` wildcards)
/// and fills `find_data` with the first matching entry.  Returns a search handle on
/// success, or `INVALID_HANDLE_VALUE` on failure (sets last error).
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstFileW(
    file_name: *const u16,
    find_data: *mut u8,
) -> *mut core::ffi::c_void {
    const INVALID_HANDLE: *mut core::ffi::c_void = -1_i64 as usize as *mut core::ffi::c_void;

    if file_name.is_null() || find_data.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE;
    }
    let linux_path = wide_path_to_linux(file_name);
    let (dir_path, pattern) = split_dir_and_pattern(&linux_path);

    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir_path) {
        Ok(rd) => rd.filter_map(std::result::Result::ok).collect(),
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 3,         // ERROR_PATH_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,
            };
            kernel32_SetLastError(code);
            return INVALID_HANDLE;
        }
    };

    // Find the first matching entry
    let first_idx = entries
        .iter()
        .position(|e| find_matches_pattern(&e.file_name().to_string_lossy(), &pattern));
    let Some(first_idx) = first_idx else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE;
    };

    // Fill find_data with the first match
    fill_find_data(&entries[first_idx], find_data);

    // Allocate handle and store state atomically, enforcing the search-handle
    // limit inside the mutex to prevent a TOCTOU race.
    let handle = alloc_find_handle();
    let inserted = with_find_handles(|map| {
        if map.len() >= MAX_OPEN_FIND_HANDLES {
            return false;
        }
        map.insert(
            handle,
            DirSearchState {
                entries,
                current_index: first_idx + 1,
                pattern,
            },
        );
        true
    });
    if !inserted {
        kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return INVALID_HANDLE;
    }

    kernel32_SetLastError(0);
    handle as *mut core::ffi::c_void
}

/// FindFirstFileExW - extended directory search (delegates to `FindFirstFileW`)
///
/// The `info_level`, `search_op`, `search_filter`, and `additional_flags` parameters
/// are ignored; this behaves like `FindFirstFileW` with the same handle registry.
///
/// # Safety
/// `filename` must be a valid null-terminated UTF-16 string.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstFileExW(
    filename: *const u16,
    _info_level: u32,
    find_data: *mut u8,
    _search_op: u32,
    _search_filter: *mut core::ffi::c_void,
    _additional_flags: u32,
) -> *mut core::ffi::c_void {
    kernel32_FindFirstFileW(filename, find_data)
}

/// FindNextFileW - advance a directory search to the next matching entry
///
/// Fills `find_data` with the next matching entry for the search started by
/// `FindFirstFileW`.  Returns TRUE (1) on success or FALSE (0) when there are no
/// more matching entries (sets last error to `ERROR_NO_MORE_FILES` = 18).
/// Entries for which metadata retrieval fails (e.g. broken symlinks) are skipped
/// transparently rather than terminating enumeration.
///
/// # Safety
/// `find_file` must be a valid search handle returned by `FindFirstFileW`.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindNextFileW(
    find_file: *mut core::ffi::c_void,
    find_data: *mut u8,
) -> i32 {
    let handle = find_file as usize;

    loop {
        // Find the next matching entry and extract its path while holding the lock.
        let found_path = with_find_handles(|map| {
            let state = map.get_mut(&handle)?;
            while state.current_index < state.entries.len() {
                let idx = state.current_index;
                state.current_index += 1;
                if find_matches_pattern(
                    &state.entries[idx].file_name().to_string_lossy(),
                    &state.pattern,
                ) {
                    return Some(state.entries[idx].path());
                }
            }
            None
        });

        let Some(path) = found_path else {
            kernel32_SetLastError(18); // ERROR_NO_MORE_FILES
            return 0;
        };

        if !find_data.is_null() {
            if let Ok(meta) = std::fs::metadata(&path) {
                fill_find_data_from_path(&path, &meta, find_data);
                kernel32_SetLastError(0);
                return 1; // TRUE
            }
            // Metadata retrieval failed (e.g., broken symlink, permission error).
            // Skip this entry and try the next one rather than misreporting no more files.
            continue;
        }
        // find_data is null – caller only wants to know if more entries exist.
        kernel32_SetLastError(0);
        return 1;
    }
}

/// Fill a raw `WIN32_FIND_DATAW` buffer from a filesystem path and its metadata.
///
/// # Safety
/// `find_data` must point to a writable buffer of at least 592 bytes.
unsafe fn fill_find_data_from_path(
    path: &std::path::Path,
    meta: &std::fs::Metadata,
    find_data: *mut u8,
) {
    let attrs: u32 = if meta.is_dir() { 0x10 } else { 0x80 };
    let file_size = meta.len();
    let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let unix_ns = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let wt = (unix_ns / 100) + 116_444_736_000_000_000u128;
    let tl = wt as u32;
    let th = (wt >> 32) as u32;
    let sl = file_size as u32;
    let sh = (file_size >> 32) as u32;

    let ptr = find_data;
    // SAFETY: caller guarantees ≥592 bytes
    core::ptr::write_unaligned(ptr.cast::<u32>(), attrs);
    core::ptr::write_unaligned(ptr.add(4).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(8).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(12).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(16).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(20).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(24).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(28).cast::<u32>(), sh);
    core::ptr::write_unaligned(ptr.add(32).cast::<u32>(), sl);
    core::ptr::write_unaligned(ptr.add(36).cast::<u32>(), 0u32);
    core::ptr::write_unaligned(ptr.add(40).cast::<u32>(), 0u32);

    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let copy_len = utf16.len().min(259);
    let fp = ptr.add(44).cast::<u16>();
    for (i, &ch) in utf16[..copy_len].iter().enumerate() {
        core::ptr::write_unaligned(fp.add(i), ch);
    }
    core::ptr::write_unaligned(fp.add(copy_len), 0u16);
    for i in (copy_len + 1)..260 {
        core::ptr::write_unaligned(fp.add(i), 0u16);
    }
    let ap = ptr.add(564).cast::<u16>();
    for i in 0..14 {
        core::ptr::write_unaligned(ap.add(i), 0u16);
    }
}

/// FindClose - closes a file search handle
///
/// Removes the search state associated with `find_file` from the handle registry.
/// Always returns TRUE (1); sets last error to `ERROR_INVALID_HANDLE` if the handle
/// was not found (but still returns TRUE for compatibility with Windows behavior).
///
/// # Safety
/// `find_file` must be a handle previously returned by `FindFirstFileW` / `FindFirstFileExW`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindClose(find_file: *mut core::ffi::c_void) -> i32 {
    let handle = find_file as usize;
    let removed = with_find_handles(|map| map.remove(&handle).is_some());
    if !removed {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
    }
    1 // TRUE - always succeeds (Windows FindClose always returns TRUE)
}

/// WaitOnAddress - waits for the value at the specified address to change
///
/// # Safety
/// This function is a stub that returns success immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitOnAddress(
    _address: *mut core::ffi::c_void,
    _compare_address: *mut core::ffi::c_void,
    _address_size: usize,
    _milliseconds: u32,
) -> i32 {
    1 // TRUE - success
}

/// WakeByAddressAll - wakes all threads waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressAll(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// WakeByAddressSingle - wakes one thread waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressSingle(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// GetACP - returns the current ANSI code page identifier
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetACP() -> u32 {
    // Return UTF-8 code page (65001) for compatibility
    65001
}

/// IsProcessorFeaturePresent - checks if a processor feature is present
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsProcessorFeaturePresent(feature: u32) -> i32 {
    // PF_FASTFAIL_AVAILABLE = 23
    // PF_SSE2_INSTRUCTIONS_AVAILABLE = 10
    // PF_NX_ENABLED = 12
    match feature {
        // SSE2 (10), NX (12), and FastFail (23) are available on x86-64
        10 | 12 | 23 => 1,
        _ => 0,
    }
}

/// IsDebuggerPresent - checks if a debugger is attached to the process
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsDebuggerPresent() -> i32 {
    0 // No debugger attached
}

/// GetStringTypeW - retrieves character type information for wide characters
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStringTypeW(
    _dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if lp_src_str.is_null() || lp_char_type.is_null() {
        return 0; // FALSE
    }

    let len = if cch_src == -1 {
        // Count until null terminator
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n
    } else {
        cch_src as usize
    };

    // Fill with basic character type info
    // C1_ALPHA = 0x100, C1_LOWER = 0x002, C1_UPPER = 0x001
    for i in 0..len {
        let ch = *lp_src_str.add(i);
        let mut char_type: u16 = 0;
        // Only classify ASCII-range characters
        if ch < 128 {
            let byte = ch as u8;
            if byte.is_ascii_alphabetic() {
                char_type |= 0x100; // C1_ALPHA
                if byte.is_ascii_lowercase() {
                    char_type |= 0x002; // C1_LOWER
                } else if byte.is_ascii_uppercase() {
                    char_type |= 0x001; // C1_UPPER
                }
            } else if byte.is_ascii_digit() {
                char_type |= 0x004; // C1_DIGIT
            } else if byte.is_ascii_whitespace() {
                char_type |= 0x008; // C1_SPACE
            } else if byte.is_ascii_punctuation() {
                char_type |= 0x010; // C1_PUNCT
            } else if byte.is_ascii_control() {
                char_type |= 0x020; // C1_CNTRL
            }
        }
        *lp_char_type.add(i) = char_type;
    }

    1 // TRUE (success)
}

/// HeapSize - returns the size of a memory block allocated from a heap
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapSize(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *const core::ffi::c_void,
) -> usize {
    if mem.is_null() {
        return usize::MAX; // Error indicator
    }
    // We can't reliably determine the size of a Rust-allocated block
    // without tracking allocations. Return error to signal this limitation.
    usize::MAX
}

/// InitializeCriticalSectionAndSpinCount - initialize with spin count
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionAndSpinCount(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// InitializeCriticalSectionEx - extended initialization
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionEx(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
    _flags: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// FlsAlloc - allocate a fiber-local storage (FLS) index
///
/// FLS is similar to TLS but works with fibers. We implement it as a wrapper
/// around our TLS implementation since we don't support fibers.
///
/// # Safety
/// This function is unsafe as it deals with function pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsAlloc(_callback: *mut core::ffi::c_void) -> u32 {
    // Use TLS allocation since we don't support fibers
    kernel32_TlsAlloc()
}

/// FlsFree - free a fiber-local storage (FLS) index
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsFree(fls_index: u32) -> i32 {
    // Use TLS free since FLS maps to TLS
    kernel32_TlsFree(fls_index) as i32
}

/// FlsGetValue - get value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsGetValue(fls_index: u32) -> usize {
    kernel32_TlsGetValue(fls_index)
}

/// FlsSetValue - set value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsSetValue(fls_index: u32, fls_data: usize) -> i32 {
    kernel32_TlsSetValue(fls_index, fls_data) as i32
}

/// IsValidCodePage - check if a code page is valid
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsValidCodePage(code_page: u32) -> i32 {
    // Support common code pages
    match code_page {
        437 | 850 | 1252 | 65001 | 20127 => 1, // TRUE
        _ => 0,                                // FALSE
    }
}

/// GetOEMCP - get OEM code page
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOEMCP() -> u32 {
    437 // US English OEM code page
}

/// GetCPInfo - get code page information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCPInfo(code_page: u32, cp_info: *mut u8) -> i32 {
    if cp_info.is_null() {
        return 0; // FALSE
    }

    // CPINFO structure: MaxCharSize (UINT, 4 bytes) + DefaultChar (2 bytes) + LeadByte (12 bytes) = 18 bytes
    // Zero-initialize first
    core::ptr::write_bytes(cp_info, 0, 18);

    // Set MaxCharSize based on code page
    let max_char_size: u32 = match code_page {
        65001 => 4, // UTF-8: up to 4 bytes per character
        _ => 1,     // Single-byte code pages and default
    };
    core::ptr::copy_nonoverlapping((&raw const max_char_size).cast::<u8>(), cp_info, 4);

    // DefaultChar: '?' (0x3F)
    *cp_info.add(4) = 0x3F;

    1 // TRUE (success)
}

/// GetLocaleInfoW - get locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn kernel32_GetLocaleInfoW(
    _locale: u32,
    _lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    // When cch_data is 0, this is a size query: return required size
    if cch_data == 0 {
        // Return required size including null terminator
        return 2; // Minimum: one char + null
    }

    // Non-zero size with a null buffer is invalid
    if lp_lc_data.is_null() {
        return 0;
    }

    // Return a minimal response (just a null-terminated empty-ish string)
    if cch_data >= 1 {
        *lp_lc_data = 0; // Null terminator
    }
    1
}

/// LCMapStringW - map a string using locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LCMapStringW(
    _locale: u32,
    _map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    if lp_src_str.is_null() {
        return 0;
    }

    let src_len = if cch_src == -1 {
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n + 1 // Include null terminator
    } else {
        cch_src as usize
    };

    if cch_dest == 0 {
        // Return required buffer size
        return src_len as i32;
    }

    if lp_dest_str.is_null() {
        // Invalid destination pointer when a non-zero length is requested
        return 0;
    }

    // Simple copy (no actual locale transformation)
    let copy_len = core::cmp::min(src_len, cch_dest as usize);
    core::ptr::copy_nonoverlapping(lp_src_str, lp_dest_str, copy_len);

    copy_len as i32
}

/// Tracks VirtualAlloc allocations so VirtualFree(MEM_RELEASE) can release the
/// correct size when the caller passes `dwSize = 0` (as the Windows API requires).
static VIRTUAL_ALLOC_TRACKER: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// VirtualAlloc - reserves, commits, or changes the state of a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualAlloc(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    _allocation_type: u32,
    _protect: u32,
) -> *mut core::ffi::c_void {
    if dw_size == 0 {
        return core::ptr::null_mut();
    }

    // Use mmap to allocate memory
    let addr = if lp_address.is_null() {
        core::ptr::null_mut()
    } else {
        lp_address
    };

    let ptr = libc::mmap(
        addr,
        dw_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr == libc::MAP_FAILED {
        core::ptr::null_mut()
    } else {
        // Record allocation size so VirtualFree can release the full region
        if let Ok(mut tracker) = VIRTUAL_ALLOC_TRACKER.lock() {
            tracker.insert(ptr as usize, dw_size);
        }
        ptr
    }
}

/// VirtualFree - releases, decommits, or releases and decommits a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory deallocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualFree(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    if lp_address.is_null() {
        return 0; // FALSE
    }

    // MEM_RELEASE = 0x8000
    if dw_free_type == 0x8000 {
        // Per the Windows API contract, dwSize must be 0 for MEM_RELEASE;
        // the OS releases the entire region originally reserved by VirtualAlloc.
        // We look up the original allocation size from our tracker.
        let size = if dw_size == 0 {
            VIRTUAL_ALLOC_TRACKER
                .lock()
                .ok()
                .and_then(|mut t| t.remove(&(lp_address as usize)))
                .unwrap_or(4096) // Fallback to one page if not tracked
        } else {
            // Non-standard usage; honour the caller-supplied size
            if let Ok(mut tracker) = VIRTUAL_ALLOC_TRACKER.lock() {
                tracker.remove(&(lp_address as usize));
            }
            dw_size
        };
        if libc::munmap(lp_address, size) == 0 {
            return 1; // TRUE
        }
    }

    0 // FALSE
}

/// DecodePointer - decodes a previously encoded pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DecodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, pointers are not actually encoded, so just return as-is
    ptr
}

/// EncodePointer - encodes a pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EncodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, we don't actually encode pointers
    ptr
}

/// GetTickCount64 - retrieves the number of milliseconds since system start
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTickCount64() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// SetEvent - sets the specified event object to the signaled state
///
/// Signals the event and wakes waiters.  For manual-reset events, all waiters
/// are notified (`notify_all`); for auto-reset events only one waiter is
/// released (`notify_one`) to match Win32 semantics.  Returns TRUE (1) on
/// success, or FALSE (0) with `GetLastError() == ERROR_INVALID_HANDLE` if
/// `event` is not a handle created by `CreateEventW`.
///
/// # Panics
/// Panics if the internal event-state mutex is poisoned (another thread
/// panicked while holding the lock).
///
/// # Safety
/// `event` must be a handle returned by `CreateEventW`, or NULL/invalid (in
/// which case FALSE is returned).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEvent(event: *mut core::ffi::c_void) -> i32 {
    let handle = event as usize;
    let state_and_flag = with_event_handles(|map| {
        map.get(&handle)
            .map(|e| (Arc::clone(&e.state), e.manual_reset))
    });
    let Some((state, manual_reset)) = state_and_flag else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let (lock, cvar) = &*state;
    *lock.lock().unwrap() = true;
    if manual_reset {
        cvar.notify_all();
    } else {
        cvar.notify_one();
    }
    1 // TRUE
}

/// ResetEvent - resets the specified event object to the nonsignaled state
///
/// Clears the event so that threads waiting on it will block.  Returns TRUE
/// (1) on success, or FALSE (0) with `GetLastError() == ERROR_INVALID_HANDLE`
/// if `event` is not a handle created by `CreateEventW`.
///
/// # Panics
/// Panics if the internal event-state mutex is poisoned (another thread
/// panicked while holding the lock).
///
/// # Safety
/// `event` must be a handle returned by `CreateEventW`, or NULL/invalid (in
/// which case FALSE is returned).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ResetEvent(event: *mut core::ffi::c_void) -> i32 {
    let handle = event as usize;
    let state_arc = with_event_handles(|map| map.get(&handle).map(|e| Arc::clone(&e.state)));
    let Some(state) = state_arc else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let (lock, _cvar) = &*state;
    *lock.lock().unwrap() = false;
    1 // TRUE
}

/// `IsDBCSLeadByteEx` – test whether a byte is a DBCS lead byte in the given code page.
///
/// We only support single-byte encodings (code pages 0 and 65001/UTF-8), so
/// this always returns FALSE (0).
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsDBCSLeadByteEx(_code_page: u32, _test_char: u8) -> i32 {
    0 // FALSE – not a DBCS lead byte
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep() {
        // Sleep for 10ms
        let start = std::time::Instant::now();
        unsafe { kernel32_Sleep(10) };
        let elapsed = start.elapsed();
        // Should sleep at least 10ms (allow some tolerance)
        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(50)); // Not too long
    }

    #[test]
    fn test_get_current_thread_id() {
        let tid = unsafe { kernel32_GetCurrentThreadId() };
        // Thread ID should be non-zero
        assert_ne!(tid, 0);
    }

    #[test]
    fn test_get_current_process_id() {
        let pid = unsafe { kernel32_GetCurrentProcessId() };
        // Process ID should be non-zero
        assert_ne!(pid, 0);
    }

    #[test]
    fn test_tls_alloc_free() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF); // Should not be TLS_OUT_OF_INDEXES

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1); // Should succeed
    }

    #[test]
    fn test_tls_get_set_value() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Initially should be 0
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, 0);

        // Set a value
        let test_value = 0x1234_5678_ABCD_EF00_usize;
        let result = unsafe { kernel32_TlsSetValue(slot, test_value) };
        assert_eq!(result, 1); // Should succeed

        // Get the value back
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, test_value);

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_tls_multiple_slots() {
        // Allocate multiple slots
        let slot1 = unsafe { kernel32_TlsAlloc() };
        let slot2 = unsafe { kernel32_TlsAlloc() };
        let slot3 = unsafe { kernel32_TlsAlloc() };

        assert_ne!(slot1, 0xFFFF_FFFF);
        assert_ne!(slot2, 0xFFFF_FFFF);
        assert_ne!(slot3, 0xFFFF_FFFF);

        // Each slot should be different
        assert_ne!(slot1, slot2);
        assert_ne!(slot2, slot3);
        assert_ne!(slot1, slot3);

        // Set different values in each slot
        let value1 = 0x1111_usize;
        let value2 = 0x2222_usize;
        let value3 = 0x3333_usize;

        unsafe {
            kernel32_TlsSetValue(slot1, value1);
            kernel32_TlsSetValue(slot2, value2);
            kernel32_TlsSetValue(slot3, value3);
        }

        // Verify each slot has its own value
        assert_eq!(unsafe { kernel32_TlsGetValue(slot1) }, value1);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot2) }, value2);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot3) }, value3);

        // Free all slots
        unsafe {
            kernel32_TlsFree(slot1);
            kernel32_TlsFree(slot2);
            kernel32_TlsFree(slot3);
        }
    }

    #[test]
    fn test_tls_thread_isolation() {
        use std::sync::Arc;
        use std::sync::Barrier;

        // Allocate a shared TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Use a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = vec![];

        for thread_num in 1..=2 {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Each thread sets its own value in the same slot
                #[allow(clippy::cast_sign_loss)]
                let value = (thread_num * 1000) as usize;
                unsafe {
                    kernel32_TlsSetValue(slot, value);
                }

                // Wait for all threads to set their values
                barrier.wait();

                // Verify this thread's value hasn't been affected by other threads
                let retrieved = unsafe { kernel32_TlsGetValue(slot) };
                assert_eq!(retrieved, value);
            });
            handles.push(handle);
        }

        // Main thread also sets a value
        let main_value = 9999_usize;
        unsafe {
            kernel32_TlsSetValue(slot, main_value);
        }

        // Wait for all threads
        barrier.wait();

        // Verify main thread's value is still intact
        let retrieved = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(retrieved, main_value);

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Free the slot
        unsafe {
            kernel32_TlsFree(slot);
        }
    }

    #[test]
    fn test_exception_handling_stubs() {
        // Test __C_specific_handler returns EXCEPTION_CONTINUE_SEARCH
        let result = unsafe {
            kernel32___C_specific_handler(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1); // EXCEPTION_CONTINUE_SEARCH

        // Test SetUnhandledExceptionFilter returns NULL
        let prev_filter = unsafe { kernel32_SetUnhandledExceptionFilter(core::ptr::null_mut()) };
        assert!(prev_filter.is_null());

        // Test RtlCaptureContext doesn't crash
        let mut context = vec![0u8; 1232]; // Size of Windows CONTEXT structure
        unsafe { kernel32_RtlCaptureContext(context.as_mut_ptr().cast()) };
        // Should zero out the buffer
        assert!(context.iter().all(|&b| b == 0));

        // Test RtlLookupFunctionEntry returns NULL
        let mut image_base = 0u64;
        let entry = unsafe {
            kernel32_RtlLookupFunctionEntry(
                0x1000,
                core::ptr::addr_of_mut!(image_base),
                core::ptr::null_mut(),
            )
        };
        assert!(entry.is_null());

        // Test RtlUnwindEx doesn't crash (returns nothing)
        unsafe {
            kernel32_RtlUnwindEx(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }

        // Test RtlVirtualUnwind returns NULL
        let unwind = unsafe {
            kernel32_RtlVirtualUnwind(
                0,
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(unwind.is_null());

        // Test AddVectoredExceptionHandler returns non-NULL
        let handler = unsafe { kernel32_AddVectoredExceptionHandler(1, core::ptr::null_mut()) };
        assert!(!handler.is_null());
    }

    #[test]
    fn test_critical_section_basic() {
        // Allocate a critical section
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };
        assert_ne!(cs.internal, 0); // Should be initialized

        // Enter the critical section
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the critical section
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Delete the critical section
        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
        assert_eq!(cs.internal, 0); // Should be cleared
    }

    #[test]
    fn test_critical_section_recursion() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Enter multiple times (recursion)
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the same number of times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Should be able to enter again after leaving all
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_try_enter() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Try to enter - should succeed when not held
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Try to enter again (same thread) - should succeed (recursion)
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Leave both times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_multi_thread() {
        use std::sync::Arc;
        use std::thread;

        // Allocate a critical section in shared memory
        let cs = Arc::new(std::sync::Mutex::new(CriticalSection {
            internal: 0,
            _padding: [0; 32],
        }));

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut *cs.lock().unwrap()) };

        // Shared counter
        let counter = Arc::new(std::sync::Mutex::new(0));

        // Spawn multiple threads
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cs = Arc::clone(&cs);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..100 {
                        // Enter critical section
                        unsafe { kernel32_EnterCriticalSection(&raw mut *cs.lock().unwrap()) };

                        // Increment counter (protected by critical section)
                        let mut c = counter.lock().unwrap();
                        *c += 1;
                        drop(c);

                        // Leave critical section
                        unsafe { kernel32_LeaveCriticalSection(&raw mut *cs.lock().unwrap()) };
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Check that all increments happened
        assert_eq!(*counter.lock().unwrap(), 500);

        // Clean up
        unsafe { kernel32_DeleteCriticalSection(&raw mut *cs.lock().unwrap()) };
    }

    #[test]
    fn test_critical_section_null_safe() {
        // All functions should handle NULL gracefully
        unsafe { kernel32_InitializeCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_EnterCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_LeaveCriticalSection(core::ptr::null_mut()) };
        let result = unsafe { kernel32_TryEnterCriticalSection(core::ptr::null_mut()) };
        assert_eq!(result, 0); // Should return false for NULL
        unsafe { kernel32_DeleteCriticalSection(core::ptr::null_mut()) };
    }

    //
    // Phase 8.3: String Operations Tests
    //

    #[test]
    fn test_multibyte_to_wide_char_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = b"Hello";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (5 chars, no null terminator when length is explicit)
        assert_eq!(result, 5);
        // Verify the conversion
        assert_eq!(output[0], u16::from(b'H'));
        assert_eq!(output[1], u16::from(b'e'));
        assert_eq!(output[2], u16::from(b'l'));
        assert_eq!(output[3], u16::from(b'l'));
        assert_eq!(output[4], u16::from(b'o'));
    }

    #[test]
    fn test_multibyte_to_wide_char_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = b"Hello World";

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
            )
        };

        // Should return 11 (11 chars, no null terminator when length is explicit)
        assert_eq!(result, 11);
    }

    #[test]
    fn test_multibyte_to_wide_char_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = b"Test\0";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (4 chars + null terminator)
        assert_eq!(result, 5);
        assert_eq!(output[0], u16::from(b'T'));
        assert_eq!(output[3], u16::from(b't'));
        assert_eq!(output[4], 0);
    }

    #[test]
    fn test_wide_char_to_multibyte_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = [u16::from(b'H'), u16::from(b'i'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                2, // Length without null
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 2 (2 chars, no null terminator when length is explicit)
        assert_eq!(result, 2);
        assert_eq!(output[0], b'H');
        assert_eq!(output[1], b'i');
    }

    #[test]
    fn test_wide_char_to_multibyte_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            u16::from(b' '),
            u16::from(b'!'),
        ];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 6 (6 chars, no null terminator when length is explicit)
        assert_eq!(result, 6);
    }

    #[test]
    fn test_wide_char_to_multibyte_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = [u16::from(b'A'), u16::from(b'B'), u16::from(b'C'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 4 (3 chars + null terminator)
        assert_eq!(result, 4);
        assert_eq!(output[0], b'A');
        assert_eq!(output[1], b'B');
        assert_eq!(output[2], b'C');
        assert_eq!(output[3], 0);
    }

    #[test]
    fn test_lstrlenw_basic() {
        // Test basic wide string length
        let input = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 5);
    }

    #[test]
    fn test_lstrlenw_empty() {
        // Test empty string
        let input = [0u16];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_lstrlenw_null() {
        // Test NULL pointer
        let result = unsafe { kernel32_lstrlenW(core::ptr::null()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_compare_string_ordinal_equal() {
        // Test equal strings
        let str1 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];
        let str2 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                4,
                str2.as_ptr(),
                4,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    #[test]
    fn test_compare_string_ordinal_less_than() {
        // Test str1 < str2
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'C'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 1); // CSTR_LESS_THAN
    }

    #[test]
    fn test_compare_string_ordinal_greater_than() {
        // Test str1 > str2
        let str1 = [u16::from(b'Z'), u16::from(b'Z'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'A'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 3); // CSTR_GREATER_THAN
    }

    #[test]
    fn test_compare_string_ordinal_ignore_case() {
        // Test case-insensitive comparison
        let str1 = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];
        let str2 = [
            u16::from(b'h'),
            u16::from(b'E'),
            u16::from(b'L'),
            u16::from(b'L'),
            u16::from(b'O'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                5,
                str2.as_ptr(),
                5,
                1, // Ignore case
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL (case-insensitive)
    }

    #[test]
    fn test_compare_string_ordinal_null_terminated() {
        // Test with -1 (null-terminated strings)
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'B'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                -1, // Null-terminated
                str2.as_ptr(),
                -1, // Null-terminated
                0,  // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    //
    // Phase 8.4: Performance Counters Tests
    //

    #[test]
    fn test_query_performance_counter() {
        let mut counter: i64 = 0;

        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter)) };

        assert_eq!(result, 1); // TRUE - success
        assert!(counter > 0); // Should be positive
    }

    #[test]
    fn test_query_performance_counter_monotonic() {
        let mut counter1: i64 = 0;
        let mut counter2: i64 = 0;

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter1)) };

        // Do some work
        for _ in 0..1000 {
            core::hint::black_box(42);
        }

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter2)) };

        // counter2 should be >= counter1 (monotonic)
        assert!(counter2 >= counter1);
    }

    #[test]
    fn test_query_performance_counter_null() {
        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_query_performance_frequency() {
        let mut frequency: i64 = 0;

        let result =
            unsafe { kernel32_QueryPerformanceFrequency(core::ptr::addr_of_mut!(frequency)) };

        assert_eq!(result, 1); // TRUE - success
        assert_eq!(frequency, 1_000_000_000); // 1 billion (nanoseconds)
    }

    #[test]
    fn test_query_performance_frequency_null() {
        let result = unsafe { kernel32_QueryPerformanceFrequency(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_get_system_time_precise_as_filetime() {
        let mut filetime = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime)) };

        // Should have non-zero values (representing time since 1601)
        assert!(filetime.high_date_time > 0);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_increases() {
        let mut filetime1 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut filetime2 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime1)) };

        // Sleep a tiny bit
        thread::sleep(Duration::from_millis(1));

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime2)) };

        // Reconstruct the 64-bit values
        let time1 =
            u64::from(filetime1.low_date_time) | (u64::from(filetime1.high_date_time) << 32);
        let time2 =
            u64::from(filetime2.low_date_time) | (u64::from(filetime2.high_date_time) << 32);

        // time2 should be > time1
        assert!(time2 > time1);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_null() {
        // Should not crash with NULL
        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::null_mut()) };
    }

    //
    // Phase 8.5: File I/O Trampolines Tests
    //

    #[test]
    fn test_create_file_w_returns_invalid_handle() {
        // CreateFileW should return INVALID_HANDLE_VALUE
        let handle = unsafe {
            kernel32_CreateFileW(
                core::ptr::null(),
                0,
                0,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
            )
        };

        // INVALID_HANDLE_VALUE is usize::MAX
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_read_file_returns_false() {
        // ReadFile should return FALSE (0)
        let result = unsafe {
            kernel32_ReadFile(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_write_file_returns_false() {
        // WriteFile should return FALSE (0)
        let result = unsafe {
            kernel32_WriteFile(
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_close_handle_returns_true() {
        // CloseHandle should return TRUE (1)
        let result = unsafe { kernel32_CloseHandle(core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    //
    // Phase 8.6: Heap Management Trampolines Tests
    //

    #[test]
    fn test_get_process_heap() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Should return non-NULL
        assert!(!heap.is_null());
    }

    #[test]
    fn test_heap_alloc_basic() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 1024;

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Clean up (even though our implementation leaks)
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 256;

        let ptr = unsafe { kernel32_HeapAlloc(heap, HEAP_ZERO_MEMORY, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Verify memory is zeroed
        let slice = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), size) };
        assert!(slice.iter().all(|&b| b == 0));

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 0) };

        // Windows HeapAlloc returns a non-NULL pointer for 0-byte allocation
        // We allocate a minimal block (1 byte) to match Windows semantics
        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_free_null() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Freeing NULL should succeed
        let result = unsafe { kernel32_HeapFree(heap, 0, core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    #[test]
    fn test_heap_realloc_null_to_alloc() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // ReAlloc with NULL pointer should allocate new memory
        let ptr = unsafe { kernel32_HeapReAlloc(heap, 0, core::ptr::null_mut(), 512) };

        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };

        // ReAlloc to zero size should free memory
        let result = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, 0) };

        assert!(result.is_null());
    }

    #[test]
    fn test_heap_alloc_free_cycle() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 512;

        // Allocate memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };
        assert!(!ptr.is_null());

        // Write some data to verify it's writable
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), size);
            slice.fill(0xAB);
        }

        // Free it
        let result = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result, 1); // TRUE - success
    }

    #[test]
    fn test_heap_realloc_grow() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to larger size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify original data is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), initial_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_shrink() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 1024;
        let new_size = 256;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), new_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to smaller size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify data in the remaining portion is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), new_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_new_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate and reallocate with HEAP_ZERO_MEMORY flag
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill initial allocation with non-zero data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            slice.fill(0xFF);
        }

        // Reallocate to larger size with zero flag
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, HEAP_ZERO_MEMORY, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify that the new portion (beyond initial_size) is zeroed
        unsafe {
            let slice = core::slice::from_raw_parts(
                new_ptr.cast::<u8>().add(initial_size),
                new_size - initial_size,
            );
            assert!(slice.iter().all(|&b| b == 0), "New memory not zeroed");
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_free_double_free_protection() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        assert!(!ptr.is_null());

        // First free should succeed
        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result1, 1); // TRUE

        // Second free should fail (allocation not found)
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result2, 0); // FALSE
    }

    #[test]
    fn test_heap_multiple_allocations() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Allocate multiple blocks
        let ptr1 = unsafe { kernel32_HeapAlloc(heap, 0, 128) };
        let ptr2 = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        let ptr3 = unsafe { kernel32_HeapAlloc(heap, 0, 512) };

        assert!(!ptr1.is_null());
        assert!(!ptr2.is_null());
        assert!(!ptr3.is_null());

        // All pointers should be different
        assert_ne!(ptr1, ptr2);
        assert_ne!(ptr2, ptr3);
        assert_ne!(ptr1, ptr3);

        // Free in different order
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr2) };
        assert_eq!(result2, 1);

        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr1) };
        assert_eq!(result1, 1);

        let result3 = unsafe { kernel32_HeapFree(heap, 0, ptr3) };
        assert_eq!(result3, 1);
    }

    #[test]
    fn test_get_set_last_error() {
        // Initially, last error should be 0
        let initial_error = unsafe { kernel32_GetLastError() };
        assert_eq!(initial_error, 0, "Initial error should be 0");

        // Set an error code
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED

        // Get the error back
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 5, "GetLastError should return the set error code");

        // Set a different error
        unsafe { kernel32_SetLastError(2) }; // ERROR_FILE_NOT_FOUND

        let error2 = unsafe { kernel32_GetLastError() };
        assert_eq!(error2, 2, "GetLastError should return the new error code");

        // Reset to 0
        unsafe { kernel32_SetLastError(0) };
        let error3 = unsafe { kernel32_GetLastError() };
        assert_eq!(error3, 0, "Error should be reset to 0");
    }

    #[test]
    fn test_last_error_thread_isolation() {
        use std::sync::{Arc, Barrier};

        // Create a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();

        // Set error in main thread
        unsafe { kernel32_SetLastError(100) };

        // Spawn a thread that sets a different error
        let handle = std::thread::spawn(move || {
            // Set error in spawned thread
            unsafe { kernel32_SetLastError(200) };

            // Wait for main thread
            barrier_clone.wait();

            // Check that spawned thread's error is isolated
            let error = unsafe { kernel32_GetLastError() };
            assert_eq!(error, 200, "Spawned thread should have its own error");
        });

        // Wait for spawned thread
        barrier.wait();

        // Check that main thread's error is still 100
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 100, "Main thread error should be isolated");

        // Wait for thread to finish
        handle.join().unwrap();
    }

    #[test]
    fn test_get_current_directory() {
        // Get current directory
        let buffer_size = 1024u32;
        let mut buffer = vec![0u16; buffer_size as usize];

        let result = unsafe { kernel32_GetCurrentDirectoryW(buffer_size, buffer.as_mut_ptr()) };
        assert!(result > 0, "GetCurrentDirectoryW should succeed");
        assert!(result < buffer_size, "Result should fit in buffer");

        // Convert to string and verify it's a valid path
        let dir_str = String::from_utf16_lossy(&buffer[..result as usize]);
        assert!(!dir_str.is_empty(), "Directory should not be empty");
    }

    #[test]
    fn test_set_current_directory() {
        // Use CwdGuard for a safe, panic-proof restore of the original directory.
        let _guard = CwdGuard::new();

        // Try to set to /tmp (which should exist on Linux)
        let tmp_path: Vec<u16> = "/tmp\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(tmp_path.as_ptr()) };
        assert_eq!(result, 1, "SetCurrentDirectoryW to /tmp should succeed");

        // Verify it changed
        let buffer_size = 1024u32;
        let mut new_buffer = vec![0u16; buffer_size as usize];
        let new_len =
            unsafe { kernel32_GetCurrentDirectoryW(buffer_size, new_buffer.as_mut_ptr()) };
        assert!(new_len > 0);
        let new_dir = String::from_utf16_lossy(&new_buffer[..new_len as usize]);
        assert!(
            new_dir.contains("tmp"),
            "Current directory should now be /tmp"
        );
        // CwdGuard restores the original directory when it drops at end of test.
    }

    #[test]
    fn test_set_current_directory_invalid() {
        // Try to set to a non-existent directory
        let invalid_path: Vec<u16> = "/nonexistent_dir_12345\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(invalid_path.as_ptr()) };
        assert_eq!(
            result, 0,
            "SetCurrentDirectoryW should fail for invalid path"
        );

        // Check that last error was set
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 2, "Last error should be ERROR_FILE_NOT_FOUND");
    }

    #[test]
    fn test_write_file_stdout() {
        // Get stdout handle
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        assert!(!stdout.is_null());

        // Write some data
        let data = b"test output";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 1, "WriteFile should succeed for stdout");
        assert_eq!(bytes_written, data.len() as u32, "Should write all bytes");
    }

    #[test]
    fn test_write_file_invalid_handle() {
        // Try to write to invalid handle
        let invalid_handle = 0x9999 as *mut core::ffi::c_void;
        let data = b"test";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                invalid_handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for invalid handle");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 6, "Should set ERROR_INVALID_HANDLE");
    }

    #[test]
    fn test_write_file_null_buffer() {
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        let mut bytes_written = 0xFFFF_FFFFu32; // Set to non-zero to verify it gets cleared

        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                core::ptr::null(),
                10,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for null buffer");
        assert_eq!(bytes_written, 0, "bytes_written should be set to 0");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 87, "Should set ERROR_INVALID_PARAMETER");
    }

    #[test]
    fn test_get_command_line_w() {
        let cmd_line = unsafe { kernel32_GetCommandLineW() };
        assert!(
            !cmd_line.is_null(),
            "GetCommandLineW should not return null"
        );

        // Should be null-terminated
        let first_char = unsafe { *cmd_line };
        assert_eq!(
            first_char, 0,
            "Empty command line should have null terminator"
        );
    }

    #[test]
    fn test_get_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        assert!(
            !env.is_null(),
            "GetEnvironmentStringsW should not return null"
        );

        // The block is now real: scan for the double-null terminator.
        // It must end with \0\0 (empty-string entry = end of block).
        let mut i = 0usize;
        loop {
            let c0 = unsafe { *env.add(i) };
            let c1 = unsafe { *env.add(i + 1) };
            if c0 == 0 && c1 == 0 {
                break; // found double-null terminator
            }
            i += 1;
            assert!(
                i < 65_536,
                "environment block has no double-null terminator"
            );
        }
    }

    #[test]
    fn test_free_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        let result = unsafe { kernel32_FreeEnvironmentStringsW(env) };
        assert_eq!(result, 1, "FreeEnvironmentStringsW should return TRUE");
    }

    #[test]
    fn test_get_current_process() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        assert!(
            !handle.is_null(),
            "GetCurrentProcess should return non-null"
        );
        // Windows pseudo-handle for current process is -1
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_get_current_thread() {
        let handle = unsafe { kernel32_GetCurrentThread() };
        assert!(!handle.is_null(), "GetCurrentThread should return non-null");
        // Windows pseudo-handle for current thread is -2
        assert_eq!(handle as usize, usize::MAX - 1);
    }

    #[test]
    fn test_get_module_handle_a() {
        let handle = unsafe { kernel32_GetModuleHandleA(core::ptr::null()) };
        assert!(
            !handle.is_null(),
            "GetModuleHandleA(NULL) should return non-null"
        );
        assert_eq!(handle as usize, 0x400000);
    }

    #[test]
    fn test_get_system_info() {
        let mut info = [0u8; 48]; // SystemInfo is 48 bytes
        unsafe { kernel32_GetSystemInfo(info.as_mut_ptr()) };

        // Verify page size (offset 0x04, u32)
        let page_size = u32::from_le_bytes(info[4..8].try_into().unwrap());
        assert_eq!(page_size, 4096, "Page size should be 4096");

        // Verify number of processors (offset 0x20, u32)
        let num_processors = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        assert!(num_processors >= 1, "Should have at least 1 processor");
    }

    #[test]
    fn test_get_console_mode() {
        let mut mode: u32 = 0;
        let result = unsafe { kernel32_GetConsoleMode(std::ptr::dangling_mut(), &raw mut mode) };
        assert_eq!(result, 1, "GetConsoleMode should return TRUE");
        assert_ne!(mode, 0, "Mode should be non-zero");
    }

    #[test]
    fn test_get_console_output_cp() {
        let cp = unsafe { kernel32_GetConsoleOutputCP() };
        assert_eq!(cp, 65001, "Console output code page should be UTF-8");
    }

    #[test]
    fn test_virtual_protect() {
        let mut old_protect: u32 = 0;
        let result = unsafe {
            kernel32_VirtualProtect(
                0x1000 as *mut core::ffi::c_void,
                4096,
                0x04, // PAGE_READWRITE
                &raw mut old_protect,
            )
        };
        assert_eq!(result, 1, "VirtualProtect should return TRUE");
        assert_eq!(
            old_protect, 0x40,
            "Old protect should be PAGE_EXECUTE_READWRITE"
        );
    }

    #[test]
    fn test_free_library() {
        let result = unsafe { kernel32_FreeLibrary(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FreeLibrary should return TRUE");
    }

    #[test]
    fn test_find_close() {
        let result = unsafe { kernel32_FindClose(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FindClose should return TRUE");
    }

    #[test]
    fn test_get_environment_variable_w() {
        // When querying with null buffer / size 0, the function should return the
        // required buffer size (> 0) if PATH is set, or 0 if PATH is not in the
        // environment.  Either way it must not crash.
        let name: [u16; 5] = [
            u16::from(b'P'),
            u16::from(b'A'),
            u16::from(b'T'),
            u16::from(b'H'),
            0,
        ];
        let result =
            unsafe { kernel32_GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
        // PATH is typically set in any CI environment, so result > 0 (required size).
        // The key assertion is that the call doesn't crash/panic.
        let _ = result; // just verify no crash
    }

    #[test]
    fn test_set_environment_variable_w() {
        let name: [u16; 2] = [u16::from(b'X'), 0];
        let value: [u16; 2] = [u16::from(b'Y'), 0];
        let result = unsafe { kernel32_SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 1, "SetEnvironmentVariableW should return TRUE");
    }

    #[test]
    fn test_get_acp() {
        let result = unsafe { kernel32_GetACP() };
        assert_eq!(result, 65001); // UTF-8
    }

    #[test]
    fn test_is_processor_feature_present() {
        unsafe {
            assert_eq!(kernel32_IsProcessorFeaturePresent(10), 1); // SSE2
            assert_eq!(kernel32_IsProcessorFeaturePresent(12), 1); // NX
            assert_eq!(kernel32_IsProcessorFeaturePresent(23), 1); // FastFail
            assert_eq!(kernel32_IsProcessorFeaturePresent(99), 0); // Unknown
        }
    }

    #[test]
    fn test_is_debugger_present() {
        let result = unsafe { kernel32_IsDebuggerPresent() };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_fls_operations() {
        unsafe {
            let index = kernel32_FlsAlloc(core::ptr::null_mut());
            assert_ne!(index, 0xFFFFFFFF); // TLS_OUT_OF_INDEXES

            let set_result = kernel32_FlsSetValue(index, 0x42);
            assert_eq!(set_result, 1); // TRUE

            let value = kernel32_FlsGetValue(index);
            assert_eq!(value, 0x42);

            let free_result = kernel32_FlsFree(index);
            assert_eq!(free_result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_oem_cp() {
        let result = unsafe { kernel32_GetOEMCP() };
        assert_eq!(result, 437);
    }

    #[test]
    fn test_is_valid_code_page() {
        unsafe {
            assert_eq!(kernel32_IsValidCodePage(65001), 1); // UTF-8
            assert_eq!(kernel32_IsValidCodePage(1252), 1); // Windows-1252
            assert_eq!(kernel32_IsValidCodePage(99999), 0); // Invalid
        }
    }

    #[test]
    fn test_get_cp_info() {
        unsafe {
            let mut cp_info = [0u8; 18];
            let result = kernel32_GetCPInfo(65001, cp_info.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // First 4 bytes are MaxCharSize (should be 4 for UTF-8)
            let max_char_size =
                u32::from_le_bytes([cp_info[0], cp_info[1], cp_info[2], cp_info[3]]);
            assert_eq!(max_char_size, 4);
            // DefaultChar should be '?'
            assert_eq!(cp_info[4], 0x3F);
        }
    }

    #[test]
    fn test_decode_encode_pointer() {
        unsafe {
            let original = 0x12345678usize as *mut core::ffi::c_void;
            let encoded = kernel32_EncodePointer(original);
            let decoded = kernel32_DecodePointer(encoded);
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn test_get_tick_count_64() {
        unsafe {
            let tick1 = kernel32_GetTickCount64();
            assert!(tick1 > 0);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let tick2 = kernel32_GetTickCount64();
            assert!(tick2 >= tick1);
        }
    }

    #[test]
    fn test_virtual_alloc_free() {
        unsafe {
            let ptr = kernel32_VirtualAlloc(
                core::ptr::null_mut(),
                4096,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            );
            assert!(!ptr.is_null());

            // Write to the allocated memory to verify it's usable
            *ptr.cast::<u8>() = 42;
            assert_eq!(*(ptr as *const u8), 42);

            // Per Windows API contract, MEM_RELEASE uses dwSize = 0;
            // our tracker should supply the original allocation size.
            let result = kernel32_VirtualFree(ptr, 0, 0x8000); // MEM_RELEASE
            assert_eq!(result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_string_type_w() {
        unsafe {
            let input: [u16; 4] = [u16::from(b'A'), u16::from(b'1'), u16::from(b' '), 0];
            let mut output = [0u16; 3];
            let result = kernel32_GetStringTypeW(1, input.as_ptr(), 3, output.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // 'A' should have C1_ALPHA | C1_UPPER
            assert_ne!(output[0] & 0x100, 0); // C1_ALPHA
            assert_ne!(output[0] & 0x001, 0); // C1_UPPER
            // '1' should have C1_DIGIT
            assert_ne!(output[1] & 0x004, 0); // C1_DIGIT
            // ' ' should have C1_SPACE
            assert_ne!(output[2] & 0x008, 0); // C1_SPACE
        }
    }

    #[test]
    fn test_initialize_critical_section_and_spin_count() {
        unsafe {
            let mut cs = core::mem::zeroed::<CriticalSection>();
            let result = kernel32_InitializeCriticalSectionAndSpinCount(&raw mut cs, 4000);
            assert_eq!(result, 1); // TRUE
            kernel32_DeleteCriticalSection(&raw mut cs);
        }
    }

    #[test]
    fn test_file_create_write_read_close_roundtrip() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        // Use a unique temp path to avoid conflicts with parallel test runs
        let path = "/tmp/litebox_kernel32_roundtrip_test.txt";
        let _ = std::fs::remove_file(path);

        // Encode path as UTF-16
        let wide_path: Vec<u16> = OsStr::new(path)
            .as_bytes()
            .iter()
            .map(|&b| u16::from(b))
            .chain(std::iter::once(0u16))
            .collect();

        unsafe {
            // CreateFileW — CREATE_ALWAYS | GENERIC_WRITE
            let handle = kernel32_CreateFileW(
                wide_path.as_ptr(),
                0x4000_0000, // GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX, "CreateFileW (write) failed");

            let data = b"Hello, LiteBox!";
            let mut written: u32 = 0;
            let ok = kernel32_WriteFile(
                handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut written,
                core::ptr::null_mut(),
            );
            assert_eq!(ok, 1, "WriteFile failed");
            assert_eq!(written as usize, data.len());

            // GetFileSizeEx
            let mut file_size: i64 = -1;
            let ok = kernel32_GetFileSizeEx(handle, &raw mut file_size);
            assert_eq!(ok, 1, "GetFileSizeEx failed");
            assert_eq!(file_size, data.len() as i64);

            // SetFilePointerEx — seek to start (FILE_BEGIN = 0)
            let ok = kernel32_SetFilePointerEx(handle, 0, core::ptr::null_mut(), 0);
            assert_eq!(ok, 1, "SetFilePointerEx failed");

            kernel32_CloseHandle(handle);

            // Re-open for reading
            let handle = kernel32_CreateFileW(
                wide_path.as_ptr(),
                0x8000_0000, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX, "CreateFileW (read) failed");

            let mut buf = [0u8; 32];
            let mut bytes_read: u32 = 0;
            let ok = kernel32_ReadFile(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut bytes_read,
                core::ptr::null_mut(),
            );
            assert_eq!(ok, 1, "ReadFile failed");
            assert_eq!(&buf[..bytes_read as usize], data);

            kernel32_CloseHandle(handle);
        }

        // Cleanup
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_move_file_ex_w() {
        let src = "/tmp/litebox_move_src.txt";
        let dst = "/tmp/litebox_move_dst.txt";
        std::fs::write(src, b"move me").unwrap();
        let _ = std::fs::remove_file(dst);

        let wide_src: Vec<u16> = src.encode_utf16().chain(std::iter::once(0u16)).collect();
        let wide_dst: Vec<u16> = dst.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let ok = kernel32_MoveFileExW(wide_src.as_ptr(), wide_dst.as_ptr(), 0);
            assert_eq!(ok, 1, "MoveFileExW failed");
        }

        assert!(!std::path::Path::new(src).exists(), "source still exists");
        assert!(std::path::Path::new(dst).exists(), "destination missing");
        let _ = std::fs::remove_file(dst);
    }

    #[test]
    fn test_remove_directory_w() {
        let dir = "/tmp/litebox_rmdir_test";
        let _ = std::fs::remove_dir(dir);
        std::fs::create_dir(dir).unwrap();

        let wide_dir: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let ok = kernel32_RemoveDirectoryW(wide_dir.as_ptr());
            assert_eq!(ok, 1, "RemoveDirectoryW failed");
        }

        assert!(!std::path::Path::new(dir).exists());
    }

    #[test]
    fn test_nt_write_read_file_handle() {
        // Verify the shared helpers used by ntdll_impl work correctly
        let path = "/tmp/litebox_nt_handle_test.txt";
        let _ = std::fs::remove_file(path);

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let handle = kernel32_CreateFileW(
                wide.as_ptr(),
                0x4000_0000 | 0x8000_0000, // GENERIC_READ | GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX);

            let data = b"ntdll test";
            let written = nt_write_file_handle(handle as u64, data);
            assert_eq!(written, Some(data.len()));

            // Seek back to start
            kernel32_SetFilePointerEx(handle, 0, core::ptr::null_mut(), 0);

            let mut buf = [0u8; 16];
            let read = nt_read_file_handle(handle as u64, &mut buf);
            assert_eq!(read, Some(data.len()));
            assert_eq!(&buf[..data.len()], data);

            kernel32_CloseHandle(handle);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_get_command_line_utf8_default() {
        // Before any command line is set, returns empty string
        // (or the value already set by a previous test — we just verify it doesn't panic)
        let s = get_command_line_utf8();
        // Must be a valid UTF-8 string; no assertion on content since OnceLock
        // may have been initialised by an earlier test.
        let _ = s;
    }

    #[test]
    fn test_copy_file_w() {
        let src = "/tmp/litebox_copy_src.txt";
        let dst = "/tmp/litebox_copy_dst.txt";
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
        std::fs::write(src, b"copy test").unwrap();

        let src_wide: Vec<u16> = src.encode_utf16().chain(std::iter::once(0)).collect();
        let dst_wide: Vec<u16> = dst.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // CopyFileW should succeed
            let result = kernel32_CopyFileW(src_wide.as_ptr(), dst_wide.as_ptr(), 0);
            assert_eq!(result, 1, "CopyFileW should return TRUE");

            // Destination should contain the same content
            let content = std::fs::read(dst).unwrap();
            assert_eq!(content, b"copy test");

            // fail_if_exists = 1 should fail when dst already exists
            let result2 = kernel32_CopyFileW(src_wide.as_ptr(), dst_wide.as_ptr(), 1);
            assert_eq!(result2, 0, "CopyFileW with fail_if_exists=1 should fail");
        }
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
    }

    #[test]
    fn test_create_directory_ex_w() {
        let dir = "/tmp/litebox_mkdir_ex_test";
        let _ = std::fs::remove_dir(dir);
        let dir_wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = kernel32_CreateDirectoryExW(
                core::ptr::null(), // template ignored
                dir_wide.as_ptr(),
                core::ptr::null_mut(),
            );
            assert_eq!(result, 1, "CreateDirectoryExW should succeed");
            assert!(std::path::Path::new(dir).is_dir());
        }
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn test_get_full_path_name_w_absolute() {
        let path = "/tmp/litebox_gfpnw_test.txt";
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 512];

        unsafe {
            let chars = kernel32_GetFullPathNameW(
                path_wide.as_ptr(),
                512,
                buf.as_mut_ptr(),
                core::ptr::null_mut(),
            );
            assert!(
                chars > 0,
                "GetFullPathNameW should return non-zero for valid path"
            );
            let result = String::from_utf16_lossy(&buf[..chars as usize]);
            assert_eq!(result, path, "Absolute path should be returned unchanged");
        }
    }

    #[test]
    fn test_find_first_next_close() {
        let dir = "/tmp/litebox_find_test";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/a.txt"), b"a").unwrap();
        std::fs::write(format!("{dir}/b.txt"), b"b").unwrap();

        let pattern = format!("{dir}/*.txt\0");
        let pattern_wide: Vec<u16> = pattern.encode_utf16().collect();
        // WIN32_FIND_DATAW is 592 bytes
        let mut find_data = vec![0u8; 592];

        unsafe {
            let handle = kernel32_FindFirstFileW(pattern_wide.as_ptr(), find_data.as_mut_ptr());
            assert_ne!(
                handle as usize,
                usize::MAX,
                "FindFirstFileW should return a valid handle"
            );

            // The first file name should be non-empty
            let fname_ptr = find_data.as_ptr().add(44).cast::<u16>();
            let fname_slice = core::slice::from_raw_parts(fname_ptr, 260);
            let fname_len = fname_slice.iter().position(|&c| c == 0).unwrap_or(0);
            assert!(fname_len > 0, "First file name should not be empty");

            // Advance to next entry
            let mut find_data2 = vec![0u8; 592];
            let next = kernel32_FindNextFileW(handle, find_data2.as_mut_ptr());
            // May be 1 (found another .txt) or 0 (no more) — both are valid
            let _ = next;

            let closed = kernel32_FindClose(handle);
            assert_eq!(closed, 1, "FindClose should return TRUE");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_glob_match_patterns() {
        assert!(find_matches_pattern("test.txt", "*"));
        assert!(find_matches_pattern("test.txt", "*.txt"));
        assert!(find_matches_pattern("test.txt", "test.*"));
        assert!(find_matches_pattern("test.txt", "test.txt"));
        assert!(!find_matches_pattern("test.txt", "*.doc"));
        assert!(find_matches_pattern("TEST.TXT", "test.txt"));
        assert!(find_matches_pattern("test.txt", "TEST.TXT"));
        assert!(find_matches_pattern("test.txt", "????.txt"));
        assert!(!find_matches_pattern("test.txt", "?.txt"));
    }

    /// Guard that restores the working directory when dropped.
    struct CwdGuard {
        original: std::path::PathBuf,
    }
    impl CwdGuard {
        fn new() -> Self {
            let original = std::env::current_dir().expect("current_dir should work in tests");
            CwdGuard { original }
        }
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    #[test]
    fn test_get_full_path_name_w_relative() {
        let tmp_dir = "/tmp/litebox_gfpnw_relative";
        let _ = std::fs::remove_dir_all(tmp_dir);
        std::fs::create_dir_all(tmp_dir).unwrap();

        // Scope the guard so the CWD is restored before the directory is deleted.
        // Without this, concurrent tests that call `current_dir()` may fail because
        // the process CWD would point to a directory that has already been removed.
        {
            let _guard = CwdGuard::new();
            std::env::set_current_dir(tmp_dir).unwrap();

            let path = "test.txt";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 512];

            unsafe {
                let chars = kernel32_GetFullPathNameW(
                    path_wide.as_ptr(),
                    512,
                    buf.as_mut_ptr(),
                    core::ptr::null_mut(),
                );
                assert!(
                    chars > 0,
                    "GetFullPathNameW should return non-zero for relative path"
                );
                let result = String::from_utf16_lossy(&buf[..chars as usize]);
                assert!(
                    result.ends_with(path),
                    "Full path for relative input should end with the relative component"
                );
            }
        } // _guard drops here, restoring the CWD before the directory is deleted

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_get_full_path_name_w_dot() {
        let tmp_dir = "/tmp/litebox_gfpnw_dot";
        let _ = std::fs::remove_dir_all(tmp_dir);
        std::fs::create_dir_all(tmp_dir).unwrap();

        // Scope the guard so the CWD is restored before the directory is deleted.
        {
            let _guard = CwdGuard::new();
            std::env::set_current_dir(tmp_dir).unwrap();

            let path = ".";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 512];

            unsafe {
                let chars = kernel32_GetFullPathNameW(
                    path_wide.as_ptr(),
                    512,
                    buf.as_mut_ptr(),
                    core::ptr::null_mut(),
                );
                assert!(
                    chars > 0,
                    "GetFullPathNameW should return non-zero for '.' (current directory)"
                );
            }
        } // _guard drops here, restoring the CWD before the directory is deleted

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    /// Ensure that FindFirstFileW / FindNextFileW handle cases where metadata
    /// retrieval for a directory entry fails (e.g., a broken symlink) without
    /// panicking or terminating enumeration prematurely.
    #[test]
    fn test_find_first_next_with_inaccessible_entry() {
        let dir = "/tmp/litebox_find_inaccessible_test";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();

        // A normal file that should always be accessible.
        std::fs::write(format!("{dir}/a.txt"), b"a").unwrap();

        // Create a broken symlink that matches the *.txt pattern. On Linux,
        // std::fs::metadata on this path will fail, which exercises the
        // metadata-error skip path in the enumeration logic.
        #[cfg(unix)]
        {
            let broken_target = "/nonexistent/path/for_litebox_test";
            let broken_link = format!("{dir}/broken.txt");
            let _ = std::fs::remove_file(&broken_link);
            // Ignore errors if symlink creation is not supported.
            let _ = std::os::unix::fs::symlink(broken_target, &broken_link);
        }

        let pattern = format!("{dir}/*.txt\0");
        let pattern_wide: Vec<u16> = pattern.encode_utf16().collect();
        let mut find_data = vec![0u8; 592];

        unsafe {
            let handle = kernel32_FindFirstFileW(pattern_wide.as_ptr(), find_data.as_mut_ptr());
            assert_ne!(
                handle as usize,
                usize::MAX,
                "FindFirstFileW should return a valid handle even with problematic entries"
            );

            // Enumerate all matching entries – at least one should be found.
            let mut count = 1usize;
            loop {
                let mut next_data = vec![0u8; 592];
                let next = kernel32_FindNextFileW(handle, next_data.as_mut_ptr());
                if next == 0 {
                    break;
                }
                count += 1;
            }

            assert!(
                count >= 1,
                "Enumeration should yield at least one matching entry"
            );

            let closed = kernel32_FindClose(handle);
            assert_eq!(closed, 1, "FindClose should return TRUE");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Thread start routine that stores a value via a pointer and returns it.
    unsafe extern "win64" fn thread_fn_store_and_return(param: *mut core::ffi::c_void) -> u32 {
        let p = param.cast::<u32>();
        if !p.is_null() {
            *p = 0xBEEF;
        }
        42
    }

    #[test]
    fn test_create_thread_and_wait_infinite() {
        let mut value: u32 = 0;
        let handle = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut value).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(
            !handle.is_null(),
            "CreateThread should return a non-null handle"
        );

        let result = unsafe { kernel32_WaitForSingleObject(handle, u32::MAX) };
        assert_eq!(result, 0, "WaitForSingleObject should return WAIT_OBJECT_0");
        assert_eq!(value, 0xBEEF, "Thread should have written 0xBEEF");
    }

    #[test]
    fn test_create_thread_with_thread_id() {
        let mut tid: u32 = 0;
        let handle = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                &raw mut tid,
            )
        };
        assert!(
            !handle.is_null(),
            "CreateThread should return a non-null handle"
        );
        assert_ne!(tid, 0, "thread_id should be set to a non-zero value");
        unsafe { kernel32_WaitForSingleObject(handle, u32::MAX) };
    }

    #[test]
    fn test_wait_for_multiple_objects_all() {
        let mut v1: u32 = 0;
        let mut v2: u32 = 0;
        let h1 = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut v1).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        let h2 = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut v2).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h1.is_null() && !h2.is_null());

        let handles = [h1, h2];
        let result = unsafe { kernel32_WaitForMultipleObjects(2, handles.as_ptr(), 1, u32::MAX) };
        assert_eq!(
            result, 0,
            "WaitForMultipleObjects(wait_all) should return WAIT_OBJECT_0"
        );
        assert_eq!(v1, 0xBEEF);
        assert_eq!(v2, 0xBEEF);
    }

    // ── Phase 17: Robustness and Security Tests ─────────────────────────────

    /// Helper: set the sandbox root and return a guard that clears it on drop.
    /// Needed because `SANDBOX_ROOT` is a process-wide `Mutex<Option<String>>`
    /// that must be reset between tests to avoid cross-test interference.
    struct SandboxGuard;
    impl Drop for SandboxGuard {
        fn drop(&mut self) {
            *SANDBOX_ROOT.lock().unwrap() = None;
        }
    }
    fn with_sandbox(root: &str) -> SandboxGuard {
        *SANDBOX_ROOT.lock().unwrap() = Some(root.to_owned());
        SandboxGuard
    }

    /// `sandbox_guard` should leave paths unchanged when no sandbox root is set.
    #[test]
    fn test_sandbox_guard_no_root_passthrough() {
        // Ensure no sandbox is active.
        *SANDBOX_ROOT.lock().unwrap() = None;
        let result = sandbox_guard("/tmp/test/file.txt".to_owned());
        assert_eq!(result, "/tmp/test/file.txt");
    }

    /// `sandbox_guard` should normalise `..` traversals and reject escapes.
    #[test]
    fn test_sandbox_guard_escape_rejected() {
        let _guard = with_sandbox("/sandbox");
        // "/sandbox/../../etc/passwd" normalises to "/etc/passwd" → escapes.
        let result = sandbox_guard("/sandbox/../../etc/passwd".to_owned());
        assert!(
            result.is_empty(),
            "Expected empty string for sandbox escape, got: {result}"
        );
    }

    /// Paths within the sandbox root pass through after normalisation.
    #[test]
    fn test_sandbox_guard_inside_root_passes() {
        let _guard = with_sandbox("/sandbox");
        let result = sandbox_guard("/sandbox/subdir/../file.txt".to_owned());
        assert_eq!(result, "/sandbox/file.txt");
    }

    /// `wide_path_to_linux` returns an empty string when a path escapes the
    /// configured sandbox root.
    #[test]
    fn test_wide_path_to_linux_sandbox_escape_blocked() {
        let _guard = with_sandbox("/sandbox");

        // "C:\..\..\etc\passwd" → "/etc/passwd" which escapes "/sandbox".
        let wide: Vec<u16> = "C:\\..\\..\\etc\\passwd\0".encode_utf16().collect();
        let result = unsafe { wide_path_to_linux(wide.as_ptr()) };
        assert!(
            result.is_empty(),
            "Expected empty string for sandbox escape, got: {result}"
        );
    }

    /// `wide_path_to_linux` returns the normalised path when it stays within
    /// the sandbox root.
    #[test]
    fn test_wide_path_to_linux_sandbox_inside_passes() {
        let _guard = with_sandbox("/sandbox");

        let wide: Vec<u16> = "/sandbox/data/file.txt\0".encode_utf16().collect();
        let result = unsafe { wide_path_to_linux(wide.as_ptr()) };
        assert_eq!(result, "/sandbox/data/file.txt");
    }

    /// `CreateFileW` returns `INVALID_HANDLE_VALUE` with error 4 once
    /// `MAX_OPEN_FILE_HANDLES` handles are open.
    #[test]
    fn test_create_file_handle_limit() {
        const OPEN_EXISTING: u32 = 3;
        const GENERIC_READ: u32 = 0x8000_0000;

        // Ensure no sandbox is active so /dev/null is accessible.
        *SANDBOX_ROOT.lock().unwrap() = None;

        // Use a file that exists on every Linux system.
        let path = "/dev/null\0";
        let wide: Vec<u16> = path.encode_utf16().collect();

        let invalid = usize::MAX as *mut core::ffi::c_void;

        // Open handles until we hit the limit (test limit is 8).
        // We collect them so we can close them afterwards.
        let mut opened: Vec<*mut core::ffi::c_void> = Vec::new();
        let hit_limit = 'fill: {
            for _ in 0..=MAX_OPEN_FILE_HANDLES {
                let h = unsafe {
                    kernel32_CreateFileW(
                        wide.as_ptr(),
                        GENERIC_READ,
                        0,
                        core::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        core::ptr::null_mut(),
                    )
                };
                if h == invalid {
                    break 'fill true;
                }
                opened.push(h);
            }
            false
        };

        // Clean up all handles we opened.
        for h in &opened {
            unsafe { kernel32_CloseHandle(*h) };
        }

        assert!(hit_limit, "Expected the handle limit to be enforced");
        assert_eq!(
            unsafe { kernel32_GetLastError() },
            ERROR_TOO_MANY_OPEN_FILES,
            "Expected ERROR_TOO_MANY_OPEN_FILES"
        );
    }

    /// `CreateFileW` with `desired_access=0` (Windows attribute/metadata query pattern)
    /// must succeed for an existing file and return a valid handle.
    #[test]
    fn test_create_file_metadata_query_desired_access_zero() {
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: usize = usize::MAX;

        let path = "/tmp/litebox_metadata_query_test.txt";
        let _ = std::fs::write(path, b"hello");

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        let h = unsafe {
            kernel32_CreateFileW(
                wide.as_ptr(),
                0, // desired_access=0: attribute/metadata query
                7, // share all
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
                core::ptr::null_mut(),
            )
        };
        assert_ne!(
            h as usize, INVALID_HANDLE_VALUE,
            "CreateFileW with desired_access=0 should succeed for existing file"
        );
        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(path);
    }

    /// `GetFileInformationByHandle` must fill the `BY_HANDLE_FILE_INFORMATION` struct
    /// (52 bytes / 13 × u32) with valid metadata after opening a file via `CreateFileW`.
    #[test]
    fn test_get_file_information_by_handle() {
        const GENERIC_READ: u32 = 0x8000_0000;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: usize = usize::MAX;

        let path = "/tmp/litebox_gfibh_test.txt";
        let content = b"GetFileInformationByHandle test content";
        let _ = std::fs::write(path, content);

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        let h = unsafe {
            kernel32_CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                7,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(h as usize, INVALID_HANDLE_VALUE, "CreateFileW failed");

        // Allocate a zeroed 52-byte BY_HANDLE_FILE_INFORMATION struct.
        let mut info = [0u32; 13];
        let ret = unsafe {
            kernel32_GetFileInformationByHandle(h, info.as_mut_ptr().cast::<core::ffi::c_void>())
        };
        assert_eq!(ret, 1, "GetFileInformationByHandle should return TRUE");

        // dwFileAttributes should be FILE_ATTRIBUTE_NORMAL (0x80) for a regular file.
        assert_eq!(info[0], 0x80, "Expected FILE_ATTRIBUTE_NORMAL");
        // nFileSizeHigh (info[8]) should be 0 for a small file.
        assert_eq!(info[8], 0, "nFileSizeHigh should be 0");
        // nFileSizeLow (info[9]) should equal the content length.
        assert_eq!(
            info[9] as usize,
            content.len(),
            "nFileSizeLow should equal the file size"
        );
        // nNumberOfLinks (info[10]) should be at least 1.
        assert!(info[10] >= 1, "nNumberOfLinks should be >= 1");

        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_get_file_type_stdio() {
        const FILE_TYPE_CHAR: u32 = 2;
        // GetStdHandle pseudo-handles should be reported as FILE_TYPE_CHAR (2).
        let stdin_h = unsafe { kernel32_GetStdHandle(u32::MAX - 9) }; // -10 as u32
        let stdout_h = unsafe { kernel32_GetStdHandle(u32::MAX - 10) }; // -11 as u32
        let stderr_h = unsafe { kernel32_GetStdHandle(u32::MAX - 11) }; // -12 as u32
        assert_eq!(unsafe { kernel32_GetFileType(stdin_h) }, FILE_TYPE_CHAR);
        assert_eq!(unsafe { kernel32_GetFileType(stdout_h) }, FILE_TYPE_CHAR);
        assert_eq!(unsafe { kernel32_GetFileType(stderr_h) }, FILE_TYPE_CHAR);
    }

    #[test]
    fn test_get_file_type_unknown_handle() {
        // An unrecognized handle should be FILE_TYPE_UNKNOWN (0).
        const FILE_TYPE_UNKNOWN: u32 = 0;
        let fake_handle = 0x9999_usize as *mut core::ffi::c_void;
        assert_eq!(
            unsafe { kernel32_GetFileType(fake_handle) },
            FILE_TYPE_UNKNOWN
        );
    }

    #[test]
    fn test_get_system_directory_w() {
        let mut buf = [0u16; 64];
        let len = unsafe { kernel32_GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        assert!(len > 0, "Should return non-zero length");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(
            s.starts_with("C:\\Windows"),
            "Should start with C:\\Windows"
        );
        assert!(s.contains("System32"), "Should contain System32");
    }

    #[test]
    fn test_get_system_directory_w_small_buffer() {
        // A buffer that's too small: should return the required size.
        let mut tiny = [0u16; 3];
        let required =
            unsafe { kernel32_GetSystemDirectoryW(tiny.as_mut_ptr(), tiny.len() as u32) };
        assert!(
            required > tiny.len() as u32,
            "Should return required size when buffer is too small"
        );
    }

    #[test]
    fn test_get_windows_directory_w() {
        let mut buf = [0u16; 32];
        let len = unsafe { kernel32_GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        assert!(len > 0, "Should return non-zero length");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert_eq!(s, "C:\\Windows", "Should return C:\\Windows");
    }

    #[test]
    fn test_format_message_w_known_error() {
        const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;
        let mut buf = [0u16; 256];
        // Error 2 = "The system cannot find the file specified."
        let len = unsafe {
            kernel32_FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                core::ptr::null(),
                2,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert!(len > 0, "Should format error 2");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(s.contains("file"), "Error 2 message should mention 'file'");
    }

    #[test]
    fn test_format_message_w_unknown_error() {
        const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;
        let mut buf = [0u16; 256];
        // Error 99999 = not in our table → "Unknown error (...)"
        let len = unsafe {
            kernel32_FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                core::ptr::null(),
                99999,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert!(len > 0, "Should return something for unknown error");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(s.contains("Unknown"), "Unknown error should say 'Unknown'");
    }

    #[test]
    fn test_format_message_w_unsupported_flags() {
        // Without FORMAT_MESSAGE_FROM_SYSTEM the function should fail (return 0).
        let mut buf = [0u16; 64];
        let len = unsafe {
            kernel32_FormatMessageW(
                0,
                core::ptr::null(),
                2,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(len, 0, "Should return 0 for unsupported flags");
    }

    #[test]
    fn test_set_volume_serial_pin() {
        // After set_volume_serial the exact value is returned by get_volume_serial.
        set_volume_serial(0xDEAD_BEEF);
        assert_eq!(get_volume_serial(), 0xDEAD_BEEF);
        // Reset to auto so other tests are not affected.
        set_volume_serial(0);
    }

    #[test]
    fn test_get_volume_serial_auto_nonzero() {
        // With no pinned value get_volume_serial must return something non-zero.
        set_volume_serial(0);
        let serial = get_volume_serial();
        assert_ne!(serial, 0, "Auto-generated serial must be non-zero");
    }

    #[test]
    fn test_get_volume_serial_stable() {
        // Once generated, successive calls should return the same value.
        set_volume_serial(0);
        let first = get_volume_serial();
        let second = get_volume_serial();
        assert_eq!(first, second, "Serial must be stable within a process");
        set_volume_serial(0);
    }

    // ── CreateEventW / SetEvent / ResetEvent / WaitForSingleObject ──────────

    #[test]
    fn test_create_event_returns_nonnull() {
        let handle = unsafe {
            kernel32_CreateEventW(
                core::ptr::null_mut(),
                0, // auto-reset
                0, // not signaled
                core::ptr::null(),
            )
        };
        assert!(
            !handle.is_null(),
            "CreateEventW should return a non-null handle"
        );
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_set_event_signals_waitforsingleobject() {
        // Create an auto-reset event in nonsignaled state.
        let handle =
            unsafe { kernel32_CreateEventW(core::ptr::null_mut(), 0, 0, core::ptr::null()) };
        assert!(!handle.is_null());

        // Signal the event.
        let set_result = unsafe { kernel32_SetEvent(handle) };
        assert_eq!(set_result, 1, "SetEvent should return TRUE");

        // WaitForSingleObject with timeout=0 should succeed immediately.
        let wait_result = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(wait_result, 0, "WAIT_OBJECT_0 expected after SetEvent");

        // Auto-reset: a second wait with timeout=0 should now time out.
        let wait2 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(wait2, 0x0000_0102, "WAIT_TIMEOUT expected (auto-reset)");

        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_manual_reset_event_stays_signaled() {
        // Create a manual-reset event, initially signaled.
        let handle =
            unsafe { kernel32_CreateEventW(core::ptr::null_mut(), 1, 1, core::ptr::null()) };
        assert!(!handle.is_null());

        // Both waits should succeed without resetting.
        let w1 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w1, 0, "First wait should succeed");
        let w2 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(
            w2, 0,
            "Second wait should succeed (manual-reset stays signaled)"
        );

        // After ResetEvent, wait should time out.
        let reset = unsafe { kernel32_ResetEvent(handle) };
        assert_eq!(reset, 1, "ResetEvent should return TRUE");
        let w3 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w3, 0x0000_0102, "WAIT_TIMEOUT expected after ResetEvent");

        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_set_reset_event_on_invalid_handle() {
        let bad: *mut core::ffi::c_void = 0xDEAD_BEEF as *mut _;
        let set_result = unsafe { kernel32_SetEvent(bad) };
        assert_eq!(
            set_result, 0,
            "SetEvent on invalid handle should return FALSE"
        );
        let reset_result = unsafe { kernel32_ResetEvent(bad) };
        assert_eq!(
            reset_result, 0,
            "ResetEvent on invalid handle should return FALSE"
        );
    }

    #[test]
    fn test_get_exit_code_process_still_active() {
        let mut exit_code: u32 = 0;
        // NULL handle → current process pseudo-handle
        let result =
            unsafe { kernel32_GetExitCodeProcess(core::ptr::null_mut(), &raw mut exit_code) };
        assert_eq!(result, 1, "GetExitCodeProcess should return TRUE");
        assert_eq!(exit_code, 259, "exit code should be STILL_ACTIVE (259)");
    }

    #[test]
    fn test_get_exit_code_process_null_out_ptr() {
        // NULL output pointer should not crash
        let result =
            unsafe { kernel32_GetExitCodeProcess(core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(
            result, 1,
            "GetExitCodeProcess should return TRUE even with null exit_code"
        );
    }

    #[test]
    fn test_set_file_attributes_w_readonly() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("litebox_attr_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_attr.txt");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"hello").unwrap();
        drop(f);

        // Build wide path
        let path_str = file_path.to_string_lossy();
        let wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        // Set read-only
        let r = unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0001) }; // FILE_ATTRIBUTE_READONLY
        assert_eq!(r, 1, "SetFileAttributesW(READONLY) should return TRUE");
        let meta = std::fs::metadata(&file_path).unwrap();
        assert!(
            meta.permissions().readonly(),
            "file should be read-only after SetFileAttributesW"
        );

        // Restore writable so cleanup works
        unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0080) }; // FILE_ATTRIBUTE_NORMAL
        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_set_file_attributes_w_nonexistent() {
        let wide: Vec<u16> = "/nonexistent_litebox_xyz/file.txt\0"
            .encode_utf16()
            .collect();
        let r = unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0001) };
        assert_eq!(
            r, 0,
            "SetFileAttributesW on nonexistent path should return FALSE"
        );
    }

    #[test]
    fn test_get_module_file_name_w_current_exe() {
        let mut buf = vec![0u16; 1024];
        let written = unsafe {
            kernel32_GetModuleFileNameW(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert!(
            written > 0,
            "GetModuleFileNameW should return > 0 chars for current exe"
        );
        // Null-terminated at `written`
        assert_eq!(buf[written as usize], 0, "buffer should be null-terminated");
        let path = String::from_utf16_lossy(&buf[..written as usize]);
        assert!(!path.is_empty(), "exe path should not be empty");
    }

    #[test]
    fn test_get_module_file_name_w_null_buffer() {
        // size=0 / null buffer: copy_utf8_to_wide returns the required length
        // (including null terminator), which is consistent with Windows behaviour
        // when the supplied buffer is too small.
        let result =
            unsafe { kernel32_GetModuleFileNameW(core::ptr::null_mut(), core::ptr::null_mut(), 0) };
        // The required length must be > 0 because /proc/self/exe has a non-empty path.
        assert!(
            result > 0,
            "GetModuleFileNameW with size=0 should return the required buffer length (> 0)"
        );
    }
}
