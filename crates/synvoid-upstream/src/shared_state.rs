//! Cross-process shared-memory tables for worker coordination.
//!
//! Phase 42 hardening: this module is the crate's small, auditable unsafe
//! boundary. All mmap size/offset arithmetic lives in checked layout value
//! types ([`ConnectionTableLayout`], [`RateLimitTableLayout`]) that are
//! independently testable without touching the filesystem. Unsafe atomic
//! references are constructed only from release-mode validated invariants,
//! never from `debug_assert!` alone. Every `unsafe` block carries a
//! `// SAFETY:` comment naming the constructor invariant that makes it sound.
//!
//! # Ownership contract (Workstream C)
//!
//! - The supervisor is the sole creator. [`SharedConnectionTable::new`] and
//!   [`SharedRateLimitTable::new`] truncate/create the backing file, size it
//!   with `set_len`, write the magic/version/dimension header with safe byte
//!   copies, and memory-map it — all before any worker is spawned. Workers are
//!   spawned afterwards (see `supervisor::process`), so file creation
//!   happens-before any cross-process open.
//! - Workers never truncate. If a future worker needs to observe the tables,
//!   it must use [`SharedConnectionTable::open_existing`] /
//!   [`SharedRateLimitTable::open_existing`], which validate
//!   magic/version/dimensions/total-length before exposing any reference and
//!   never truncate or re-size the file. Today no worker opens these files:
//!   worker processes that never call `open_existing` observe `None` from the
//!   per-process globals and fall back to process-local counters. That
//!   fallback is intentional and documented, not a silent sharing failure.
//! - Mappings are recreated on every supervisor generation (`create(true)` +
//!   `truncate(true)`) and are never reused across binary versions. There is
//!   deliberately no upgrade path that reinterprets a file written by a
//!   different binary: a magic or version mismatch is `InvalidData`, and a
//!   dimension/total-length mismatch is rejected rather than referenced.
//!   See `architecture/shared_memory_atomic_contract.md`.
//!
//! # Cross-process atomics (Workstream D summary)
//!
//! The tables share `AtomicU64`/`AtomicU32`/`AtomicUsize` through a
//! `MAP_SHARED`-backed writable mmap (`memmap2::MmapMut`). This relies on
//! hardware cache-coherent process-shared mappings on the claimed targets
//! (Linux x86_64/aarch64; best-effort elsewhere, see the architecture
//! decision doc for the full matrix). `AtomicUsize` width is part of the
//! validated layout: connections-region sizes use
//! `size_of::<AtomicUsize>()` at both construction and access time, and mixed
//! width/architecture sharing is impossible by construction because the file
//! is recreated per supervisor generation with a version marker. Ordering is
//! `Relaxed` for counters/heartbeats except where documented at the call
//! site. Full rationale: `architecture/shared_memory_atomic_contract.md`.
//!
//! # File hardening (Workstream E summary)
//!
//! Backing files live under `PlatformPaths::runtime_dir` with fixed file
//! names (`connections.shm`, `ratelimit.shm`); no path component comes from
//! operator configuration. Creators ensure the parent directory exists via
//! `SecureDir` (0700 on Unix), reject symlink final components (`O_NOFOLLOW`
//! on Unix plus a pre-open `symlink_metadata` check), reject non-regular
//! targets, create with mode `0600`, and re-tighten to `0600` after sizing so
//! a pre-existing wider mode cannot survive truncation.

use memmap2::{MmapMut, MmapOptions};
use parking_lot::RwLock;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

pub static GLOBAL_SHARED_CONNECTION_TABLE: LazyLock<RwLock<Option<SharedConnectionTable>>> =
    LazyLock::new(|| RwLock::new(None));

pub static GLOBAL_SHARED_RATELIMIT_TABLE: LazyLock<RwLock<Option<SharedRateLimitTable>>> =
    LazyLock::new(|| RwLock::new(None));

// ---------------------------------------------------------------------------
// File-format constants
// ---------------------------------------------------------------------------

/// Magic for the connection table: ASCII "SVCT".
pub const CONNECTION_TABLE_MAGIC: u32 = 0x5443_5653;
/// Current connection-table format version.
pub const CONNECTION_TABLE_VERSION: u32 = 1;
/// Connection-table header length in bytes.
///
/// Layout: `[0..4]` magic (u32 LE), `[4..8]` version (u32 LE),
/// `[8..16]` max_workers (u64 LE), `[16..24]` max_backends (u64 LE),
/// `[24..32]` reserved (u64 LE, zero).
pub const CONNECTION_HEADER_LEN: usize = 32;

/// Magic for the rate-limit table: ASCII "SVRL".
pub const RATELIMIT_TABLE_MAGIC: u32 = 0x4c52_5653;
/// Current rate-limit-table format version.
pub const RATELIMIT_TABLE_VERSION: u32 = 1;
/// Rate-limit-table header length in bytes.
///
/// Layout: `[0..4]` magic (u32 LE), `[4..8]` version (u32 LE),
/// `[8..16]` num_slots (u64 LE).
pub const RATELIMIT_HEADER_LEN: usize = 16;

/// Constructor bounds (fail-closed for caller-controlled dimensions).
pub const MAX_TABLE_WORKERS: usize = 4096;
pub const MAX_TABLE_BACKENDS: usize = 8192;
/// Maximum slots for the rate-limit table (2^24).
pub const MAX_RATELIMIT_SLOTS: usize = 1 << 24;
/// Hard ceiling on any single mapping (512 MiB). Both tables stay far below
/// this at their constructor bounds (~256 MiB worst case for connections,
/// ~194 MiB for rate limits); the ceiling exists so a future bound change
/// cannot silently approve a multi-gigabyte truncation.
pub const MAX_MAPPING_BYTES: usize = 512 << 20;

fn invalid_input(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.into())
}

fn invalid_data(msg: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.into())
}

// ---------------------------------------------------------------------------
// Workstream A: checked layout value types
// ---------------------------------------------------------------------------

/// Validated byte layout for [`SharedConnectionTable`].
///
/// Constructible only via [`ConnectionTableLayout::new`], which enforces
/// nonzero dimensions, constructor bounds, checked size arithmetic, `u64`
/// convertibility, the global mapping ceiling, and element alignment. All
/// index-to-offset math reuses this object; call sites must not duplicate
/// the formulas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionTableLayout {
    max_workers: usize,
    max_backends: usize,
    heartbeats_len: usize,
    connections_len: usize,
    connections_base: usize,
    total_len: usize,
}

impl ConnectionTableLayout {
    /// Validate dimensions and compute every region offset/length.
    ///
    /// Returns `InvalidInput` for caller-controlled dimension errors; never
    /// panics.
    pub fn new(max_workers: usize, max_backends: usize) -> std::io::Result<Self> {
        if max_workers == 0 || max_backends == 0 {
            return Err(invalid_input(
                "SharedConnectionTable requires nonzero max_workers and max_backends",
            ));
        }
        if max_workers > MAX_TABLE_WORKERS || max_backends > MAX_TABLE_BACKENDS {
            return Err(invalid_input(format!(
                "SharedConnectionTable capacities exceed bounds ({MAX_TABLE_WORKERS} workers, {MAX_TABLE_BACKENDS} backends)"
            )));
        }
        let heartbeats_len = max_workers
            .checked_mul(std::mem::size_of::<AtomicU64>())
            .ok_or_else(|| invalid_input("SharedConnectionTable heartbeats size overflow"))?;
        let connections_len = max_workers
            .checked_mul(max_backends)
            .and_then(|v| v.checked_mul(std::mem::size_of::<AtomicUsize>()))
            .ok_or_else(|| invalid_input("SharedConnectionTable connections size overflow"))?;
        let connections_base = CONNECTION_HEADER_LEN
            .checked_add(heartbeats_len)
            .ok_or_else(|| invalid_input("SharedConnectionTable region offset overflow"))?;
        let total_len = connections_base
            .checked_add(connections_len)
            .ok_or_else(|| invalid_input("SharedConnectionTable total size overflow"))?;
        // Reject lengths that cannot be expressed to the file-sizing API.
        u64::try_from(total_len)
            .map_err(|_| invalid_input("SharedConnectionTable total size exceeds u64"))?;
        if total_len > MAX_MAPPING_BYTES {
            return Err(invalid_input(format!(
                "SharedConnectionTable total size {total_len} exceeds mapping ceiling {MAX_MAPPING_BYTES}"
            )));
        }
        // Release-mode alignment proof for the whole region: the header is
        // 32 bytes (multiple of 8) and heartbeats advance in 8-byte steps,
        // so both region bases are aligned for their element types on every
        // supported target. Checked here rather than `debug_assert!`-only so
        // release builds enforce it.
        if !CONNECTION_HEADER_LEN.is_multiple_of(std::mem::align_of::<AtomicU64>()) {
            return Err(invalid_input(
                "SharedConnectionTable header misaligned for heartbeats",
            ));
        }
        if !connections_base.is_multiple_of(std::mem::align_of::<AtomicUsize>()) {
            return Err(invalid_input(
                "SharedConnectionTable connections region misaligned",
            ));
        }
        Ok(Self {
            max_workers,
            max_backends,
            heartbeats_len,
            connections_len,
            connections_base,
            total_len,
        })
    }

    /// Rebuild a layout from dimensions read out of an existing file header.
    ///
    /// File content errors are `InvalidData` (not caller input). Bounds and
    /// arithmetic are re-validated identically to [`Self::new`].
    pub fn from_file_dimensions(max_workers: usize, max_backends: usize) -> std::io::Result<Self> {
        Self::new(max_workers, max_backends)
            .map_err(|e| invalid_data(format!("SharedConnectionTable file header invalid: {e}")))
    }

    pub fn max_workers(&self) -> usize {
        self.max_workers
    }
    pub fn max_backends(&self) -> usize {
        self.max_backends
    }
    pub fn heartbeats_base(&self) -> usize {
        CONNECTION_HEADER_LEN
    }
    pub fn heartbeats_len(&self) -> usize {
        self.heartbeats_len
    }
    pub fn connections_base(&self) -> usize {
        self.connections_base
    }
    pub fn connections_len(&self) -> usize {
        self.connections_len
    }
    pub fn total_len(&self) -> usize {
        self.total_len
    }
    pub fn total_len_u64(&self) -> std::io::Result<u64> {
        u64::try_from(self.total_len)
            .map_err(|_| invalid_input("SharedConnectionTable total size exceeds u64"))
    }

    /// Byte offset of `heartbeats[worker_id]`; `None` when out of range or
    /// on arithmetic overflow.
    pub fn heartbeat_offset(&self, worker_id: usize) -> Option<usize> {
        if worker_id >= self.max_workers {
            return None;
        }
        CONNECTION_HEADER_LEN.checked_add(worker_id.checked_mul(std::mem::size_of::<AtomicU64>())?)
    }

    /// Byte offset of `connections[worker_id][backend_index]`; `None` when
    /// out of range or on arithmetic overflow.
    pub fn counter_offset(&self, worker_id: usize, backend_index: usize) -> Option<usize> {
        if worker_id >= self.max_workers || backend_index >= self.max_backends {
            return None;
        }
        self.connections_base.checked_add(
            worker_id
                .checked_mul(self.max_backends)?
                .checked_add(backend_index)?
                .checked_mul(std::mem::size_of::<AtomicUsize>())?,
        )
    }
}

/// Validated byte layout for [`SharedRateLimitTable`].
///
/// Counter regions advance in whole-`AtomicU32` steps from a 16-byte header,
/// so every region base is 4-byte aligned by construction; still validated
/// here in release mode. The dirty-bit region holds `ceil(num_slots / 32)`
/// words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitTableLayout {
    num_slots: usize,
    counter_len: usize,
    dirty_words: usize,
    dirty_len: usize,
    minute_base: usize,
    five_min_base: usize,
    dirty_base: usize,
    total_len: usize,
}

impl RateLimitTableLayout {
    /// Validate `num_slots` and compute every region offset/length.
    pub fn new(num_slots: usize) -> std::io::Result<Self> {
        if num_slots == 0 {
            return Err(invalid_input(
                "SharedRateLimitTable requires nonzero num_slots",
            ));
        }
        if num_slots > MAX_RATELIMIT_SLOTS {
            return Err(invalid_input(format!(
                "SharedRateLimitTable slots exceed bound {MAX_RATELIMIT_SLOTS}"
            )));
        }
        let counter_len = num_slots
            .checked_mul(std::mem::size_of::<AtomicU32>())
            .ok_or_else(|| invalid_input("SharedRateLimitTable counter size overflow"))?;
        // Checked ceil division: (num_slots + 31) / 32 without wrapping.
        let dirty_words = num_slots
            .checked_add(31)
            .and_then(|v| v.checked_div(32))
            .ok_or_else(|| invalid_input("SharedRateLimitTable dirty-bits size overflow"))?;
        let dirty_len = dirty_words
            .checked_mul(std::mem::size_of::<AtomicU32>())
            .ok_or_else(|| invalid_input("SharedRateLimitTable dirty-bits size overflow"))?;
        let second_base = RATELIMIT_HEADER_LEN;
        let minute_base = second_base
            .checked_add(counter_len)
            .ok_or_else(|| invalid_input("SharedRateLimitTable region offset overflow"))?;
        let five_min_base = minute_base
            .checked_add(counter_len)
            .ok_or_else(|| invalid_input("SharedRateLimitTable region offset overflow"))?;
        let dirty_base = five_min_base
            .checked_add(counter_len)
            .ok_or_else(|| invalid_input("SharedRateLimitTable region offset overflow"))?;
        let total_len = dirty_base
            .checked_add(dirty_len)
            .ok_or_else(|| invalid_input("SharedRateLimitTable total size overflow"))?;
        u64::try_from(total_len)
            .map_err(|_| invalid_input("SharedRateLimitTable total size exceeds u64"))?;
        if total_len > MAX_MAPPING_BYTES {
            return Err(invalid_input(format!(
                "SharedRateLimitTable total size {total_len} exceeds mapping ceiling {MAX_MAPPING_BYTES}"
            )));
        }
        for base in [second_base, minute_base, five_min_base, dirty_base] {
            if base % std::mem::align_of::<AtomicU32>() != 0 {
                return Err(invalid_input(
                    "SharedRateLimitTable region misaligned for AtomicU32",
                ));
            }
        }
        Ok(Self {
            num_slots,
            counter_len,
            dirty_words,
            dirty_len,
            minute_base,
            five_min_base,
            dirty_base,
            total_len,
        })
    }

    /// Rebuild a layout from the slot count read out of an existing file.
    pub fn from_file_dimensions(num_slots: usize) -> std::io::Result<Self> {
        Self::new(num_slots)
            .map_err(|e| invalid_data(format!("SharedRateLimitTable file header invalid: {e}")))
    }

    pub fn num_slots(&self) -> usize {
        self.num_slots
    }
    pub fn counter_len(&self) -> usize {
        self.counter_len
    }
    pub fn dirty_words(&self) -> usize {
        self.dirty_words
    }
    pub fn dirty_len(&self) -> usize {
        self.dirty_len
    }
    pub fn second_base(&self) -> usize {
        RATELIMIT_HEADER_LEN
    }
    pub fn minute_base(&self) -> usize {
        self.minute_base
    }
    pub fn five_min_base(&self) -> usize {
        self.five_min_base
    }
    pub fn dirty_base(&self) -> usize {
        self.dirty_base
    }
    pub fn total_len(&self) -> usize {
        self.total_len
    }
    pub fn total_len_u64(&self) -> std::io::Result<u64> {
        u64::try_from(self.total_len)
            .map_err(|_| invalid_input("SharedRateLimitTable total size exceeds u64"))
    }

    /// Byte offset of `second/minute/five_min[slot]` for region base `base`.
    pub fn counter_offset(&self, base: usize, slot: usize) -> Option<usize> {
        if slot >= self.num_slots {
            return None;
        }
        base.checked_add(slot.checked_mul(std::mem::size_of::<AtomicU32>())?)
    }

    /// Byte offset of `dirty[word_idx]`.
    pub fn dirty_offset(&self, word_idx: usize) -> Option<usize> {
        if word_idx >= self.dirty_words {
            return None;
        }
        self.dirty_base
            .checked_add(word_idx.checked_mul(std::mem::size_of::<AtomicU32>())?)
    }
}

// ---------------------------------------------------------------------------
// Workstream E: file/path hardening helpers
// ---------------------------------------------------------------------------

/// Ensure the parent directory exists with owner-only permissions and open
/// the backing file as a fresh regular file.
///
/// - Parent directories are created via `SecureDir` (0700 on Unix).
/// - A pre-existing symlink at the final path is rejected (`InvalidInput`);
///   on Unix the open itself passes `O_NOFOLLOW` so a symlink swapped in
///   between the check and the open still fails with `ELOOP`.
/// - Files are created with mode `0600` on Unix and re-tightened to `0600`
///   afterwards so truncating a pre-existing wider-mode file cannot leave
///   world-readable shared state behind.
/// - After opening, non-regular targets (directories, FIFOs, sockets) are
///   rejected.
fn create_shm_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            synvoid_platform::fs::SecureDir::new(parent).create()?;
            let parent_meta = std::fs::metadata(parent)?;
            if !parent_meta.file_type().is_dir() {
                return Err(invalid_input(format!(
                    "shared-state parent is not a directory: {}",
                    parent.display()
                )));
            }
        }
    }
    // Best-effort pre-check for a clear error message; the O_NOFOLLOW flag
    // below closes the check/open TOCTOU on Unix.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(invalid_input(format!(
                "refusing to open symlinked shared-state file: {}",
                path.display()
            )));
        }
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(invalid_input(format!(
            "shared-state target is not a regular file: {}",
            path.display()
        )));
    }
    // Tighten permissions even when truncating a pre-existing file whose
    // mode was wider than 0600 at creation time.
    let _ = synvoid_platform::fs::set_file_permissions(path, false);
    Ok(file)
}

/// Open an existing backing file for validation (never truncates).
///
/// Rejects symlinks and non-regular files like [`create_shm_file`].
fn open_shm_file(path: &Path) -> std::io::Result<std::fs::File> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(invalid_input(format!(
                "refusing to open symlinked shared-state file: {}",
                path.display()
            )));
        }
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(invalid_input(format!(
            "shared-state target is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

/// Validate that a mapped region can back `layout` bytes starting at zero.
///
/// Release-mode precondition for every unsafe reference construction: the
/// mapping must be at least as long as the layout demands and its base
/// address must satisfy the maximum element alignment used by the table.
fn validate_mapping(mmap: &MmapMut, total_len: usize, align: usize) -> std::io::Result<()> {
    if mmap.len() < total_len {
        return Err(invalid_data(format!(
            "shared-memory mapping too short: {} < {total_len}",
            mmap.len()
        )));
    }
    if !(mmap.as_ptr() as usize).is_multiple_of(align) {
        return Err(invalid_data(
            "shared-memory mapping base misaligned for atomic access",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SharedConnectionTable
// ---------------------------------------------------------------------------

/// Shared connection table for distributed load balancing with worker liveness.
///
/// Byte layout (all integers little-endian):
/// - `[0..4]`: magic (`CONNECTION_TABLE_MAGIC`)
/// - `[4..8]`: version (`CONNECTION_TABLE_VERSION`)
/// - `[8..16]`: max_workers (u64)
/// - `[16..24]`: max_backends (u64)
/// - `[24..32]`: reserved (u64, zero)
/// - `[32..32 + max_workers * 8]`: heartbeats (`AtomicU64` per worker)
/// - `[32 + max_workers * 8 ..]`: connections (`AtomicUsize`
///   `[worker_id][backend_index]`)
pub struct SharedConnectionTable {
    mmap: Arc<MmapMut>,
    layout: ConnectionTableLayout,
}

impl SharedConnectionTable {
    pub fn init_global(
        path: PathBuf,
        max_workers: usize,
        max_backends: usize,
    ) -> std::io::Result<()> {
        let table = Self::new(path, max_workers, max_backends)?;
        let mut global = GLOBAL_SHARED_CONNECTION_TABLE.write();
        *global = Some(table);
        Ok(())
    }

    pub fn get_global() -> Option<SharedConnectionTable> {
        GLOBAL_SHARED_CONNECTION_TABLE.read().as_ref().cloned()
    }

    /// Create, size, header-initialize, and map a fresh table (supervisor
    /// ownership: truncates; must complete before workers are spawned).
    pub fn new(path: PathBuf, max_workers: usize, max_backends: usize) -> std::io::Result<Self> {
        let layout = ConnectionTableLayout::new(max_workers, max_backends)?;
        let file = create_shm_file(&path)?;
        file.set_len(layout.total_len_u64()?)?;
        let mut mmap = unsafe {
            // SAFETY: the file was just created/truncated to exactly
            // `layout.total_len()` bytes by the supervisor; no other process
            // holds the mapping yet, so sizing is exclusive to this call.
            MmapOptions::new().map_mut(&file)?
        };
        // Release-mode mapping precondition (no `assert!`: invalid sizes
        // return errors, they never panic).
        validate_mapping(
            &mmap,
            layout.total_len(),
            std::mem::align_of::<AtomicUsize>().max(std::mem::align_of::<AtomicU64>()),
        )?;
        // Header via safe byte copies only: no non-atomic racing writes are
        // needed because no reader can observe this mapping yet (supervisor
        // publishes it to the global after `new` returns, and workers are
        // spawned after `init_global`).
        mmap[0..4].copy_from_slice(&CONNECTION_TABLE_MAGIC.to_le_bytes());
        mmap[4..8].copy_from_slice(&CONNECTION_TABLE_VERSION.to_le_bytes());
        mmap[8..16].copy_from_slice(&(max_workers as u64).to_le_bytes());
        mmap[16..24].copy_from_slice(&(max_backends as u64).to_le_bytes());
        mmap[24..32].copy_from_slice(&0u64.to_le_bytes());
        // Fresh `set_len` regions are zero-filled, so heartbeat/counter
        // arrays start at zero without further writes.
        let _ = mmap.flush();
        Ok(Self {
            mmap: Arc::new(mmap),
            layout,
        })
    }

    /// Open a table created by [`Self::new`] without truncating it.
    ///
    /// Validates magic, version, dimensions, and total length. Intended for
    /// future worker-side opens; today no worker calls this (workers without
    /// an explicit open keep process-local counters).
    pub fn open_existing(path: &Path) -> std::io::Result<Self> {
        let file = open_shm_file(path)?;
        let meta_len = file.metadata()?.len() as usize;
        if meta_len < CONNECTION_HEADER_LEN {
            return Err(invalid_data(
                "shared connection table file shorter than header",
            ));
        }
        let mmap = unsafe {
            // SAFETY: the file is a validated regular file; the mapping
            // length is checked against the header-derived layout below
            // before any atomic reference is constructed.
            MmapOptions::new().map_mut(&file)?
        };
        if mmap.len() < CONNECTION_HEADER_LEN {
            return Err(invalid_data(
                "shared connection table mapping shorter than header",
            ));
        }
        let magic = u32::from_le_bytes(
            mmap[0..4]
                .try_into()
                .map_err(|_| invalid_data("shared connection table header unreadable"))?,
        );
        let version = u32::from_le_bytes(
            mmap[4..8]
                .try_into()
                .map_err(|_| invalid_data("shared connection table header unreadable"))?,
        );
        if magic != CONNECTION_TABLE_MAGIC {
            return Err(invalid_data("shared connection table magic mismatch"));
        }
        if version != CONNECTION_TABLE_VERSION {
            return Err(invalid_data(format!(
                "unsupported shared connection table version {version}"
            )));
        }
        let max_workers = u64::from_le_bytes(
            mmap[8..16]
                .try_into()
                .map_err(|_| invalid_data("shared connection table header unreadable"))?,
        ) as usize;
        let max_backends = u64::from_le_bytes(
            mmap[16..24]
                .try_into()
                .map_err(|_| invalid_data("shared connection table header unreadable"))?,
        ) as usize;
        // `usize` is 64-bit on supported targets; a stored u64 that does not
        // fit is rejected rather than truncated.
        if std::mem::size_of::<usize>() < 8 {
            return Err(invalid_data(
                "shared connection table dimensions require 64-bit usize",
            ));
        }
        let layout = ConnectionTableLayout::from_file_dimensions(max_workers, max_backends)?;
        validate_mapping(
            &mmap,
            layout.total_len(),
            std::mem::align_of::<AtomicUsize>().max(std::mem::align_of::<AtomicU64>()),
        )?;
        Ok(Self {
            mmap: Arc::new(mmap),
            layout,
        })
    }

    /// Validated layout backing this table (offsets/sizes for tests and
    /// accessors; no raw pointer exposure).
    pub fn layout(&self) -> ConnectionTableLayout {
        self.layout
    }

    pub fn record_heartbeat(&self, worker_id: usize, timestamp: u64) {
        if let Some(h) = self.get_heartbeat_atomic(worker_id) {
            h.store(timestamp, Ordering::SeqCst);
        }
    }

    pub fn get_heartbeat_atomic(&self, worker_id: usize) -> Option<&AtomicU64> {
        // Workstream B: index range, checked offset, in-bounds end, and
        // release-mode alignment are all proven before the unsafe
        // construction; the constructor proved whole-region alignment, so
        // per-access work is bounds plus the alignment re-check.
        let offset = self.layout.heartbeat_offset(worker_id)?;
        let end = offset.checked_add(std::mem::size_of::<AtomicU64>())?;
        if end > self.mmap.len() {
            return None;
        }
        if !offset.is_multiple_of(std::mem::align_of::<AtomicU64>()) {
            return None;
        }
        // SAFETY: `offset` is in range for `worker_id`, `end` is within the
        // validated mapping, and the address satisfies `align_of::<AtomicU64>()`.
        // The region was zero-initialized at creation and heartbeats are only
        // accessed as `AtomicU64`.
        let ptr = unsafe { self.mmap.as_ptr().add(offset) } as *const AtomicU64;
        if !(ptr as usize).is_multiple_of(std::mem::align_of::<AtomicU64>()) {
            return None;
        }
        Some(unsafe { &*ptr })
    }

    pub fn get_counter_atomic(
        &self,
        worker_id: usize,
        backend_index: usize,
    ) -> Option<&AtomicUsize> {
        // Workstream B: same four preconditions as heartbeats, via the
        // shared layout object (no duplicated formulas).
        let offset = self.layout.counter_offset(worker_id, backend_index)?;
        let end = offset.checked_add(std::mem::size_of::<AtomicUsize>())?;
        if end > self.mmap.len() {
            return None;
        }
        if !offset.is_multiple_of(std::mem::align_of::<AtomicUsize>()) {
            return None;
        }
        // SAFETY: `offset` derives from the validated layout for in-range
        // indices, `end` is within the mapping, and alignment holds. The
        // region is used exclusively as `AtomicUsize`.
        let ptr = unsafe { self.mmap.as_ptr().add(offset) } as *const AtomicUsize;
        if !(ptr as usize).is_multiple_of(std::mem::align_of::<AtomicUsize>()) {
            return None;
        }
        Some(unsafe { &*ptr })
    }

    pub fn sum_active_connections(&self, backend_index: usize, timeout_secs: u64) -> usize {
        if backend_index >= self.layout.max_backends() {
            return 0;
        }

        let now = synvoid_utils::current_timestamp();

        let mut total = 0;
        for w in 0..self.layout.max_workers() {
            if let Some(h) = self.get_heartbeat_atomic(w) {
                let last_h = h.load(Ordering::Relaxed);
                if now.saturating_sub(last_h) <= timeout_secs {
                    if let Some(c) = self.get_counter_atomic(w, backend_index) {
                        total += c.load(Ordering::Relaxed);
                    }
                }
            }
        }
        total
    }

    pub fn max_backends(&self) -> usize {
        self.layout.max_backends()
    }

    pub fn max_workers(&self) -> usize {
        self.layout.max_workers()
    }
}

impl Clone for SharedConnectionTable {
    fn clone(&self) -> Self {
        Self {
            mmap: self.mmap.clone(),
            layout: self.layout,
        }
    }
}

// ---------------------------------------------------------------------------
// SharedRateLimitTable
// ---------------------------------------------------------------------------

/// Shared rate limit table for cross-worker IP rate limiting.
///
/// Byte layout (all integers little-endian):
/// - `[0..4]`: magic (`RATELIMIT_TABLE_MAGIC`)
/// - `[4..8]`: version (`RATELIMIT_TABLE_VERSION`)
/// - `[8..16]`: num_slots (u64)
/// - `[16..16 + N*4]`: second counters (`AtomicU32` per slot)
/// - `[.. + N*4]`: minute counters
/// - `[.. + N*4]`: five-minute counters
/// - `[.. + ceil(N/32)*4]`: dirty-bit words (`AtomicU32` per 32 slots)
///
/// where `N` is `num_slots`. See [`RateLimitTableLayout`] for the checked
/// derivation. Raw `MmapMut` is intentionally not exposed (Workstream F):
/// consumers use the typed counter slices below.
pub struct SharedRateLimitTable {
    mmap: Arc<MmapMut>,
    layout: RateLimitTableLayout,
}

impl SharedRateLimitTable {
    pub fn init_global(path: PathBuf, num_slots: usize) -> std::io::Result<()> {
        let table = Self::new(path, num_slots)?;
        let mut global = GLOBAL_SHARED_RATELIMIT_TABLE.write();
        *global = Some(table);
        Ok(())
    }

    pub fn get_global() -> Option<SharedRateLimitTable> {
        GLOBAL_SHARED_RATELIMIT_TABLE.read().as_ref().cloned()
    }

    /// Create, size, header-initialize, and map a fresh table (supervisor
    /// ownership: truncates; must complete before workers are spawned).
    pub fn new(path: PathBuf, num_slots: usize) -> std::io::Result<Self> {
        let layout = RateLimitTableLayout::new(num_slots)?;
        let file = create_shm_file(&path)?;
        file.set_len(layout.total_len_u64()?)?;
        let mut mmap = unsafe {
            // SAFETY: freshly truncated to `layout.total_len()` with no other
            // mapping holder yet; sizing is exclusive to this call.
            MmapOptions::new().map_mut(&file)?
        };
        validate_mapping(&mmap, layout.total_len(), std::mem::align_of::<AtomicU32>())?;
        // Safe header initialization (no concurrent readers exist yet).
        mmap[0..4].copy_from_slice(&RATELIMIT_TABLE_MAGIC.to_le_bytes());
        mmap[4..8].copy_from_slice(&RATELIMIT_TABLE_VERSION.to_le_bytes());
        mmap[8..16].copy_from_slice(&(num_slots as u64).to_le_bytes());
        let _ = mmap.flush();
        Ok(Self {
            mmap: Arc::new(mmap),
            layout,
        })
    }

    /// Open a table created by [`Self::new`] without truncating it.
    pub fn open_existing(path: &Path) -> std::io::Result<Self> {
        let file = open_shm_file(path)?;
        if file.metadata()?.len() < RATELIMIT_HEADER_LEN as u64 {
            return Err(invalid_data("shared rate-limit file shorter than header"));
        }
        let mmap = unsafe {
            // SAFETY: regular-file mapping; length is validated against the
            // header-derived layout before any atomic reference construction.
            MmapOptions::new().map_mut(&file)?
        };
        if mmap.len() < RATELIMIT_HEADER_LEN {
            return Err(invalid_data(
                "shared rate-limit mapping shorter than header",
            ));
        }
        let magic = u32::from_le_bytes(
            mmap[0..4]
                .try_into()
                .map_err(|_| invalid_data("shared rate-limit header unreadable"))?,
        );
        let version = u32::from_le_bytes(
            mmap[4..8]
                .try_into()
                .map_err(|_| invalid_data("shared rate-limit header unreadable"))?,
        );
        if magic != RATELIMIT_TABLE_MAGIC {
            return Err(invalid_data("shared rate-limit magic mismatch"));
        }
        if version != RATELIMIT_TABLE_VERSION {
            return Err(invalid_data(format!(
                "unsupported shared rate-limit version {version}"
            )));
        }
        let num_slots = u64::from_le_bytes(
            mmap[8..16]
                .try_into()
                .map_err(|_| invalid_data("shared rate-limit header unreadable"))?,
        ) as usize;
        if std::mem::size_of::<usize>() < 8 {
            return Err(invalid_data(
                "shared rate-limit dimensions require 64-bit usize",
            ));
        }
        let layout = RateLimitTableLayout::from_file_dimensions(num_slots)?;
        validate_mapping(&mmap, layout.total_len(), std::mem::align_of::<AtomicU32>())?;
        Ok(Self {
            mmap: Arc::new(mmap),
            layout,
        })
    }

    /// Validated layout backing this table.
    pub fn layout(&self) -> RateLimitTableLayout {
        self.layout
    }

    pub fn num_slots(&self) -> usize {
        self.layout.num_slots()
    }

    fn counter_slice(&self, base: usize, len: usize) -> &[AtomicU32] {
        let byte_len = match len.checked_mul(std::mem::size_of::<AtomicU32>()) {
            Some(v) => v,
            None => return &[],
        };
        let byte_end = match base.checked_add(byte_len) {
            Some(v) => v,
            None => return &[],
        };
        // Release-mode bounds precondition (fail-closed to an empty view;
        // constructors guarantee the full layout fits, so this only fires
        // for a corrupted or externally truncated mapping).
        if byte_end > self.mmap.len() {
            return &[];
        }
        if !base.is_multiple_of(std::mem::align_of::<AtomicU32>()) {
            return &[];
        }
        // SAFETY: `base..byte_end` lies within the validated mapping, holds
        // exactly `len` `AtomicU32` values, satisfies alignment, and the
        // region is used exclusively as `AtomicU32` counters.
        let ptr = unsafe { self.mmap.as_ptr().add(base) } as *const AtomicU32;
        if !(ptr as usize).is_multiple_of(std::mem::align_of::<AtomicU32>()) {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    /// Per-second counters (Workstream F typed accessor; replaces raw mmap).
    pub fn second_counters(&self) -> &[AtomicU32] {
        self.counter_slice(self.layout.second_base(), self.layout.num_slots())
    }

    /// Per-minute counters.
    pub fn minute_counters(&self) -> &[AtomicU32] {
        self.counter_slice(self.layout.minute_base(), self.layout.num_slots())
    }

    /// Per-five-minute counters.
    pub fn five_min_counters(&self) -> &[AtomicU32] {
        self.counter_slice(self.layout.five_min_base(), self.layout.num_slots())
    }

    /// Dirty-bit words (one bit per slot, `ceil(num_slots / 32)` words).
    pub fn dirty_words(&self) -> &[AtomicU32] {
        self.counter_slice(self.layout.dirty_base(), self.layout.dirty_words())
    }
}

impl Clone for SharedRateLimitTable {
    fn clone(&self) -> Self {
        Self {
            mmap: self.mmap.clone(),
            layout: self.layout,
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    #[test]
    fn connection_layout_rejects_zero_dimensions() {
        assert!(ConnectionTableLayout::new(0, 1).is_err());
        assert!(ConnectionTableLayout::new(1, 0).is_err());
        assert!(ConnectionTableLayout::new(0, 0).is_err());
        assert!(RateLimitTableLayout::new(0).is_err());
    }

    #[test]
    fn connection_layout_minimum_one_by_one() {
        let layout = ConnectionTableLayout::new(1, 1).expect("1x1 must succeed");
        assert_eq!(layout.heartbeats_base(), CONNECTION_HEADER_LEN);
        assert_eq!(
            layout.connections_base(),
            CONNECTION_HEADER_LEN + std::mem::size_of::<AtomicU64>()
        );
        assert_eq!(layout.heartbeat_offset(0), Some(CONNECTION_HEADER_LEN));
        assert!(layout.heartbeat_offset(1).is_none());
        assert!(layout.counter_offset(0, 0).is_some());
        assert!(layout.counter_offset(1, 0).is_none());
        assert!(layout.counter_offset(0, 1).is_none());
    }

    #[test]
    fn connection_layout_production_sizes() {
        // Supervisor derivation: unified workers + 10 headroom, 2048 backends.
        let layout = ConnectionTableLayout::new(266, 2048).expect("production size must succeed");
        assert!(layout.total_len() < MAX_MAPPING_BYTES);
        // Last valid / first invalid indices.
        assert!(layout.heartbeat_offset(265).is_some());
        assert!(layout.heartbeat_offset(266).is_none());
        assert!(layout.counter_offset(265, 2047).is_some());
        assert!(layout.counter_offset(266, 0).is_none());
        assert!(layout.counter_offset(0, 2048).is_none());
        // Every region base stays aligned in release mode.
        assert_eq!(
            layout.heartbeats_base() % std::mem::align_of::<AtomicU64>(),
            0
        );
        assert_eq!(
            layout.connections_base() % std::mem::align_of::<AtomicUsize>(),
            0
        );
    }

    #[test]
    fn connection_layout_rejects_huge_dimensions_without_panic() {
        assert!(ConnectionTableLayout::new(usize::MAX, 1).is_err());
        assert!(ConnectionTableLayout::new(1, usize::MAX).is_err());
        assert!(ConnectionTableLayout::new(usize::MAX, usize::MAX).is_err());
        assert!(RateLimitTableLayout::new(usize::MAX).is_err());
    }

    #[test]
    fn connection_layout_rejects_bounds() {
        assert!(ConnectionTableLayout::new(MAX_TABLE_WORKERS + 1, 1).is_err());
        assert!(ConnectionTableLayout::new(1, MAX_TABLE_BACKENDS + 1).is_err());
        assert!(RateLimitTableLayout::new(MAX_RATELIMIT_SLOTS + 1).is_err());
    }

    #[test]
    fn ratelimit_layout_dirty_bit_ceil_boundaries() {
        // ceil(N/32) boundaries: 31 -> 1 word, 32 -> 1 word, 33 -> 2 words.
        assert_eq!(RateLimitTableLayout::new(31).expect("31").dirty_words(), 1);
        assert_eq!(RateLimitTableLayout::new(32).expect("32").dirty_words(), 1);
        assert_eq!(RateLimitTableLayout::new(33).expect("33").dirty_words(), 2);
        let layout = RateLimitTableLayout::new(65536).expect("production slots");
        assert_eq!(layout.dirty_words(), 65536 / 32);
        assert_eq!(layout.second_base() % std::mem::align_of::<AtomicU32>(), 0);
        assert_eq!(layout.minute_base() % std::mem::align_of::<AtomicU32>(), 0);
        assert_eq!(
            layout.five_min_base() % std::mem::align_of::<AtomicU32>(),
            0
        );
        assert_eq!(layout.dirty_base() % std::mem::align_of::<AtomicU32>(), 0);
        // Last valid / first invalid slots.
        assert!(layout.counter_offset(layout.second_base(), 65535).is_some());
        assert!(layout.counter_offset(layout.second_base(), 65536).is_none());
        assert!(layout.dirty_offset(2047).is_some());
        assert!(layout.dirty_offset(2048).is_none());
    }

    #[test]
    fn atomic_usize_width_is_layout_input() {
        // The connections region explicitly depends on the platform's
        // AtomicUsize width; record it so mixed-width reuse is visible.
        let elem = std::mem::size_of::<AtomicUsize>();
        assert!(
            elem == 4 || elem == 8,
            "unexpected AtomicUsize width {elem}"
        );
        let a = ConnectionTableLayout::new(2, 3).expect("small");
        assert_eq!(
            a.connections_len(),
            2 * 3 * elem,
            "connections region must scale with AtomicUsize width"
        );
    }
}
