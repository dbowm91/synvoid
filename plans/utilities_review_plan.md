# Cross-Cutting Utilities Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/common.md`, `architecture/filter.md`, `architecture/zero_copy.md`, `architecture/serder.md`

## Verified Correct Items

### common.md
- `setup_panic_handler(process_name, log_file)` signature matches source (`src/common/panic_handler.rs:1`)
- `setup_default_panic_handler()` exists and calls `setup_panic_handler("synvoid", None)` (`:48-49`)
- File permissions set to `0o600` on panic logs (`:28-31`)
- Structured output includes location, message, process name via `tracing::error!` (`:19`)
- Dual output: both file and stderr (`:20-23`, `:27-31`)
- Thread-safe via `std::panic::set_hook` (`:5`)
- Integration points verified: Supervisor (`src/supervisor/process.rs:325`), Worker (`src/worker/mod.rs:46`), UnifiedServerWorker (`src/worker/unified_server.rs:55`), MeshAgent (`src/supervisor/mesh.rs:32`)

### filter.md
- `FilterAction` trait with `is_allow()` and `is_drop()` (`src/filter/common.rs:1-4`)
- `Protocol` trait with `as_str()` and `from_str()` (`:6-9`)
- `BaseFilterConfig<P>` struct with `enabled`, `strict_mode`, allowlist, denylist fields (`:11-18`)
- `ProtocolFilterCore<P, A>` struct with `config` and `PhantomData<A>` (`:49-53`)
- All public API methods exist: `new`, `check`, `with_allowlist`, `with_denylist`, `with_strict_mode`, `check_protocol_match`
- `PortConfigBase` struct exists (`:135-148`)
- TCP `ProtocolFilter` and UDP `UdpProtocolFilter` use `ProtocolFilterCore` as documented
- Integration with TCP (`src/tcp/filter.rs`) and UDP (`src/udp/filter.rs`) verified

### zero_copy.md
- `ZeroCopyReader` struct with `file: File` and `size: u64` (`src/zero_copy.rs:20-23`)
- `FilePath` trait with `fn path(&self) -> Result<PathBuf>` (`:124-126`)
- All methods exist: `open`, `size`, `fd`, `read_to_vec`, `sendfile_to_socket`, `copy_file_range`
- Platform implementations for Linux, macOS, FreeBSD verified with correct syscall signatures
- Module declared in `lib.rs:101` as `pub mod zero_copy`

### serder.md
- `src/serder.rs` exists and is declared in `lib.rs:80`
- Feature-gated rkyv re-export: `#[cfg(feature = "rkyv")] pub use rkyv::{Archive, Deserialize, Serialize}` (`:114-117`)
- `rkyv` feature defined in `Cargo.toml:36`
- Serialization paths documented (Postcard for DHT/Mesh/Persistence, JSON for Admin API) align with AGENTS.md

## Discrepancies Found

### filter.md - Critical: `Protocol::from_str` return type wrong
- **Doc claims:** `fn from_str(s: &str) -> Option<Self>`
- **Actual code:** `fn from_str(s: &str) -> Self` (`src/filter/common.rs:8`)
- **Impact:** All implementors (TCP `Protocol`, UDP `UdpProtocol`) return `Self` directly. The doc's `Option<Self>` implies fallibility that doesn't exist.

### filter.md - Critical: `BaseFilterConfig` allowlist/denylist types wrong
- **Doc claims:** `pub protocol_allowlist: Vec<P>` and `pub protocol_denylist: Vec<P>`
- **Actual code:** `pub protocol_allowlist: Vec<String>` and `pub protocol_denylist: Vec<String>` (`src/filter/common.rs:15-16`)
- **Impact:** The doc implies type-safe protocol vectors; actual implementation uses stringly-typed lists.

### filter.md - Error: Allow/Deny priority reversed
- **Doc claims:** "Allow/Deny Priority: Allowlist checked first, then denylist"
- **Actual code:** Denylist is checked first (`:74-84`), then allowlist (`:86-96`)
- **Impact:** Security-relevant documentation error. Deny-first is the correct default for security filtering, but the doc describes the opposite.

### filter.md - Missing: `PhantomData` field name mismatch
- **Doc shows:** `ProtocolFilterCore` has `_phantom: PhantomData<A>` and `BaseFilterConfig` has no PhantomData
- **Actual code:** `ProtocolFilterCore` has `_marker: PhantomData<A>` (`:52`), and `BaseFilterConfig` has `_marker: PhantomData<P>` (`:17`)

### filter.md - Missing: Trait bounds undocumented
- **Doc shows:** Plain `pub trait FilterAction` and `pub trait Protocol`
- **Actual code:** Both traits have additional bounds: `Clone + PartialEq + Eq + Debug + Send + Sync + 'static`

### zero_copy.md - Inaccurate: `sendfile_to_socket` fallback claim
- **Doc claims:** "Other → Fallback: Userspace copy"
- **Actual code:** Non-Linux/macOS/FreeBSD returns `Err("sendfile not supported")` (`:112-122`), no userspace fallback
- **Note:** `copy_file_range` does have a userspace fallback (`:211-220`), but `sendfile_to_socket` does not

### serder.md - Misleading: Postcard determinism claim
- **Doc claims:** "Postcard produces deterministic output"
- **Reality:** Postcard guarantees single-allocation encoding but NOT cross-version/platform determinism. Its `std` feature uses platform-dependent integer encoding. Only `no_std` mode with explicit endianness is deterministic.

## Bugs Identified

### BUG: `common.md` - `log_file` parameter documented as required
- **Doc claims:** `setup_panic_handler(process_name, log_file)` — implies `log_file` is required
- **Actual signature:** `setup_panic_handler(process_name: &str, log_file: Option<&str>)` — parameter is `Option`
- **Impact:** Misleading API documentation; callers may not know `None` is valid.

### BUG: `zero_copy.rs` - `FilePath::path()` on macOS returns `/proc/self/fd/...`
- **Issue:** The `FilePath` impl for `File` on Unix (`:128-133`) uses `/proc/self/fd/{fd}` which is Linux-only
- **Impact:** On macOS, this path doesn't exist. The method will succeed in constructing the PathBuf but will fail at I/O time if the path is used. The `copy_file_range` fallback at `:213` calls `src.path()?` which would fail on macOS for open files.

### BUG: `zero_copy.rs` - Fallback `copy_file_range` opens files by path, not fd
- **Issue:** Fallback at `:213` does `File::open(src.path()?)` — reopens files from the path returned by `FilePath`
- **Impact:** On macOS, `FilePath::path()` returns `/proc/self/fd/N` which doesn't exist, so the fallback will fail with a file-not-found error.

### BUG: `serder.rs` - `serialization_rkyv.rs` is orphaned dead code
- **Issue:** `src/serialization_rkyv.rs` exists but is NOT declared in `lib.rs` (no `mod serialization_rkyv`)
- **Impact:** File is unreachable dead code. It also misleadingly uses postcard (not rkyv) despite its name.

## Suggested Improvements

### common.md
1. Document the optional `log_file` parameter with `Option<&str>` type
2. Document the secondary panic log written to temp dir (`synvoid-{name}-panic.log` at `:33-44`)
3. Note that `setup_default_panic_handler` is defined but never called in production — it's a convenience wrapper only
4. Document error handling: `std::fs::write` and `set_permissions` errors are silently ignored via `let _ =`

### filter.md
1. Fix `Protocol::from_str` return type to `-> Self` (not `Option<Self>`)
2. Fix `BaseFilterConfig` allowlist/denylist types to `Vec<String>` (not `Vec<P>`)
3. Fix "Allow/Deny Priority" to "Denylist checked first, then allowlist" — matches the code
4. Add `PhantomData` fields to struct diagrams
5. Add trait bounds (`Clone + PartialEq + Eq + Debug + Send + Sync + 'static`)
6. Document `PortConfigBase` struct (exported in mod.rs but missing from docs)
7. Document the TCP `FilterConfig` struct with `block_unknown_ports` field (extends `BaseFilterConfig` with port blocking)
8. Document UDP-specific types: `UdpFilterAction` (with `RateLimit` and `Challenge` variants), `UdpFilterConfig` (with `amplification_threshold`, `max_response_size`, `port_overrides`)

### zero_copy.md
1. Fix `sendfile_to_socket` fallback: returns `Err`, not userspace copy
2. Document that `FilePath::path()` on Unix uses `/proc/self/fd/` (Linux-only; broken on macOS)
3. Document that `ZeroCopyReader`, `FilePath`, `sendfile_to_socket`, and `copy_file_range` have ZERO external callers — the entire module is dead code
4. Document that macOS `copy_file_range` uses `fcopyfile` (a userspace copy), not a true zero-copy kernel operation
5. Document that `copy_file_range` fallback reopens files by path, which is incorrect on macOS

### serder.md
1. Remove "deterministic" claim for Postcard or clarify it requires `no_std` with explicit endianness
2. Add note that `serialization_rkyv.rs` exists as a separate, unreachable file (dead code)
3. The doc says "Postcard for DHT/Mesh/Persistence" but should also note that `serder.rs` itself only provides rkyv re-exports and documentation — it doesn't implement any serialization
4. Document that the `rkyv` feature gate re-export is unused across the codebase

## Stale Content

### common.md
- **Stale claim:** "Integration Points → Main: Called at process startup" — `main.rs` does NOT call `setup_panic_handler` or `setup_default_panic_handler` directly. Worker modules call `setup_unified_server_panic_handler` / `setup_worker_panic_handler` which internally call `setup_panic_handler`.

### filter.md
- **Missing documentation:** No mention of `PortConfigBase` which is a public API exported from `src/filter/mod.rs:4`
- **Incomplete integration list:** Document mentions "ICMP Filter" and "HTTP Listener" but the actual primary consumers are TCP (`src/tcp/filter.rs`) and UDP (`src/udp/filter.rs`)

### zero_copy.md
- **Entire module is dead code:** `ZeroCopyReader`, `FilePath`, `sendfile_to_socket`, and `copy_file_range` have zero callers outside `zero_copy.rs` itself. The module is declared in `lib.rs` but never imported or used.
- **"Static Files" integration claim:** The doc claims "Static Files: High-performance file serving" as an integration point, but there are no references to `zero_copy` from `src/static_files/` or any other module.

### serder.md
- **Dead file:** `src/serialization_rkyv.rs` is NOT declared in `lib.rs` — it's unreachable. Its content is postcard-based serialization (not rkyv), and it unconditionally re-exports `rkyv` without a feature gate (incompatible with the library's rkyv feature gate).
- **Re-export is unused:** `#[cfg(feature = "rkyv")] pub use rkyv::{Archive, Deserialize, Serialize}` at `:114-117` has no consumers in the codebase.

## Cross-Reference Status

| Document | Cross-ref with AGENTS.md | Status |
|----------|-------------------------|--------|
| common.md | "Structured panic logging" / "Panic hook installation" | ✅ Aligned |
| filter.md | "Generic protocol matching" / "Allowlist/denylist filtering" | ✅ Aligned (but filter priority doc is wrong) |
| zero_copy.md | "Platform-specific kernel-level file-to-socket transfer" | ⚠️ Module exists but is dead code — not used by any integration point |
| serder.md | "Postcard preferred for DHT/Mesh/Persistence" | ✅ Serialization strategy matches AGENTS.md |
| serder.md | "Rkyv for hot paths requiring zero-copy" | ⚠️ Feature gate exists but re-export is unused |
| common.md | "File Permissions: Set 0o600 on private key files" pattern | ✅ Panic logs use 0o600 |
| filter.md | N/A (no direct AGENTS.md reference) | ✅ N/A |
