# Dependency Reduction Plan — MaluWAF

**Date**: 2026-03-27
**Goal**: Reduce total dependency load and binary size without reducing any current features or changing the overseer/master/worker architecture.

---

## Phase 1: Remove Dead Dependencies (zero risk, zero feature loss)

These crates are declared in `Cargo.toml` but never imported or called in any `.rs` file. Removing them has zero functional impact.

### 1.1 Remove `bincode`

- **File**: `Cargo.toml:76`
- **Evidence**: No `use bincode` anywhere. `serialize_bincode`/`deserialize_bincode` in `src/serialization.rs` are misnomers — they delegate to `postcard`, not bincode.
- **Action**: Delete `bincode = "1"` from `[dependencies]`
- **Feature loss**: None

### 1.2 Remove `wasmtime-wasi`

- **File**: `Cargo.toml:182`
- **Evidence**: No `use wasmtime_wasi` anywhere. `wasmtime` (line 181) is used in `src/plugin/wasm_runtime.rs` but `wasmtime-wasi` is never imported.
- **Action**: Delete `wasmtime-wasi = "36"` from `[dependencies]`
- **Feature loss**: None. Verify WASM plugin runtime still compiles after removal.
- **Verification**: `cargo check` and confirm `src/plugin/wasm_runtime.rs` still compiles.

### 1.3 Remove `ab_glyph`

- **File**: `Cargo.toml:123`
- **Evidence**: No `use ab_glyph` or `ab_glyph::` anywhere in the codebase.
- **Action**: Delete `ab_glyph = "0.2"` from `[dependencies]`
- **Feature loss**: None

### 1.4 Remove `flare`

- **File**: `Cargo.toml:124`
- **Evidence**: No `use flare` or `flare::` anywhere in the codebase.
- **Action**: Delete `flare = "0.1"` from `[dependencies]`
- **Feature loss**: None

### 1.5 Remove `memmap2`

- **File**: `Cargo.toml:119`
- **Evidence**: No `use memmap2` or `memmap2::` anywhere in the codebase.
- **Action**: Delete `memmap2 = "0.9"` from `[dependencies]`
- **Feature loss**: None

### 1.6 Remove `url`

- **File**: `Cargo.toml:101`
- **Evidence**: No `use url`, `url::`, or `Url::parse` in any `.rs` file. The `url` crate is transitively available from `axum`/`hyper` if needed, but nothing in this project directly imports it.
- **Action**: Delete `url = "2.5"` from `[dependencies]`
- **Feature loss**: None
- **Risk**: If any code uses `url::Url` via re-export from another crate (e.g., `axum`), this removal is still safe because Cargo resolves transitive dependencies independently. The direct `url = "2.5"` entry is only needed for direct imports.

### 1.7 Remove `futures-util`

- **File**: `Cargo.toml:95`
- **Evidence**: No `use futures_util::` anywhere. All code uses `use futures::` which re-exports everything from `futures-util`.
- **Action**: Delete `futures-util = "0.3"` from `[dependencies]`
- **Feature loss**: None. The `futures` crate at line 94 re-exports `futures-util` types (`SinkExt`, `StreamExt`, `FutureExt`, `future::join_all`, etc.).

---

## Phase 2: Trim Unused Feature Flags (zero risk, zero feature loss)

These dependency feature flags enable code paths that are never used. Trimming them reduces compile surface without changing behavior.

### 2.1 Remove `tower` "timeout" feature

- **File**: `Cargo.toml:61`
- **Current**: `tower = { version = "0.5", features = ["util", "timeout"] }`
- **Evidence**: Zero matches for `tower::timeout`, `tower::Timeout`, `TimeoutLayer`, `TimeoutService`. The project uses `tokio::time::timeout()` directly (359+ call sites).
- **Action**: Change to `tower = { version = "0.5", features = ["util"] }`
- **Feature loss**: None

### 2.2 Remove `tower-http` "trace" feature

- **File**: `Cargo.toml:62`
- **Current**: `tower-http = { version = "0.6", features = ["fs", "cors", "trace"] }`
- **Evidence**: Zero matches for `tower_http::trace`, `TraceLayer`, or any tracing middleware from tower-http. The project uses `tracing` directly for its own instrumentation.
- **Action**: Change to `tower-http = { version = "0.6", features = ["fs", "cors"] }`
- **Feature loss**: None

### 2.3 Remove `nix` "net" and "uio" features

- **File**: `Cargo.toml:97`
- **Current**: `nix = { version = "0.29", features = ["signal", "process", "socket", "fs", "net", "uio"] }`
- **Evidence**: Zero matches for `nix::net::` or `nix::uio::`. The used nix features are:
  - `signal` — 38 usages (SIGTERM, SIGKILL, SIGUSR1, etc.)
  - `process` — 30 usages (`unistd::Pid`, process management)
  - `socket` — 9 usages (`recvmsg`, `setsockopt`, `SockaddrIn`, etc.)
  - `fs` — 1 usage (`fcntl::flock` in `src/process/pidfile.rs`)
- **Action**: Change to `nix = { version = "0.29", features = ["signal", "process", "socket", "fs"] }`
- **Feature loss**: None

---

## Phase 3: Modernize `once_cell` (low effort, zero feature loss)

### 3.1 Replace `once_cell` with `std::sync::LazyLock`

- **File**: `Cargo.toml:83` and 10 source files
- **Rationale**: `std::sync::LazyLock` has been stable since Rust 1.80 (July 2024). The project compiles with Rust 1.93.0. This eliminates one crate from the dependency tree.
- **Evidence**: `once_cell::sync::Lazy` is used in 13 files (10 via `use` import, 3 via inline qualified path):

**Files with `use once_cell::sync::Lazy` import (10):**

| File | Line | Pattern |
|------|------|---------|
| `src/udp/listener.rs` | 10 | `use once_cell::sync::Lazy` — closure |
| `src/proxy.rs` | 24 | `use once_cell::sync::Lazy` — closure (x3) |
| `src/upload/malware_scanner.rs` | 2 | `use once_cell::sync::Lazy` — closure |
| `src/tunnel/wireguard/session.rs` | 6 | `use once_cell::sync::Lazy` — fn pointer |
| `src/tarpit/generator.rs` | 1 | `use once_cell::sync::Lazy` — closure |
| `src/waf/bot.rs` | 2 | `use once_cell::sync::Lazy` — fn pointer |
| `src/tunnel/quic/registry.rs` | 5 | `use once_cell::sync::Lazy` — fn pointer |
| `src/log_controller.rs` | 1 | `use once_cell::sync::Lazy` — closure |
| `src/mime/mod.rs` | 3 | `use once_cell::sync::Lazy` — closure |
| `src/waf/attack_detection/rfi.rs` | 2 | `use once_cell::sync::Lazy` — closure |

**Files with inline `once_cell::sync::Lazy` (3):**

| File | Lines | Pattern |
|------|-------|---------|
| `src/metrics/mod.rs` | 18-31 | 5 statics using `once_cell::sync::Lazy::new(\|\| ...)` |
| `src/waf/rule_feed.rs` | 12-13 | 1 static using `once_cell::sync::Lazy::new(\|\| ...)` |
| `src/upload/signature.rs` | 31-32 | 1 static using `once_cell::sync::Lazy::new(\|\| ...)` |

- **Actions**:
  1. For the 10 files with `use once_cell::sync::Lazy`: replace import with `use std::sync::LazyLock`
  2. For the 3 files with inline `once_cell::sync::Lazy`: add `use std::sync::LazyLock;` and replace inline references
  3. In all 13 files: replace all `Lazy::new(...)` / `once_cell::sync::Lazy::new(...)` with `LazyLock::new(...)`
  4. Delete `once_cell = "1"` from `Cargo.toml`
- **Feature loss**: None. `LazyLock` has identical API to `once_cell::sync::Lazy` (both accept closures and function pointers via `FnOnce() -> T`).

---

## Phase 4: Feature-Gate DNS Dependencies (medium impact, zero feature loss when dns enabled)

These 7 crates are used exclusively inside `src/dns/` (which is gated by `#[cfg(feature = "dns")]`). However, they are currently non-optional in `Cargo.toml`, so they compile even when the `dns` feature is disabled. Making them optional eliminates unnecessary compilation when `dns` is off, while preserving full functionality when `dns` is on (the default).

### 4.1 Make DNS-specific crates optional

- **File**: `Cargo.toml`
- **Crates affected**:

| Crate | Current line | Used only in |
|-------|-------------|--------------|
| `hickory-proto` | 106 | `src/dns/resolver.rs`, `src/dns/server/mod.rs` |
| `hickory-resolver` | 107 | `src/dns/resolver.rs` |
| `hickory-recursor` | 108 | `src/dns/resolver.rs` |
| `dns-parser` | 109 | `src/dns/recursive.rs`, `src/dns/recursive_cache.rs`, `src/dns/wire.rs` |
| `tokio-dstip` | 112 | `src/dns/anycast.rs` |
| `cryptoki` | 158 | `src/dns/hsm.rs` |
| `getrandom` | 111 | `src/dns/crypto_rng.rs` |

- **Actions**:
  1. Add `optional = true` to each of the 7 crate declarations
  2. Update the `dns` feature definition from `dns = []` to:
     ```toml
     dns = [
         "dep:hickory-proto",
         "dep:hickory-resolver",
         "dep:hickory-recursor",
         "dep:dns-parser",
         "dep:tokio-dstip",
         "dep:cryptoki",
         "dep:getrandom",
     ]
     ```
  3. Confirm `default` features still include `"dns"` (no change to default behavior)
- **Feature loss**: None when `dns` is enabled (default). When `dns` is disabled, these crates no longer compile — which is correct since the code that uses them is also excluded.
- **Verification note**: `getrandom` is also used by `src/wasm_pow/src/lib.rs`, but `wasm_pow` is a separate workspace member with its own `Cargo.toml` that declares its own `getrandom` dependency. No cross-dependency.

---

## Phase 5: Verification

After all changes, run the following to confirm no regressions:

### 5.1 Build verification

```bash
# Default features (dns, mesh, socket-handoff, post-quantum all ON)
cargo check

# With dns disabled (to verify optional gating works)
cargo check --no-default-features --features mesh,socket-handoff,post-quantum

# Release build for binary size comparison
cargo build --release 2>&1 | tail -5
```

### 5.2 Test verification

```bash
# Full test suite
cargo test

# Integration tests
cargo test --test integration_test

# DNS-specific tests
cargo test --features dns
```

### 5.3 Clippy verification

```bash
cargo clippy -- -D warnings
```

---

## Summary of Changes

| Phase | Dependencies removed | Feature flags trimmed | Files modified | Feature loss |
|-------|---------------------|----------------------|----------------|--------------|
| 1: Dead deps | 7 (bincode, wasmtime-wasi, ab_glyph, flare, memmap2, url, futures-util) | 0 | 1 (Cargo.toml) | None |
| 2: Unused flags | 0 | 4 (tower timeout, tower-http trace, nix net, nix uio) | 1 (Cargo.toml) | None |
| 3: Modernize | 1 (once_cell) | 0 | 14 (13 .rs + Cargo.toml) | None |
| 4: Feature gate | 0 (reclassified, not removed) | 1 (dns feature gains 7 deps) | 1 (Cargo.toml) | None (when dns enabled) |
| **Total** | **8 crate removals** | **5 flag removals** | **~15 files** | **None** |

### Expected impact

- **Binary size**: Reduction of 5-15 MB (estimated, depends on linker behavior). Largest wins from removing `memmap2` (C binding), `url` (idna/percent-encoding transitive tree), and enabling DNS feature gating to drop `hickory-*` + `ring` when DNS is disabled.
- **Compile time**: 7 fewer crates to compile in default builds. 14+ fewer when DNS is disabled.
- **Architecture**: No changes. Overseer/master/worker architecture unchanged. All IPC, process management, and worker lifecycle code untouched.
- **Feature set**: Identical. Every current feature, behavior, and API surface preserved.
