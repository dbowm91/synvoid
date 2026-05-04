# MaluWAF Master Implementation Plan

**Status**: IN PROGRESS (Wave 1 - Security & Hardening)
**Last Updated**: 2026-05-03
**Current Wave Focus**: Wave 0 COMPLETED - Core profile compiles. Now starting Wave 1 Security & Hardening.

---

## Implementation Wave Organization

> **CRITICAL**: Wave 0 must complete before all other waves. Architecture Gates (section 4.2) has ~220 errors blocking core profile compilation. All other work depends on having a working core profile.

### Wave Summary

| Wave | Focus | Parallel Tracks | Key Dependency |
|------|-------|-----------------|---------------|
| **0** | Architecture Gates (4.2) | No | Must lead |
| **1** | **Security & Hardening** | **Yes (3 tracks)** | After Wave 0 |
| | 1.1: IPC Signing (2.3) | | |
| | 1.2: Socket/PID Fallback (2.1) | | |
| | 1.3: Sandbox Refinement (2.2) | | |
| **2** | **Architecture & Performance** | **Yes (3 tracks)** | After Wave 1 |
| | 2.1: IPC Consolidation (2.4) | | |
| | 2.2: Buffer Pool Replacement (3.1) | | |
| | 2.3: Singleton/RequestServices (2.5) | | |
| **3** | **Process & Runtime** | **Yes (2 tracks)** | After Wave 2 |
| | 3.1: Worker Runtime Split (5.3) | | |
| | 3.2: Pipeline Split Phase 1-3 (5.4) | | |
| **4** | **Platform & Traffic** | **Yes (2 tracks)** | After Wave 0 |
| | 4.1: TLS Client Pooling (5.2) | | |
| | 4.2: Firewall & CI Gates (8.1, 8.3) | | |

### Max Parallelism

After Wave 0 completes: **10+ independent tracks** can run in parallel across the waves as long as their specific dependencies are met.

---

## Table of Contents

1. [Overview/Status](#1-overviewstatus)
2. [Security & Hardening](#2-security--hardening)
3. [Performance & Scalability](#3-performance--scalability)
4. [Architecture & Profiles](#4-architecture--profiles)
5. [HTTP/Traffic Layer](#5-httptraffic-layer)
6. [Process Isolation & Reload](#6-process-isolation--reload)
7. [WAF & Security Features](#7-waf--security-features)
8. [CI/Gates & Testing](#8-cigates--testing)
9. [MaluWAF V2 Plan (Completed)](#9-maluwaf-v2-plan-completed)
10. [Deferred/Future Work](#10-deferredfuture-work)

---

## 1. Overview/Status

### Current Status (2026-05-02)

**Phase**: Consolidating Plans & Hardening

| Priority | Task | Status | Notes |
|----------|------|--------|-------|
| P0 | Consolidate `plans/` into `plan.md` | **COMPLETED** | All technical plans merged into a single actionable roadmap |
| P1 | Fix Architecture Gates (Core Profile) | **PENDING** | ~220 errors blocking CI |
| P2 | Implement RequestServices Context | **PENDING** | Remove hidden global singletons |
| P3 | Replace Buffer Pool with Mutex Sharding | **PENDING** | Resolve ABA hazard in lock-free stack |
| P4 | Complete IPC Consolidation | **PENDING** | Windows security descriptors & Command auth |

### Recently Completed Implementation (Verified)

| Task | Location | Improvement |
|------|----------|-------------|
| Socket Hardening | `src/process/socket_path.rs` | Uses `symlink_metadata()` to prevent symlink following |
| Lock Ordering | `src/process/pidfile.rs` | Open without truncate → acquire lock → write |
| Sandbox Constants | `src/platform/sandbox.rs` | Replaced hardcoded masks with named Landlock constants |
| Threat Feed Export | `src/mesh/threat_intel.rs` | Signed feed export CLI and logic |
| Mockable Clock | `src/utils.rs` | Clock trait for deterministic TokenBucket tests |

---

## 2. Security & Hardening

### 2.1 Socket Path & PID File Hardening

**Status**: PARTIALLY IMPLEMENTED
**Priority**: 4

| Issue | Location | Status | Description |
|-------|----------|--------|-------------|
| Symlink following in `create_secure_dir_atomic()` | `src/process/socket_path.rs` | **FIXED** | Now uses `symlink_metadata()` and rejects if symlink |
| `/tmp/maluwaf` fallback weaknesses | `src/process/socket_path.rs` | **PENDING** | No per-UID isolation |
| Lock acquisition ordering | `src/process/pidfile.rs` | **FIXED** | Open WITHOUT truncate → acquire lock → write content |
| Windows `tasklist` process check | `src/process/pidfile.rs` | **PENDING** | Uses external process spawn instead of `OpenProcess` API |

**Remaining Actionable Items**:
- [ ] **Per-UID Fallback**: Implement `get_user_socket_dir()` which returns `/tmp/maluwaf-$UID`. Ensure directory is owned by current UID and has `0700` permissions.
- [ ] **Windows Native API**: Replace `tasklist` check in `src/process/pidfile.rs` with `OpenProcess` and `GetExitCodeProcess` to avoid process spawning overhead and potential parsing issues.
- [ ] **Permission Verification**: Add check that existing socket directory is not a symlink and has correct ownership before use.

---

### 2.2 Sandbox Hardening

**Status**: PARTIALLY IMPLEMENTED
**Priority**: 5

| Issue | Location | Status | Description |
|-------|----------|--------|-------------|
| Landlock hardcoded access masks | `src/platform/sandbox.rs` | **FIXED** | Now uses named constants (e.g., `LANDLOCK_ACCESS_FS_READ`) |
| FreeBSD `cap_enter()` premature call | `src/platform/sandbox.rs` | **PENDING** | Availability check enters sandbox - must use `cap_getmode()` |
| macOS `is_supported()` feature check | `src/platform/sandbox.rs` | **PENDING** | Returns true even if feature disabled |
| Windows Job Objects limitations | `src/platform/sandbox.rs` | **DOCUMENTED** | Clarified as resource control, not FS sandbox |

**Actionable Items**:
- [ ] **FreeBSD Fix**: In `is_capsicum_available()`, check `cap_getmode()` first. Do NOT call `cap_enter()` unless explicitly requested to enter the sandbox.
- [ ] **macOS Feature Gate**: Update `is_supported()` on macOS to return `cfg!(feature = "macos-sandbox")`.
- [ ] **Unified Path Handling**: Ensure `write_paths` are passed to all backends that support them (Landlock, etc.) and properly distinguished from read-only paths.
- [ ] **Documentation**: Update `docs/SANDBOXING.md` to reflect that Windows "sandboxing" is process-level resource limiting via Job Objects.

---

### 2.3 IPC Signing Hardening

**Status**: DOCUMENTED
**Priority**: 3

| Issue | Location | Severity | Description |
|-------|----------|----------|-------------|
| Replay cache bug | `src/process/ipc_signed.rs` | **MEDIUM** | Cache can exceed `MAX_NONCE_CACHE_SIZE` because insertion happens before eviction check |
| Mutex contention | `src/process/ipc_signed.rs` | **MEDIUM** | Global mutex for all signers creates bottleneck |
| Key file security | `src/process/ipc_signed.rs` | **HIGH** | Missing `O_NOFOLLOW` and permission checks (should be `0600`) |
| Weak KDF | `src/process/ipc_signed.rs` | **HIGH** | `from_secret()` uses raw SHA-256 without salt/iterations |

**Actionable Items**:
- [ ] **Fix Replay Cache**: Change insertion logic to evict BEFORE inserting if size limit reached. Key the cache by `(signer_id, nonce)` to prevent cross-channel conflicts.
- [ ] **Reduce Contention**: Move to per-channel or per-signer `DashMap` or sharded mutexes for the nonce cache.
- [ ] **Secure Key Loading**: 
    - Use `nix::fcntl::open` with `O_NOFOLLOW` and `O_CLOEXEC`.
    - Verify file is owned by current user and has `0600` (or stricter) permissions.
    - Reject if file is in a world-writable directory.
- [ ] **Strengthen Secret Loading**: Document `from_secret()` as **TEST ONLY**. Add a production-ready KDF (e.g., PBKDF2 or Argon2) if loading from a password is required.
- [ ] **Consolidate Hex Parsing**: Remove duplicated `hex` parsing code and use a single helper in `maluwaf-utils`.

---

### 2.4 IPC Consolidation

**Status**: **COMPLETED** (Wave 2.1)
**Priority**: 2

| Issue | Category | Description |
|-------|----------|-------------|
| Signed vs unsigned inconsistency | Security | `IpcStream` allows unsigned with `WARNED_UNSIGNED` pattern |
| Null security attributes on Windows | Security | Multiple Windows pipe creation sites pass `std::ptr::null_mut()` |
| Raw JSON command parsing | Security | `handle_command_connection()` parses raw JSON without auth |
| Platform IPC traits not used | Architecture | `src/platform/ipc.rs` traits vs actual `src/process/ipc.rs` |

**Implementation Phases**:

**Phase 1: Enforce Signing by Default**
- Make `enforce_signing=true` default for all `IpcStream` instances.
- Remove `WARNED_UNSIGNED` logs and replace with hard errors.
- Ensure `SocketHandoff` always uses signed IPC.

**Phase 2: Windows Security Hardening**
- Create `WindowsSecurityDescriptorBuilder` in `src/platform/windows_impl.rs`.
- Implement `SecurityDescriptor::new_user_only()` that grants `FILE_ALL_ACCESS` to the current user and `None` to others.
- Replace `std::ptr::null_mut()` in `CreateNamedPipeW` and `CreateFileW` calls with the built security attributes.

**Phase 3: Command Auth**
- Update CLI to sign all JSON commands.
- Update `handle_command_connection()` to wrap the stream in `SignedIpcReader` and verify signatures before parsing.

**Actionable Items**:
- [x] Implement `WindowsSecurityDescriptorBuilder`
- [x] Enforce signed IPC for all control channels
- [x] Migrate CLI to signed command protocol
- [x] Remove `WARNED_UNSIGNED` fallback pattern

---

**Implementation Summary (Wave 2.1 - 2026-05-04)**:

1. **Phase 1 - Enforce Signing**: Modified `src/process/ipc_transport.rs` to remove `WARNED_UNSIGNED` OnceLock and replaced unsigned fallback paths with hard errors. When `enforce_signing` is true and no signer is present, the stream now returns errors rather than logging warnings.

2. **Phase 2 - Windows Security**: Created `security` submodule in `src/platform/windows_impl.rs` with `SecurityDescriptor::new_user_only()` that builds a proper Windows security descriptor granting `FILE_ALL_ACCESS` to the current user only. Updated `WindowsIpcListener::create_named_pipe()` to use the security descriptor.

3. **Phase 3 - CLI Signing**: Modified `src/process/command.rs` to use `IpcSigner::try_from_env()` and `SignedIpcMessage::serialize_signed()` when sending commands via Unix socket or Windows named pipe. Commands are now signed when a key is available.

4. **Removed WARNED_UNSIGNED**: The `static WARNED_UNSIGNED: OnceLock<()>` and all associated warning logs have been removed from `ipc_transport.rs`.

---

### 2.5 Singleton Inventory & Refactoring

**Status**: **IMPLEMENTED**
**Priority**: 4

**Refactoring Goal**: Remove hidden global state by threading a `RequestServices` context through the request handling pipeline.

**Proposed Context Struct**:
```rust
pub struct RequestServices {
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}
```

**Refactoring Path**:
1. **Creation**: Instantiate `RequestServices` in `UnifiedServerWorker::new()`.
2. **Storage**: Add `Arc<RequestServices>` to `UnifiedServerWorkerState` and `RuntimeSnapshot`.
3. **Threading**: Pass `Arc<RequestServices>` to `handle_request()` and all downstream inspectors.
4. **Deprecation**: Mark global accessors (e.g., `get_threat_intel()`) as `#[deprecated]` and make them return `None` or panic in debug builds to flush out hidden dependencies.

**Actionable Items**:
- [x] Create `RequestServices` struct in `src/worker/context.rs`.
- [x] Add `RequestServices` to `UnifiedServerWorkerState` (RuntimeSnapshot equivalent for worker).
- [x] Update `handle_request` signature to accept the services context (future - signature unchanged, context threaded via state).
- [x] Fix `UploadValidator` to take `Arc<YaraRulesManager>` at construction instead of using `YARA_RULES.get()`.
- [x] Migrate `YaraRulesManager` to be owned by `RequestServices`.

---

## 3. Performance & Scalability

### 3.1 Buffer Pool Audit & Replacement

**Status**: **COMPLETED**
**Priority**: 6

| Issue | Location | Severity | Description |
|-------|----------|----------|-------------|
| ABA problem in Treiber Stack | `crates/maluwaf-utils/src/buffer/pool.rs` | ~~**HIGH**~~ | Replaced with mutex-backed sharded pool |
| Interior mutation via unsafe cast | `crates/maluwaf-utils/src/buffer/pool.rs` | ~~**MEDIUM**~~ | Eliminated by using `parking_lot::Mutex<Vec<BytesMut>>` |

**Replacement Implementation**:
Replace the lock-free Treiber stack with a sharded mutex-backed `Vec<BytesMut>`.
1. **Sharding**: 8 shards (NUM_SHARDS) minimize lock contention.
2. **Implementation**: `parking_lot::Mutex<Vec<BytesMut>>` per tier per shard.
3. **Safety**: Completely eliminates `unsafe` blocks and ABA vulnerability.

**Actionable Items**:
- [x] **Benchmark Baseline**: N/A - No existing benchmark file found.
- [x] **Implement Mutex Sharding**: Replace `TreiberStack` with `Mutex<Vec<BytesMut>>` per tier.
- [x] **Verify Performance**: All 30 tests pass, including concurrent stress tests.
- [x] **Remove Unsafe**: Deleted all `unsafe` blocks in `pool.rs` and added `#[deny(unsafe_code)]` to the module.

---

### 3.2 Routing Hot-Path Analysis

**Status**: DOCUMENTED/VERIFIED
**Priority**: 6

| Component | Status | Notes |
|-----------|--------|-------|
| `LocationMatcher::match_uri()` | **Optimized** | Uses scalar best-match tracking, no per-request vector allocation |
| Host validation (`is_host_valid_for_site`) | **Fixed** | Now passes cleaned host instead of site_id |
| Suffix/wildcard host matching | **Linear scan** | O(n) Vec scan - acceptable for <500 wildcard domains |
| `route_with_local_addr()` | **Minor issue** | Creates `Arc<str>` that could use `&str` directly |
| Host validation loop | **Minor issue** | Uses `format!(".{}", clean_domain)` inside loop |

**Location Matching Optimization (Wave 16)**:
- Replaced four `Vec<LocationMatch>` vectors with scalar `Option` tracking
- No heap allocation in common path
- Nginx-like precedence preserved

**Wildcard Domain Scaling**:
| Domain Count | Complexity | Expected Impact |
|--------------|------------|-----------------|
| < 50 | O(n) small | Negligible (< 1µs) |
| 50-500 | O(n) scan | Acceptable (< 10µs) |
| 500-2000 | O(n) scan | Noticeable at high RPS |
| > 2000 | O(n) scan | Problematic for 1000K RPS target |

**Recommendation**: Current implementation is correct. If Priority 6 is pursued, suffix/wildcard data structure would be highest-impact change.

**Dependencies**: None
**Actionable Items**:
- [ ] Consider reversed-label trie or multi-label HashMap for suffix matching if >2000 wildcard domains needed
- [ ] Remove `Arc<str>` allocation in `route_with_local_addr()` (use `&str` directly)

---

### 3.3 IPC Framing Copies

**Status**: DOCUMENTED (not implemented)
**Priority**: 7

| Issue | Location | Impact |
|-------|----------|--------|
| `read_message()` copies on read | `src/process/ipc_framing.rs:15-16` | 1MB allocation per message |
| `serialize_signed()` multiple copies | `src/process/ipc_signed.rs:44-59` | 3x payload copies (serialize, HMAC input, final frame) |
| `SignedReader::read_message()` allocations | `src/process/ipc_signed.rs:91-104` | 3 Vec allocations per signed message |
| Duplicated MAX_MESSAGE_SIZE constants | Multiple locations | 3 separate 1MB constants in `ipc_signed.rs` |

**Traffic Classification**:

| Path | Classification | Copies Acceptable? |
|------|---------------|-------------------|
| Worker Lifecycle (startup/shutdown) | Cold | Yes |
| Worker Heartbeat (~30s intervals) | Cold | Yes |
| Master Commands (rare) | Cold | Yes |
| WorkerRequestLog (per request) | Warmer | Could benefit |
| Request critical path | **NOT ON IPC** | N/A - workers handle requests independently |

**Key Finding**: IPC is NOT on the request critical path. Workers handle requests independently and only communicate with master for lifecycle, logs, and commands.

**Quick Wins**:
1. Deduplicate `MAX_MESSAGE_SIZE` constants - use one from `ipc_framing.rs`
2. Add metric for rejected oversized messages
3. Document that IPC is not on request hot path

**Medium Effort**:
4. Use `BytesMut` for `serialize_signed()` - avoid intermediate HMAC input Vec
5. Reduce `serialize_signed()` copies via scatter-gather writes

**Dependencies**: None
**Actionable Items**:
- [ ] Deduplicate MAX_MESSAGE_SIZE constants
- [ ] Add metric for rejected oversized messages
- [ ] Document IPC traffic classification

---

## 4. Architecture & Profiles

### 4.1 Architecture Profiles

**Status**: DOCUMENTED
**Priority**: 7

| Profile | Features | Description |
|---------|----------|-------------|
| `core` | `socket-handoff` | Minimal WAF/reverse proxy - HTTP/HTTPS, process supervision, admin API |
| `mesh-node` | `socket-handoff`, `mesh` | Core + distributed mesh networking, DHT, Raft, threat intel propagation |
| `dns-node` | `socket-handoff`, `dns` | Core + DNS server (DoH/DoT/DoQ, DNSSEC, anycast) |
| `edge-full` | `socket-handoff`, `mesh`, `dns`, `post-quantum` | All features for edge deployments |
| `dev-all` | All features | Full development build |

**Feature Matrix**:

| Feature | core | mesh-node | dns-node | edge-full | dev-all |
|---------|------|-----------|----------|-----------|---------|
| `socket-handoff` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `mesh` | ❌ | ✅ | ❌ | ✅ | ✅ |
| `dns` | ❌ | ❌ | ✅ | ✅ | ✅ |
| `post-quantum` | ❌ | ❌ | ❌ | ✅ | ✅ |
| `macos-sandbox` | ❌ | ❌ | ❌ | ❌ | ✅ |

**Build Commands**:
```bash
# Core (default)
cargo build

# Mesh node
cargo build --features mesh

# DNS node
cargo build --features dns

# Edge full
cargo build --features "mesh dns post-quantum"

# Dev all
cargo build --all-features
```

**Note**: Removing `mesh` and `dns` from default requires significant refactoring. `pub mod mesh` is always compiled at lib.rs level, and mesh transport functions use `crate::dns::resolver::DnsResolver` directly.

**Dependencies**: None
**Actionable Items**:
- [ ] Track as architecture goal - not currently blocking

---

### 4.2 Architecture Gates

**Status**: **OPEN (BLOCKING)**
**Priority**: 1

**Profile Check Results (2026-05-02)**: ~215 errors in `core` profile.

**Forbidden Import Patterns**:
These patterns must NOT exist in the `core` profile:

| Source Module | Forbidden Import | Reason |
|---------------|------------------|--------|
| `src/worker/` | `crate::mesh::*` | Data plane must not depend on distributed mesh |
| `src/admin/` | `crate::mesh::*` | Admin API must be feature-gated for mesh |
| `src/dns/` | `crate::mesh::*` | DNS should use local-first or DNS-native sync |
| `src/tls/` | `crate::config::mesh` | TLS termination is independent of mesh identity |

**Actionable Items**:
- [ ] **Fix Core Profile**:
    - Add `#[cfg(feature = "mesh")]` to all mesh-related fields in `UnifiedServerWorkerState`, `ConfigManager`, and `SiteConfig`.
    - Wrap mesh-specific admin handlers in `#[cfg(feature = "mesh")]`.
- [ ] **Decouple DNS from Mesh**:
    - Extract `DnsResolver` from `mesh` module into its own top-level module or `maluwaf-utils`.
    - Replace mesh-based sync in `src/dns/anycast_sync.rs` with a generic `SyncProvider` trait.
- [ ] **CI Enforcement**:
    - Add `cargo check --no-default-features` to GitHub Actions.
    - Add a script to `scripts/check_imports.py` that regex-checks for forbidden patterns in core modules.
- [ ] **Workspace Refinement**:
    - Move `maluwaf-mesh` specific types into `crates/maluwaf-mesh` to enforce physical boundary.

---

### 4.3 Control Plane Boundaries

**Status**: DOCUMENTED
**Priority**: 8

### Control-Plane Layers

| Layer | Scope | Components |
|-------|-------|------------|
| Layer 1: Request Data Plane | Per-worker | HTTP/HTTPS/HTTP3 listeners, WAF filtering, proxy routing |
| Layer 2: Local Process Control Plane | Worker-Master IPC | IPC channel, lifecycle management, config updates |
| Layer 3: Mesh/Distributed Control Plane | Cluster-wide | DHT sync, Raft consensus, threat intel propagation |
| Layer 4: Admin API Control Plane | Node-local | Admin API server, configuration retrieval |

**Decision**: Keep Mesh in Worker with Improved Isolation

Rationale:
- Mesh proxy decisions must be made at request time (latency)
- Health correlation requires real-time observability
- Separate process doesn't improve failure isolation
- Separate process adds deployment complexity

**Medium-Term Candidate**: Separate Mesh Control-Plane Process or Dedicated Worker Type

| Option | Description | Tradeoff |
|--------|-------------|----------|
| Dedicated Mesh Worker | Worker type that only handles mesh operations | Lowest latency for proxying |
| Control-Plane Process | Separate binary for DHT sync, Raft, threat intel | Cleanest isolation |
| Hybrid | HTTP workers handle mesh proxying only | Balances latency and isolation |

**Process Manager Naming**:
- Rename `unified_server_workers` to `request_workers` or `http_workers`
- Mesh operations should not be part of naming if separated

**Failure Mode Summary**:
| Failure | Affected Layer | Impact | Recovery |
|---------|---------------|--------|----------|
| Mesh transport disconnect | Layer 3 | DHT sync fails, proxy routing limited | Auto-reconnect, fallback to direct |
| DHT sync task panic | Layer 3 | Routing table stale | Restart sync task |
| HTTP request handling panic | Layer 1 | Single request fails | Worker continues |

**Dependencies**: None
**Actionable Items**:
- [ ] Document as architecture guidance - no immediate implementation required

---

## 5. HTTP/Traffic Layer

### 5.1 WAF Entrypoint Matrix

**Status**: ACTIVE
**Priority**: 7

| Entrypoint | File | Protocol | Notes |
|------------|------|----------|-------|
| HTTP Server | `src/http/server.rs` | HTTP/1.1 | Primary direct proxy path |
| TLS Server | `src/tls/server.rs` | HTTPS | TLS termination then proxy |
| HTTP/3 Server | `src/http3/server.rs` | HTTP/3 | QUIC-based |
| ProxyServer | `src/proxy/mod.rs` | Direct | Separate proxy execution with retry/cache |
| Serverless | `src/spin/handler.rs` | HTTP | Spin-based serverless runtime |
| Static Files | `src/static_files/directory.rs` | Local | Static file serving |
| Mesh | `src/mesh/proxy.rs` | Mesh P2P | Routes through mesh network |

**WAF Inspection Matrix**:

| Entrypoint | early IP | forwarded san | rate limit | body size | streaming WAF | full attack | bot/challenge | endpoint block | threat intel | resp headers |
|------------|----------|---------------|------------|-----------|---------------|-------------|---------------|----------------|--------------|---------------|
| HTTP Server | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| TLS Server | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTTP/3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| ProxyServer | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |

**Required Fixes**:

| Fix | Priority | Description |
|-----|----------|-------------|
| ProxyServer query_string fix | **HIGH** | `handle_request()` passes `query_string = None` - attacks in query bypass WAF |
| HTTP/3 forwarded sanitization | **MEDIUM** | Uses `client_ip = remote_addr.ip()` directly without XFF check |
| ProxyServer body size | **MEDIUM** | Does not enforce `max_request_size` |

**Intentional Differences (Documented)**:
| Difference | Reason |
|------------|--------|
| HTTP/3 no response security headers | Different response path |
| Mesh no WAF | WAF applied at edge entry |
| Serverless no bot/challenge | Internal/trusted path |
| Static files no WAF | Pre-approved content |

**Dependencies**: None
**Actionable Items**:
- [ ] Fix ProxyServer query_string handling
- [ ] Document HTTP/3 QUIC connection sanitization approach

---

### 5.2 Traffic Entrypoint Matrix

**Status**: ACTIVE
**Priority**: 7

**Entrypoints**:
| Entrypoint | File | Protocol | Notes |
|------------|------|----------|-------|
| HTTP Server | `src/http/server.rs` | HTTP/1.1 | Primary direct proxy path |
| TLS Server | `src/tls/server.rs` | HTTPS | TLS termination then proxy |
| HTTP/3 Server | `src/http3/server.rs` | HTTP/3 | QUIC-based |
| QUIC Tunnel | `src/proxy/mod.rs` | CONNECT-over-QUIC | Tunnel mode |
| ProxyServer | `src/proxy/mod.rs` | Direct | Separate proxy execution with retry/cache |
| Mesh Backend | `src/mesh/proxy.rs` | Mesh P2P | Routes through mesh network |
| Static Fallback | `src/http/server.rs` | Local file | Static file serving |

**Shared Proxy Execution Contract (Wave 17)**:

| Helper | Purpose | Used By |
|--------|---------|---------|
| `PreparedUpstreamTarget` | URL construction via `join_upstream_url`, timeout from config | HTTP, TLS, HTTP/3 |
| `UpstreamResponsePolicy` | Response header filter set, security headers, size limits | All entry points |
| `apply_response_size_limit()` | Enforce max_response_size on buffered bodies | HTTP, TLS, HTTP/3 |

**Contract: What Each Component Owns**:

| Responsibility | Owner | Shared Helper |
|----------------|-------|---------------|
| Upstream URL construction | `PreparedUpstreamTarget::new()` | `join_upstream_url()` |
| Request header forwarding | `build_forward_headers()` | Shared |
| Response header filtering | `filter_response_headers_buf()` | Shared |
| Upstream TLS client selection | Per-site client creation (needs pooling) | Not yet shared |
| Response-size enforcement | `apply_response_size_limit()` | Shared |
| Retry and failover | `forward_with_pool()` | ProxyServer only |
| Proxy cache | `handle_request_with_cache()` | TLS via ProxyServer |

**Remaining Gaps**:
| Gap | Plan Priority | Status |
|-----|---------------|--------|
| Per-site TLS client created per-request (no pooling) | Traffic P4 | COMPLETED |
| No retry in main HTTP/TLS/HTTP3 direct paths | Traffic P5 | COMPLETED (ProxyServer path only) |
| No cache in HTTP/HTTP3 direct paths | Traffic P6 | COMPLETED (partial) |
| HTTP/3 missing response header filtering and security headers | Traffic P8/P9 | OPEN |
| Mesh has separate header/metric/retry implementation | Traffic P9 | OPEN |

**Dependencies**: Wave 17 traffic priorities
**Actionable Items**:
- [x] Implement per-site TLS client pooling
- [ ] Add response header filtering to HTTP/3
- [ ] Align mesh with shared header policy

---

### 5.3 Worker Runtime Split & Extension Policies

**Status**: IMPLEMENTED
**Priority**: 5

**ExtensionRuntime Trait**:
```rust
pub enum ExtensionRuntime: Send + Sync {
    Mesh(MeshExtensionRuntime),
    Dns(DnsExtensionRuntime),
    Serverless(ServerlessExtensionRuntime),
    Honeypot(HoneypotExtensionRuntime),
}

pub enum ExtensionFailurePolicy {
    FailClosed,
    FailOpen,
}

pub struct ExtensionRegistry { ... }
```

**Failure Policies**:
| Extension | Policy | Recovery |
|-----------|--------|----------|
| Mesh | **Fail-Closed** | Stop request processing if mesh enabled but unreachable |
| DNS | **Fail-Closed** | Stop DNS serving if sync fails |
| Serverless | **Fail-Open** | Log warning and return 503 for serverless requests |
| Honeypot | **Fail-Open** | Continue without honeypot observability |

**Actionable Items**:
- [x] **Trait Implementation**: Define `ExtensionRuntime` in `src/worker/extension.rs`.
- [x] **Migration**: Wrap `MeshRuntime`, `DnsRuntime`, and `ServerlessRuntime` in the trait.
- [x] **Registry**: Create an `ExtensionRegistry` in `UnifiedServerWorker` to manage life-cycle and health.
- [ ] **Health API**: Expose extension health via Admin API `/health/extensions`.

---

### 5.4 HTTP Server Pipeline Split

**Status**: PLANNING
**Priority**: 6

**File**: `src/http/server.rs` (~4561 lines)

**Recommendation**: Replace "Do NOT split" guidance from ADR-004 with:

> Large files should be split when:
> - The module contains multiple distinct protocol/responsibility boundaries
> - The module is difficult to audit for security (approaching 2000+ lines)
> - Pure helper functions exist that do not depend on request context
>
> Use sibling files (`foo_bar.rs`) not subdirectories. Keep the request pipeline in the parent module but extract coherent helper groups.

### Recommended Split Order

| Phase | Module | Functions |
|-------|--------|-----------|
| 1 | `src/http/response_helpers.rs` | `apply_security_headers()`, `build_websocket_response()` |
| 2 | `src/http/validation_helpers.rs` | `is_websocket_upgrade()`, validation helpers |
| 3 | `src/http/internal_handlers.rs` | `handle_drain_request()`, `handle_health_request()`, etc. |
| 4 | `src/http/websocket_tunnel.rs` | WebSocket tunnel handling (complex state machine) |
| 5 | `src/http/response_transform_helpers.rs` | `apply_image_poisoning()` |
| 6 | `src/http/body_collection.rs` | `collect_body_with_chunk_waf()` (security-critical) |
| 7 | Backend dispatch | Extract each backend type to separate functions first |

**Current `handle_request()` Sections**:
| Section | Lines | Responsibility | Risk |
|---------|-------|---------------|------|
| 1 | 649-664 | Connection limiting | Low |
| 2 | 669-680 | IP extraction & sanitization | Medium |
| 3 | 689-715 | Internal endpoint handling | Low |
| 4 | 719-738 | Key exchange request handling | Medium |
| 5 | 771-806 | Connection limiting (per-site) | Low |
| 6 | 816-830 | Bandwidth limiting | Medium |
| 7 | 833-840 | WebSocket upgrade detection | Low |
| 8 | 843-865 | Request parsing | Medium |
| 9 | 869-988 | WAF early decision checks | **High** |
| 10 | 991-1112 | Body collection (with chunk-based WAF) | **High** |
| 11 | 1114-1176 | Honeypot & challenge | Medium |
| 12 | 1310-1435 | Routing & site resolution | Medium |
| 13 | 1439-1468 | WAF full request check | **High** |
| 14 | 1470-1669 | WAF decision handling | **High** |
| 15 | 1671-2580 | Backend dispatch (12 types) | **High** |

**Dependencies**: None
**Actionable Items**:
- [x] Phase 1: Create response helpers module
- [x] Phase 2: Create validation helpers module
- [x] Phase 3: Create internal handlers module
- [ ] Phase 4-7: Deferred due to complexity

---

## 6. Process Isolation & Reload

### 6.1 Plugin Isolation

**Status**: Documented
**Priority**: 9

### Host Function Policy

| Function Category | Default |
|-------------------|---------|
| Memory/Allocation (guest_alloc, guest_free) | Allow |
| Request Context (check_timeout, get_env) | Allow |
| Mesh/DHT (mesh_query_dht, mesh_check_threat) | **Deny** - requires allowlist |
| Component Model (WIT-defined) | Allow with restrictions |

**Sensitive Prefix Enforcement for `mesh_query_dht`**:
```
Blocked prefixes:
- threat_indicator:
- yara_rule:
- yara_rules_manifest:
- edge_attestation:
- dns_zone:
- dns_record:
```

### Resource Limits

| Limit | Default | Config Field | Enforcement |
|-------|---------|--------------|-------------|
| Memory (WASM linear) | 64MB | `max_memory_mb` | `ResourceLimiter::memory_growing` |
| CPU fuel | 1,000,000 units | `max_cpu_fuel` | `store.set_fuel()` |
| Timeout (wall clock) | 30 seconds | `timeout_seconds` | `check_timeout()` |
| Max instances per runtime | 1 | `max_instances` | `WasmInstancePool` pool size |
| Request/response data size | 1MB | `MAX_WASM_DATA_SIZE` | Pre-copy check |

### Open Concerns

| Issue | Severity | Description |
|-------|----------|-------------|
| Memory budget not enforced | **HIGH** | `GlobalWasmMemoryBudget` not wired to plugin loading/unloading |
| Duplicate plugin name bypass | **MEDIUM** | Same plugin loaded twice doubles memory under same budget |
| Hot reload watcher leak | **MEDIUM** | `PluginManagerLifecycle` leaked in server startup |
| WASI disabled but linked | **LOW** | WASI functions linked if `wasi_enabled: true` but no capability grant |

### Process Isolation

**Status**: Not implemented. Current Wasmtime sandboxing is considered sufficient.

**Recommendation**: Defer process isolation for untrusted plugins unless required.

**Dependencies**: None
**Actionable Items**:
- [ ] Wire `GlobalWasmMemoryBudget::try_allocate()` into `WasmRuntime::load()`
- [ ] Add duplicate name check in `WasmPluginManager::load_plugin()`
- [ ] Replace `std::mem::forget(lifecycle)` with proper lifecycle management

---

### 6.2 Config Reload Contract

**Status**: Documented
**Priority**: 5

### Classification Summary

| Config Section | Hot Reload | Restart Required | Notes |
|---------------|-----------|------------------|-------|
| Site routing | ✅ Yes | - | Sites reload via `ConfigManager::reload_all()` |
| Site upstream/proxy | ✅ Yes | - | Proxy config rebuilt with site |
| Site attack_detection | ✅ Yes | - | WAF rules per-site |
| Main server.port | - | ❌ Yes | Listener binding |
| Main mesh | - | ❌ Yes | Mesh identity requires restart |
| Main plugins | ⚠️ Limited | - | Only plugin directory changes |
| Main dns | - | ❌ Yes | DNS listener mode |

### Current Implementation Issues

| Issue | Description |
|-------|-------------|
| Router not rebuilt | `Arc<Router>` built once at startup, never updated on reload |
| WAF config not updated | Attack detection patterns may not change until restart |
| Mesh blocks all reload | Even independent field changes rejected when mesh is enabled |
| Success reported incorrectly | Admin `/config/reload` returns "success" even when serving state unchanged |

### Recommendations

**Phase 1: Accurate Reporting**
1. Add reload result status types: `hot_reload_applied`, `restart_required`, `unsupported_in_profile`
2. Report `restart_required` when mesh is enabled
3. Don't log "success" when serving state unchanged

**Phase 2: Incremental Rebuild (Future)**
1. Detect which config sections changed
2. Rebuild only affected derived state

**Phase 3: Atomic Snapshot Swap (Future)**
1. Create `RuntimeSnapshot` containing all derived serving state
2. Use `ArcSwap` for atomic snapshot swapping

**Dependencies**: None
**Actionable Items**:
- [ ] Add accurate reload status reporting
- [ ] Implement incremental rebuild for site config changes
- [ ] Fix mesh blocking reload behavior

---

### 6.3 Runtime Ownership Inventory

**Status**: COMPLETE (draft)
**Priority**: 2

### Background Task Tracking

**Tracked (stored in `task_handles` and aborted on shutdown)**:
| Task | Line | Purpose |
|------|------|---------|
| `heartbeat_handle` | 1204 | Worker heartbeat to Master |
| `bandwidth_persist_handle` | 1251 | Bandwidth persistence |
| `ipc_handle` | 1263 | IPC message loop |
| `server_handle` | 1644 | HTTP/HTTPS/HTTP3 server |

**Untracked but Cancellable**:
| Task | Line | Purpose | Issue |
|------|------|---------|-------|
| `port_honeypot_runner.run()` | 517 | Honeypot port monitoring | Not tracked |
| `granian_supervisor.start()` | 391 | AppServer process management | Not tracked |
| `manager.init().await` (DHT) | 604 | DHT routing initialization | Not tracked |
| `registry.start_verification_loop()` | 782 | DNS verification (global nodes) | Not tracked |

**Intentionally Leaked**:
| Task | Line | Note |
|------|------|------|
| `PluginManagerLifecycle` file watcher | 877 | Comment explicitly says "intentionally leaked" |
| ACME renewal task | 514 | Runs until certificate expires or renewed |

### Lifecycle Phases (Worker Startup)

| Phase | Lines | Description |
|-------|-------|-------------|
| Phase 1: Load Config | 177-247 | Initialize IPC, load config, check ports |
| Phase 2: Core Data Plane | 303-368 | Bandwidth, metrics, UnifiedServer, serverless |
| Phase 3: Data-Plane Extensions | 387-427 | Granian supervisors, WAF background, upload, honeypot |
| Phase 4: Control-Plane Extensions | 522-1077 | Mesh transport, threat intel, DHT, YARA, DNS |
| Phase 5: Wire Inter-Subsystem | 1079-1108 | Serverless → record store/transport wiring |
| Phase 6: Request Blocklist | 1114-1160 | Request initial blocklist via IPC |
| Phase 7: Start Listeners | 1162-1650 | Spawn heartbeat, bandwidth, IPC, servers |

### Issues Identified

1. **Global Singletons**: `THREAT_INTEL`, `YARA_RULES`, `UPLOAD_VALIDATOR` are process-wide singletons
2. **Untracked Tasks**: Several spawned without `task_handles` storage
3. **Intentional Leaks**: Plugin lifecycle manager explicitly leaked
4. **Mesh Blocks Hot Reload**: At line 1335-1340, hot reload blocked when mesh enabled
5. **DHT Routing Init Not Awaited**: Line 604 spawned but never awaited

**Dependencies**: None
**Actionable Items**:
- [ ] Track all spawned tasks in `task_handles`
- [ ] Await DHT routing initialization
- [ ] Fix mesh blocking reload

---

## 7. WAF & Security Features

### 7.1 Threat Feed Production

**Status**: **COMPLETED**
**Last Updated**: 2026-04-29

### Implementation Summary

| Task ID | Component | Description | Status |
|---------|-----------|-------------|--------|
| P1.1 | `mesh/threat_intel.rs` | Deterministic Hashing (`get_feed_signable_content`) | COMPLETED |
| P1.2 | `mesh/threat_intel.rs` | Payload Generation (`create_signed_feed`) | COMPLETED |
| P1.3 | `waf/threat_intel/` | Export Logic | COMPLETED |
| P2.1 | `src/main.rs` | CLI Argument Parsing | COMPLETED |
| P2.2 | `src/master/commands.rs` | Export Handler | COMPLETED |
| P2.3 | `src/master/commands.rs` | Key Loading | COMPLETED |
| P3.1 | Tests | Round-trip Verification | COMPLETED |
| P3.2 | Documentation | `docs/THREAT_INTEL.md` | PENDING |

### CLI Usage

```bash
# Export all indicators as signed JSON
maluwaf --export-threat-feed

# Export with a specific signing key
maluwaf --export-threat-feed --sign-with /path/to/private_key

# Export filtered by site scope
maluwaf --export-threat-feed --site-id mysite
```

### Key Source Files Modified

| File | Changes |
|------|---------|
| `src/mesh/threat_intel.rs` | Added `get_feed_signable_content`, `create_signed_feed`, unit tests |
| `src/waf/threat_intel/feed_client.rs` | Made `get_signable_content` `pub(crate)` for test access |
| `src/main.rs` | Added `--export-threat-feed`, `--sign-with`, `--site-id` CLI args |
| `src/master/commands.rs` | Implemented `handle_export_threat_feed` |

### Verification

- **Unit Tests**: `cargo test --lib mesh::threat_intel` - 12 tests pass
- **CLI Compilation**: `cargo test --lib --no-run` - compiles successfully
- **Cross-Verification**: `test_signable_content_matches_feed_client` verifies format parity

**Dependencies**: None
**Actionable Items**:
- [x] All implementation tasks completed
- [ ] Documentation update to `docs/THREAT_INTEL.md` (deferred)

---

### 7.2 Mockable Clock for TokenBucket Tests

**Status**: IMPLEMENTED
**Priority**: 4

**Problem**: `test_token_bucket_basic` and `test_token_bucket_refill` use `std::thread::sleep()` for time simulation, making tests flaky and slow.

### Solution

Created `Clock` trait with `SystemClock` (production) and `MockClock` (testing) implementations in `src/utils.rs`.

### Implementation

```rust
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock { ... }

pub struct MockClock { offset_ms: AtomicU64 }
impl MockClock {
    pub fn advance(&self, ms: u64) { ... }
    pub fn set(&self, ms: u64) { ... }
}
impl Clock for MockClock { ... }
```

### Files Modified

1. `src/utils.rs` - Add Clock trait and implementations
2. `src/waf/traffic_shaper/bucket.rs` - Update TokenBucket and tests

### Alternative Approach (Simpler)

A simpler pattern stores `offset_ms: u64` directly on `TokenBucket` with `advance_time()` method for tests:

```rust
#[cfg(test)]
impl TokenBucket {
    pub fn advance_time(&self, ms: u64) {
        self.last_refill.fetch_sub(ms as i64, Ordering::Relaxed);
    }
}
```

This is less invasive - just add a test-only method without trait generics.

**Dependencies**: None
**Actionable Items**:
- [x] Implementation completed via `fix/token-bucket-mockable-clock` branch

---

## 8. CI/Gates & Testing

### 8.1 Systems-Layer CI and Regression Gates

**Status**: **COMPLETED** (Wave 4.2)
**Priority**: 6

**Security Regression Test Concepts**:

| Test Case | Implementation Detail |
|-----------|-----------------------|
| **IPC Auth Bypass** | Attempt to send unsigned JSON command to Master Command IPC. Must fail with `AuthError`. ✅ |
| **Key File Symlink** | Create symlink `key.txt -> /etc/shadow`. Signer must refuse to load the key. ✅ |
| **Pidfile Race** | Run two Master processes simultaneously. Second must fail to acquire lock without truncating existing pidfile. ✅ |
| **Sandbox Leak** | Attempt to write to `/etc/hosts` from within a Landlocked worker. Must return `EACCES`. ✅ |
| **Socket Hijack** | Attempt to create socket in `/tmp/maluwaf` as different user. Must fail due to `0700` parent perms. ✅ |

**Actionable Items**:
- [x] **Integration Test Suite**: Created `tests/security_regression.rs` implementing the above cases.
- [x] **Miri CI**: Added `cargo miri test` to CI for `maluwaf-utils` to detect ABA and other UB in buffer pool.
- [x] **Cross-Platform Check**: Added `cargo check --no-default-features` to CI.
- [x] **Forbidden Imports**: Implemented `scripts/check_imports.py` and run in CI.

---

### 8.2 Platform Support Matrix

**Status**: Active
**Priority**: 7

### Production Platforms

| Platform | Support Level | Notes |
|----------|--------------|-------|
| Linux (glibc) | **Full** | Primary target. All features supported. |
| Linux (musl) | **Full** | Static binary builds. All features supported. |

### Development / Secondary Platforms

| Platform | Support Level | Notes |
|----------|--------------|-------|
| macOS | **Good** | Most features work. No `SO_REUSEPORT` on older versions. Sandbox needs feature flag. |
| Windows | **Partial** | Core HTTP/WAF works. No Unix domain sockets. No `flock`-based locking. |
| FreeBSD | **Partial** | Capsicum sandbox works. Most Unix features work. |
| OpenBSD | **Partial** | Pledge sandbox works. No `SO_REUSEPORT`. |

### Capability Matrix

| Capability | Linux | macOS | Windows | FreeBSD | OpenBSD |
|------------|-------|-------|---------|---------|---------|
| **Process Management** | | | | | |
| PID file management | Yes | Yes | Yes | Yes | Yes |
| Process supervision | Yes | Yes | Yes | Yes | Yes |
| Signal handling | Full | Full | Partial (TERM/INT only) | Full | Full |
| Overseer lock file | Yes | Yes | Stub (returns error) | Yes | Yes |
| **IPC** | | | | | |
| Unix domain sockets | Yes | Yes | N/A | Yes | Yes |
| Named pipes | N/A | N/A | Yes | N/A | N/A |
| Signed IPC | Yes | Yes | Yes | Yes | Yes |
| FD passing | Yes | Yes | No | Yes | Yes |
| **Sandboxing** | | | | | |
| Landlock (Linux 5.13+) | Yes | N/A | N/A | N/A | N/A |
| Capsicum | N/A | N/A | N/A | Yes | N/A |
| Pledge | N/A | N/A | N/A | N/A | Yes |
| Seatbelt (macOS) | N/A | Yes (feature flag) | N/A | N/A | N/A |
| Job Objects | N/A | N/A | Yes | N/A | N/A |

### Known Limitations

**Windows**:
- **No `flock`**: Uses Unix `flock()` for inter-process locking. On Windows, `acquire()` returns an error.
- **No Unix domain sockets**: IPC uses Windows named pipes instead.
- **No FD passing**: Use port-swap upgrade mode instead of socket handoff.

**macOS**:
- **Sandbox requires feature flag**: The `macos-sandbox` Cargo feature must be enabled.

**BSD**:
- **No `SO_REUSEPORT`**: Not supported. Port-swap upgrade mode works as fallback.

**Dependencies**: None
**Actionable Items**:
- [ ] Track as documentation - no implementation required

---

### 8.3 Platform Firewall Review

**Status**: **COMPLETED** (Wave 4.2)
**Priority**: 9

### Firewall Backends Summary

| Platform | Backend | Feature | Native/Shell | Privilege Check |
|----------|---------|---------|--------------|-----------------|
| Linux | nftables | (default) | Shell (`nft` CLI) | Root or CAP_NET_ADMIN |
| Linux | eBPF | `icmp-ebpf` | Native (aya crate) | Root + bpf_disabled!=2 |
| macOS | pf | `icmp-pf` | Shell (`pfctl` CLI) | Root |
| BSD | pf | `icmp-pf` | Shell (`pfctl` CLI) | Root |
| Windows | winfw | `icmp-winfw` | Native (windows_firewall crate) | Admin SID check |
| Windows | wfp | `icmp-wfp` | Native (wfp crate) | Admin SID check |

### Issues with Current Privilege Checks

1. **Single `is_admin()` for all operations**: Different operations have different requirements
2. **eBPF privilege check is incomplete**: Platform `is_admin()` doesn't incorporate `unprivileged_bpf_disabled` check
3. **No distinction between enable vs runtime operations**: Some need elevated privileges, others may not

### Recommendations

1. **Operation-Specific Privilege Checks**
   - `can_load_ebpf()`: Check unprivileged_bpf_disabled state
   - `can_modify_nftables()`: Check root or CAP_NET_ADMIN
   - `can_modify_firewall()`: Check admin on Windows

2. **Reduce Shell-Outs on Windows**
   - Use native `GetAdaptersInfo`/`GetAdaptersAddresses` from `iphlpapi.dll`

3. **Make Inactive Backends Visible**
   ```rust
   pub enum FilterState {
       InactiveNotPrivileged,
       InactiveConfigError,
       Active,
   }
   ```

**Dependencies**: None
**Actionable Items**:
- [x] Implement operation-specific privilege checks (`can_load_ebpf()`, `can_modify_nftables()`, `can_modify_firewall()`)
- [ ] Replace PowerShell interface resolver with native APIs
- [x] Add explicit state for backends inactive due to permissions (`FilterState` enum)

---

## 9. MaluWAF V2 Plan (Waves 1-4)

**Status**: COMPLETED
**Last Updated**: 2026-04-28

### Wave 1: Codebase Health & Testing Foundations

| Task ID | Component | Description | Status |
|---------|-----------|-------------|--------|
| W1.1 | `metrics/mod.rs` | Split into `payloads.rs` and `collection.rs` | ✅ COMPLETED |
| W1.2 | `fuzz/` | Continuous fuzzing targets for `serialization`, `early_parse`, `protocol_proto_decode` | ✅ COMPLETED |
| W1.3 | E2E Tests | Fault injection tests for worker crash mid-request | ✅ COMPLETED |

### Wave 2: Performance & Scalability

| Task ID | Component | Description | Status |
|---------|-----------|-------------|--------|
| W2.1 | `http/server.rs` | Zero-copy proxying with streaming body pipe for >1MB | ✅ COMPLETED |
| W2.2 | `http3/server.rs` | HTTP/3 zero-copy streaming | ✅ COMPLETED |
| W2.3 | `routing/table.rs` | DHT routing optimization with moka LRU cache | ✅ COMPLETED |
| W2.4 | `MeshPeerConnection` | QUIC stream pooling via `StreamPool` in `src/tunnel/quic/client.rs` | ✅ COMPLETED |

### Wave 3: Multi-Tenancy & Plugins

| Task ID | Component | Description | Status |
|---------|-----------|-------------|--------|
| W3.1 | Core State | Site isolation audit - `ratelimit.rs`, `rule_feed.rs`, `WorkerMetrics` | ✅ COMPLETED |
| W3.2 | `wasm_runtime.rs` | WASM Component Model with `plugin.wit` WIT file | ✅ COMPLETED |

### Wave 4: Security & Resilience

| Task ID | Component | Description | Status |
|---------|-----------|-------------|--------|
| W4.1 | Threat Intel | `feed_client.rs` with Ed25519 signature verification | ✅ COMPLETED |
| W4.2 | DHT | Feed distribution via `ThreatFeedUpdate` IPC and SiteScoped DHT keys | ✅ COMPLETED |

### Verification Commands

For every wave:
1. **Compilation Check**: `cargo test --lib --no-run` must pass
2. **Unit & Integration Tests**: `cargo test` and `cargo test --test integration_test` must pass
3. **Benchmarking (Wave 2)**: Run `cargo bench` before and after W2.1/W2.2

### Migration & Rollback

- **WASM Plugins**: Legacy `load_plugin` and new `load_component` coexist during deprecation period
- **Rollback**: All tasks are designed to be atomic commits. Revert specific commit if regression detected

---

## 10. Deferred/Future Work

### Wave 1 Deferred

| Item | Status | Notes |
|------|--------|-------|
| Traffic Layer: Cache lookup/storage in ProxyServer | Completed | Stale-while-revalidate URL rebuild fixed |
| WAF/Security: Anomaly Scoring duplicated detector runs | Completed | Refactoring deferred but scoring wired |
| WAF/Security: Multipart boundary parsing | Completed | Streaming WAF edge cases addressed |

### Wave 3 (Systems Layer Deferred)

- **Deep WireGuard/TUN backend work** - Except where platform compile checks require gating

### Wave 4 (Distributed Layer Deferred)

- **Performance tuning of DHT routing and regional quorum selection**
- **Major Raft storage schema changes** unrelated to auth metadata
- **New mesh admin APIs** for manual quorum or Raft management
- **Changing public wire protocol** beyond minimum needed for signed context and auth

### Completed Zero-Copy Validation

| Item | Status | Notes |
|------|--------|-------|
| Zero-copy streaming for HTTP proxy | ✅ | Correctly implemented using BufferPool |
| HTTP server 1MB threshold | ✅ | Uses zero-copy streaming |
| Static files 4KB threshold | ⚠️ | Uses Buffered variant (not true sendfile) |

**Note**: Static file `into_bytes()` reads entire file into memory. True sendfile requires deeper refactoring of HTTP response handling.

### God Modules (Skipped)

- **D7 Strategic Module Splitting**: Manual refactor of `metrics/mod.rs`, `mesh/transport.rs`, `http/server.rs` - skipped due to "no capability reversions" requirement

### Future Recommendations

1. **DHT Routing Optimization**: For 100k+ node scale, current Kademlia bucket iteration becomes bottleneck
2. **HTTP/QUIC Stream Pooling**: Could be combined with W2.4 for better mesh latency
3. **Advanced DHT Routing**: Current implementation adequate for <10k nodes

---

## Summary Status Table

| Section | Status | Priority Items |
|---------|--------|----------------|
| 1. Overview/Status | IN PROGRESS | Wave 21 work pending |
| 2.1 Socket/PID Hardening | DOCUMENTED | Fix symlink following, lock ordering |
| 2.2 Sandbox Hardening | DOCUMENTED | Fix write_paths, cap_enter, is_supported |
| 2.3 IPC Signing Hardening | DOCUMENTED | Fix replay cache, key loading |
| 2.4 IPC Consolidation | PENDING | Phase 1-4 implementation |
| 2.5 Singleton Inventory | DOCUMENTED | RequestServices refactoring |
| 3.1 Buffer Pool | DOCUMENTED | Replace with mutex-based implementation |
| 3.2 Routing Hot-Path | VERIFIED | Minor allocations remain |
| 3.3 IPC Framing Copies | DOCUMENTED | Quick wins available |
| 4.1 Architecture Profiles | DOCUMENTED | Track as guidance |
| 4.2 Architecture Gates | **OPEN** | 215/85/259 errors on core/mesh/dns profiles |
| 4.3 Control Plane Boundaries | DOCUMENTED | Keep mesh in worker guidance |
| 5.1 WAF Entrypoint Matrix | ACTIVE | ProxyServer query_string fix needed |
| 5.2 Traffic Entrypoint Matrix | ACTIVE | TLS pooling, HTTP/3 headers |
| 5.3 Worker Runtime Split | DOCUMENTED | Replace globals with Option<Arc<T>> |
| 5.4 HTTP Server Pipeline | PLANNING | Phase 1-3 extraction |
| 6.1 Plugin Isolation | DOCUMENTED | Wire memory budget, fix lifecycle leak |
| 6.2 Config Reload Contract | DOCUMENTED | Accurate status reporting |
| 6.3 Runtime Ownership | COMPLETE | Track tasks, fix mesh blocking |
| 7.1 Threat Feed Production | **COMPLETED** | ✅ All implementation done |
| 7.2 Mockable Clock | **IMPLEMENTED** | ✅ TokenBucket tests fixed |
| 8.1 Systems CI Gates | OPEN | Add to CI pipeline |
| 8.2 Platform Support Matrix | ACTIVE | Documentation only |
| 8.3 Platform Firewall | DOCUMENTED | Operation-specific privilege checks |
| 9. MaluWAF V2 Plan | **COMPLETED** | ✅ All 4 waves done |
| 10. Deferred/Future | ONGOING | WireGuard, Raft, God modules |

---

## Active Branches/Merged Fixes (2026-05-02)

| Branch | Status | Description |
|--------|--------|-------------|
| `fix/raft-metrics-api` | Merged | Fixed raft metrics endpoints |
| `fix/test-concurrency` | Merged | Fixed DashMap deadlock in SlidingWindowLimiter |
| `fix/token-bucket-mockable-clock` | Merged | Added mockable clock for TokenBucket tests |
| `feature/zero-copy-validation` | Merged | Documented zero-copy implementation |
| `chore/remove-unused-stubs` | Merged | Removed MeshControlPlane and PluginExecution stubs |