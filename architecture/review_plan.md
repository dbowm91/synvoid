# Architecture Review Plan

**Generated:** 2026-05-27
**Status:** INCOMPLETE
**Purpose:** Systematically review architecture documents, verify claims against code, identify improvements and bugs, prune stale content.

---

## Overview

This plan orchestrates parallel subagent reviews of discrete architecture modules. Each subagent:
1. Reads their assigned architecture document in `architecture/`
2. Verifies claims against actual source code in `src/`
3. Identifies discrepancies, bugs, and improvements
4. Writes a detailed improvement plan to `plans/<module>_review_plan.md`

---

## Phase 1: Architecture Modules to Review (17 Modules)

| # | Document | Subagent Task | Output File |
|---|----------|---------------|-------------|
| 1 | `admin_deep_dive.md` | Review Admin API architecture | `plans/admin_review_plan.md` |
| 2 | `app_handlers.md` | Review App Handlers architecture | `plans/app_handlers_review_plan.md` |
| 3 | `auth.md` | Review Authentication architecture | `plans/auth_review_plan.md` |
| 4 | `config.md` + `config_deep_dive.md` | Review Configuration architecture | `plans/config_review_plan.md` |
| 5 | `dns.md` + `dns_deep_dive.md` | Review DNS architecture | `plans/dns_review_plan.md` |
| 6 | `http_server.md` + `http_shared.md` | Review HTTP Server architecture | `plans/http_server_review_plan.md` |
| 7 | `layer_3_5_deep_dive.md` | Review Layer 3.5 (TLS/Crypto) architecture | `plans/layer_3_5_review_plan.md` |
| 8 | `mesh.md` + `mesh_deep_dive.md` | Review Mesh Networking architecture | `plans/mesh_review_plan.md` |
| 9 | `networking_deep_dive.md` | Review Networking architecture | `plans/networking_review_plan.md` |
| 10 | `platform.md` + `platform_deep_dive.md` | Review Platform architecture | `plans/platform_review_plan.md` |
| 11 | `plugin_wasm.md` + `plugin_deep_dive.md` | Review Plugin/WASM architecture | `plans/plugin_review_plan.md` |
| 12 | `process_lifecycle.md` | Review Process Lifecycle architecture | `plans/process_lifecycle_review_plan.md` |
| 13 | `proxy.md` + `proxy_deep_dive.md` | Review Proxy architecture | `plans/proxy_review_plan.md` |
| 14 | `routing_deep_dive.md` | Review Routing architecture | `plans/routing_review_plan.md` |
| 15 | `serverless.md` | Review Serverless architecture | `plans/serverless_review_plan.md` |
| 16 | `spin.md` | Review Spin WASM runtime | `plans/spin_review_plan.md` |
| 17 | `waf.md` + `waf_deep_dive.md` | Review WAF architecture | `plans/waf_review_plan.md` |
| 18 | `worker_architecture.md` | Review Worker Architecture | `plans/worker_review_plan.md` |

---

## Excluded Documents

| Document | Reason |
|----------|--------|
| `review_plan.md` | This file itself (generated fresh) |
| `deep_dive_review.md` | General review methodology, not module-specific |
| `overview.md` | General overview (not a discrete module) |
| `supervisor.md` | Leadership process, stable - minimal review needed |
| `ipc_process.md` | Low-level IPC mechanics, stable |
| `tunnel.md` | Deprecated/tunnel backend removed |
| `tls.md` | Handled under layer_3_5_deep_dive.md |

---

## Phase 2: Subagent Review Instructions

Each subagent must perform a **systematic code review** covering:

### 2.1 Source Code Verification
- Locate and verify all file paths and line numbers cited in the document
- Verify enum variants (e.g., `BackendType` has 11 variants at `src/router.rs:66-77`)
- Verify struct definitions, method signatures, and feature gates
- Verify feature availability (`#[cfg(feature = "...")]` attributes)

### 2.2 Implementation Status Check
- Compare documented behavior with actual implementation
- Identify stub functions vs. complete implementations
- Verify feature completeness (what's claimed vs. what's there)

### 2.3 Security Pattern Audit
- Check constant-time comparisons for secrets (keys, MACs, tokens)
- Verify file permissions on private key files
- Verify authorized genesis keys default deny
- Check PoW requirements for edge nodes

### 2.4 Cross-Reference with AGENTS.md
- Check known bugs in AGENTS.md for relevant module
- Verify bug fixes are still in place
- Check dependency vulnerability status

### 2.5 Improvement Discovery
- Identify API inconsistencies
- Identify missing error handling
- Identify performance concerns
- Identify dead code or unused functions
- Identify outdated documentation

### 2.6 Output Format
Write improvement plan to `plans/<module>_review_plan.md` containing:

```markdown
# <Module> Review Plan

## Verified Correct Items
- [item]: [verification result]

## Discrepancies Found
- [item]: [expected vs actual]

## Bugs Identified
- [severity]: [description] (location)

## Suggested Improvements
- [category]: [description]
```

---

## Phase 3: Stale Content Pruning

### 3.1 Check for Stale Architecture Files

Identify files that are:
- Superceded by deeper-dive documents (e.g., `dns.md` superceded by `dns_deep_dive.md`)
- Referencing Removed Code (e.g., `tunnel.md` references `TunnelBackend` which was removed)
- Outdated architecture decisions not reflected in code
- Duplicate content covered by other documents

### 3.2 Identify Stale References

Subagents should flag:
- File paths that no longer exist
- Struct/enum names that have changed
- Feature flags that were renamed or removed
- Configuration keys that are no longer used

### 3.3 Prune Commands (to be executed after review)

```bash
# Remove identified stale files from architecture/
git rm architecture/<stale_file>.md

# Update any index files if they exist
```

---

## Phase 4: Subagent Launch

Launch 18 parallel subagents, one per module. Each subagent should:
- Use the `explore` agent for research
- Use the `general` agent for deep review and writing
- Focus on verifying specific claims in the assigned document
- Cross-reference with `AGENTS.md` known bugs section
- Write findings to the specified output file in `plans/`

---

## Phase 5: Verification

After all reviews complete:

```bash
# Verify all profiles still compile
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns    # NOTE: Pre-existing error (dns feature + mesh config mismatch)
cargo check --no-default-features --features mesh,dns

# Run tests
cargo test --lib --no-run
```

**Note on DNS profile**: There is a pre-existing compilation error in `--features dns` mode at `src/server/mod.rs:311,318` where `MainTunnelConfig` lacks a `.mesh` field. This is unrelated to the review process and existed before this review cycle.

---

## Completed Review Plans

All 18 module review plans have been completed and are available in `plans/`:

| Module | Review Plan | Status |
|--------|-------------|--------|
| Admin API | `plans/admin_review_plan.md` | ✅ Complete |
| App Handlers | `plans/app_handlers_review_plan.md` | ✅ Complete |
| Auth | `plans/auth_review_plan.md` | ✅ Complete |
| Config | `plans/config_review_plan.md` | ✅ Complete |
| DNS | `plans/dns_review_plan.md` | ✅ Complete |
| HTTP Server | `plans/http_server_review_plan.md` | ✅ Complete |
| Layer 3.5 | `plans/layer_3_5_review_plan.md` | ✅ Complete |
| Mesh | `plans/mesh_review_plan.md` | ✅ Complete |
| Networking | `plans/networking_review_plan.md` | ✅ Complete |
| Platform | `plans/platform_review_plan.md` | ✅ Complete |
| Plugin/WASM | `plans/plugin_review_plan.md` | ✅ Complete |
| Process Lifecycle | `plans/process_lifecycle_review_plan.md` | ✅ Complete |
| Proxy | `plans/proxy_review_plan.md` | ✅ Complete |
| Routing | `plans/routing_review_plan.md` | ✅ Complete |
| Serverless | `plans/serverless_review_plan.md` | ✅ Complete |
| Spin WASM | `plans/spin_review_plan.md` | ✅ Complete |
| WAF | `plans/waf_review_plan.md` | ✅ Complete |
| Worker | `plans/worker_review_plan.md` | ✅ Complete |

---

## Implemented Fixes (Phase 4)

The following fixes have been implemented based on review findings:

| Bug ID | Description | Status |
|--------|-------------|--------|
| BUG-L3 | ML-KEM proof-of-possession verification added to `confirm_key()` | ✅ FIXED |
| BUG-SPIN-1 | Race condition fixed in `get_or_create_instance()` (write lock first) | ✅ FIXED |
| BUG-AUTH-1/2 | Username validation added (max length, control chars) | ✅ FIXED |
| BUG-DNS-2 | Documentation updated - ECDSA NOT implemented (only Ed25519/RSA) | ✅ FIXED |
| BUG-PL-4 | AGENTS.override.md updated - `is_admin_required_for_tun` correctly returns false for Unix | ✅ FIXED |

---

## Implementation Guide: Remaining Items

This section provides detailed implementation instructions for the remaining work items.

---

### IMP-DNS-1: Fix HickoryRecursor DNSSEC Policy (HIGH Priority)

**Bug ID:** BUG-DNS-1
**Location:** `src/dns/resolver.rs:693-702`, `Cargo.toml:121`
**Complexity:** LOW

#### Problem Summary
When `enable_dnssec=true`, the recursive DNS server still uses `DnssecPolicy::SecurityUnaware` which means DNSSEC records are NOT requested or processed, even though trust anchors are built.

#### Root Cause
1. The `dnssec-ring` feature is not enabled on `hickory-resolver` in Cargo.toml
2. Without this feature, `DnssecPolicy::ValidateWithStaticKey` and `DnssecPolicy::ValidationDisabled` variants are not available at compile time

#### Implementation Steps

**Step 1: Update Cargo.toml (line ~121)**

Change:
```toml
hickory-resolver = { version = "0.26", features = ["system-config", "recursor"], optional = true }
```

To:
```toml
hickory-resolver = { version = "0.26", features = ["system-config", "recursor", "dnssec-ring"], optional = true }
```

**Step 2: Update resolver.rs (lines 693-702)**

Change the `dnssec_policy` construction from:
```rust
let dnssec_policy = if enable_dnssec {
    let _trust_anchors =
        Self::build_trust_anchors(trust_anchor_path, trust_anchor_manager.as_ref());
    // In 0.26, SecurityUnaware doesn't take trust_anchor.
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
} else {
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
};
```

To:
```rust
let dnssec_policy = if enable_dnssec {
    let trust_anchors =
        Self::build_trust_anchors(trust_anchor_path, trust_anchor_manager.as_ref());

    hickory_resolver::recursor::DnssecPolicy::ValidateWithStaticKey(
        hickory_resolver::recursor::DnssecConfig {
            trust_anchor: Some(trust_anchors),
            nsec3_soft_iteration_limit: None,
            nsec3_hard_iteration_limit: None,
            validation_cache_size: None,
        }
    )
} else {
    hickory_resolver::recursor::DnssecPolicy::SecurityUnaware
};
```

**Step 3: Verify hickory TrustAnchors type**

The `build_trust_anchors()` method returns `hickory_proto::dnssec::TrustAnchors`. Verify this is compatible with `DnssecConfig::trust_anchor: Option<Arc<TrustAnchors>>`. If there are type mismatches, use `Arc::new(...)` wrapping or `.clone()` as appropriate.

**Step 4: Test**
```bash
cargo check --features dns  # Verify compilation
# Test with: dig +sigquery @localhost yourdomain.com
```

---

### IMP-DNS-3: Implement QueryCoalescer max_wait_ms (MEDIUM Priority)

**Bug ID:** BUG-DNS-3
**Location:** `src/dns/query_coalesce.rs:108-124`, `src/dns/query_coalesce.rs:40-55`
**Complexity:** LOW

#### Problem Summary
The `max_wait_ms` parameter in `with_config()` and `with_max_wait_time()` is ignored. Callers wait indefinitely for coalesced responses.

#### Implementation Steps

**Step 1: Add `max_wait` field to QueryCoalescer struct (line ~40)**

Current struct:
```rust
pub struct QueryCoalescer {
    in_flight: Arc<RwLock<HashMap<QueryKey, CoalescerEntry>>>,
    max_entries: usize,
    entry_ttl: Duration,
    metrics: Arc<RwLock<QueryCoalescerMetrics>>,
}
```

Change to:
```rust
pub struct QueryCoalescer {
    in_flight: Arc<RwLock<HashMap<QueryKey, CoalescerEntry>>>,
    max_entries: usize,
    max_wait: Duration,  // NEW: maximum time to wait before giving up
    entry_ttl: Duration,
    metrics: Arc<RwLock<QueryCoalescerMetrics>>,
}
```

**Step 2: Update `with_config()` to store max_wait**

Change from:
```rust
pub fn with_config(_max_wait_ms: u64, max_entries: usize, entry_ttl_secs: u64) -> Self {
    Self {
        in_flight: Arc::new(RwLock::new(HashMap::new())),
        max_entries,
        entry_ttl: Duration::from_secs(entry_ttl_secs),
        metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
    }
}
```

To:
```rust
pub fn with_config(max_wait_ms: u64, max_entries: usize, entry_ttl_secs: u64) -> Self {
    Self {
        in_flight: Arc::new(RwLock::new(HashMap::new())),
        max_entries,
        max_wait: Duration::from_millis(max_wait_ms),
        entry_ttl: Duration::from_secs(entry_ttl_secs),
        metrics: Arc::new(RwLock::new(QueryCoalescerMetrics::default())),
    }
}
```

**Step 3: Update `get_or_wait()` to use age-based short-circuit (lines ~126-139)**

In `get_or_wait()`, after finding an existing entry, check if `max_wait` has elapsed. If so, return `NewQuery` instead of `Timeout`:

```rust
if let Some(entry) = in_flight.get(&key) {
    let elapsed = entry.created_at.elapsed();
    if elapsed > self.max_wait {
        // Timed out waiting for response - let caller handle it
        return Some(CoalesceResult::NewQuery(tx));
    }
    // ... existing try_recv logic unchanged ...
}
```

**Step 4: Update `CoalescerEntry` struct if needed**

Verify `CoalescerEntry` has a `created_at: Instant` field (it should per agent analysis). If not, add it.

**Step 5: Verify all call sites**

Search for `with_config` calls and ensure they pass appropriate `max_wait_ms` values (typically 500ms for responsive coalescing without long waits).

---

### IMP-HTTP-2: Consolidate HTTP/3 Body Collection (MEDIUM Priority)

**Bug ID:** BUG-HTTP-2
**Location:** `src/http3/server.rs:340-398`, `src/http/shared_handler.rs:330-418`
**Complexity:** MEDIUM

#### Problem Summary
HTTP/3 uses a custom body collection loop that differs from HTTP/1.1:
- No 256KB chunk threshold
- Lower body size limit (1MB vs 10MB)
- No 64KB scan chunking
- No `BodyCollectionProtocol` metrics

#### Implementation Steps

**Step 1: Add `Http3` variant to BodyCollectionProtocol (shared_handler.rs:308)**

Add to enum:
```rust
#[derive(Clone, Copy Debug)]
pub enum BodyCollectionProtocol {
    Http,
    Https,
    Http3,  // NEW variant
}
```

**Step 2: Create Quinn-to-Body adapter (new file or in http3/server.rs)**

Create a struct implementing `http_body::Body` trait:

```rust
use http_body::{Body, Frame, Data};
use bytes::Bytes;

pub struct QuinnRequestStreamBody {
    stream: QuicRequestStream,
    trailers: Option<Bytes>,
}

impl Body for QuinnRequestStreamBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Use request_stream.recv_data() to get chunks
        // Map to Frame::Data(chunk) responses
        // Return Frame::Trailers when done
    }
}
```

**Step 3: Update HTTP/3 request handler to use shared path**

In `src/http3/server.rs` around line 340, replace custom loop with:

```rust
// Create adapter for QUIC stream
let body = QuinnRequestStreamBody::new(request_stream);

// Use shared streaming WAF with correct limits
let max_size = http_config.max_streaming_body_size.unwrap_or(10 * 1024 * 1024);
let waf_streamed = crate::http::shared_handler::stream_body_with_waf(
    body,
    &self.waf,
    client_ip,
    BodyCollectionProtocol::Http3,
    max_size,
);

// Pass to existing request handling flow that expects Body trait
```

**Step 4: Align size limits**

Ensure `http_config.max_streaming_body_size` (default 10MB) is used for HTTP/3, replacing the current `max_request_size` (1MB).

**Step 5: Add metrics for HTTP/3 body collection**

Add HTTP/3 case to `BodyCollectionProtocol::counter_blocked()` if exists.

**Verification:**
```bash
cargo check --features h3  # Verify compilation with HTTP/3
# Test large body uploads via HTTP/3
```

---

### IMP-PL-3: Document Windows Socket FD Passing (LOW Priority)

**Bug ID:** BUG-PL-3
**Location:** `src/platform/windows_impl.rs:71-100`
**Complexity:** N/A (Documentation only)

#### Problem Summary
The error message "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead." is misleading because Windows does have working socket handoff via `Message::WindowsSocketInfo` - just not through the `SocketFDPassing` trait.

#### Implementation Steps

**Step 1: Update error messages in WindowsSocketFDPassing (windows_impl.rs:87-98)**

Change:
```rust
fn send_sockets(&self, _handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
    Err(SocketHandoffError::NotSupported(
        "Socket FD passing requires WSADuplicateSocket. Use port-swap upgrade mode instead."
            .into(),
    ))
}
```

To:
```rust
fn send_sockets(&self, _handles: &[Self::Handle]) -> Result<(), SocketHandoffError> {
    // NOTE: Windows socket handoff uses Message::WindowsSocketInfo protocol
    // via WSADuplicateSocketW, not SCM_RIGHTS-style FD passing.
    // See duplicate_socket_for_child() and create_socket_from_duplicate() in this file.
    // This method exists to satisfy the SocketFDPassing trait but is not called on Windows.
    Err(SocketHandoffError::NotSupported(
        "Windows uses WSADuplicateSocketW-based handoff via Message::WindowsSocketInfo (see windows_impl.rs:128-182)".into(),
    ))
}
```

**Step 2: Update recv_sockets similarly**

---

## Remaining Work

The following items from review plans were identified and implementation instructions have been provided above:

### HIGH Priority

| Item | Description | Implementation Guide |
|------|-------------|----------------------|
| BUG-DNS-1 | HickoryRecursor DNSSEC Policy always SecurityUnaware | **See IMP-DNS-1 above** |
| BUG-DNS-4 | HickoryResolver always returns `is_dnssec_validated: false` | Related to IMP-DNS-1 - fix DNSSEC policy first |

### MEDIUM Priority

| Item | Description | Implementation Guide |
|------|-------------|----------------------|
| BUG-DNS-3 | QueryCoalescer `max_wait_ms` parameter unused | **See IMP-DNS-3 above** |
| BUG-HTTP-2 | HTTP/3 body collection inconsistent | **See IMP-HTTP-2 above** |
| IMPROVE-1 | Consolidate HTTP/3 body collection | Same as BUG-HTTP-2 |

### LOW Priority (Documentation/Enhancement)

| Item | Description | Implementation Guide |
|------|-------------|----------------------|
| BUG-PL-3 | Windows socket FD passing documentation | **See IMP-PL-3 above** |
| IMP-1 | Update `calculate_backoff` documentation | Update `architecture/proxy.md:210-215` |
| IMP-2 | Update HTTP/2 status documentation | Update `architecture/proxy_deep_dive.md:260-264` |
| IMP-3 | Add `supports_seatbelt()` method | Add to `src/platform/mod.rs` |
| BUG-SL-1 | `handle_serverless_function` mesh-only | Document in `architecture/serverless.md` |
| BUG-R2 | Inconsistent port resolution | Refactor `src/router.rs:403,1320` to use helper |

---

## Cross-Reference Checklist

Subagents should verify these known references from AGENTS.md:

| Reference | Expected Location |
|-----------|-------------------|
| ConfigManager | `crates/synvoid-config/src/lib.rs:113` |
| BackendType enum | `src/router.rs:66-77` (11 variants) |
| StreamingWafCore | `src/waf/attack_detection/streaming.rs:129-134` |
| Quorum verification | `src/mesh/dht/signed.rs:860-934` |
| `collect_body_with_chunk_waf` | `src/http/server.rs:4662` |
| MeshProxy key routing | `src/mesh/proxy.rs:63` |
| MeshRaftNetwork::send_raw retry | `src/mesh/raft/network.rs:53-91` |
| DnsConfig.validate() | `crates/synvoid-config/src/main_config.rs:192-203` |

---

## Known Bugs from AGENTS.md (Verify Still Present/Fixed)

| Bug ID | Location | Issue | Status |
|--------|----------|-------|--------|
| BUG-L3 | `src/mesh/ml_kem_key_exchange.rs:204-265` | ML-KEM key exchange proof-of-possession | ✅ FIXED (025582ee) |
| BUG-ROUTER-1 | `src/router.rs:1318` | Hardcoded port 80 | ✅ FIXED (per review) |
| BUG-CORS-1 | `src/admin/mod.rs:860` | CORS config dropped | Known - may be intentional |
| HTTP2-POOL | `src/http_client/mod.rs:893` | HTTP/2 pooling incomplete | DEFERRED |

---

## Phase 6: Commit

After all subagents complete and stale items are identified:

1. Add all new review plan files: `git add plans/*_review_plan.md`
2. Remove stale architecture files if any identified
3. Commit with message: `Review: Add comprehensive architecture review plans`
4. Push to main

**Status**: ✅ Phase 6 completed (commit 025582ee)

---

(End of file)
