# SynVoid Implementation Plan

**Status**: 🔄 IN PROGRESS - Plan pruning after 2026-05-23 verification
**Target**: Bug fixes, security hardening, and documentation updates
**Consolidated from**: All architecture review plans in `plans/` directory

---

## Overview

This plan has been pruned to remove all completed items. Only incomplete/deferred items remain.

**Verification Summary (2026-05-23):**
- 37 action items originally planned
- 4 items required additional fixes (REC-1, REC-3, REC-5, DOC-4, DOC-3, ISSUE-5, PLUGIN-3)
- All fixes completed and committed
- Remaining: 6 deferred items (architectural/large effort)

---

## Deferred Items (Architectural/Large Effort)

These items require significant architectural changes and are deferred until resources permit.

| ID | Issue | Reason | Status |
|----|-------|--------|--------|
| MESH-14 | No Source Node ID Binding Validation in All Ingress Paths | DHT ingress validation gaps require fundamental changes to bind node_id to TLS/cert identity | Deferred - Architectural |
| MESH-15 | Quorum Deadlock Risk During Partition | Raft implementation incomplete per TODO at `instance.rs:214`. Requires Raft migration. | Deferred - Requires Raft |
| MESH-17 | Session Establishment Failure Silently Ignored | Intentional - offer doesn't depend on session state for bidirectional communication | Working As Designed |
| APP-15 | FastCGI Response NOT Truly Streamed | Known limitation - buffers entire stdout. True streaming requires architectural refactor. | Deferred - Architectural |
| SUP-1 | gRPC Control Plane TLS | Intentional - localhost IPC between Supervisor and Master processes | Working As Designed |
| DOC-MESH-1 | DHT Ingress Verification Gaps Not Documented | Requires documenting full identity/trust model - larger architectural task | Deferred |

---

## Recently Fixed Items (2026-05-23 Verification)

These items were verified and fixed during the 2026-05-23 plan review:

### REC-1: Fast-path patterns expanded
- **File**: `src/waf/attack_detection/mod.rs:156-170`
- **Fix**: Expanded from 13 to 38 patterns to include SQLi, XSS, command injection, SSRF, XXE, request smuggling indicators

### REC-3: Streaming WAF block_status configurable
- **File**: `src/waf/attack_detection/config.rs:181-186`
- **Fix**: Added `block_status: Option<u16>` field to `AttackDetectionResult` struct
- **File**: `src/waf/attack_detection/streaming.rs:376-387`
- **Fix**: `get_block_status()` now checks `self.block_status` first before defaulting to 403

### REC-5: Request smuggling in fast-path
- **File**: `src/waf/attack_detection/mod.rs:156-170`
- **Fix**: Added `transfer-encoding` and `content-length` patterns to fast_path_patterns

### DOC-3: VpnClientBuilder documentation corrected
- **File**: `architecture/dns_deep_dive.md:222`
- **Fix**: Clarified VpnClientBuilder is a struct (not a method on VpnClient)

### DOC-4: DNS modules added to documentation
- **File**: `architecture/dns_deep_dive.md:37-42`
- **Fix**: Added `hsm.rs`, `cookie.rs`, `update.rs`, `transfer.rs` to key files table

### ISSUE-5: Handler count corrected
- **File**: `architecture/admin_deep_dive.md:120,124-150`
- **Fix**: Added `behavioral_intel` handler to documentation, corrected count to 28

### PLUGIN-3: verify_caller_permission documented
- **File**: `src/serverless/manager.rs:145-157`
- **Fix**: Added `verify_caller_permission()` to mesh-only feature documentation

---

## Already Verified As Correct

| Item | Source | Verification |
|------|--------|--------------|
| SEC-1 (DNS DS digest) | `src/dns/dnssec_validation.rs:273` | Uses `ct_eq()` - FIXED |
| PLUGIN-4 (mesh_check_threat) | `src/plugin/wasm_runtime.rs:946-960` | Properly implemented with DHT integration |
| M1 (overseer mesh agent spawn) | `src/overseer/process.rs:412` | Has `running.is_running()` check |
| H2 (dead code reference) | `src/supervisor/process.rs:180` | Function exists at `master/ipc.rs:317` |
| SAFE_HEADERS count | `src/proxy/cache.rs:97-126` | 28 headers |
| MESH-11 (Quorum Manager race) | `src/mesh/dht/quorum.rs:337-381` | FIXED - uses oneshot with Result tracking |
| MESH-16 (Role validation duplication) | `src/mesh/peer_auth.rs:275-304` | FIXED - duplicate block removed |
| APP-17 (pip install hashes) | `src/app_server/granian.rs:491-508` | FIXED - require_hashes field added |
| ISSUE-1 (config AGENTS.override.md) | `src/config/AGENTS.override.md` | File exists and is complete |

---

## Verification Commands

```bash
# Core profile check
cargo check --no-default-features

# Mesh profile check  
cargo check --no-default-features --features mesh

# Full profile check
cargo check --no-default-features --features mesh,dns

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Run all lib tests (compile check)
cargo test --lib --no-run
```

---

**Last Updated**: 2026-05-23
**Verification Status**: All action items completed or deferred. 6 deferred items require architectural work.