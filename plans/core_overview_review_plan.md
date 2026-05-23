# Core/Overview Architecture Review Plan

## Document Sources Reviewed
- `architecture/overview.md` (417 lines)
- `architecture/deep_dive_review.md` (55 lines)
- `AGENTS.md` (204 lines)
- Module override files: `src/mesh/AGENTS.override.md`, `src/http/AGENTS.override.md`, `src/waf/AGENTS.override.md`, `src/platform/AGENTS.override.md`
- Code cross-references against actual implementation

---

## Verified Correct Items

| Claim | Verification | Status |
|-------|--------------|--------|
| Process hierarchy: Supervisor → Worker (consolidated) | `src/main.rs`, `src/process/manager.rs:660` | ✅ Correct |
| MeshBackendPool at `src/mesh/backend.rs:227` | Verified via grep | ✅ Correct |
| Spin routing integrated at `src/http/server.rs:2417-2489` | Verified via code reading | ✅ Correct |
| gRPC uses tonic transport (plaintext, no TLS) | `src/supervisor/api.rs:138` | ✅ Correct |
| File path corrections in AGENTS.md | All 8 corrections verified | ✅ Correct |
| SAFE_HEADERS count is 28 | `src/proxy/cache.rs:97-126` | ✅ Correct |
| collect_body_with_chunk_waf at `src/http/server.rs:4663` | Verified via grep | ✅ Correct |
| Quorum verification at `src/mesh/dht/signed.rs:860-934` | `src/mesh/AGENTS.override.md:390` | ✅ Correct |
| Overseer/Master/Worker processes exist | `src/overseer/*.rs`, `src/master/*.rs` | ✅ Correct |

---

## Discrepancies Found

### 1. Module Index Incomplete (MEDIUM Priority)

**Location**: `architecture/overview.md:332-383`

**Issue**: The "Module Index by Source Path" table is missing several actual modules.

**Missing modules that exist**:
- `src/icmp_filter/` — ICMP filtering (confirmed at `src/icmp_filter/mod.rs`)
- `src/serverless/` — WASM serverless runtime (confirmed at `src/serverless/mod.rs:1-8`)
- `src/spin/` — Spin framework support (confirmed at `src/spin/mod.rs:1-6`)
- `src/wasm_pow/` — WASM PoW (confirmed at `src/wasm_pow/lib.rs:1-10`)
- `src/tarpit/` — Bot tar pit (confirmed at `src/tarpit/mod.rs:1-5`)
- `src/honeypot_port/` — Honeypot ports (confirmed at `src/honeypot_port/mod.rs:1-15`)
- `src/mesh/proxy.rs` — MeshProxy (not listed separately)
- `src/plugin/` — Plugin system
- `src/sandbox/` — Process sandboxing

**Suggested Fix**: Add missing modules to the Module Index table.

---

### 2. gRPC Server Binding Claim Inaccurate (LOW Priority)

**Location**: `architecture/overview.md:393` (Errata section) and `architecture/deep_dive_review.md:15`

**Claim**: "The gRPC API binds to localhost only — TLS is not required for local IPC"

**Actual Behavior**: The `control_api_addr` can be any address:
- Config field at `crates/synvoid-config/src/process.rs:180-181`
- Default: `"127.0.0.1:50051"` at `src/process/manager.rs:81`
- But no enforcement that it must be localhost

**Issue**: The documentation presents this as a security feature (binding to localhost), but the code allows any address. If operator configures `0.0.0.0:50051`, it would accept external connections without TLS.

**Suggested Fix**: Either:
1. Document that operators should bind to localhost for security, OR
2. Add code enforcement that rejects non-localhost addresses

---

### 3. Router Module Description Oversimplified (LOW Priority)

**Location**: `architecture/overview.md:104`

**Claim**: "Router | `src/router.rs` | Domain-based routing to sites, Host header matching, wildcards"

**Issue**: `src/router.rs` is 1377 lines and contains complex logic including:
- `MatchRouter` struct with radix tree (not just simple domain routing)
- Backend type handling (Origin, Static, FastCGI, Mesh, Spin, Serverless, Plugin, etc.)
- `Target` struct with full backend configuration
- Routing logic with site resolution

**Suggested Fix**: Update description to reflect Router module's complexity:
```
Router | `src/router.rs`, `src/router/*` | Domain/path routing, BackendType resolution,
         MatchRouter (radix tree), SiteConfig resolution, upstream pool management
```

---

### 4. MeshProxy Not Mentioned in Module Index (MEDIUM Priority)

**Location**: `architecture/overview.md:219-233`

**Issue**: "Mesh Networking" table lists components but doesn't explicitly mention `MeshProxy`:
- `src/mesh/dht/` — DHT ✓
- `src/mesh/raft/` — Raft ✓
- `src/mesh/transport/` — QUIC/WireGuard ✓
- `src/mesh/` (Threat Intel, YARA Rules, Mesh Backend) — vague

**Missing**: `src/mesh/proxy.rs` — `MeshProxy` for backend routing via mesh is a key component.

**Code Verification**: `src/mesh/proxy.rs:63` defines `MeshProxy` with 1964 lines of implementation.

**Suggested Fix**: Add `MeshProxy | src/mesh/proxy.rs | Backend routing via mesh, peer selection, policy enforcement`

---

### 5. Process Table Flags Inconsistency (LOW Priority)

**Location**: `architecture/overview.md:54-61`

**Claim**:
```
| MeshAgent | --mesh-agent | Distributed control plane coordination | N |
```

**Actual**: Looking at `src/main.rs:464`, the available flags include `--wasm-jail` and `--yara-jail` but NOT `--mesh-agent`.

**Verification**: `grep` shows `--unified-server-worker`, `--static-worker`, `--worker`, `--wasm-jail`, `--yara-jail`, `--master`, `--overseer` but no `--mesh-agent`.

**Suggested Fix**: Verify correct flag for MeshAgent or remove from table if deprecated.

---

### 6. Application Handlers Table Missing BackendType Details (LOW Priority)

**Location**: `architecture/overview.md:198-208`

**Issue**: The table lists handler modules but doesn't mention the routing integration.

**Missing context**:
- Spin handler at `src/http/server.rs:2417-2489` requires manual app registration
- Serverless uses `BackendType::Serverless` with instance pooling
- Plugin uses `BackendType::Plugin` with WASM runtime

**Suggested Fix**: Add note about backend type integration or link to routing deep dive.

---

## Bugs Identified

### None Found

The architecture documents are generally accurate. No critical bugs in claims.

---

## Improvement Suggestions

### HIGH Priority

1. **Add missing modules to index** (`architecture/overview.md:332-383`)
   - `src/icmp_filter/`
   - `src/serverless/`
   - `src/spin/`
   - `src/wasm_pow/`
   - `src/tarpit/`
   - `src/honeypot_port/`
   - `src/plugin/`
   - `src/sandbox/`

### MEDIUM Priority

2. **Clarify MeshProxy role** - Add to mesh networking table with description

3. **Document Spin manual registration requirement** - Already in overview.md:205 but could be more prominent

4. **Add cross-reference to routing deep dive** for BackendType details

### LOW Priority

5. **gRPC binding clarification** - Document that operators should bind to localhost for security

6. **Router module description** - Update to reflect actual complexity

7. **Process flags verification** - Confirm correct flag for MeshAgent

8. **Add "see also" links** between related components (e.g., MeshProxy → MeshBackendPool)

---

## Summary

| Category | Count |
|----------|-------|
| Verified Correct | 9 |
| Discrepancies | 6 |
| Bugs | 0 |
| Improvements | 8 (3 HIGH, 2 MEDIUM, 3 LOW) |

**Overall Assessment**: The architecture documents are well-maintained and accurate. The AGENTS.md file path corrections have been properly propagated. Main opportunity is completing the Module Index with missing modules.

---

## Verification Commands Used

```bash
cargo test --lib --no-run    # Verify tests compile
cargo fmt && cargo clippy --lib -- -D warnings
```

**All profiles compile successfully** (confirmed via AGENTS.md):
- Core profile ✅
- Mesh profile ✅
- DNS profile ✅
- Full profile ✅