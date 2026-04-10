# MaluWAF Improvement Plan

This document tracks remaining future work items. Completed items have been removed to keep this document focused.

## Quick Reference

| Wave | Focus Area | Status |
|------|------------|--------|
| 1 | Critical Performance Fixes | 🔶 Future Work |
| 2 | Mesh & DHT Infrastructure | 🔶 Future Work |
| 7 | Security Audit Remediation | 🔶 Future Work |
| 8 | Code Quality & Technical Debt | 🔶 Future Work |

**Legend**:
- 🔶 Future Work = Deferred or partially complete, needs attention
- ✅ Completed = See git history or skill files for details

---

## Wave 1: Critical Performance Fixes

### 1.1 `.to_lowercase()` Calls in WAF Detectors

**Status**: 🔶 Future Work (Architectural Limitation)

The `BasePatternDetector` uses AhoCorasick with pre-lowercased patterns. Since AhoCorasick performs exact matching, input strings MUST be lowercased before pattern matching.

**Decision**: Accept as architectural limitation. Each detection is a single allocation that is freed after detection completes.

**Files with remaining calls**: `request_smuggling.rs`, `detector_common.rs`, `jwt.rs`, `path_traversal.rs`, `rfi.rs`, `xxe.rs`, `open_redirect.rs`, `header_validation.rs`

### 1.2 Memory Allocations in Hot Paths

**Status**: 🔶 Future Work (Architectural Limitation)

Some hot path allocations are inherent to the design:
- `src/http/server.rs:718-724` - Fixed: Changed from `full_body.clone()` to `Arc::new(full_body)`
- `src/proxy.rs:246,263,1482,1489` - API signature would need breaking changes
- `src/waf/attack_detection/normalizer.rs:63-64` - Allocation necessary for owned `NormalizedInput`

**Decision**: Accept as architectural limitation.

---

## Wave 2: Mesh & DHT Infrastructure

### 2.8 DHT-Primary Rule Propagation

**Status**: 🔶 Future Work

**Items**:
- Wire `sync_from_dht()` for YARA rules (partially done)
- Wire `sync_from_dht()` for ThreatIntel (partially done)
- Mark mesh broadcast as fallback (to be removed later)
- Ensure `publish_rules_to_dht()` called for all rule sources (done)

**Architecture**: Both YARA rules and ThreatIntel use DHT as primary propagation mechanism. See `skills/malu_mesh.md` for detailed documentation.

**Key Files**:
- `src/mesh/yara_rules.rs` - `publish_rules_to_dht()`, `sync_from_dht()`
- `src/mesh/threat_intel.rs` - `sync_from_dht()`
- `src/mesh/dht/keys.rs` - DHT key types

### 2.2 YARA Rules Mesh Distribution

**Status**: 🔶 Future Work (Phases 1-2 done, Phase 3-4 partial)

Previous phases completed:
- ✅ Fix mesh broadcast transport - use `broadcast_to_all_peers()` with `Some(GLOBAL)` role filtering
- ✅ Auto-broadcast after `apply_rules_from_feed()` on global nodes
- ✅ DHT-based global-to-global sync with content-addressed delta sync

**See Section 2.8 for DHT-primary propagation implementation.**

---

## Wave 7: Security Audit Remediation

### 7.2 Medium Severity Items

**Status**: 🔶 Future Work

| Category | Issue | Fix | Status |
|----------|-------|-----|--------|
| Mesh | node_id to Public Key Binding | Include hash of pubkey in node_id | 🔄 DEFERRED |
| Mesh | TOFU Accepts First Certificate | Add out-of-band verification option | 🔄 DEFERRED |

**Completed items** (see git history for details):
- ✅ X-Forwarded-For Single IP validation
- ✅ Open Redirect Path Check
- ✅ Domain Check Before URL Decode
- ✅ TLS skip_verify warning improvement
- ✅ TLS allow_plaintext HTTP upstream warning
- ✅ IPC Mutual Authentication via `UnixStream::peer_credentials()`
- ✅ DNSSEC validation for Recursive provider
- ✅ RRL implemented for UDP responses

---

## Wave 8: Code Quality & Technical Debt

### 8.4 Private Key Encryption at Rest

**Status**: 🔄 DEFERRED

**Location**: `src/mesh/config.rs:781-847`

**Issue**: 
1. `EncryptedKey` type does not exist in codebase
2. Infrastructure exists in `NodeIdentityConfig` (`encrypt_key`/`decrypt_key` methods)
3. `GlobalNodeConfig` and `OriginSigningKeyConfig` don't use encryption pattern
4. Needs proper design before implementation

### 8.5 Large File Splitting

**Status**: 🔶 Future Work (Partially Done)

**Completed splits**:
- ✅ `src/process/ipc.rs` - split into 6 sibling modules
- ✅ `src/process/manager.rs` - worker types extracted to `worker.rs`
- ✅ `src/mesh/topology.rs` - types extracted to `topology/types.rs`

**Ergonomics improvements**:
- ✅ `src/http/server.rs` - Added `apply_security_headers()` helper (reduces duplication)
- ✅ `src/http/server.rs` - Added `RequestMetrics` struct (wired in)

**Remaining**:
- 🔄 `src/http/server.rs` - `handle_request()` is 2,257 lines. Cannot be mechanically split without architectural refactor. Ergonomics improved.

---

## Completed Work History

For details on completed items, see:
- Git history: `git log --oneline`
- Skill files: `skills/malu_mesh.md`, `skills/dns_dnssec.md`, `skills/admin_ui.md`
- AGENTS.md: Contains architecture documentation and testing patterns

---

## Dependencies and Notes

### Private Key Encryption (Wave 8.4)

The encryption/decryption infrastructure in `src/mesh/config_identity.rs` supports passphrase-based encryption, but integration with `GlobalNodeConfig` and `OriginSigningKeyConfig` is not complete.

### node_id to Public Key Binding (Wave 7.2)

This is a security improvement to prevent man-in-the-middle attacks between peers. Currently, TOFU is used which accepts the first certificate presented.

### http/server.rs Split (Wave 8.5)

The `handle_request()` function handles routing to 8+ backend types (Static, Serverless, FastCGI, PHP, AppServer, Proxy, etc.). Extracting backend-specific logic would require significant architectural refactoring. Current ergonomics improvements (helper functions, RequestMetrics) make the file more maintainable without full split.