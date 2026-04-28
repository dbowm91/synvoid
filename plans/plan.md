# MaluWAF Implementation Plan

**Status**: Pruned - Implementation Complete
**Last Updated**: 2026-04-28
**Verification Completed**: 2026-04-28 (all items verified against codebase)

---

## Overview

All implementation waves (1-11) are **COMPLETE**. See AGENTS.md "Recently Completed Items" section for the full list of completed features with verification dates.

**Only the following items remain incomplete:**

---

## Remaining Items

### Pending (Incomplete)

| Item | Issue | Files | Priority |
|------|-------|-------|----------|
| P1.8 | `proxy_cache` not wired in `MeshProxy::route_request()` — field exists but cache lookup/insert never called in request path | `src/mesh/proxy.rs:766-909` | HIGH |
| P11.1 | Spin WASM HTTP routing not integrated — SpinRuntime implemented, admin API works, but HTTP requests don't route to Spin apps | `src/http/server.rs:1869-1949` | MEDIUM |
| P7A | WireGuard mesh transport enum not fully removed — deprecated variant still exists in `MeshTransportPreference` | `src/mesh/config.rs:619-620` | LOW |

---

## Deferred Items

These items are intentionally deferred and do not block the current release:

| # | Issue | Reason |
|---|-------|--------|
| D1 | dashmap 5.5.3 → 7.0.0-rc2 | Await stable release; 172 usages, major breaking changes |
| D2 | notify 6.0.0 → 9.0.0-rc.3 | Major API changes; consider v8.x first |
| D3 | O(k×n) DHT lookup complexity | Acceptable until 10x/100x scale |
| D4 | Hardcoded quorum timeout (10s) | Reasonable default for current scale |
| D5 | Veto abuse score unused | Not currently observed in production |
| D6 | ArcStr duplication cleanup | `utils.rs` vs `protocol.rs` — cosmetic |
| D7 | God module splits | metrics/mod.rs (2086 lines), mesh/transport.rs (3291), http/server.rs (4211) |
| D8 | WASM component support | ABI incompatible with current wasmtime runtime |
| D9 | Site scope in DHT key | Multi-tenant feature for future release |
| D10 | IPC key env fallback | Intentional opt-in via `allow_insecure_ipc_key` flag |

---

## Recently Fixed Items

| # | Issue | Fix | Date |
|---|-------|-----|------|
| D11 | DNS TSIG timing side channel | Replaced XOR loop with `subtle::ConstantTimeEq::ct_eq()` at `src/dns/tsig.rs:237-240` | 2026-04-28 |

---

## Removed Items (Verified False/Invalid)

| # | Original Claim | Resolution |
|---|----------------|------------|
| ~~P0.10~~ | Rate Limit Bypass via WASM Filters | **REMOVED**: Wrong file references. Actual execution order (rate limit → WASM) is correct. WASM-blocked requests consuming rate limit quota is intended DDoS protection behavior. |
| ~~P0.11~~ | AxumDynamic WAF Bypass | **REMOVED**: False claim. AxumDynamic dispatch is inside the `WafDecision::Pass` branch — WAF checks ARE applied. |

---

## Key Codebase Facts

- **Architecture**: Overseer → Master → Workers (Unix domain socket IPC)
- **Mesh types**: `MeshBackend`, `MeshBackendPool` in `src/mesh/backend.rs`
- **Base64**: `get_public_key()` uses `URL_SAFE_NO_PAD`; any decoder using `STANDARD` is wrong for mesh/DHT keys
- **Serialization**: Use `crate::serialization::serialize/deserialize` (Postcard) for binary; JSON only for admin API
- **Timestamps**: Use `u64` via `crate::mesh::safe_unix_timestamp()` or `crate::utils::current_timestamp()`
- **WireGuard**: MESH transport deprecated/non-functional (slated for removal in P7A). VPN tunnel (`src/tunnel/wireguard/`) is separate and working.

---

## Verification Commands

```bash
# Verify tests compile (cargo check does NOT compile test code)
cargo test --lib --no-run

# Run targeted tests
cargo test --lib <test_name>
cargo test --test integration_test

# Format and lint
cargo fmt
cargo clippy -- -D warnings

# Feature-specific checks
cargo check --features dns
cargo check --features post-quantum
```

---

## Historical Context

All waves 1-11 were implemented and verified between 2026-04-27 and 2026-04-28. The full history of completed items is maintained in AGENTS.md under "Recently Completed Items."
