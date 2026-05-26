# Compilation Issues Cleanup Plan

## Overview
Fix all compilation errors, clippy lint errors, and warnings to achieve a clean build.

---

## Wave 1: Critical - Make `cargo clippy -D warnings` Pass

| # | Crate | Issue | Location | Fix |
|---|-------|-------|----------|-----|
| 1 | cloakrs | collapsible match | `cloak/src/jpeg_transcoder/header.rs:290` | Remove braces from `0xDD` match arm |
| 2 | synvoid-config | unused import | `crates/synvoid-config/src/app_server.rs:5` | Remove `use utoipa::ToSchema;` |
| 3 | synvoid-config | dead code | `crates/synvoid-config/src/mesh.rs:12` | Remove `POW_CACHE_TTL_SECS` constant |
| 4 | synvoid-config | derivable impl | `crates/synvoid-config/src/icmp_filter.rs:88-92` | Add `#[derive(Default)]` + `#[default]` variant |
| 5 | synvoid-config | needless borrow | `crates/synvoid-config/src/mesh.rs:656` | Change `&public_key` to `public_key` |
| 6 | synvoid | overly complex bool | `src/http/server.rs:3302` | Simplify to `use_erased_client = false;` |

### Wave 1 Fix Details

**Fix 1: cloakrs collapsible match**
```rust
// Before
0xDD => {
    if segment_data.len() >= 2 {
        header.restart_interval = ...;
    }
}

// After
0xDD => if segment_data.len() >= 2 {
    header.restart_interval = ...;
}
```

**Fix 2-5: synvoid-config issues**
- Remove `use utoipa::ToSchema;` from app_server.rs
- Remove `POW_CACHE_TTL_SECS` constant from mesh.rs
- Change `impl Default for InterfaceSpec` to `#[derive(Default)]` with `#[default]`

**Fix 6: http/server.rs overly complex bool**
```rust
// Before
let use_erased_client = false
    && !needs_body_transform
    && !crate::http_client::is_quictunnel_url(&target.upstream)
    && ...;

// After
let use_erased_client = false;
```

---

## Wave 2: Fix Test Compilation Errors

**2.1 AttackDetection API Mismatch (~144 errors)**
- `check_request` method at `src/waf/attack_detection/mod.rs:254` takes 6 args
- Tests pass 5 args (missing `client_ip: IpAddr` as first arg)
- Tests don't `.await` the async call
- **Location**: `tests/integration_test.rs:4666+`
- **Fix**: Update test calls to pass `client_ip: IpAddr` and add `.await`

**2.2 Missing Struct Fields**
| Struct | Missing Fields | Test Location |
|--------|---------------|---------------|
| `UnifiedServerWorkerArgs` | `cpu_affinity`, `total_workers` | `src/worker/unified_server.rs:1884-1941` |
| `OverseerConfig` | `restart_backoff_max_secs`, `process_stop_timeout_secs` | `tests/integration_test.rs:45-60` |
| `ProcessManagerConfig` | `control_api_addr` | `tests/integration_test.rs:139-159` |

**2.3 Wrong Import**
- `WhitelistConfig` doesn't exist in `synvoid::waf`
- **Fix**: Update to use `crate::config::SiteWhitelistConfig` with corrected field names

**2.4 Missing Debug Impl**
- `Http1PooledConnection` needs `#[derive(Debug)]` or manual impl

---

## Wave 3: Address Warnings

**3.1 Unused Imports (~40)** - Remove unused imports across:
- `src/admin/handlers/alerting.rs`, `src/admin/mod.rs`
- `src/challenge/pow.rs`
- `src/http/server.rs`, `src/http/shared_handler.rs`, `src/http3/server.rs`
- `src/http_client/erased_pool.rs`, `src/http_client/typed_pool.rs`
- `src/proxy/dispatch.rs`, `src/proxy/executor.rs`, `src/proxy/governor.rs`
- `src/sandbox/mod.rs`, `src/server/waf_handler.rs`
- `src/supervisor/*.rs`, `src/tunnel/wireguard/userspace.rs`
- `src/upstream/pool.rs`, `src/waf/attack_detection/*.rs`

**3.2 Dead Code (~15)** - Remove or `#[allow(dead_code)]`:
- `update_mesh_config` function (admin/handlers/config.rs)
- `compute_websocket_accept_key` function (http/server.rs)
- `HttpProtocol` enum, `PooledConnection` trait
- `Http2PooledConnection` struct
- `MlKemKeyExchangeService.key_max_age_secs` field
- `MeshTransport.handle_pong` method
- Various other unused structs/functions

**3.3 Deprecated API** - Update 5 occurrences:
- `Nonce::from_slice` → `Nonce::from_bytes` in `cert_dist.rs` (lines 56, 98, 172)
- `Nonce::from_slice` → `Nonce::from_bytes` in `config_identity.rs` (lines 428, 460)

**3.4 Minor Issues**:
- `mut chunk_bytes` → `chunk_bytes` (http3/server.rs:708)
- `drop(rx)` → `let _ = rx` (mesh/dht/quorum.rs:411)

---

## Wave 4: Formatting

Run `cargo fmt` to fix formatting in:
- `src/mesh/dht/quorum.rs`
- `src/mesh/raft/mod.rs`
- `src/mesh/raft/network.rs`

---

## Execution Order

1. **Wave 1** - Fix clippy errors (`cargo clippy -D warnings` passes)
2. **Wave 2** - Fix test compilation (`cargo test --no-run` passes)
3. **Wave 3** - Address all warnings
4. **Wave 4** - Apply formatting

---

## Verification Commands

```bash
# Check clippy
cargo clippy --no-default-features --features mesh,dns -- -D warnings

# Check test compilation
cargo test --no-default-features --features mesh,dns --no-run

# Check for warnings
cargo build --no-default-features --features mesh,dns

# Check formatting
cargo fmt && cargo fmt --check
```
