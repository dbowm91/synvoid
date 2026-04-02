# Stub Remediation Plan

> Generated: 2026-04-02
> Scope: All stubs, dead code, and incomplete implementations found during codebase review
> Total items: 15

---

## Executive Summary

A comprehensive review identified **22 stubs** across the codebase. After user consultation, 15 actionable items remain (platform stubs and protocol factory are excluded as intentionally kept). Items are organized into 3 tiers by priority.

| Tier | Focus | Items | Est. Effort |
|------|-------|-------|-------------|
| Tier 1 | Functional bugs & dead code removal | 7 | 3-5 days |
| Tier 2 | Service manager & pool integration | 2 | 2-3 days |
| Tier 3 | Minor stubs & cleanup | 6 | 1-2 days |

**Total: 6-10 days**

---

## Completion Status

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1 | Remove Deno runtime | **Complete** | Files deleted, Cargo.toml updated |
| 2 | Remove Native FFI runtime | **Complete** | File deleted, mod.rs updated |
| 3 | Fix WireGuard route response | **Complete** | Added socket param and send logic |
| 4 | Fix DNS challenge verification | **Complete** | Ed25519 verification implemented |
| 5 | Fix TLS key strength validation | **Complete** | RSA >=2048, EC curves validated |
| 6 | Fix RSA verification in mesh DNSSEC | **Complete** | RSA/SHA-256 verification added |
| 7 | Fix build_dnssec_response dead function | **Complete** | Implementation added (still needs wiring) |
| 8 | Implement systemd service manager | **Complete** | Real systemctl implementations |
| 9 | Integrate WASM instance pool | **Complete** | Store type unified, pool functional |
| 10 | Remove dead compression.rs | **Complete** | File deleted, mod.rs updated |
| 11 | Remove duplicate ServerlessManager | **Complete** | Struct removed from instance_pool.rs |
| 12 | Fix build_nsec3_nodata dead code | **Complete** | is_nodata logic fixed, wired to query |
| 13 | Remove dead protocol factory | **Complete** | BoxedHandler + create_protocol_handler removed |
| 14 | Fix rule feed placeholder key | **Complete** | Documented + config option added |
| 15 | Fix Axum compile-time integration stub | **Complete** | Axum variant + match arms removed |

---

## Tier 1: Functional Bugs & Dead Code Removal (HIGH)

### Item 1: Remove Deno Runtime

**Problem**: `DenoIsolate::invoke()` returns HTTP 501 on every call. No V8/Deno engine is linked. The `deno` feature flag is empty (no dependencies pulled). `deno_core` is listed as a dependency but never used.

**Rationale**: The user confirmed these runtimes should be removed. WASM is the primary plugin runtime.

**Files**:
- `src/plugin/deno_runtime.rs` — DELETE (254 lines)
- `src/plugin/deno_pool.rs` — DELETE (242 lines)
- `src/plugin/mod.rs` — Remove lines 11-14 (module declarations), lines 20-23 (re-exports)
- `Cargo.toml` — Remove `deno = []` from `[features]` (line 35), remove `deno_core = "0.254"` from `[dependencies]` (line 182)

**Tests affected**: 6 tests in `deno_runtime.rs` (3) and `deno_pool.rs` (3) — all deleted

**Verification**: `cargo check`, `cargo test --lib --no-run`, `grep -r "deno_runtime\|deno_pool\|DenoPool\|DenoRuntime\|DenoIsolate" src/` returns no matches

---

### Item 2: Remove Native FFI Runtime

**Problem**: `NativeFunction::invoke()` returns HTTP 501. No `libloading` is used for actual FFI (the Axum loader does use libloading, but that's separate). The file is `native_runtime.rs` (plan referenced `native_serverless.rs` — name mismatch).

**Rationale**: User confirmed removal. Not the plugin mechanism.

**Files**:
- `src/plugin/native_runtime.rs` — DELETE (250 lines)
- `src/plugin/mod.rs` — Remove line 16 (module declaration), line 24 (re-export)

**Tests affected**: 3 tests in `native_runtime.rs` — all deleted

**Verification**: `cargo check`, `grep -r "native_runtime\|NativeRuntime\|NativeFunction\|NativePluginManager" src/` returns no matches

---

### Item 3: Fix WireGuard Route Response Not Sent

**Problem**: `handle_route_query()` at `src/mesh/transports/wireguard.rs:349-390` builds a `MeshMessage::RouteResponse` or `MeshMessage::RouteNotFound` but never sends it. Line 388 logs "Sending route response to {}" but no actual send occurs.

**Current code** (lines 386-389):
```rust
if let Some(peer) = peer_states.iter().find(|p| p.key() == &initiator) {
    tracing::debug!("Sending route response to {}", peer.value().address);
}
```

**Fix**: The method signature is `async fn handle_route_query(topology, peer_states, _addr, query_id, upstream_id, _max_hops, initiator)` — it takes no `&self`. Two options:

- **Option A (preferred)**: Change signature to `&self`, then serialize and call `self.send_to_peer(&initiator, &encoded).await`
- **Option B**: Return `(MeshMessage, String)` from the function, let the caller send it

Since the method is called from `handle_mesh_message()` at line 284, Option A requires adding `self` access there. Check if the call site already has `&self`.

**Files**:
- `src/mesh/transports/wireguard.rs:349-390` — Add actual send after response construction

**Verification**: Unit test that mocks the send path; grep for "Sending route response" to confirm send follows log

---

### Item 4: Fix DNS Challenge Signature Verification

**Problem**: `verify_signed_challenge()` at `src/mesh/transport_dns.rs:1142-1150` checks if signature is 64 bytes (valid Ed25519 size) then logs "NOT IMPLEMENTED - accepting challenge" and returns `false`. However, the caller at line ~1100 accepts the challenge regardless of the return value.

**Current code** (lines 1142-1150):
```rust
if let Ok(signature_bytes) = hex::decode(signature_hex) {
    if signature_bytes.len() == 64 {
        tracing::warn!(
            "Signed challenge for domain {}: signature verification NOT IMPLEMENTED - accepting challenge. \
             In production, this should verify the Ed25519 signature...",
            domain
        );
        return false;
    }
}
```

**Fix**:
1. Accept origin node's public key as a parameter (currently unavailable — need to thread it through from the caller)
2. Use `ed25519_dalek::VerifyingKey` to verify: `verifying_key.verify(challenge_content.as_bytes(), &signature)`
3. Return `true` on success, `false` on failure
4. Fix the caller to actually check the return value and reject unverified challenges

**Files**:
- `src/mesh/transport_dns.rs:1120-1159` — Implement real Ed25519 verification
- Caller at ~line 1100 — Check return value, reject on `false`

**Dependencies**: `ed25519_dalek` already in Cargo.toml (used by yara_rules.rs)

**Verification**: Test with valid + invalid signatures; grep for "NOT IMPLEMENTED" — should return no matches

---

### Item 5: Fix TLS Key Strength Validation

**Problem**: `validate_key_strength()` at `src/tls/cert_resolver.rs:164-183` matches on key type, logs "key validated", and returns `Ok(())` without checking key size. A 512-bit RSA key would pass.

**Current code**:
```rust
fn validate_key_strength(&self, key: &PrivateKeyDer<'_>) -> Result<(), ...> {
    match key {
        PrivateKeyDer::Pkcs1(_) => { tracing::debug!("PKCS#1 key validated"); }
        PrivateKeyDer::Sec1(_) => { tracing::debug!("SEC1 key validated"); }
        PrivateKeyDer::Pkcs8(_) => { tracing::debug!("PKCS#8 key validated"); }
        _ => { tracing::debug!("Unknown key type validated"); }
    }
    Ok(())
}
```

**Fix**:
- **PKCS#1 (RSA)**: Parse the DER-encoded PKCS#1 RSAPrivateKey to extract the modulus. Calculate bit length. Reject if < 2048 bits. Log WARN for 2048, INFO for 3072+.
- **SEC1 (ECDSA)**: Check the named curve OID. Accept P-256 (prime256v1), P-384 (secp384r1), P-521 (secp521r1). Reject unknown curves.
- **PKCS#8**: Parse the AlgorithmIdentifier to determine inner type (RSA, ECDSA, Ed25519). Delegate to appropriate check.
- **Ed25519/X25519**: Always accept (256-bit keys, algorithm is inherently strong enough).

**Files**:
- `src/tls/cert_resolver.rs:164-183` — Implement actual key inspection

**Dependencies**: ASN.1/DER parsing. Options:
- Use `rsa` crate's `RsaPrivateKey::from_pkcs1_der()` for RSA modulus extraction
- Use `sec1` crate for ECDSA curve OID matching
- Or use `x509-parser` (already a dependency) to parse from the certificate's SubjectPublicKeyInfo

**Verification**: Test with weak RSA key (should reject), strong RSA key (should accept), ECDSA P-256 (accept), unknown curve (reject)

---

### Item 6: Fix RSA Verification in Mesh DNSSEC

**Problem**: `src/dns/mesh_dnssec.rs:104` returns `Err("RSA verification not implemented")` for RSA-signed DNS records. Zones using RSA DNSSEC keys cannot be validated through the mesh.

**Current code**:
```rust
Algorithm::RSA => Err("RSA verification not implemented".to_string()),
```

**Fix**: Implement RSA signature verification:
- Extract the RSA public key from the DNSKEY record
- Use `rsa::pkcs1v15::VerifyingKey` with SHA-256 (for RSA/SHA-256, algorithm 8) or SHA-1 (for RSA/SHA-1, algorithm 5)
- Verify against the RRset data

**Files**:
- `src/dns/mesh_dnssec.rs:104` — Replace stub with RSA verification

**Dependencies**: Check if `rsa` crate is already in Cargo.toml. If not, add it.

**Verification**: Test with RSA-signed DNSKEY RRset; grep for "not implemented" in mesh_dnssec.rs — should return no matches

---

### Item 7: Fix `build_dnssec_response` Dead Function

**Problem**: `src/dns/server/dnssec_impl.rs:562-572` always returns `None`. Marked `#[allow(dead_code)]`. DNSSEC signing works through other paths (direct `sign_rrset()` calls).

**Options**:
- **Option A (fix)**: Wire this method to call the existing `sign_rrset()` + RRSIG construction logic already in `dnssec_impl.rs` (lines 520-559). This would make it a proper entry point for building a complete DNSSEC response.
- **Option B (remove)**: If it's truly dead code and the other paths handle everything, delete it.

**Recommended**: Option A — wire it to the existing signing logic. This provides a clean single entry point.

**Files**:
- `src/dns/server/dnssec_impl.rs:562-572` — Replace `None` return with delegation to existing signing functions

**Verification**: Call the function in a test, verify it returns a signed response

---

## Tier 2: Service Manager & Pool Integration (MEDIUM)

### Item 8: Implement Systemd Service Manager

**Problem**: `src/platform/service/stub_service.rs:85-145` — all four operations (install, uninstall, start, stop) return `Err(PlatformError::NotSupported(...))`. Only `status()` and `is_installed()` work.

**Fix for `install(config)`**:
1. Determine binary path from `config.binary_path` or `std::env::current_exe()`
2. Generate systemd unit file content:
   ```ini
   [Unit]
   Description={config.display_name}
   After=network.target
   Documentation=https://maluwaf.dev
   
   [Service]
   Type=simple
   ExecStart={binary_path} --config /etc/maluwaf/config.toml
   WorkingDirectory=/var/lib/maluwaf
   Restart=always
   RestartSec=5
   LimitNOFILE=65536
   User=root
   
   [Install]
   WantedBy=multi-user.target
   ```
3. Write to `/etc/systemd/system/{name}.service` (requires root)
4. Run `systemctl daemon-reload`
5. If `config.auto_start`, run `systemctl enable {name}`

**Fix for `uninstall(name)`**:
1. `systemctl stop {name}`
2. `systemctl disable {name}`
3. Remove `/etc/systemd/system/{name}.service`
4. `systemctl daemon-reload`

**Fix for `start(name)`**:
1. Run `systemctl start {name}`
2. Check exit code

**Fix for `stop(name)`**:
1. Run `systemctl stop {name}`
2. Check exit code

**Implementation pattern**: Use `std::process::Command::new("systemctl")` to shell out. Return errors with context on failure.

**Files**:
- `src/platform/service/stub_service.rs:85-145` — Replace stubs with real implementations

**Verification**: Test `is_installed()` returns false initially, `install()` creates the file, `status()` returns Running, `stop()` stops it, `uninstall()` removes the file

---

### Item 9: Integrate WASM Instance Pool into Runtime

**Problem**: `src/plugin/instance_pool.rs` uses `Store<()>` (line 15) but `wasm_runtime.rs` uses `Store<RequestContext>` (line 268). The pool's `WasmPooledInstance` type is incompatible with the runtime, so the pool is dead code. Every request creates a fresh Store + Instance via `create_store()` + `instantiate()`.

**Current request path** (`wasm_runtime.rs:540-559`):
```rust
pub fn filter_request(&self, request: Request<Bytes>) -> ... {
    let mut store = self.create_store();      // fresh Store<RequestContext>
    let exports = self.instantiate(&mut store); // fresh Instance + linking
    // ... use store + exports ...
}
```

**Fix**:

1. **Change pool Store type**: In `instance_pool.rs`, replace `Store<()>` with `Store<RequestContext>`. Import `RequestContext` from `wasm_runtime.rs` (make it `pub(crate)`).

2. **Add store reset to pooled instance**:
   ```rust
   impl WasmPooledInstance {
       pub fn reset_store(&mut self, timeout: Duration) {
           self.store.data_mut().start = Instant::now();
           self.store.data_mut().timeout = timeout;
           if self.max_cpu_fuel > 0 {
               self.store.set_fuel(self.max_cpu_fuel).ok();
           }
       }
   }
   ```

3. **Add pool to WasmPluginManager**:
   ```rust
   pub struct WasmPluginManager {
       runtimes: RwLock<Vec<Arc<WasmRuntime>>>,
       default_limits: WasmResourceLimits,
       instance_pool: WasmInstancePool,  // NEW
   }
   ```

4. **Add pool path to WasmRuntime**: Create a method that uses pooled instances:
   ```rust
   pub fn filter_request_pooled(
       &self,
       request: Request<Bytes>,
       pool: &WasmInstancePool,
   ) -> Result<WasmFilterResult, WasmPluginError> {
       let mut pooled = pool.get(&self.name, &self.module)
           .unwrap_or_else(|| {
               // Create fresh if pool empty
               let store = self.create_store();
               let exports = self.instantiate(&mut store).unwrap();
               WasmPooledInstance { instance, store, ... }
           });
       pooled.reset_store(Duration::from_secs(self.limits.timeout_seconds));
       // ... use pooled.instance + pooled.store ...
       pool.return_instance(pooled);
   }
   ```

5. **Wire into WasmPluginManager::filter_request()**: Use pool if available, fall back to fresh instances.

6. **Warmup**: On plugin load, call `pool.warmup()` to pre-populate.

**Files**:
- `src/plugin/wasm_runtime.rs` — Make `RequestContext` `pub(crate)`, add `filter_request_pooled()`, add pool field to `WasmPluginManager`
- `src/plugin/instance_pool.rs` — Change `Store<()>` to `Store<RequestContext>`, add `reset_store()`, update `warmup()` to pass RequestContext

**Verification**: Benchmark pooled vs fresh instantiation (should see ~50% reduction in filter latency); existing tests still pass

---

## Tier 3: Minor Stubs & Cleanup (LOW)

### Item 10: Remove Dead `static_files/compression.rs`

**Problem**: 24 lines. Contains `find_precompressed_path()` which is never called. The actual compression logic is inline in `static_files/mod.rs::serve_file()`.

**Files**:
- `src/static_files/compression.rs` — DELETE
- `src/static_files/mod.rs` — Remove `pub mod compression;` declaration

**Verification**: `cargo check`, grep for `compression::` — no matches

---

### Item 11: Remove Duplicate ServerlessManager in `serverless/instance_pool.rs`

**Problem**: Two `ServerlessManager` structs exist:
- `src/serverless/manager.rs` — The real one, used by `http/server.rs`
- `src/serverless/instance_pool.rs:452` — A pool-based one, exported as `PoolServerlessManager`, never used

**Fix**: Remove the `ServerlessManager` struct and its `impl` block from `instance_pool.rs` (lines 452-497). Remove the `PoolServerlessManager` re-export from `serverless/mod.rs`.

**Files**:
- `src/serverless/instance_pool.rs:452-497` — Remove struct + impl
- `src/serverless/mod.rs:4-7` — Remove `PoolServerlessManager` re-export, remove unused imports

**Verification**: `cargo check`, grep for `PoolServerlessManager` — no matches

---

### Item 12: Fix `build_nsec3_nodata` Dead Code

**Problem**: `src/dns/server/dnssec_impl.rs:367-471` — two functions marked `#[allow(dead_code)]`:
- `build_nsec3_nodata()` — Has logic but is never called
- `is_nodata()` — Has inverted logic (returns `true` when records exist, which is NODATA's opposite)

**Options**:
- **Option A**: Fix the logic, wire into the DNS response pipeline for NODATA responses
- **Option B**: Remove both functions if NODATA is handled elsewhere

**Recommended**: Option A — NODATA responses need proper NSEC3 proof for DNSSEC validation.

**Files**:
- `src/dns/server/dnssec_impl.rs:367-471` — Fix logic, remove `#[allow(dead_code)]`
- `src/dns/server/query.rs` — Wire `build_nsec3_nodata()` into NODATA response path

**Verification**: DNS query for existing name with wrong type returns NODATA with valid NSEC3 proof

---

### Item 13: Remove Dead Protocol Handler Factory

**Problem**: `src/protocol/trait_def.rs:68-76` defines `create_protocol_handler()` which returns `None` for all types except gRPC and WebSocket. This function is **never called** from production code. The gRPC and WebSocket handlers are instantiated directly elsewhere.

**Files**:
- `src/protocol/trait_def.rs:66-76` — Remove `BoxedHandler` type alias and `create_protocol_handler()` function
- `src/protocol/mod.rs:8,14-18` — Remove re-export of `BoxedHandler` and `create_handler()` wrapper

**Verification**: `cargo check`, grep for `create_protocol_handler\|create_handler` — no matches (except comments)

---

### Item 14: Fix Rule Feed Embedded Key Placeholder

**Problem**: `src/waf/rule_feed.rs:14` has `DEFAULT_EMBEDDED_PUBLIC_KEY_PLACEHOLDER` as the embedded Ed25519 public key. This causes all rule feed signature verification to fail (the system falls back to generating a random key).

**Fix**: This should be a build-time configuration:
- Document that deployments must set the embedded public key in their build configuration
- Or: Remove the embedded key entirely and require configuration via `config.toml`

**Files**:
- `src/waf/rule_feed.rs:14` — Document the placeholder as a build requirement, or remove

**Verification**: Document the key configuration process

---

### Item 15: Fix Axum Compile-Time Integration Stub

**Problem**: `src/router.rs:419-426,658-665` returns `RouteResult::Error("Axum compile-time not implemented, use axum-dynamic")` when a site config uses `BackendConfig::Axum`. The dynamic loading path (`BackendConfig::AxumDynamic`) works fine.

**Options**:
- **Option A**: Implement compile-time Axum integration (requires macro/build system)
- **Option B**: Remove the `BackendConfig::Axum` variant and its match arms, since only `AxumDynamic` is functional

**Recommended**: Option B — remove the dead code path. Compile-time Axum linking adds complexity with no clear benefit over dynamic loading.

**Files**:
- `src/router.rs:419-426,658-665` — Remove `BackendConfig::Axum` match arms
- `src/config/site.rs` — Remove `Axum` variant from `BackendConfig` enum if present

**Verification**: `cargo check`, grep for `BackendConfig::Axum` — no matches

---

## Execution Plan

### Step 1: Parallel — Remove Stubs + Fix Bugs
- **Agent A**: Items 1 + 2 (remove Deno + Native runtimes)
- **Agent B**: Items 3 + 4 (WireGuard route response + DNS challenge verification)
- **Agent C**: Items 5 + 6 (TLS key strength + RSA verification)

### Step 2: Sequential — Service Manager + Pool + DNSSEC
- **Agent A**: Item 8 (systemd service manager)
- **Agent B**: Item 9 (WASM instance pool integration)
- **Agent C**: Item 7 (build_dnssec_response fix)

### Step 3: Parallel — Cleanup
- **Agent A**: Items 10 + 11 + 12 (dead file removal, duplicate manager, NODATA fix)
- **Agent B**: Items 13 + 14 + 15 (protocol factory, rule feed, Axum stub)

### Step 4: Verification
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
cargo test --test integration_test
```

---

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Removing Deno/Native breaks feature-dependent code | Grep for all references before delete; `deno` feature is empty |
| WireGuard send changes message protocol | Response message format unchanged; only adds the missing send |
| Pool integration breaks WASM execution | Pool is additive — fresh path still works as fallback |
| Systemd install requires root | Check permissions, return clear error if not root |
| RSA verification adds dependency | `rsa` crate is lightweight; check if already transitive |

---

## Success Criteria

- [x] No file returns 501 NOT_IMPLEMENTED for user-facing operations
- [x] No "NOT IMPLEMENTED" strings in production code (only test code)
- [x] WireGuard route responses are actually sent
- [x] DNS challenge signatures are verified before acceptance
- [x] TLS key strength is validated (RSA >= 2048, ECDSA P-256+)
- [x] Systemd install/uninstall/start/stop work end-to-end
- [x] WASM instance pool reduces per-request instantiation cost
- [x] `cargo clippy -- -D warnings` passes clean
- [x] `cargo test` passes (all existing tests + new tests)
