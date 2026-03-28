# Readability, Verbosity, and Duplication Reduction Plan

**Status:** Draft — not started
**Scope:** `src/` — no behavioral changes, pure refactoring

---

## Table of Contents

1. [TokenBucket Deduplication](#1-tokenbucket-deduplication)
2. [current_timestamp() Deduplication](#2-current_timestamp-deduplication)
3. [now_secs() / timestamp utility consolidation](#3-now_secs--timestamp-utility-consolidation)
4. [DNS Resolver: extract ensure_fqdn helper](#4-dns-resolver-extract-ensure_fqdn-helper)
5. [DNS Resolver: generic lookup_records helper](#5-dns-resolver-generic-lookup_records-helper)
6. [Validation Error Type Unification](#6-validation-error-type-unification)
7. [parse_size_string Deduplication](#7-parse_size_string-deduplication)
8. [Admin Config Handler Boilerplate](#8-admin-config-handler-boilerplate)
9. [HTTP Response Builder Consolidation](#9-http-response-builder-consolidation)
10. [Mesh Transport send-and-log Helper](#10-mesh-transport-send-and-log-helper)
11. [Status Code Text Mapping Consolidation](#11-status-code-text-mapping-consolidation)
12. [TrustAnchorConfig Consolidation](#12-trustanchorconfig-consolidation)

---

## 1. TokenBucket Deduplication

**Problem:** `src/dns/rate_limiter.rs` (239 lines) and `src/dns/server/rate_limit.rs` (240 lines) are copy-pasted duplicates. They contain identical `TokenBucket`, `TimedTokenBucket`, `TimedBucketMap<K>`, and `DnsRateLimiter` implementations. The only difference is import style (`use super::*` vs explicit imports).

Two other TokenBucket variants exist but are structurally different and should remain separate:
- `src/process/ipc_rate_limit.rs` — `u64` refill_rate, `consume(amount)` method, mutex-wrapped
- `src/waf/traffic_shaper/bucket.rs` — `AtomicU64` fields, lock-free, byte-oriented consumption

**Plan:**

1. Create `src/rate_limit/mod.rs` with the shared types:
   - `TokenBucket` (the non-atomic, `f64` refill_rate version)
   - `TimedTokenBucket`
   - `TimedBucketMap<K>`
   - Constants: `DEFAULT_MAX_BUCKETS`, `DEFAULT_CLEANUP_INTERVAL_SECS`, `DEFAULT_BUCKET_EXPIRY_SECS`
   - All types `pub`, methods `pub`

2. In `src/dns/rate_limiter.rs`:
   - Remove the 4 local type definitions and 4 constants
   - Add `use crate::rate_limit::{TokenBucket, TimedTokenBucket, TimedBucketMap};`
   - Keep `DnsRateLimiter` and its impl here (it's DNS-specific)

3. In `src/dns/server/rate_limit.rs`:
   - Remove all local type definitions and constants
   - Add `use crate::rate_limit::{TokenBucket, TimedTokenBucket, TimedBucketMap};`
   - Keep `DnsRateLimiter` and its impl here (it's the server-side variant)

4. Add `pub mod rate_limit;` to `src/lib.rs`

5. Verify: `cargo check && cargo test`

**Files touched:** `src/lib.rs` (+1 line), `src/rate_limit/mod.rs` (new, ~110 lines), `src/dns/rate_limiter.rs` (~120 lines removed), `src/dns/server/rate_limit.rs` (~120 lines removed)

**Net impact:** ~130 lines removed, single source of truth for token bucket logic

---

## 2. current_timestamp() Deduplication

**Problem:** The function `current_timestamp() -> u64` (returns Unix epoch seconds) is defined independently in **7 places**:

| File | Line | Visibility |
|------|------|-----------|
| `src/utils.rs` | 414 | `pub` |
| `src/process/ipc.rs` | 1311 | `pub` |
| `src/overseer/state.rs` | 148 | method on `OverseerState` |
| `src/waf/probe_tracker.rs` | 446 | private `fn` |
| `src/mesh/dht/stake.rs` | 533 | private `fn` |
| `src/mesh/transports/manager.rs` | 32 | private `fn` |
| `src/captcha/mod.rs` | 185 | private `fn` |

Some use `.unwrap()` (panic on clock skew), some use `.unwrap_or_default()` (silent zero). The `utils.rs` version uses `.unwrap_or_default()` and should be the canonical one.

**Plan:**

1. Standardize on `crate::utils::current_timestamp()` (already `pub`, uses `unwrap_or_default`).

2. For each duplicate definition, remove it and add `use crate::utils::current_timestamp;`:
   - `src/process/ipc.rs:1311` — remove the `pub fn`, re-export from `utils` if needed by consumers
   - `src/overseer/state.rs:148` — remove method, use free function
   - `src/waf/probe_tracker.rs:446` — remove, import
   - `src/mesh/dht/stake.rs:533` — remove, import
   - `src/mesh/transports/manager.rs:32` — remove, import
   - `src/captcha/mod.rs:185` — remove, import

3. Check for re-exports: `src/process/ipc.rs` re-exports `current_timestamp` via `src/process/mod.rs:30`. One consumer exists at `src/worker/mod.rs:633` (`crate::process::current_timestamp()`). Fix:
   - Remove `current_timestamp` from the `pub use ipc::{ ... }` block in `src/process/mod.rs:30`
   - Change `src/worker/mod.rs:633` from `crate::process::current_timestamp()` to `crate::utils::current_timestamp()`

4. Verify: `cargo check && cargo test`

**Files touched:** 7 files (remove ~3-5 lines each, add import)

**Net impact:** ~30 lines removed, single source of truth for timestamp

---

## 3. now_secs() / timestamp utility consolidation

**Problem:** 44+ occurrences of `SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()` across 15 files, especially concentrated in:
- `src/dns/trust_anchor.rs` — 11 occurrences (lines 89, 111, 133, 143, 443, 516, 610, 715, 809, 820, 836)
- `src/dns/dnssec.rs` — 6 occurrences
- `src/waf/threat_level/persistence/sqlite.rs` — 6 occurrences
- `src/block_store.rs` — 3 occurrences

`utils::current_timestamp()` already exists but many call sites inline the pattern (sometimes with `.unwrap()` which panics on clock skew, vs `current_timestamp()`'s `.unwrap_or_default()`).

**Plan:**

1. Audit each of the 44 inline occurrences. For each:
   - If it uses `.unwrap()` and the surrounding context tolerates a default (0), replace with `crate::utils::current_timestamp()`
   - If it uses `.unwrap()` and the surrounding context cannot tolerate 0, consider `unwrap_or_else(|e| { tracing::warn!(...); 0 })` — but in practice, clock going backward before Unix epoch is not a real concern, so `current_timestamp()` suffices

2. Focus on `src/dns/trust_anchor.rs` first (highest concentration, 11 occurrences):
   - Add `use crate::utils::current_timestamp;` at top
   - Replace each 4-line block with `let now = current_timestamp();`

3. Then address remaining files in order of occurrence count.

4. Verify: `cargo check && cargo test`

**Files touched:** ~15 files (each ~4 lines → 1 line)

**Net impact:** ~130 lines simplified, consistent error handling for timestamp

---

## 4. DNS Resolver: extract ensure_fqdn helper

**Problem:** Every DNS resolver lookup method repeats this 4-line normalization:

```rust
let name = if name.ends_with('.') {
    name.to_string()
} else {
    format!("{}.", name)
};
```

This appears 9 times in `src/dns/resolver.rs` (lines 299, 319, 339, 354, 378, 408, 440, 466, 498).

**Plan:**

1. Add a private helper in `src/dns/resolver.rs`:
   ```rust
   fn ensure_trailing_dot(name: &str) -> String {
       if name.ends_with('.') {
           name.to_string()
       } else {
           format!("{}.", name)
       }
   }
   ```

2. Replace all 9 occurrences of the inline pattern with `let name = ensure_trailing_dot(name);`

3. Verify: `cargo check && cargo test`

**Files touched:** `src/dns/resolver.rs` (add ~7 lines, remove ~27 lines)

**Net impact:** ~20 lines removed, single place to change normalization logic

---

## 5. DNS Resolver: generic lookup_records helper

**Problem:** `lookup_mx`, `lookup_soa`, `lookup_ptr`, `lookup_srv`, `lookup_cname` (lines 377-521) follow identical structure: normalize name, call `self.resolver.lookup(&name, RecordType::X).await`, extract records.

**Plan:**

1. Add a private generic helper in `src/dns/resolver.rs`:
   ```rust
   async fn lookup_records<T>(
       &self,
       name: &str,
       rtype: RecordType,
       extract: impl Fn(&RData) -> Option<T>,
   ) -> ResolverResult<Vec<(T, u32)>>
   ```

2. Refactor each lookup method to use this helper. Note: `lookup_soa`, `lookup_ptr`, `lookup_cname` return `Option<T>` (not `Vec<T>`) and silently return `Ok(None)` on error. These need a separate variant or a thin wrapper.

3. The `lookup_mx` and `lookup_srv` methods (return `Vec`, propagate errors) map cleanly to the helper.

4. For the `Option`-returning variants, add:
   ```rust
   async fn lookup_optional_record<T>(
       &self,
       name: &str,
       rtype: RecordType,
       extract: impl Fn(&RData) -> Option<T>,
   ) -> ResolverResult<Option<T>>
   ```

5. Verify: `cargo check && cargo test`

**Files touched:** `src/dns/resolver.rs` (add ~30 lines, reduce ~100 lines from 5 methods)

**Net impact:** ~70 lines removed, single place to change lookup behavior

---

## 6. Validation Error Type Unification

**Problem:** Three near-identical validation error types:

| File | Type | Fields |
|------|------|--------|
| `src/config/validation.rs:2` | `ConfigValidationError` | `field: String, message: String` |
| `src/config/site.rs:1045` | `SiteConfigValidationError` | `field: String, message: String` |
| `src/tunnel/quic/validation.rs:24` | `ValidationError` | `field: &'static str, reason: String, value_preview: String` |

The first two are structurally identical with identical `Display`/`Error` impls. The third has a different shape (static str field + preview).

**Plan:**

1. Keep `ConfigValidationError` in `src/config/validation.rs` as the canonical type.

2. In `src/config/site.rs`:
   - Remove `SiteConfigValidationError` definition and its `Display`/`Error` impls (~12 lines)
   - Add `use crate::config::validation::ConfigValidationError;`
   - Replace all `SiteConfigValidationError` references with `ConfigValidationError`
   - Check for constructor calls — field names are identical so no changes needed

3. Leave `src/tunnel/quic/validation.rs::ValidationError` as-is — it has a different shape (`&'static str` field, `value_preview`) serving a different purpose.

4. Verify: `cargo check && cargo test`

**Files touched:** `src/config/site.rs` (~15 lines removed, 1 import added)

**Net impact:** ~12 lines removed, single config validation error type

---

## 7. parse_size_string Deduplication

**Problem:** `src/config/validation.rs:15` has a public `parse_size_string`. `src/config/site.rs:1816` has a byte-for-byte identical private copy.

**Plan:**

1. In `src/config/site.rs`:
   - Remove the private `fn parse_size_string` at line 1816 (~16 lines)
   - Add `use crate::config::validation::parse_size_string;` to the imports at the top of the file
   - Verify: the `validation` module is a sibling under `config/mod.rs` (line 27), so the `crate::config::validation` path is correct
   - Check that all call sites within `site.rs` still resolve

2. Verify: `cargo check && cargo test`

**Files touched:** `src/config/site.rs` (~16 lines removed, 1 import added)

**Net impact:** ~15 lines removed, single implementation

---

## 8. Admin Config Handler Boilerplate

**Problem:** In `src/admin/handlers/config.rs`, 3+ config update handlers follow near-identical patterns:
1. Acquire write lock
2. Read `main.toml`
3. Parse TOML
4. Update specific field
5. Serialize
6. Write back
7. Write reload signal file

The Overseer and Supervisor handlers are line-for-line identical except for the field name and signal filename. Additionally, 4 identical `ConfigResponse`/`UpdateConfigRequest` struct pairs add boilerplate.

**Plan:**

**Phase A: Generic config response/request types**

1. Create generic types (in `src/admin/handlers/config.rs` or `src/admin/handlers/common.rs`):
   ```rust
   #[derive(Debug, Serialize, Deserialize, utoipa::ToSchema)]
   pub struct ConfigResponse<T> {
       pub config: T,
   }
   
   #[derive(Debug, Deserialize, utoipa::ToSchema)]
   pub struct UpdateConfigRequest<T> {
       pub config: T,
   }
   ```

2. Replace the 4 concrete pairs (`OverseerConfigResponse`/`UpdateOverseerConfigRequest`, etc.) with type aliases:
   ```rust
   type OverseerConfigResponse = ConfigResponse<crate::config::OverseerConfig>;
   type UpdateOverseerConfigRequest = UpdateConfigRequest<crate::config::OverseerConfig>;
   ```

3. Check utoipa `ToSchema` derive compatibility — may need `#[schema(inline)]` or explicit schema attributes.

**Phase B: Extract config update helper**

1. Create a helper function:
   ```rust
   async fn update_config_field<T, F>(
       state: &AdminState,
       config_path: &Path,
       update_fn: F,
       reload_signal: Option<&str>,
   ) -> Result<(), StatusCode>
   where
       T: Serialize + for<'de> Deserialize<'de>,
       F: FnOnce(&mut MainConfig, T),
   ```

2. Refactor `update_overseer_config` and `update_supervisor_config` to use this helper. The ProcessManager handler has different logic (tries dynamic update first), so it can remain separate.

3. Verify: `cargo check && cargo test`

**Files touched:** `src/admin/handlers/config.rs` (~60 lines removed), possibly `src/admin/handlers/common.rs` (+30 lines for generics)

**Net impact:** ~30 lines removed, easier to add new config endpoints

---

## 9. HTTP Response Builder Consolidation

**Problem:** 6 nearly identical `build_response` / `build_response_with_cookie` / `build_response_with_alt_svc` functions across:
- `src/tls/server.rs:700,713`
- `src/http/server.rs:1129,1156`
- (Dead code) `src/http/handler.rs:1496,1505`

All share the same structure: set status, Content-Type, Content-Length, optional cookie, optional alt-svc, optional security headers, Date, build body.

**Plan:**

1. Create a response builder helper in a new `src/http/response_builder.rs`:
   ```rust
   pub struct ResponseBuilder {
       status: u16,
       content_type: String,
       body: String,
       cookie: Option<String>,
       alt_svc: Option<String>,
       security_headers: bool,
   }
   
   impl ResponseBuilder {
       pub fn new(status: u16, body: String, content_type: &str) -> Self { ... }
       pub fn with_cookie(mut self, cookie: &str) -> Self { ... }
       pub fn with_alt_svc(mut self, alt_svc: &Option<String>) -> Self { ... }
       pub fn with_security_headers(mut self, enabled: bool) -> Self { ... }
       pub fn build(self) -> Response<Full<Bytes>> { ... }
   }
   ```

2. Replace the 5 live `build_response*` functions with calls to `ResponseBuilder`.

3. The security header block (`Cache-Control`, `X-Content-Type-Options`, `X-Frame-Options`) is embedded in the builder's `build()` method.

4. Add `pub mod response_builder;` to `src/http/mod.rs`.

5. Verify: `cargo check && cargo test`

**Files touched:** `src/http/response_builder.rs` (new, ~50 lines), `src/tls/server.rs` (~30 lines removed), `src/http/server.rs` (~50 lines removed)

**Net impact:** ~30 lines removed, single place to manage response construction and security headers

---

## 10. Mesh Transport send-and-log Helper

**Problem:** 30 occurrences of this pattern across 8 mesh transport files:
```rust
if let Err(e) = self.send_datagram_to_peer(peer_id, &message).await {
    tracing::warn!("Failed to send X to {}: {}", peer_id, e);
}
```

**Plan:**

1. Add a convenience method to the transport type(s) that own `send_datagram_to_peer`:
   ```rust
   async fn send_datagram_to_peer_logged(
       &self,
       peer: &PeerId,
       message: &MeshMessage,
       description: &str,
       level: tracing::Level,
   ) {
       if let Err(e) = self.send_datagram_to_peer(peer, message).await {
           match level {
               tracing::Level::ERROR => tracing::error!("Failed to send {} to {}: {}", description, peer, e),
               tracing::Level::WARN => tracing::warn!("Failed to send {} to {}: {}", description, peer, e),
               _ => tracing::debug!("Failed to send {} to {}: {}", description, peer, e),
           }
       }
   }
   ```

   Alternatively, always use `warn` since that's the predominant level (10/30 uses) and the distinction between warn/debug/error at fire-and-forget call sites is not meaningful.

2. Replace all 30 occurrences with `self.send_datagram_to_peer_logged(peer, &msg, "FindNodeResponse").await;`

3. Verify: `cargo check && cargo test`

**Files touched:** 8 mesh transport files (~3 lines each → 1 line each)

**Net impact:** ~60 lines removed, consistent error logging

---

## 11. Status Code Text Mapping Consolidation

**Problem:** Two near-identical match blocks mapping HTTP status codes to reason phrases:
- `src/waf/endpoints.rs:440-456`
- `src/theme/template.rs:194-205`

**Plan:**

1. Create a shared utility function in `src/utils.rs` (or a new `src/http/status.rs`):
   ```rust
   pub fn status_reason_phrase(code: u16) -> &'static str {
       match code {
           200 => "OK",
           400 => "Bad Request",
           401 => "Unauthorized",
           403 => "Forbidden",
           404 => "Not Found",
           500 => "Internal Server Error",
           502 => "Bad Gateway",
           503 => "Service Unavailable",
           504 => "Gateway Timeout",
           _ => "Unknown",
       }
   }
   ```

2. Replace both match blocks with calls to this function.

3. Verify: `cargo check && cargo test`

**Files touched:** `src/utils.rs` (+15 lines), `src/waf/endpoints.rs` (~10 lines → 1), `src/theme/template.rs` (~10 lines → 1)

**Net impact:** ~4 lines removed (small but eliminates copy-paste drift risk)

---

## 12. TrustAnchorConfig Consolidation

**Problem:** `TrustAnchorConfig` is defined in two places with identical fields and identical `Default` impls:
- `src/config/dns.rs:783` — with `#[serde(default)]` attributes, 9 fields
- `src/dns/trust_anchor.rs:163` — with unused `Archive, RkyvSerialize, RkyvDeserialize` derives, same 9 fields

Both `Default` impls produce identical values. The rkyv derives on the `trust_anchor.rs` version are never used (no archival/rkyv serialization of `TrustAnchorConfig` exists in the mesh or elsewhere). The `config::dns` version is used in `DnsConfig` (line 77) for TOML config loading.

**Plan:**

1. Keep `src/config/dns.rs:783` as the canonical `TrustAnchorConfig` (has serde support for config file loading, same fields, same defaults).

2. In `src/dns/trust_anchor.rs`:
   - Remove the local `TrustAnchorConfig` struct definition (lines 162-173) and its `Default` impl (lines 175-189) — ~27 lines total
   - Add `use crate::config::dns::TrustAnchorConfig;`
   - `TrustAnchorManager::new(config: TrustAnchorConfig)` — the serde annotations are additive and don't affect code usage

3. In `src/dns/mod.rs:82`:
   - Change `pub use trust_anchor::TrustAnchorConfig` to `pub use crate::config::dns::TrustAnchorConfig` (since it's no longer re-exported from `trust_anchor`)
   - Alternatively: the import in `trust_anchor.rs` makes it accessible via `trust_anchor::TrustAnchorConfig` as a re-import, but explicit re-export is clearer

4. In `src/dns/resolver.rs:55`:
   - Update `use crate::dns::trust_anchor::TrustAnchorConfig` to `use crate::config::dns::TrustAnchorConfig` (or it will resolve via the `dns::mod.rs` re-export)

5. Verify: `cargo check && cargo test`

**Files touched:** `src/dns/trust_anchor.rs` (~27 lines removed, 1 import added), `src/dns/mod.rs` (1 line changed), `src/dns/resolver.rs` (1 import path changed)

**Net impact:** ~25 lines removed, single source of truth for trust anchor config

---

## Execution Order

Execute in this order (each step is independent unless noted):

| Step | Task | Dependencies | Estimated Lines Changed |
|------|------|-------------|------------------------|
| 1 | `parse_size_string` dedup (§7) | None | -15 |
| 2 | Validation error unification (§6) | None | -12 |
| 3 | Status code mapping (§11) | None | -4 |
| 4 | `ensure_fqdn` helper (§4) | None | -20 |
| 5 | `current_timestamp` dedup (§2) | None | -30 |
| 6 | `now_secs` / timestamp consolidation (§3) | Step 5 (shares `current_timestamp`) | -130 |
| 7 | TrustAnchorConfig consolidation (§12) | None | -24 |
| 8 | TokenBucket dedup (§1) | None | -130 |
| 9 | Admin config handler boilerplate (§8) | None | -30 |
| 10 | DNS generic lookup (§5) | Step 4 (uses `ensure_fqdn`) | -70 |
| 11 | HTTP response builder (§9) | None | -30 |
| 12 | Mesh transport send-and-log (§10) | None | -60 |

**Total estimated reduction: ~555 lines removed, ~60 lines added for shared utilities**

---

## Verification

After each step:
```bash
cargo check
cargo test --test integration_test
```

After all steps:
```bash
cargo check
cargo clippy -- -D warnings
cargo test
```

---

## Out of Scope

The following were identified but excluded from this plan due to higher risk or larger scope:

- Splitting `run_unified_server_worker` (737 lines) — functional refactor, not just readability
- Splitting `WafCore` impl (1110 lines) — would change module structure significantly
- Replacing stringly-typed mode ("shared"/"isolated") with enum — changes config file format
- HTTP server `Arc<RequestContext>` bundling — changes constructor signature + all call sites
- `.map_err` helper macro for admin handlers — gains are marginal with the config update helper (§8)
