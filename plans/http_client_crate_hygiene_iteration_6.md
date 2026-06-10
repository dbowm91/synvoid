# HTTP Client Crate Hygiene — Iteration 6

## Goal

The typed-pool migration succeeded: root no longer owns `src/http_client/typed_pool.rs`, root no longer declares `webpki-roots`, and `synvoid-http-client` owns the upstream HTTP client/TLS-root behavior. The next step is to clean up the crate internals without changing the public API.

This pass should split the oversized `crates/synvoid-http-client/src/lib.rs` into focused modules, keep the root compatibility shim intact, and add focused non-network tests around TLS config, pooling keys, and request/response helpers where practical.

## Non-Goals

Do not redesign the HTTP client.

Do not change upstream TLS verification semantics.

Do not change hostname-skip behavior.

Do not change connection pooling semantics, cache TTLs, timeout defaults, ALPN settings, or Unix-socket behavior.

Do not remove the root `src/http_client/mod.rs` compatibility shim unless all call sites are trivially direct imports and the change is low churn.

Do not start mesh trust-domain work in this pass.

Do not add live network tests.

## Phase 1 — Split `synvoid-http-client/src/lib.rs` By Responsibility

### Current Problem

`crates/synvoid-http-client/src/lib.rs` now owns the right behavior, but it is doing too much directly in the crate root. It contains public types, TLS config building, native/webpki root loading, custom CA loading, client cache construction, upstream client construction, Unix socket helpers, request helpers, response conversion, and module exports.

That is acceptable immediately after migration, but it will become hard to maintain.

### Required Changes

Create focused internal modules. Suggested structure:

```text
crates/synvoid-http-client/src/
  lib.rs
  client.rs
  tls.rs
  pool.rs
  unix.rs
  request.rs
  response.rs
  erased_pool.rs
  streaming_waf_body.rs
```

Suggested ownership:

- `client.rs`: public client type aliases and construction entry points.
- `tls.rs`: `UpstreamTlsConfig`, `upstream_tls_from_site_config`, `build_tls_config`, custom CA loading, native/webpki root loading, `HostnameSkippingVerifier`.
- `pool.rs`: `UpstreamClientKey`, `UpstreamTlsConfigHashable`, `UPSTREAM_CLIENT_CACHE`, `UPSTREAM_STREAMING_CLIENT_CACHE`, cache builder helpers, upstream client constructors if that is cleaner.
- `unix.rs`: Unix socket URL parsing, Unix client creation, Unix request helpers.
- `request.rs`: generic HTTP request helper functions.
- `response.rs`: `HttpResponse` and response conversion helpers if currently in `lib.rs`.
- `lib.rs`: module declarations and stable public re-exports only.

Do not over-split if the existing file shape makes one of these modules artificial. The key is to move TLS and pooling out of `lib.rs`.

### Acceptance Criteria

`lib.rs` becomes mostly module declarations, docs, type re-exports, and public API re-exports.

TLS config/root-loading implementation is in `tls.rs`.

Client pooling/cache behavior is no longer directly in `lib.rs`.

Public API remains source-compatible for root and existing call sites.

## Phase 2 — Preserve Public API Through Re-Exports

### Required Changes

Keep the externally visible API stable by re-exporting the moved types/functions from `lib.rs`.

Examples:

```rust
pub use client::{create_http_client, create_http_client_with_config, HttpClient, StreamingHttpClient};
pub use tls::{upstream_tls_from_site_config, UpstreamTlsConfig};
pub use unix::{create_unix_http_client, is_unix_socket_url, send_unix_request_with_timeout};
```

Do not force downstream/root call-site churn unless there is an obvious mistaken import that should be corrected.

Root `src/http_client/mod.rs` should remain thin:

```rust
pub use synvoid_http_client::*;
```

plus root-specific modules like `quic_tunnel_dispatch` and `streaming_waf_body` if they are still root-owned.

### Acceptance Criteria

Existing imports of `synvoid_http_client::*` continue to compile.

Existing imports through `crate::http_client::*` continue to compile if the compatibility shim remains.

No root implementation logic is reintroduced.

## Phase 3 — Add Non-Network Tests For TLS and Pooling

### Required Tests

Add focused tests inside `synvoid-http-client` for behavior that does not require network access.

Minimum tests:

1. `UpstreamTlsConfig::default()` preserves current defaults:
   - `verify = true`
   - `skip_verify = false`
   - `allow_plaintext = false`
   - no custom CA/server name/reason

2. `upstream_tls_from_site_config()` returns `None` when upstream TLS is disabled.

3. `upstream_tls_from_site_config()` maps `skip_verify` and `skip_verify_reason` correctly.

4. `is_unix_socket_url()` recognizes:
   - `http+unix://...`
   - `http+unix:...`
   - `unix://...`
   - `unix:...`
   - absolute paths
   - relative `./...` paths
   - rejects normal HTTP/HTTPS URLs

5. Pool-key behavior is stable if exposed to tests. If the key type remains private, add `#[cfg(test)]` tests in the owning module:
   - identical TLS/pool settings produce equal keys;
   - different CA path / skip-verify / allow-plaintext / pool idle settings produce different keys.

6. TLS config construction smoke tests:
   - default TLS config can be built without panicking;
   - skip-hostname-verification TLS config can be built without panicking;
   - invalid custom CA path does not panic and preserves fallback behavior if that is current behavior.

Do not add tests that require live upstream servers, live DNS, or external network connectivity.

### Acceptance Criteria

`cargo test -p synvoid-http-client` exercises the moved TLS/pool logic.

Tests remain deterministic and offline.

## Phase 4 — Reduce Duplication With Root HTTP Helpers

### Required Changes

Inspect root HTTP-client helpers that remain:

```bash
find src/http_client -maxdepth 2 -type f -print
rg "pub use synvoid_http_client|quic_tunnel_dispatch|streaming_waf_body|create_http_client|UpstreamTlsConfig" src/http_client src crates
```

Keep root-specific helpers in root only if they truly depend on root-only concepts.

For each remaining root helper, classify it:

- root-only because it depends on WAF/core/server state;
- should eventually move into `synvoid-http-client`;
- compatibility re-export only.

Do not move QUIC tunnel or streaming WAF body code unless it is obviously crate-owned and low-risk. This phase is primarily classification and comment cleanup.

### Acceptance Criteria

Root `src/http_client/mod.rs` clearly indicates whether it is a compatibility shim.

No duplicate typed-pool or TLS-root code exists in root.

A short comment or commit message notes why remaining root helpers stay root-owned.

## Phase 5 — Update Ownership Notes

### Required Changes

Update `plans/root_dependency_ownership_iteration_2.md` only if this pass changes dependency ownership further.

At minimum, ensure its `webpki-roots` row still says:

- owner: `synvoid-http-client`
- root direct: no
- root usage: none

If module split creates a better path than `crates/synvoid-http-client/src/lib.rs`, update the reason to name the new owning file, likely `crates/synvoid-http-client/src/tls.rs`.

### Acceptance Criteria

Ownership note names the current file/module that owns webpki fallback behavior.

No stale comments claim root owns typed-pool or webpki root loading.

## Validation Commands

Run focused checks first:

```bash
cargo fmt --all --check
cargo check -p synvoid-http-client
cargo test -p synvoid-http-client
cargo check -p synvoid
```

Then run workspace checks:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
```

Feature checks:

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If broad workspace checks are expensive or fail for unrelated reasons, record exactly which focused checks passed and what broader checks remain unverified.

## Completion Criteria

This iteration is complete when:

- `synvoid-http-client/src/lib.rs` is reduced to a stable public facade;
- TLS/root-store logic lives in a focused module;
- pooling/cache logic lives in a focused module;
- public API compatibility is preserved;
- root remains a thin HTTP-client compatibility shim plus root-specific helpers;
- offline tests cover TLS defaults, upstream TLS config mapping, Unix URL parsing, pool key behavior where practical, and TLS config construction smoke cases;
- root does not regain `webpki-roots` or typed-pool implementation ownership.

## Follow-Up Recommendation

After this pass, the HTTP-client cleanup path should be considered stable unless tests reveal behavioral drift. The next major architecture track should be the internal `synvoid-mesh` trust-domain split. Begin that with a design note, not code movement: define advisory DHT state, canonical Raft/global-node state, identity, transport, policy, and service-consumer boundaries before touching module layout.
