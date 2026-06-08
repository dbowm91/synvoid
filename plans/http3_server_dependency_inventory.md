# HTC-Q01: Inventory `src/http3/server.rs` Concrete Root Dependencies

**File**: `src/http3/server.rs` (293 lines)
**Date**: 2026-06-07
**Updated**: 2026-06-07 (HWS-Q01–Q03)
**Updated**: 2026-06-07 (MDM-Q01–Q03 — refresh + import reduction + ownership decision)
**Updated**: 2026-06-08 (HWD-H04 — H02 deferral recorded)
**Updated**: 2026-06-08 (WafAccess object-safety resolved, Http3WafBackend trait introduced)

## Summary

`src/http3/server.rs` imports **10 concrete root-owned types** across 8 `crate::` import lines. Two of these (`WafCore`, `WorkerDrainState`) are root-defined structs with no trait seam in extracted crates. The remaining 8 are re-exports from extracted crates (`synvoid-proxy`, `synvoid-waf`, `synvoid-http-client`, `synvoid-metrics`, `synvoid-config`). The `prepare_http3_request_dispatch` and `handle_http3_request_dispatch` functions in `synvoid-http` also take some of these concrete types directly in their signatures.

**HWS-Q01–Q03 update**: The `WafAccess` trait is now actively used in server.rs (imported at line 15, methods called at lines 224, 225, 267, 268, 270). The 3 accessor methods (`connection_limiter`, `is_over_bandwidth_limit`, `streaming`) no longer access WafCore fields directly.

**WafAccess refactor (2026-06-08)**: `WafAccess` is now object-safe — `StreamingScanner` associated type removed, `streaming()` returns `Option<Box<dyn StreamingWafScanner>>`. `Http3Server.waf` is now `Arc<dyn Http3WafBackend>` (composite trait `Http3RequestWaf + WafAccess`). The remaining root blockers are `accept_loop.rs` Send bound errors (pre-existing) and `WorkerDrainState` (root-owned, low-impact).

---

## Concrete Dependency Table

| # | Concrete dependency | Import line | Struct field line | Existing seam | Missing seam | Action | Notes |
|---|---------------------|-------------|-------------------|---------------|--------------|--------|-------|
| 1 | `WafCore` | 14 | 21 | `WafProcessor` (synvoid-waf) + **`WafAccess`** (synvoid-waf) + `Http3RequestWaf` (synvoid-http) | **RESOLVED** — `Http3Server.waf` is now `Arc<dyn Http3WafBackend>` (no longer concrete `Arc<WafCore>`) | **COMPLETED** — WafAccess is object-safe; `Http3WafBackend` composite trait (`Http3RequestWaf + WafAccess`) used for dispatch | `WafAccess` refactored: `StreamingScanner` associated type removed, `streaming()` returns `Box<dyn StreamingWafScanner>`. See `plans/hwd_h02_deferred.md` |
| 2 | `FloodProtector` | 14 | 22 | **None** — `FloodProtector` is a struct in `synvoid_waf::flood` | No trait abstraction for `check_tcp_connection()` | Already in extracted crate `synvoid-waf` — no root ownership issue; can be used directly from `synvoid_waf::FloodProtector` | Used at lines 62, 159 (`fp.check_tcp_connection(client_ip)`) |
| 3 | `FloodDecision` | 14 | — (enum variant only) | **None** — enum in `synvoid_waf::flood` | No seam needed — it's a simple value enum | Already in extracted crate — no action needed | Used at lines 160, 164, 168 in match arms |
| 4 | `Router` | 13 | 20 | `RouteResolver` trait (synvoid-proxy) + `RouterRouteResolver` adapter | `prepare_http3_request_dispatch` takes `&Arc<Router>` directly, not `&dyn RouteResolver` | Already in extracted crate `synvoid-proxy` — but `prepare_http3_request_dispatch` still takes concrete `Arc<Router>` | Root re-exports `pub use synvoid_proxy::router::*;` at `src/router.rs:1`. The dispatch function signature in `synvoid-http` would need changing to accept `&dyn RouteResolver` |
| 5 | `HttpClient` | 9 | 23 | **None** — type alias `Client<HttpsConnector<HttpConnector>, Full<Bytes>>` | No trait; it's a `hyper_util` client type alias | Already in extracted crate `synvoid-http-client` — use directly from `synvoid_http_client::HttpClient` | Created via `create_http_client_with_config()` at line 41-42 |
| 6 | `UpstreamClientRegistry` | 12 | 24 | **None** — struct in `synvoid_proxy::client_registry` | No trait abstraction | Already in extracted crate `synvoid-proxy` — can be used directly from `synvoid_proxy::UpstreamClientRegistry` | Created with `UpstreamClientRegistry::new()` at line 53; passed to dispatch at line 272 |
| 7 | `WorkerMetrics` | 11 | 26 | `MetricsSink` trait (synvoid-core) + `WorkerMetricsSink` adapter (synvoid-metrics) | `handle_http3_request_dispatch` takes `Option<&Arc<WorkerMetrics>>` directly | Already in extracted crate `synvoid-metrics` — but dispatch function signature still takes concrete `WorkerMetrics` | Root re-exports from `src/metrics/`. The dispatch function would need changing to accept `Option<&dyn MetricsSink>` |
| 8 | `WorkerDrainState` | 16 | 25 | `DrainState` trait (synvoid-core) + `WorkerDrainStateAdapter` (root) | `WorkerDrainState` is **root-defined** at `src/worker/drain_state.rs:23` — no extracted equivalent | Root-owned struct — keep as-is for inventory; decoupling requires either moving `WorkerDrainState` to a crate or using `DrainState` trait | Stored as `Option<Arc<WorkerDrainState>>` but never used in any method (fields exist, no drain logic in server.rs). Builder method `with_drain_state` exists at line 67 |
| 9 | `Http3Config` / `MainConfig` | 8 | 19, 29 | Both in `synvoid-config` | No trait needed — config structs | Already in extracted crate `synvoid-config` — no action needed | `Http3Config` for server config, `MainConfig` for trusted proxies and passed to dispatch |
| 10 | `create_http_client_with_config` | 9 | — (called in constructor) | **None** — standalone function | No seam needed — factory function | Already in extracted crate `synvoid-http-client` — use directly | Called at line 41-42 |
| 11 | `get_global_bandwidth_tracker_or_log` | 10 | — (called per-request) | **None** — standalone function | No seam needed — utility function | Already in extracted crate `synvoid-metrics` — use directly | Called at line 253, returns `Option<Arc<BandwidthTracker>>` |
| 12 | `bind_udp_reuse` | 100 | — (called in `serve()`) | **None** — platform function | No seam needed — platform utility | Root-owned at `src/platform/socket.rs:381` — keep as-is | Platform-specific UDP socket binding with SO_REUSEPORT |

---

## synvoid-http Dispatch Function Coupling

The `synvoid-http` crate's dispatch functions already take some generic parameters but still couple to concrete types:

### `prepare_http3_request_dispatch` (synvoid-http/src/http3_request_flow.rs:38)

```rust
pub async fn prepare_http3_request_dispatch<R>(
    start: Instant,
    resolver: R,                        // ✅ Generic (Http3RequestResolver)
    remote_addr: SocketAddr,
    trusted_proxies: &[String],
    router: &Arc<Router>,               // ❌ Concrete Router
    connection_limiter: Option<&Arc<ConnectionLimiter>>,  // ❌ Concrete ConnectionLimiter
    over_bandwidth_limit: bool,
) -> Result<Http3RequestDispatchOutcome<R::RequestStream>, R::Error>
```

### `handle_http3_request_dispatch` (synvoid-http/src/http3_request_dispatch.rs:79)

```rust
pub async fn handle_http3_request_dispatch<Waf, S, W>(
    start: Instant,
    route_result: &RouteResult,          // ❌ Concrete (from synvoid-proxy)
    path: &str,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    query_string: Option<&str>,
    user_agent: Option<&str>,
    client_ip: IpAddr,
    request_stream: &mut W,              // ✅ Generic (Http3RequestStream)
    max_request_size: usize,
    streaming_waf_for_body: Option<S>,   // ✅ Generic (StreamingWafScanner)
    streaming_waf_for_upstream: Option<S>, // ✅ Generic
    connection_guard: Option<&ConnectionTokenGuard>,
    connection_limiter: Option<&Arc<ConnectionLimiter>>,  // ❌ Concrete ConnectionLimiter
    main_config: &Arc<MainConfig>,       // ❌ Concrete MainConfig
    client: &HttpClient,                 // ❌ Concrete HttpClient
    upstream_client_registry: &Arc<UpstreamClientRegistry>, // ❌ Concrete UpstreamClientRegistry
    bandwidth: Option<&Arc<BandwidthTracker>>,  // ❌ Concrete BandwidthTracker
    metrics: Option<&Arc<WorkerMetrics>>,  // ❌ Concrete WorkerMetrics
    waf: &Waf,                           // ✅ Generic (Http3RequestWaf)
) -> Result<(), BoxError>
```

---

## Classification

### Already in extracted crates (no root ownership issue)

These types are defined in extracted crates and merely re-exported by root. They can be imported directly from the extracted crate once `src/http3/server.rs` moves there:

| Type | Crate | Import path |
|------|-------|-------------|
| `Router` | synvoid-proxy | `synvoid_proxy::Router` |
| `FloodProtector` | synvoid-waf | `synvoid_waf::FloodProtector` |
| `FloodDecision` | synvoid-waf | `synvoid_waf::FloodDecision` |
| `HttpClient` | synvoid-http-client | `synvoid_http_client::HttpClient` |
| `UpstreamClientRegistry` | synvoid-proxy | `synvoid_proxy::UpstreamClientRegistry` |
| `WorkerMetrics` | synvoid-metrics | `synvoid_metrics::WorkerMetrics` |
| `Http3Config` | synvoid-config | `synvoid_config::Http3Config` |
| `MainConfig` | synvoid-config | `synvoid_config::MainConfig` |
| `ConnectionLimiter` | synvoid-waf | `synvoid_waf::ConnectionLimiter` |

### Root-owned (need work to decouple)

| Type | Root location | Trait seam in extracted crate | Effort |
|------|---------------|-------------------------------|--------|
| `WafCore` | `src/waf/mod.rs:97` | `WafProcessor` + `WafAccess` + `Http3RequestWaf` — all now object-safe. `Http3Server.waf` is `Arc<dyn Http3WafBackend>` | **COMPLETED** — WafAccess refactored; `Http3WafBackend` composite trait in use |
| `WorkerDrainState` | `src/worker/drain_state.rs:23` | `DrainState` trait exists in synvoid-core, `WorkerDrainStateAdapter` wraps it | Low — stored but unused in server.rs methods; remaining root blocker after WafAccess refactor |

### Standalone functions (no ownership concern)

| Function | Crate | Notes |
|----------|-------|-------|
| `create_http_client_with_config` | synvoid-http-client | Factory function |
| `get_global_bandwidth_tracker_or_log` | synvoid-metrics | Utility function |
| `bind_udp_reuse` | root (platform) | Platform utility — stays in root |

---

## HWS-Q01–Q03 Decision

### Decision: `KEEP_ROOT_UNTIL_WAFACCESS_USED` → **RESOLVED**

The `WafAccess` trait (3 methods: `connection_limiter`, `is_over_bandwidth_limit`, `streaming`) is now actively used in `server.rs`:
- Imported: `use synvoid_waf::access::WafAccess;` (line 15)
- Called: `self.waf.connection_limiter().as_ref()` (lines 224, 270)
- Called: `self.waf.is_over_bandwidth_limit()` (line 225)
- Called: `self.waf.streaming()` (lines 267, 268)

### Remaining blocker: `Http3RequestWaf` dispatch

`self.waf.as_ref()` at line 276 passes `&WafCore` to `handle_http3_request_dispatch` which expects `waf: &Waf` where `Waf: Http3RequestWaf`. This requires concrete `WafCore` to implement `Http3RequestWaf`.

To resolve this, one of:
1. Store `Arc<dyn Http3RequestWaf>` instead of `Arc<WafCore>` — requires all `Http3RequestWaf` methods to be object-safe
2. Make `Http3Server` generic over `W: Http3RequestWaf` — forces all callers to specify the type
3. Extract a `Http3RequestWafBackend` trait object wrapper — moderate effort

### Decision: `MOVE_READY` → **NOT YET**

The `Http3RequestWaf` dispatch blocker prevents moving `server.rs` to an extracted crate. The `bind_udp_reuse` platform utility and `WorkerDrainState` are minor and solvable, but the `Http3RequestWaf` requirement is structural.

### H02 deferral (2026-06-08) → RESOLVED (2026-06-08)

Strategy A (`Arc<dyn Http3RequestWaf>`) was initially blocked by `WafAccess` not being object-safe. The `WafAccess` refactor has been completed: `StreamingScanner` associated type removed, `streaming()` returns `Option<Box<dyn StreamingWafScanner>>`, and a unified `StreamingWafScanner` trait exists in `synvoid-core`. A composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` was introduced and `Http3Server.waf` is now `Arc<dyn Http3WafBackend>`.

### Remaining root blockers

1. **`accept_loop.rs` Send bound** — Pre-existing errors at `src/http/server/accept_loop.rs:171` (not introduced by WafAccess refactor)
2. **`WorkerDrainState`** — Root-owned struct, stored but unused in server methods; low-impact, solvable by replacing with `Option<Arc<dyn DrainState>>`

### Next steps

1. ~~Verify `Http3RequestWaf` is object-safe~~ ✅ confirmed object-safe
2. ~~If object-safe: change `waf: Arc<WafCore>` to `waf: Arc<dyn Http3RequestWaf>`~~ ✅ done — `waf: Arc<dyn Http3WafBackend>`
3. ~~Refactor `WafAccess` to remove `StreamingScanner` associated type (return `Option<Box<dyn StreamingWafScanner>>`)~~ ✅ done
4. ~~Then re-evaluate `Arc<dyn Http3RequestWaf>` or composite trait object~~ ✅ `Arc<dyn Http3WafBackend>` in use
5. Remaining: `accept_loop.rs` Send bound fix, `WorkerDrainState` → `Arc<dyn DrainState>`

---

# MDM-Q01: Refreshed Concrete Dependency Inventory (2026-06-07)

> Wave Q, Task Q01. Refreshed inventory for `src/http3/server.rs` (293 lines).

## Count summary

| Class | Count |
|-------|-------|
| Total distinct concrete root imports | 10 (`Http3Config`, `MainConfig`, `HttpClient`, `create_http_client_with_config`, `get_global_bandwidth_tracker_or_log`, `WorkerMetrics`, `UpstreamClientRegistry`, `Router`, `FloodDecision`, `FloodProtector`, `WafCore`, `WorkerDrainState`, `bind_udp_reuse`) |
| Already moved to extracted crate (clean root → crate replacement possible) | 9 |
| Covered by WafProcessor / WafAccess (no replacement needed) | 1 (`WafAccess` is already used at lines 224, 225, 267, 268, 270) |
| Still root-only (cannot replace without trait/external reorg) | 2 (`WorkerDrainState`, `bind_udp_reuse`) |

## Refreshed Classification

| # | Concrete dependency | Import line | Classification | Notes |
|---|---------------------|-------------|----------------|-------|
| 1 | `Http3Config` | 8 | **Already moved** — re-exported by `synvoid_config::http::Http3Config` | Clean import path available. |
| 2 | `MainConfig` | 8 | **Already moved** — `synvoid_config::MainConfig` | Clean. |
| 3 | `HttpClient` | 9 | **Already moved** — `synvoid_http_client::HttpClient` | Clean. |
| 4 | `create_http_client_with_config` | 9 | **Already moved** — `synvoid_http_client::create_http_client_with_config` | Clean. |
| 5 | `get_global_bandwidth_tracker_or_log` | 10 | **Already moved** — `synvoid_metrics::bandwidth::get_global_bandwidth_tracker_or_log` | Clean. |
| 6 | `WorkerMetrics` | 11 | **Already moved** — `synvoid_metrics::WorkerMetrics` | Concrete use; not yet a trait seam (MetricsSink is too narrow). |
| 7 | `UpstreamClientRegistry` | 12 | **Already moved** — `synvoid_proxy::UpstreamClientRegistry` | Clean. |
| 8 | `Router` | 13 | **Already moved** — `synvoid_proxy::Router` | Concrete; `RouteResolver` trait exists in synvoid-proxy but the synvoid-http dispatch functions take `&Arc<Router>`. |
| 9 | `FloodDecision` | 14 | **Already moved** — `synvoid_waf::FloodDecision` (re-exported via `src/waf/flood/mod.rs`) | Clean. |
| 10 | `FloodProtector` | 14 | **Already moved** — `synvoid_waf::FloodProtector` | Clean. |
| 11 | `WafCore` | 14, 22, 38, 51, 276 | **RESOLVED.** `Http3Server.waf` is now `Arc<dyn Http3WafBackend>` (composite trait `Http3RequestWaf + WafAccess`). WafAccess is object-safe after `StreamingScanner` associated type removal. | `WafAccess` refactored; see `plans/hwd_h02_deferred.md` |
| 12 | `WorkerDrainState` | 15, 26, 55, 68 | **Root-only.** Struct in `src/worker/drain_state.rs`. Stored as field but never accessed in any server method body (no method reads/writes it after construction). | Could be replaced with `Option<Arc<dyn DrainState>>` if `Http3Server` accepted the trait; the builder `with_drain_state` would need to take the trait object. |
| 13 | `bind_udp_reuse` (inline) | 101 | **Root platform utility** (function defined in `src/platform/socket.rs`). `synvoid-platform` has a same-named function in its (private) `socket` module, but it is **not** publicly exported from `synvoid-platform`. | Stop condition hit during Q02: cannot replace without making `crates/synvoid-platform/src/socket.rs` public, which is a separate cross-cutting change. |

**Net result for Q01**: 10 of 12 distinct concrete dependencies are clean root → crate replacements; 2 (`WorkerDrainState`, `bind_udp_reuse`) remain root-only. `WafCore` has been resolved via the WafAccess object-safety refactor — `Http3Server.waf` is now `Arc<dyn Http3WafBackend>`.

---

# MDM-Q02: Import Reductions (2026-06-07)

> Wave Q, Task Q02. Replaced obvious root → extracted-crate imports in
> `src/http3/server.rs`. The `Http3Server` struct's *type* parameters and
> *construction flow* (`new`, `with_*`, `serve`) were not changed.

## Replacement list (before → after)

| File:line | Before | After |
|-----------|--------|-------|
| `src/http3/server.rs:8` | `use crate::config::{Http3Config, MainConfig};` | `use synvoid_config::http::Http3Config;` + `use synvoid_config::MainConfig;` (split) |
| `src/http3/server.rs:9` | `use crate::http_client::{create_http_client_with_config, HttpClient};` | `use synvoid_http_client::{create_http_client_with_config, HttpClient};` |
| `src/http3/server.rs:10` | `use crate::metrics::bandwidth::get_global_bandwidth_tracker_or_log;` | `use synvoid_metrics::bandwidth::get_global_bandwidth_tracker_or_log;` |
| `src/http3/server.rs:11` | `use crate::metrics::WorkerMetrics;` | `use synvoid_metrics::WorkerMetrics;` |
| `src/http3/server.rs:12` | `use crate::proxy::client_registry::UpstreamClientRegistry;` | `use synvoid_proxy::UpstreamClientRegistry;` |
| `src/http3/server.rs:13` | `use crate::router::Router;` | `use synvoid_proxy::Router;` |
| `src/http3/server.rs:14` | `use crate::waf::{FloodDecision, FloodProtector, WafCore};` | `use synvoid_waf::{FloodDecision, FloodProtector};` + `use crate::waf::WafCore;` (split — `WafCore` is root-owned) |
| `src/http3/server.rs:15` | `use crate::worker::drain_state::WorkerDrainState;` | **unchanged** (root-owned) |
| `src/http3/server.rs:16` | `use synvoid_waf::access::WafAccess;` | **unchanged** (already canonical) |
| `src/http3/server.rs:101` | `crate::platform::socket::bind_udp_reuse(...)` (inline) | **unchanged** (see Stop Conditions) |

## Stop conditions hit

One stop condition was hit:
- `crate::platform::socket::bind_udp_reuse` (line 101) is **not** a clean
  extracted-crate replacement. The function exists in
  `crates/synvoid-platform/src/socket.rs` but the `socket` module is
  **not** publicly exported from `crates/synvoid-platform/src/lib.rs`
  (only `fs` and `sandbox` are `pub mod`). Making the replacement would
  require modifying `synvoid-platform`'s public API, which is outside
  the scope of this task. That inline call was therefore left as
  `crate::platform::socket::bind_udp_reuse`.

Two further non-replacements are intentional:
- `WafCore` (line 14, 22, 38, 51, 276) is root-owned and is the
  `Http3RequestWaf` implementor. Replacing it would require
  ownership/lifetime/construction-flow changes (Q02 hard rule).
- `WorkerDrainState` (line 15, 26, 55, 68) is root-owned and is
  exercised through the `with_drain_state` builder; replacing it with
  `Option<Arc<dyn DrainState>>` would change the builder signature
  (construction-flow change) and is therefore a separate refactor.

The struct fields of `Http3Server` are unchanged: `waf: Arc<WafCore>`,
`drain_state: Option<Arc<WorkerDrainState>>`, `flood_protector: Option<Arc<FloodProtector>>`,
`router: Arc<Router>`, `client: HttpClient`, `upstream_client_registry: Arc<UpstreamClientRegistry>`,
`metrics: Option<Arc<WorkerMetrics>>`, `main_config: Arc<MainConfig>`,
`config: Http3Config`. The change is purely cosmetic at the import level.

## Validation commands run

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
```

Both pass.

---

# MDM-Q03: HTTP3 Move Readiness Decision (2026-06-07)

## Decision: `KEEP_ROOT_UNTIL_HTTP_SERVER_CONTEXT_REWORK`

### Justification

- **WafCore is the structural blocker** for moving `src/http3/server.rs` into
  a crate. The dispatch at server.rs:276 (`self.waf.as_ref()`) requires the
  concrete `WafCore` type because `WafCore` is the *only* implementor of
  `synvoid_http::Http3RequestWaf`. The plan §2 explicitly defers moving
  `WafCore` into `synvoid-waf`, so this cannot be unblocked by Q01–Q03 alone.
- **WorkerDrainState is a second blocker** with a smaller surface area. The
  field is stored but never accessed in any `Http3Server` method body (per
  Q01 inspection). Replacing it with `Option<Arc<dyn DrainState>>` would
  require changing the `with_drain_state` builder signature and the
  caller in `init_mesh.rs` / `unified_server` — a worker-construction-flow
  change that is out of scope for Wave Q.
- **bind_udp_reuse is solvable** by exporting `socket` from
  `synvoid-platform`, but that is a cross-cutting change to a different
  crate and outside Wave Q's scope.
- **All other dependencies are now extracted-crate-clean** (Q02 pass). The
  file is now in a state where, if WafCore were ever extracted and
  `Http3RequestWaf` made object-safe, the move would be a near-mechanical
  step. The other 9 root imports have been reduced to their canonical
  extracted-crate form.

### Why not `KEEP_ROOT_UNTIL_DRAIN_OR_SOCKET_SEAM`?

`KEEP_ROOT_UNTIL_DRAIN_OR_SOCKET_SEAM` understates the blocker. Drain is a
minor field with no method body use; the `WafCore` / `Http3RequestWaf`
dispatch is the real barrier. Therefore the more accurate label is the
HTTP-server-context rework decision.

### Why not `MOVE_READY`?

`Http3RequestWaf` is the only `Http3RequestWaf` implementor in the workspace
and it is the concrete `WafCore` in root. `Http3RequestWaf` is async and
returns `synvoid_proxy::WafDecision` (not `Self`), so it is *theoretically*
object-safe — but the field is declared as `Arc<WafCore>`, not
`Arc<dyn Http3RequestWaf>`. Switching to `Arc<dyn Http3RequestWaf>` requires
a trait-object conversion in the struct definition (a server-construction-
flow change), and `WafCore` itself is not in `synvoid-waf` yet. Two
upstream changes are required before `MOVE_READY` is correct.

### Why not `DEFER_LOW_VALUE`?

The HTTP/3 server is small (293 lines + 60-line `request_stream.rs`). The
movement is not "low value" — it would unlock a future compilation-time
win, and the file is now almost dependency-clean. The remaining work is
concrete (`Http3RequestWaf` object safety + WafCore extraction), not
speculative.

### Conditions that would change this decision

- Completion of the "WafCore → synvoid-waf" extraction (currently
  deferred by plan §2).
- Either (a) `Http3RequestWaf` being proven object-safe and the struct
  field changed to `Arc<dyn Http3RequestWaf>`, or (b) a thin
  `Http3RequestWafBackend` trait-object wrapper being introduced.
- Either `WorkerDrainState` being moved out of root, or `Http3Server`
  being parameterised on `D: DrainState`.

### Validation

```bash
cargo check -p synvoid-http3                 # ✅ passes
cargo check --no-default-features --features mesh,dns  # ✅ passes
cargo check --workspace --all-targets        # ✅ passes (see note below)
```

> **Note on `cargo check --workspace --all-targets`:** A pre-existing
> error in `src/worker/unified_server/init_mesh.rs:311,313` (variables
> `backend_pool` and `signer_for_mesh` out of scope) is reproducible on
> `main` *before* any of the Wave H / Wave Q changes — confirmed by
> `git stash` + retry. The error is **not** caused by H01–H03 or Q01–Q03.
> It is outside the scope of this task and is left for a separate fix.

---

## Acceptance

```bash
cargo check -p synvoid-http                                          # HWS-Q01 ✅
cargo check --no-default-features --features mesh,dns                 # HWS-Q02 ✅
cargo check --workspace --all-targets                                 # HWS-Q03 ✅ (with pre-existing init_mesh.rs error noted)
```

**Status (HWS-Q01–Q03, MDM-Q01–Q03)**: WafAccess trait actively used and now object-safe.
`Http3Server.waf` is `Arc<dyn Http3WafBackend>` (composite trait). All
non-root-owned root imports in `src/http3/server.rs` have been redirected
to their canonical extracted-crate paths. Remaining root blockers:
`WorkerDrainState` (root-owned, low-impact) and `bind_udp_reuse` (needs
`synvoid-platform` `socket` module export). Pre-existing `accept_loop.rs`
Send bound errors are unrelated to this refactor.
Decision recorded: `KEEP_ROOT_UNTIL_HTTP_SERVER_CONTEXT_REWORK`.

---

# RHP-H301: HTTP/3 Root Dependency Inventory Refresh (2026-06-08)

> Refresh pass on `src/http3/server.rs` (300 lines) to confirm the
> post-MDM-Q03 / WafAccess-object-safety state.

## Findings (2026-06-08)

`src/http3/server.rs` is now 300 lines (was 293 at MDM-Q03). All prior
content (HTC-Q01, HWS-Q01–Q03, MDM-Q01–Q03) is preserved above. The
following re-validation confirms the post-refactor state:

### Per-dependency refresh

| # | Dependency | Current owner | Existing seam | Move blocker | Notes |
|---|-----------|---------------|---------------|--------------|-------|
| 1 | `Http3Config` | `synvoid-config` | n/a (config struct) | **NONE** | Imported as `synvoid_config::http::Http3Config` at line 9 |
| 2 | `MainConfig` | `synvoid-config` | n/a (config struct) | **NONE** | Imported as `synvoid_config::MainConfig` at line 10 |
| 3 | `HttpClient` | `synvoid-http-client` | n/a (concrete type alias) | **NONE** | Imported as `synvoid_http_client::HttpClient` at line 11 |
| 4 | `create_http_client_with_config` | `synvoid-http-client` | n/a (factory) | **NONE** | Imported at line 11 |
| 5 | `get_global_bandwidth_tracker_or_log` | `synvoid-metrics` | n/a (utility) | **NONE** | Imported as `synvoid_metrics::bandwidth::get_global_bandwidth_tracker_or_log` at line 12 |
| 6 | `WorkerMetrics` | `synvoid-metrics` | `MetricsSink` trait (too narrow) | LOW (could be extended) | Imported at line 13; used as concrete `Option<Arc<WorkerMetrics>>` |
| 7 | `UpstreamClientRegistry` | `synvoid-proxy` | n/a (concrete struct) | **NONE** | Imported at line 15 |
| 8 | `Router` | `synvoid-proxy` | `RouteResolver` trait | LOW (synvoid-http still takes `&Arc<Router>`) | Imported at line 14 |
| 9 | `FloodDecision` | `synvoid-waf` | n/a (enum variant) | **NONE** | Imported at line 17 |
| 10 | `FloodProtector` | `synvoid-waf` | n/a | **NONE** | Imported at line 17 |
| 11 | `WafCore` | root (still) | `WafProcessor` + `WafAccess` + `Http3RequestWaf` | **RESOLVED via Arc<dyn Http3WafBackend>** | Composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` defined at server.rs:22-23; field at server.rs:29 is `Arc<dyn Http3WafBackend>` |
| 12 | `WorkerDrainState` | root | `DrainState` trait (in `synvoid-core`) + `WorkerDrainStateAdapter` | **RESOLVED in RHP-H303** (field removed) | The 4 occurrences in server.rs were all non-read: import (line 8), field (line 33), init `None` (line 62), builder (line 75). All removed by RHP-H303. |
| 13 | `bind_udp_reuse` | root platform, re-exported from `synvoid-platform::socket_bind` | n/a (platform utility) | **RESOLVED in RHP-H305** | The function is now in `crates/synvoid-platform/src/socket_bind.rs`; root re-exports it. HTTP/3 blocker count drops from 1 to 0 for `bind_udp_reuse`. |

### Summary (3 lines)

- WAF coupling is solved: `Http3Server.waf` is `Arc<dyn Http3WafBackend>`.
  Composite trait defined at server.rs:22-23; `WafAccess` methods
  (`connection_limiter`, `is_over_bandwidth_limit`, `streaming`) called
  at lines 231-232, 274-275, 277.
- `WorkerDrainState` was stored-but-never-read; RHP-H303 removed the
  field, init, builder, and call site cleanly.
- `bind_udp_reuse` is now reachable through both
  `synvoid_platform::socket_bind::bind_udp_reuse` and the existing
  root `crate::platform::socket::bind_udp_reuse` path; RHP-H305
  classification was `MOVE_TO_SYNVOID_PLATFORM` (using a new
  `socket_bind` module, not the pre-existing orphan `socket.rs`).

---

# RHP-H302/H303: WorkerDrainState HTTP/3 Decision + Implementation (2026-06-08)

> Decision and implementation pass for the `WorkerDrainState` field
> on `Http3Server`.

## Decision: REMOVE_UNUSED_FIELD

The `drain_state: Option<Arc<WorkerDrainState>>` field on `Http3Server`
was stored but **never read** in any method body. The 4 occurrences in
`src/http3/server.rs` were all non-read:

| Line | Use | Read? |
|------|-----|-------|
| 8 | `use crate::worker::drain_state::WorkerDrainState;` | n/a (import) |
| 33 | `drain_state: Option<Arc<WorkerDrainState>>,` | n/a (field decl) |
| 62 | `drain_state: None,` | n/a (init) |
| 75-78 | `pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self { ... }` | n/a (builder only) |

## Implementation (RHP-H303)

Changes applied:

1. `/Users/davidbowman/projects/synvoid/src/http3/server.rs`:
   - Removed import (line 8)
   - Removed field decl (line 33)
   - Removed init (line 62)
   - Removed builder method (lines 75-78)

2. `/Users/davidbowman/projects/synvoid/src/server/mod.rs`:
   - Removed call site block (lines 1301-1303)
   - Other consumers of `with_drain_state` (UnifiedServer, TlsServer, HttpServer) are on different types and were left intact.

## Validation (RHP-H303)

| Command | Result |
|---------|--------|
| `cargo check -p synvoid-http3` | **PASS** |
| `cargo check --lib --no-default-features` | **PRE-EXISTING FAIL** (2 errors at `src/http/server/accept_loop.rs:154`, unrelated) |
| `cargo check --no-default-features --features mesh,dns` | **PRE-EXISTING FAIL** (3 errors at `src/http/server/accept_loop.rs:154`, unrelated) |
| `cargo check --workspace --all-targets` | **PRE-EXISTING FAIL** (3 errors, same as above) |
| `cargo test --workspace --no-run` | **PRE-EXISTING FAIL** (3 errors, same as above) |

The 3 pre-existing errors are confirmed unrelated to RHP-H303 by
`git stash` round-trip baseline test.

## Net effect

- 1 root blocker removed (the only one with low-effort cost).
- `Http3Server` root ownership blocker count drops from 2 to 1 (only
  `bind_udp_reuse` remained, and that was resolved by RHP-H305).
- No runtime behavior change.

---

# RHP-H304: Platform UDP Binding Classification (2026-06-08)

> Classify the `bind_udp_reuse` ownership: keep in root, re-export, or
> move to `synvoid-platform`.

## Inspection findings

| Question | Answer |
|----------|--------|
| Is `bind_udp_reuse` already implemented in `synvoid-platform`? | Yes — a 1:1 byte-equivalent orphan copy exists at `crates/synvoid-platform/src/socket.rs:381-400`, but the file is not compiled because (a) `socket2` is not in `crates/synvoid-platform/Cargo.toml`, (b) it references `nix` (not a dep), and (c) `pub mod socket;` is not declared in `crates/synvoid-platform/src/lib.rs`. |
| Is the `socket` module publicly exported from `synvoid-platform`? | No — only `pub mod fs;` and `pub mod sandbox;` are exported. |
| Is the function self-contained (no root-only deps)? | Yes — the function only uses `socket2` and `std::net::SocketAddr`. |
| Are there related functions? | Yes — `bind_tcp_reuse` (root src/platform/socket.rs:359) and `is_reuse_port_available` (root src/platform/socket.rs:355) form a coherent group. |

## Decision: MOVE_TO_SYNVOID_PLATFORM (with a new `socket_bind` module)

The function is self-contained, the dep is already in root, and the
canonical helper `is_reuse_port_available()` already exists. However,
the existing orphan `crates/synvoid-platform/src/socket.rs` cannot be
made compilable in this pass without:
- adding `nix` and `socket2` (with `all` feature) to synvoid-platform's Cargo.toml
- refactoring 5 different platform-specific abstractions (FD passing, listening socket creation) that the orphan file references

That scope was larger than "low-risk". Instead, **a new
`socket_bind.rs` module** in synvoid-platform was created containing
only the 3 simple binding helpers.

## Implementation plan (RHP-H305)

1. **Add `socket2 = { version = "0.6", features = ["all"] }` to `crates/synvoid-platform/Cargo.toml`.**
2. **Add `pub mod socket_bind;` and `pub use socket_bind::{bind_tcp_reuse, bind_udp_reuse, is_reuse_port_available};` to `crates/synvoid-platform/src/lib.rs`.**
3. **Create `crates/synvoid-platform/src/socket_bind.rs`** with the 3 functions, using `socket2` with the `all` feature for `set_reuse_port` support.
4. **Replace the 3 function bodies in `src/platform/socket.rs`** (lines 355-400) with `pub use synvoid_platform::socket_bind::{...};` re-exports.
5. **No call site changes needed** — `src/http3/server.rs:108`, `src/tls/server.rs:281`, and `src/http/server/accept_loop.rs:8` continue to compile because the root `pub use` preserves the public path.

## Risks/considerations

- socket2 needs the `all` feature for `set_reuse_port` to be available.
- The orphan `crates/synvoid-platform/src/socket.rs` remains in place
  but uncompiled; it has 5 unrelated platform abstractions that
  require their own migration story.
- Stop condition: if the platform function depended on root-only
  config/runtime state, keep root-owned. Verified it does not.

---

# RHP-H305: Platform UDP Binding Move Implementation (2026-06-08)

> Implement the RHP-H304 decision: move `bind_udp_reuse`,
> `bind_tcp_reuse`, and `is_reuse_port_available` to
> `synvoid-platform::socket_bind`.

## Changes applied

**File 1: `crates/synvoid-platform/Cargo.toml`** (added dep)

```toml
socket2 = { version = "0.6", features = ["all"] }
```

**File 2: `crates/synvoid-platform/src/socket_bind.rs`** (new file, 64 lines)

Contains the 3 binding functions:
- `pub fn is_reuse_port_available() -> bool`
- `pub fn bind_tcp_reuse(addr: SocketAddr) -> io::Result<TcpListener>`
- `pub fn bind_udp_reuse(addr: SocketAddr) -> io::Result<UdpSocket>`

`is_reuse_port_available()` is implemented inline with a `cfg(...)` gate
on the same OS list that `is_reuse_port_supported()` covers (Linux,
macOS, BSDs, etc.). The functions use `socket2`'s `all` feature, which
is required for `set_reuse_port`.

**File 3: `crates/synvoid-platform/src/lib.rs`** (added module + re-exports)

```rust
pub mod socket_bind;
...
pub use socket_bind::{bind_tcp_reuse, bind_udp_reuse, is_reuse_port_available};
```

**File 4: `src/platform/socket.rs`** (replaced 45 lines with 1)

The 3 function bodies (lines 355-400) are replaced with:

```rust
pub fn is_reuse_port_available() -> bool {
    crate::platform::is_reuse_port_supported()
}

pub use synvoid_platform::socket_bind::bind_tcp_reuse;
pub use synvoid_platform::socket_bind::bind_udp_reuse;
```

The rest of `src/platform/socket.rs` (FD-passing shims,
`PlatformSocketFDPassing`/`PlatformSocketHandle`, `create_listening_socket_v4`/`v6`)
is **unchanged** — those abstractions still live in root and use the
root `socket2` dep directly.

## Validation results

| Command | Result |
|---------|--------|
| `cargo check -p synvoid-platform` | **PASS** (1m 51s first build with `all` feature) |
| `cargo check -p synvoid-http3` | **PASS** (7.09s) |
| `cargo check --no-default-features --features mesh,dns` | **PRE-EXISTING FAIL** (3 errors at `src/http/server/accept_loop.rs:154`, unrelated) |
| `cargo check --workspace --all-targets` | **PRE-EXISTING FAIL** (3 errors, same) |

The 3 pre-existing errors are unrelated (HTTP/1.1, not HTTP/3) and
reproduce on `HEAD` without my changes (verified by `git stash`
round-trip).

## Net effect

- HTTP/3 root blocker count drops from 1 to 0 for `bind_udp_reuse`.
  Combined with RHP-H303, the HTTP/3 server has **zero remaining
  low-effort root blockers**.
- The remaining structural blockers (WafCore, dispatch signature
  change) are recorded in RHP-H306 below.
- `bind_udp_reuse` is now reachable from
  `synvoid_platform::socket_bind::bind_udp_reuse` AND the existing
  root `crate::platform::socket::bind_udp_reuse` path.

---

# RHP-H306: HTTP/3 Server Move Readiness Decision (2026-06-08)

> Final decision on whether `src/http3/server.rs` can move to
> `synvoid-http3`.

## Inspection findings

After RHP-H303 and RHP-H305, the only remaining structural blockers
are:

1. **`WafCore` is the sole `Http3RequestWaf` implementor** in the
   workspace. Even though `Http3Server.waf` is
   `Arc<dyn Http3WafBackend>`, the runtime value is constructed in
   root. Plan § 2 non-goal #4 explicitly says "Do not move WafCore
   into synvoid-waf."

2. **The `http3_request_dispatch.rs` signature is generic** on
   `Waf: Http3RequestWaf`. The current call at `server.rs:283` passes
   `self.waf.as_ref()` which dereferences the trait object. Changing
   the signature to take `&dyn Http3RequestWaf` directly is a
   `synvoid-http` API change.

3. **The QUIC dependency stack** (`quinn`, `h3`, `h3-quinn`,
   `webpki-roots`, `rustls-pki-types`) is partially declared in root
   and partially in `crates/synvoid-http3/Cargo.toml`. Unification
   would require cross-crate coordination.

## Decision: KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER

`src/http3/server.rs` (292-300 lines depending on whether RHP-S03
touched it — it did not) **stays in root**. It is the single
composition point for the QUIC endpoint, the `h3`/`h3-quinn` server
builder, the `synvoid-http` request-dispatch seam, the `synvoid-waf`
flood/WAF layer, the upstream client registry, the metrics sink, the
root `broadcast::Receiver<()>` shutdown channel, the
`alt_svc_header()` generator for HTTP/1.1's `Alt-Svc` response, and
the platform UDP socket binding. The file is small, leaf-position in
the dependency graph, and tightly coupled to root-level subsystems.
Moving it is not a measurable win on its own.

## Why not `MOVE_READY`

Three independent preconditions must be satisfied, each out of scope
for the current pass:

1. `bind_udp_reuse` must move or be re-exported via
   `synvoid-platform`. **DONE in RHP-H305** — function is in
   `synvoid_platform::socket_bind::bind_udp_reuse`.
2. `WafCore` must move to `synvoid-waf`. Plan § 2 non-goal #4
   prevents this.
3. The `http3_request_dispatch.rs` signature must change to accept
   `&dyn Http3RequestWaf`. A `synvoid-http` API change.

## Why not `KEEP_ROOT_UNTIL_PLATFORM_SOCKET_MOVE`

`bind_udp_reuse` is resolved. The remaining structural blockers
(WafCore, dispatch signature) are independent and load-bearing.

## Why not `DEFER_LOW_VALUE`

`server.rs` is small but it is the only place where the
`quinn::Endpoint` is constructed, the `h3` server is wired with
`h3_quinn::Connection`, the root shutdown broadcast is consumed, and
the `alt_svc_header()` is generated. These are "QUIC composition"
responsibilities with no benefit to moving the file alone. The right
label is a specific composition-layer rationale, not a deferral.

## Re-evaluation preconditions

This decision will be revisited only when **all three** of the
following are completed:

1. `WafCore` is extracted to `synvoid-waf` (requires lifting
   plan § 2 non-goal #4).
2. `handle_http3_request_dispatch` signature changes to accept
   `&dyn Http3RequestWaf` (a `synvoid-http` API change).
3. The QUIC stack dep declarations are unified between root and
   `synvoid-http3`.

Once all three are satisfied, the move is reduced to a
near-mechanical step. Until then, root-ownership of `server.rs` is
the correct architectural choice.
