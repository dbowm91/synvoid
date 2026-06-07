# HTC-Q01: Inventory `src/http3/server.rs` Concrete Root Dependencies

**File**: `src/http3/server.rs` (293 lines)
**Date**: 2026-06-07
**Updated**: 2026-06-07 (HWS-Q01–Q03)
**Updated**: 2026-06-07 (MDM-Q01–Q03 — refresh + import reduction + ownership decision)

## Summary

`src/http3/server.rs` imports **10 concrete root-owned types** across 8 `crate::` import lines. Two of these (`WafCore`, `WorkerDrainState`) are root-defined structs with no trait seam in extracted crates. The remaining 8 are re-exports from extracted crates (`synvoid-proxy`, `synvoid-waf`, `synvoid-http-client`, `synvoid-metrics`, `synvoid-config`). The `prepare_http3_request_dispatch` and `handle_http3_request_dispatch` functions in `synvoid-http` also take some of these concrete types directly in their signatures.

**HWS-Q01–Q03 update**: The `WafAccess` trait is now actively used in server.rs (imported at line 15, methods called at lines 224, 225, 267, 268, 270). The 3 accessor methods (`connection_limiter`, `is_over_bandwidth_limit`, `streaming`) no longer access WafCore fields directly. Remaining blocker: `self.waf.as_ref()` at line 276 for `Http3RequestWaf` dispatch still requires concrete `WafCore`.

---

## Concrete Dependency Table

| # | Concrete dependency | Import line | Struct field line | Existing seam | Missing seam | Action | Notes |
|---|---------------------|-------------|-------------------|---------------|--------------|--------|-------|
| 1 | `WafCore` | 14 | 21 | `WafProcessor` (synvoid-waf) + **`WafAccess`** (synvoid-waf) + `Http3RequestWaf` (synvoid-http) | `as_ref()` for `Http3RequestWaf` dispatch still requires concrete type | **WafAccess resolved** — all 3 accessors now use trait methods; remaining blocker is `self.waf.as_ref()` for `Http3RequestWaf` dispatch | `WafAccess` imported at line 15, used at lines 224, 225, 267, 268, 270. `self.waf.as_ref()` at line 276 still needs concrete `WafCore` |
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
| `WafCore` | `src/waf/mod.rs:97` | `WafProcessor` + `WafAccess` + `Http3RequestWaf` — all 3 WafAccess accessors now used via trait. Remaining: `self.waf.as_ref()` for `Http3RequestWaf` dispatch requires concrete type | **WafAccess resolved**; remaining blocker is `Http3RequestWaf` trait object or generic struct |
| `WorkerDrainState` | `src/worker/drain_state.rs:23` | `DrainState` trait exists in synvoid-core, `WorkerDrainStateAdapter` wraps it | Low — stored but unused in server.rs methods; just pass `Option<Arc<dyn DrainState>>` |

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

### Next steps

1. Verify `Http3RequestWaf` is object-safe (check for `Self` returns, generics, async)
2. If object-safe: change `waf: Arc<WafCore>` to `waf: Arc<dyn Http3RequestWaf>` in struct
3. If not object-safe: create thin wrapper trait or make struct generic
4. Then reassess `MOVE_READY`

---

# MDM-Q01: Refreshed Concrete Dependency Inventory (2026-06-07)

> Wave Q, Task Q01. Refreshed inventory for `src/http3/server.rs` (293 lines).

## Count summary

| Class | Count |
|-------|-------|
| Total distinct concrete root imports | 10 (`Http3Config`, `MainConfig`, `HttpClient`, `create_http_client_with_config`, `get_global_bandwidth_tracker_or_log`, `WorkerMetrics`, `UpstreamClientRegistry`, `Router`, `FloodDecision`, `FloodProtector`, `WafCore`, `WorkerDrainState`, `bind_udp_reuse`) |
| Already moved to extracted crate (clean root → crate replacement possible) | 9 |
| Covered by WafProcessor / WafAccess (no replacement needed) | 1 (`WafAccess` is already used at lines 224, 225, 267, 268, 270) |
| Still root-only (cannot replace without trait/external reorg) | 3 (`WafCore`, `WorkerDrainState`, `bind_udp_reuse`) |

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
| 11 | `WafCore` | 14, 22, 38, 51, 276 | **Root-only.** `Http3RequestWaf` impl is in root; `self.waf.as_ref()` (line 276) dispatches to `handle_http3_request_dispatch` which expects `waf: &Waf` where `Waf: Http3RequestWaf`. **Covered by WafAccess** for the 3 accessors used at lines 224, 225, 267, 268, 270; **NOT covered** for the dispatch at line 276. | The remaining blocker for moving `src/http3/server.rs` is structural: `WafCore` is the only implementor of `Http3RequestWaf` and lives in root. |
| 12 | `WorkerDrainState` | 15, 26, 55, 68 | **Root-only.** Struct in `src/worker/drain_state.rs`. Stored as field but never accessed in any server method body (no method reads/writes it after construction). | Could be replaced with `Option<Arc<dyn DrainState>>` if `Http3Server` accepted the trait; the builder `with_drain_state` would need to take the trait object. |
| 13 | `bind_udp_reuse` (inline) | 101 | **Root platform utility** (function defined in `src/platform/socket.rs`). `synvoid-platform` has a same-named function in its (private) `socket` module, but it is **not** publicly exported from `synvoid-platform`. | Stop condition hit during Q02: cannot replace without making `crates/synvoid-platform/src/socket.rs` public, which is a separate cross-cutting change. |

**Net result for Q01**: 10 of 12 distinct concrete dependencies are clean root → crate replacements; 3 (`WafCore`, `WorkerDrainState`, `bind_udp_reuse`) remain root-only. Of the 3, `bind_udp_reuse` is solvable in a follow-up by exporting the `socket` module from `synvoid-platform`; `WafCore` and `WorkerDrainState` are deferred by plan §2 (WafCore is explicitly off-limits; WorkerDrainState is part of worker which is also off-limits).

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

**Status (HWS-Q01–Q03, MDM-Q01–Q03)**: WafAccess trait actively used. All
non-root-owned root imports in `src/http3/server.rs` have been redirected
to their canonical extracted-crate paths. `Http3RequestWaf` dispatch
remains as the structural blocker for HTTP3 server movement, with the
secondary blockers being `WorkerDrainState` (root-owned) and
`bind_udp_reuse` (needs `synvoid-platform` `socket` module export).
Decision recorded: `KEEP_ROOT_UNTIL_HTTP_SERVER_CONTEXT_REWORK`.
