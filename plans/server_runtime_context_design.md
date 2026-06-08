# RHP-S02: Server-Runtime Context Struct Design

> Wave RHP, Task S02. Design only — no source code is changed in this task.
>
> Builds on:
> - `plans/http_server_dependency_inventory.md` (RHP-S01) — the refreshed
>   30-distinct-concrete-dependency inventory of `src/http/server.rs` and its
>   three wired submodules.
> - `plans/remaining_http_runtime_and_schema_path.md` §6 (Wave S) — the
>   parent plan that defines the goal: reduce parameter threading without
>   moving `src/http/server.rs`.
> - `crates/synvoid-http/src/runtime.rs` — the existing
>   `HttpRuntimeContext<W, R, M, D>` generic struct in `synvoid-http`.
> - `crates/synvoid-http/src/http_request_postlude.rs` — the existing
>   `HttpRequestPostludeContext<'a, W>` reference-bag in `synvoid-http`.

## 0. Goal

Reduce parameter explosion at the call sites of
`HttpServer::handle_request` and `run_accept_loop` (the TCP accept loop in
`src/http/server/accept_loop.rs`) by introducing small context structs that
group already-existing concrete dependencies **without** changing behaviour,
**without** moving `src/http/server.rs`, and **without** creating new crates.

This task produces a **design document only**. The plan §6 reserves
RHP-S03 to actually introduce the structs, and RHP-S04 to decide whether a
later `synvoid-runtime` crate is justified. This document is the input
for both.

## 1. Problem statement

### 1.1 Current parameter explosion

Per RHP-S01, `HttpServer::handle_request` (`src/http/server.rs:222-247`)
takes **20+ parameters** at the call site:

```text
handle_request(
    req, client_addr, local_addr,
    router, waf, client, alt_svc, main_config,
    drain_state, http_config,
    #[cfg(feature = "mesh")] mesh_config,
    #[cfg(feature = "mesh")] mesh_transport,
    metrics, http_conn,
    ipc, worker_id,
    serverless_manager, connection_limit,
    app_servers,
    #[cfg(feature = "mesh")] mesh_backend_pool,
    upstream_client_registry,
    _erased_http_client,    // dead parameter, prefixed _ at server.rs:246
)
```

`run_accept_loop` (`src/http/server/accept_loop.rs:3-25`) takes the same
20-arg shape (minus the per-request `http_conn`/`ipc`/`worker_id`/`req`).
Inside the loop, every parameter is `.clone()`-ed on every accepted
connection (accept_loop.rs:64-83), then re-cloned again on every request
inside the `service_fn` closure (accept_loop.rs:135-157). That is the
actual churn surface — every accept loop tick and every request performs
20+ `Arc::clone` calls.

### 1.2 Most aggressively threaded dependencies

From the RHP-S01 table, the dependencies threaded across 4+ functions are:

| Dependency | Threaded across |
|------------|-----------------|
| `WorkerDrainState` | 5 functions + `DrainGuard` |
| `MainConfig` | 5 functions (incl. `observability::send_request_log_if_enabled`) |
| `Router` | 4 functions |
| `WafCore` | 4 functions |
| `HttpConfig` | 4 functions |
| `WorkerMetrics` | 4 functions |
| `ServerlessManager` | 4 functions |
| `HttpClient` | 4 functions |
| `GranianSupervisor` (in `app_servers` map) | 4 functions |
| `IpcStream` / `WorkerId` | 4 functions |
| `UpstreamClientRegistry` | 4 functions |
| `ErasedHttpClient` | 4 functions — **but never read** |
| Mesh (3 cfg-gated types) | 4 functions each |

The `ErasedHttpClient` is the standout: it is cloned 4 times per
request and never used. A clear candidate to **drop** from the
threading chain, not just bundle.

### 1.3 Existing context structs (do not duplicate them)

Two context-like structs already exist and should be **reused**, not
re-invented:

1. **`synvoid_http::HttpRequestPostludeContext<'a, W>`**
   (`crates/synvoid-http/src/http_request_postlude.rs:94-119`).
   Bundles 21 dependencies for the postlude; takes references
   everywhere; uses a generic `W` for WAF.
   - Used at `src/http/server.rs:317-342` already.
   - Lives in `synvoid-http`; already canonical.

2. **`synvoid_http::HttpRuntimeContext<W, R, M, D>`**
   (`crates/synvoid-http/src/runtime.rs:11-33`).
   Bundles 4 trait-objected services (WAF, router, metrics, drain) for
   the HTTP pipeline.
   - Uses 4 generic parameters bounded by `WafProcessor`,
     `RouteResolver`, `MetricsSink`, `DrainState`.
   - Lives in `synvoid-http`; already canonical.
   - **Not currently used by `HttpServer`.** The server threads concrete
     types (`Arc<WafCore>`, `Arc<Router>`, `Option<Arc<WorkerMetrics>>`,
     `Option<Arc<WorkerDrainState>>`).

3. **`synvoid_http::HttpRequestFlowOutcome`** and
   **`synvoid_http::RequestPreparationOutcome`** (the value-level
   "outcome" enums returned by `prepare_http_request_flow`).
   These are per-request outputs, not context structs, and stay as-is.

This design **adds** structs in two places: the server-runtime phase
(`HttpServerRuntime`, "what the server has") and the per-request
augmentation is kept on `HttpConnection` (per-request augments), without
re-bundling the already-canonical `HttpRequestPostludeContext` or
`HttpRuntimeContext`.

## 2. Proposed struct definitions

The shapes below are **forward-pointing targets**. The actual fields and
trait bounds will be finalised in RHP-S03 once the design is approved.

### 2.1 `HttpServerRuntime` (the "what the server has" struct)

This is the struct `HttpServer` would carry on itself (replacing the
20+ individual fields) and clone into the accept loop once per tick
instead of cloning each dependency once per connection.

```rust
// File: src/http/server.rs (root-owned, see §3.1)
#[derive(Clone)]
pub struct HttpServerRuntime {
    // --- data-plane services (threaded once per accept tick) ---
    pub router: Arc<Router>,
    pub waf: Arc<dyn HttpRequestWafBackend>,         // see §2.3
    pub client: synvoid_http_client::HttpClient,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub connection_limit: Arc<tokio::sync::Semaphore>,
    pub flood_protector: Option<Arc<FloodProtector>>,

    // --- configuration (read-only) ---
    pub main_config: Arc<MainConfig>,
    pub http_config: HttpConfig,
    pub alt_svc: Option<String>,

    // --- observability (most aggressively threaded) ---
    pub metrics: Option<Arc<WorkerMetrics>>,
    pub drain_state: Option<Arc<WorkerDrainState>>,

    // --- per-process IPC (used by observability.rs) ---
    pub ipc: Option<Arc<tokio::sync::Mutex<synvoid_ipc::AsyncIpcStream>>>,
    pub worker_id: Option<synvoid_ipc::WorkerId>,

    // --- per-tenant backends (each one is its own concern; see §2.2) ---
    pub backends: HttpAppBackends,

    // --- cfg-gated mesh (kept inside the struct to avoid cfg-branches
    //     on the per-request call site) ---
    #[cfg(feature = "mesh")]
    pub mesh_config: Option<Arc<synvoid_mesh::config::MeshConfig>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<synvoid_mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: Option<Arc<synvoid_mesh::MeshBackendPool>>,
}
```

Notes:

- `Arc<Router>`, `Arc<UpstreamClientRegistry>`, `Arc<Semaphore>` stay
  Arc-wrapped because they are already shared.
- `HttpClient` is **not** Arc-wrapped; it is an internal handle that
  already supports cheap `Clone` (hyper client). One `Clone` per tick
  instead of one per connection.
- `Arc<dyn HttpRequestWafBackend>` replaces `Arc<WafCore>` to match the
  HTTP/3 server's existing pattern (`src/http3/server.rs:21-22`,
  `Http3WafBackend`). This is the *single* trait seam this design
  recommends introducing first (see §2.3).
- `HttpServerRuntime` is **not** a public type. It is an internal
  composition struct used by `HttpServer` and `run_accept_loop` only.
- `ErasedHttpClient` is **dropped** from the threading chain
  (see §2.4). It is not stored in `HttpServerRuntime`.

### 2.2 `HttpAppBackends` (the "per-tenant backends" struct)

The set of dependencies that are each owned by a different
"backend" subsystem (serverless runtime, app-server supervisor map,
plugin manager) does not naturally fit into the data-plane core
above. Grouping them in a sub-struct keeps the per-request call site
short and signals that each one is independently replaceable.

```rust
// File: src/http/server.rs (root-owned, see §3.1)
#[derive(Clone, Default)]
pub struct HttpAppBackends {
    pub serverless: Option<Arc<synvoid_serverless::ServerlessManager>>,
    pub app_servers: Option<Arc<tokio::sync::RwLock<
        std::collections::HashMap<String, Arc<synvoid_app_server::GranianSupervisor>>
    >>>,
    /// Type-erased handle to the root `PluginManager`. Cast to
    /// `&dyn synvoid_http::WasmFilterBackend` and
    /// `&dyn synvoid_http::AxumDynamicRouterLookup` at the use site
    /// (the current `downcast_ref` pattern at server.rs:309, 313).
    pub plugin_manager: Option<Arc<dyn std::any::Any + Send + Sync>>,
}
```

Notes:

- `plugin_manager` is stored as `Arc<dyn Any + Send + Sync>` to mirror
  `Router::plugin_manager()`'s return type (already a
  `Option<Arc<dyn Any + Send + Sync>>` per the RHP-S01 table row 17).
  The `downcast_ref` at server.rs:309, 313 stays.
- The struct has `Default` so `HttpServer::new` can initialise
  everything to `None` for the builder methods.

### 2.3 Trait seam: `HttpRequestWafBackend`

`HttpServer` currently stores `Arc<WafCore>` concretely
(server.rs:55). `Http3Server` already stores
`Arc<dyn Http3WafBackend>` (server.rs:28) and combines
`synvoid_http::Http3RequestWaf + synvoid_waf::WafAccess` into a
single trait. The HTTP/1.1 path should follow the same pattern.

```rust
// File: src/http/server.rs (root-owned, see §3.1)
//
// Equivalent to the existing `Http3WafBackend` combo trait
// (src/http3/server.rs:21-22), but tailored to the HTTP/1.1 postlude
// (no `Http3RequestWaf`, which is HTTP/3-only).
pub trait HttpRequestWafBackend:
    synvoid_http::BufferedRequestWaf
    + synvoid_http::RequestBodyWaf
    + synvoid_http::UploadValidationWaf
    + synvoid_http::WafErrorPageRenderer
    + synvoid_proxy::protocol::trait_def::WafCoreBackend
    + Send
    + Sync
    + 'static
{
}
impl<T> HttpRequestWafBackend for T where
    T: synvoid_http::BufferedRequestWaf
    + synvoid_http::RequestBodyWaf
    + synvoid_http::UploadValidationWaf
    + synvoid_http::WafErrorPageRenderer
    + synvoid_proxy::protocol::trait_def::WafCoreBackend
    + Send
    + Sync
    + 'static
{
}
```

This is the **only** new trait seam this design recommends introducing
in RHP-S03. It mirrors the existing HTTP/3 seam and lets `WafCore`
satisfy the bound with no changes (every bound is already implemented
in `src/waf/mod.rs:128, 919, 943, 954, 961`).

### 2.4 Drop: `ErasedHttpClient` is dead

Per RHP-S01 row 8: `ErasedHttpClient` is cloned 4 times per request
and **never read in any body** (parameter is `_erased_http_client` at
server.rs:246, no usage in the body of `handle_request`). The
struct's only consumer was the original `http_conn` early design, and
the work has since moved to `Router::plugin_manager()` + the
postlude.

Recommendation: **drop the field, drop the parameter, drop the
clone chain**. RHP-S03 may do this in the same patch that introduces
`HttpServerRuntime`, because the struct has no `ErasedHttpClient`
field and the parameter goes away naturally.

If the design decides the type may be needed in the future, an
alternative is to store it once in `HttpServerRuntime` and never
re-thread it. The recommendation is **delete**, not "thread once
and forget", because no current call site reads it.

## 3. Classification: where does each struct live?

The plan §6 default recommendation is:

> Keep structs in `synvoid-http` only if they do not depend on
> root-only types. Keep root-only composition structs in root until
> worker/server boundaries stabilize.

This section applies that rule.

### 3.1 `HttpServerRuntime` and `HttpAppBackends`: **root-only**

Both structs depend on root-only types:

| Field | Type | Lives in | Root-only? |
|-------|------|----------|------------|
| `waf` | `Arc<dyn HttpRequestWafBackend>` (backed by `WafCore`) | `src/waf/mod.rs` | **Yes** (WafCore stays in root per plan §2) |
| `drain_state` | `Option<Arc<WorkerDrainState>>` | `src/worker/drain_state.rs` | **Yes** (worker stays in root per plan §2) |
| `flood_protector` | `Option<Arc<FloodProtector>>` | `synvoid_waf::FloodProtector` re-exported at `src/waf/flood/mod.rs` | **Almost** — re-export is clean, but the accept-loop call site uses `FloodProtector::check_tcp_connection` which is implemented in the synvoid-waf crate, so it could in principle move. The call lives in `accept_loop.rs:51`; if `accept_loop.rs` moves to a crate, the struct moves with it. |
| `backends.serverless` | `Option<Arc<synvoid_serverless::ServerlessManager>>` | `synvoid-serverless` (clean) | No (extracted) |
| `backends.app_servers` | `Option<Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>>` | `synvoid-app-server` (clean) | No (extracted) |
| `backends.plugin_manager` | `Option<Arc<dyn Any + Send + Sync>>` | `crate::plugin::PluginManager` | **Yes** (`PluginManager` is a root struct per RHP-S01 row 17) |
| mesh fields | `Arc<MeshConfig>`, etc. | `synvoid-mesh` | No (extracted) |
| everything else | concrete extracted types | various | No |

Four of the structural fields depend on root-only types
(`WafCore` via the new trait, `WorkerDrainState`,
`FloodProtector` *via* root re-export, and `PluginManager` via
`dyn Any`). The struct cannot move to `synvoid-http` without one of:

1. **Trait-seam `WafCore` first.** Not in plan; deferred by plan §2.
2. **Move `WorkerDrainState` first.** Not in plan; deferred by plan §2.
3. **Move `PluginManager` first.** Not in plan; deferred by plan §2.

None of these are RHP-S03 scope. The default recommendation
applies: **root-only**.

### 3.2 `HttpRequestWafBackend`: **root-only**

The trait combines 4 `synvoid-http` traits + 1 `synvoid-proxy` trait
+ 1 implicit `WafCore` requirement. The implicit requirement is
"satisfied by `WafCore`" (the only implementor today) and is
what binds the trait to a root type. Moving the trait to
`synvoid-http` is technically possible because the trait only
**references** the bounds, not the concrete `WafCore` type.
However, the trait is **only useful where the concrete `WafCore`
lives** — and the only call sites that would consume it are in
root's `src/http/server.rs`. Putting the trait in `synvoid-http`
would add a new public type to a leaf crate whose only consumer
is root.

Default recommendation: **root-only** (in `src/http/server.rs`),
mirroring how `Http3WafBackend` is declared at the call site
(`src/http3/server.rs:21-22`, not in `synvoid-http3`).

### 3.3 Existing context structs (do not move)

| Struct | Current home | Should move? | Why |
|--------|--------------|--------------|
| `HttpRuntimeContext<W, R, M, D>` | `synvoid-http::runtime` | **No** | Already extracted. Generic on 4 trait objects. `HttpServer` does **not** consume it yet; RHP-S03 may or may not wire it up. |
| `HttpRequestPostludeContext<'a, W>` | `synvoid-http::http_request_postlude` | **No** | Already extracted. Used by `src/http/server.rs:317` already. |

These two structs are the **reference designs** for `HttpServerRuntime`
— both are reference-bag structs living in `synvoid-http`. The new
struct cannot live in `synvoid-http` because of the four root-only
field types noted in §3.1.

## 4. Trait-seam candidates

This section catalogues every possible trait seam, classifies the
cost, and recommends what to introduce in RHP-S03. Only one
(`HttpRequestWafBackend`) is recommended; the rest are documented
for future waves.

### 4.1 Recommended: `HttpRequestWafBackend` (§2.3)

- **Cost:** Trivial. 5 already-implemented trait bounds composed
  into a single trait; 1 trivial blanket impl.
- **Benefit:** Lets `HttpServerRuntime.waf` be a trait object,
  matching `Http3Server.waf`'s shape. Removes the only root-only
  concrete field from the data plane that is *also* the most
  cross-cutting (WAF is threaded into 4 functions per RHP-S01).
- **Risk:** Zero behaviour change. `WafCore` already implements
  every bound; the blanket impl is `impl<T: Bounds> HttpRequestWafBackend for T`.
- **Introduce in:** RHP-S03 (same patch as `HttpServerRuntime`).

### 4.2 Consider later: `FloodChecker`

- **Cost:** Small. One method (`check_tcp_connection(ip) -> FloodDecision`).
- **Benefit:** Decouples `accept_loop.rs` from concrete `FloodProtector`.
- **Risk:** None. `FloodProtector` already lives in `synvoid-waf`
  (re-exported at root `src/waf/flood/mod.rs`); the trait would
  live next to it.
- **Introduce in:** Future wave. Not RHP-S03. The struct-level
  `HttpServerRuntime.flood_protector` keeps the concrete type
  for now.

### 4.3 Defer: `HttpClientBackend`

- **Cost:** Medium. `HttpClient` is used by value (`client.clone()`
  in `accept_loop.rs:66`) and by reference (`&client` in
  `http_request_postlude.rs:99`). A trait would need to expose
  every method the postlude calls. Not a small surface.
- **Benefit:** Removes a `synvoid-http-client` dep from
  `HttpServerRuntime`; would let `HttpServerRuntime` live in
  `synvoid-http` if other root-only fields also get trait-seamed.
- **Risk:** None expected, but effort is not justified by the
  current file's footprint.
- **Introduce in:** Only if/when `HttpServerRuntime` is being
  considered for move to `synvoid-http` (deferred by plan §2).

### 4.4 Defer: `UpstreamClientRegistry` trait

- **Cost:** Small. Only `.as_ref()` and similar thin usage; would
  need a 1-2 method trait.
- **Benefit:** Same as `HttpClientBackend` — needed only if
  `HttpServerRuntime` moves.
- **Risk:** None.
- **Introduce in:** Only if RHP-S04 decides the struct should
  move to `synvoid-http` or a new `synvoid-runtime` crate.

### 4.5 Defer: `WorkerMetrics` trait extension

- **Cost:** **High.** `WorkerMetrics` exposes 20+ methods
  (RHP-S01 row 5). The existing `MetricsSink` trait in
  `synvoid-core::metrics` is only 5 methods. Extending
  `MetricsSink` or creating a new `WorkerMetricsSink` is
  a major refactor.
- **Benefit:** Removes the second-most-threaded concrete dep.
- **Risk:** High. The `RequestMetricsAdapter` at
  `crates/synvoid-http/src/http_request_postlude.rs:30-92`
  already shows the kind of adapter boilerplate that would
  expand.
- **Introduce in:** **Not in this wave.** Defer to a dedicated
  metrics-trait pass.

### 4.6 Defer: `DrainCounter` trait (separate from `HttpDrainControl`)

- **Cost:** Small. `DrainGuard` (`connection_types.rs:123-141`)
  calls `increment_active` / `decrement_active` directly on
  `WorkerDrainState`. A 2-method trait would suffice.
- **Benefit:** Lets `DrainGuard` move to `synvoid-http` with
  the rest of `connection_types.rs`.
- **Risk:** None.
- **Introduce in:** A future "DrainHandle" wave, not RHP-S03.
  For RHP-S03, `HttpServerRuntime.drain_state` keeps the
  concrete `Arc<WorkerDrainState>`.

### 4.7 Already done — do not duplicate

- `BufferedRequestWaf`, `RequestBodyWaf`, `UploadValidationWaf`,
  `WafErrorPageRenderer`, `WafCoreBackend` — composed into
  `HttpRequestWafBackend` (§2.3).
- `HttpDrainControl` (used by `prepare_http_request_flow<W, D>`
  and `handle_http_request_postlude<W>`). Already covers the
  flow/postlude code paths.
- `WasmFilterBackend`, `AxumDynamicRouterLookup` — already
  used as trait objects at server.rs:310, 314.

## 5. Pros and cons of each option

### 5.1 Option A: Introduce `HttpServerRuntime` only (recommended)

**Pros:**

- Reduces 20-arg call sites to 3-arg call sites:
  `(req, client_addr, local_addr, runtime, http_conn)`.
- Reduces 4-5 Arc::clone calls per connection to 1 Arc::clone
  (`runtime.clone()`).
- Mirrors the data-plane / control-plane split that the existing
  `HttpRequestPostludeContext` already uses.
- Lets `ErasedHttpClient` be dropped entirely (it is not in the
  struct).
- Zero behaviour change. The struct is purely a re-grouping of
  already-existing fields.
- Compatible with the existing `HttpRuntimeContext<W, R, M, D>`
  in `synvoid-http::runtime` — they can coexist; the new struct
  is the "what the server has" composition, the existing one is
  the "what the pipeline needs" subset.

**Cons:**

- Root-only. Cannot move to `synvoid-http` until 3-4 root-only
  fields get trait-seamed.
- `HttpServerRuntime` adds a public(ish) struct to root, but
  `pub(crate)` visibility makes it internal to the server module.
- The struct is mutable-by-builder (`with_*` methods continue
  to work) — same shape as today's `HttpServer`.

### 5.2 Option B: Move structs into `synvoid-http` (deferred)

**Pros:**

- Could live in the same crate as `HttpRequestPostludeContext`.
- "Cleaner" from a dependency-boundary perspective.

**Cons:**

- Requires trait-seaming `WafCore`, `WorkerDrainState`,
  `PluginManager` first. None of these are in plan scope.
- Forces a multi-task refactor that crosses waves RHP-S03 +
  future WAF pass + future worker pass.
- Violates the default recommendation: "Keep root-only
  composition structs in root until worker/server boundaries
  stabilize." (plan §6).

**Verdict:** Defer. Not in RHP-S03. Re-evaluate in RHP-S04
("decide whether a later server-runtime crate is justified").

### 5.3 Option C: Do nothing (defer RHP-S03 entirely)

**Pros:**

- No risk.
- No validation churn.

**Cons:**

- Does not reduce parameter explosion.
- Misses the plan §12 success criterion: "Server-runtime context
  design is documented and optionally introduced only if
  low-risk" (plan §12.4). The design is documented (this file);
  the introduction is "optional" but is the value-add.

**Verdict:** Not recommended. Option A is low-risk; the
introduction is worth doing.

### 5.4 Option D: Introduce the structs but thread them everywhere

This would be the "easy mode" — keep the parameter list and add
a new parameter. This option is explicitly **rejected**: it
adds churn without removing it.

## 6. Recommended plan (in priority order)

1. **Introduce `HttpRequestWafBackend` in `src/http/server.rs`**
   (or a new `src/http/server/waf_backend.rs` submodule). 1 trait
   + 1 blanket impl. Zero behaviour change.

2. **Introduce `HttpAppBackends` in `src/http/server.rs`**.
   Simple re-grouping of the 3 `backends` fields
   (`serverless_manager`, `app_servers`, plugin manager handle).
   `Default` impl + `Clone`.

3. **Introduce `HttpServerRuntime` in `src/http/server.rs`**.
   Re-group all 20+ `HttpServer` fields into one struct. The
   `HttpServer` struct now holds a single `runtime:
   HttpServerRuntime` field plus the per-server config it does
   not share (bind address, shutdown receiver).

4. **Refactor `HttpServer::new` to construct a default
   `HttpServerRuntime` and then apply `with_*` methods to it.**
   The `with_*` methods now mutate `self.runtime` instead of
   `self`.

5. **Refactor `HttpServer::serve` and `run_accept_loop` to take
   `HttpServerRuntime` by value / clone once per tick instead of
   20+ parameters.** This is where the Arc::clone count drops
   from 20+ per connection to 1 per connection.

6. **Refactor `HttpServer::handle_request` to take
   `HttpServerRuntime` and `HttpConnection` (per-request
   augments) instead of 20+ parameters.**

7. **Delete `ErasedHttpClient` field, parameter, and
   constructor call.** The struct has no `erased_http_client`
   field; the parameter goes away naturally; the
   `ErasedHttpClient::new(100)` call at server.rs:120 is
   removed.

8. **Validate:**
   ```bash
   cargo check --lib --no-default-features
   cargo check --no-default-features --features mesh
   cargo check --no-default-features --features mesh,dns
   cargo check -p synvoid-http
   cargo check -p synvoid-http3
   cargo check --workspace --all-targets
   cargo test --workspace --no-run
   ```

## 7. Stop conditions

This task is design-only. The implementation task (RHP-S03)
should stop and document if any of the following occurs:

- The struct's lifetime/borrow story requires generic propagation
  into `handle_request` or `run_accept_loop` (e.g., a `'static`
  bound becomes load-bearing in a way that affects call-site
  ergonomics). The structs are designed to be cloned (each field
  is `Arc`-wrapped or cheaply cloneable), so this should not
  happen.
- The struct's `Clone` impl becomes non-trivial (e.g., requires
  a `Box::new` for a closure). Currently every field is `Arc`,
  `Option<Arc<...>>`, `HttpClient` (cheap clone), or `String`
  clone — all cheap.
- Removing `ErasedHttpClient` triggers a test failure in
  `crates/synvoid-http-client` or `crates/synvoid-http3`. The
  type is unused at the call site, but tests in those crates
  may still construct `HttpServer`s and rely on the field's
  default. If so, keep the field out of the struct (return it
  to a `HttpServer`-level field), but keep the parameter
  removed from `handle_request`/`run_accept_loop` if it is
  truly unused.
- The trait blanket impl for `HttpRequestWafBackend` causes
  coherence issues. The blanket is `impl<T: Bounds> ... for T`
  over a fixed set of bounds already in scope of root, so this
  should not happen.
- Any of the four root-only fields
  (`WafCore`/`WorkerDrainState`/`FloodProtector`/`PluginManager`)
  are needed at a future call site that does not have the
  struct in scope (e.g., a new module needs them). In that
  case, the struct should be passed by reference, not by
  clone.

If any stop condition is hit, document the blocker in this file
under a new "Stop conditions hit" section, and defer the
remaining work to a follow-up RHP-S03b task.

## 8. What is explicitly **not** in this design

- **No new crates.** The plan §2 forbids creating new crates
  in this pass.
- **No movement of `src/http/server.rs`.** Plan §2 forbids it.
- **No new trait seams beyond `HttpRequestWafBackend`.** The
  others are documented for future waves but not introduced
  in RHP-S03.
- **No changes to `synvoid_http::HttpRuntimeContext` or
  `HttpRequestPostludeContext`.** These are already
  canonical and used appropriately.
- **No changes to `Http3Server`.** HTTP/3 has its own
  `Http3WafBackend` combo trait and is structurally similar;
  the structs in this design are HTTP-server-specific. If
  the same struct shapes work for HTTP/3, that is a future
  consolidation pass.
- **No changes to orphan files
  (`backend_dispatch.rs`, `request_preparation.rs`,
  `traffic_control.rs` in `src/http/server/`).** Per RHP-S01,
  these are not in the module graph and are excluded from
  this design's scope. They are already documented as
  duplicate-of-`synvoid-http` and are a separate cleanup
  task.

## 9. Acceptance (design-only)

The RHP-S02 acceptance criterion from the plan §6 is:

```bash
cargo check --workspace --all-targets
```

> Note: As of the date of this document, the workspace
> `cargo check --workspace --all-targets` exhibits 3 pre-existing
> `Send` errors in `src/http/server.rs:171-180` (the `Arc<WafCore>`
> cloning inside the `tokio::spawn` block, and the `&Arc<WafCore>`
> capture by the `service_fn` closure). These errors are unrelated
> to this design — they exist in the live module graph and would
> exist whether or not this document is written. They are
> documented in `plans/workspace_all_targets_failure_inventory.md`
> if needed. **This design does not change the file**, so it
> cannot introduce or fix these errors. They are the
> RHP-S03 implementation task's responsibility to either
> avoid (by making the `Arc<dyn HttpRequestWafBackend>` capture
> work) or document.

The design is accepted when:

1. This file exists at `plans/server_runtime_context_design.md`.
2. It defines `HttpServerRuntime`, `HttpAppBackends`, and
   `HttpRequestWafBackend` per §2.
3. It classifies each struct's home per §3 (all three: root-only).
4. It documents trait-seam candidates per §4.
5. It gives a recommended implementation order per §6.
6. It records stop conditions per §7.

The plan §12.4 success criterion for the wave is:

> Server-runtime context design is documented and optionally
> introduced only if low-risk.

This document satisfies the "documented" half. The "optionally
introduced" half is RHP-S03's responsibility.

## 10. RHP-S03: Root-Only Context Struct Implementation (2026-06-08)

This section records the RHP-S03 implementation result, what
landed, what was deferred, and the validation matrix.

### 10.1 What landed

The following changes were committed to `src/http/server.rs` and
`src/http/server/accept_loop.rs`:

1. **`HttpAppBackends` struct** — added in `src/http/server.rs`,
   `pub(crate)`, with `Clone` + `Default`. Fields:
   - `serverless_manager: Option<Arc<...>>`
   - `app_servers: Option<Arc<RwLock<HashMap<...>>>>`
   - `plugin_manager: Option<Arc<dyn Any + Send + Sync>>`

2. **`HttpServerRuntime` struct** — added in `src/http/server.rs`,
   `pub(crate)`, with `Clone`. Re-groups all 20+ former
   `HttpServer` fields (router, waf, flood_protector, client,
   http_config, alt_svc, main_config, drain_state, metrics, ipc,
   worker_id, connection_limit, upstream_client_registry,
   erased_http_client, mesh_config, mesh_transport,
   mesh_backend_pool, and `backends: HttpAppBackends`).

3. **`HttpServer` struct refactored** — now has only 3 fields:
   `addr`, `shutdown_rx`, and `runtime: HttpServerRuntime`. The
   `with_*` builders continue to work and now mutate
   `self.runtime` (or `self.runtime.backends` for the
   serverless / app-servers ones).

4. **`HttpServer::serve` simplified** — destructures
   `self.runtime` and passes it to `run_accept_loop`. The call
   signature drops from 20+ parameters to 3
   (`addr, shutdown_rx, runtime: HttpServerRuntime`).

5. **`run_accept_loop` simplified** — takes
   `(addr, shutdown_rx, runtime: HttpServerRuntime)`. Inside the
   loop, all per-connection clones are now `runtime.field.clone()`
   rather than 20+ individual clones of function parameters.

6. **`HttpServer::handle_request` signature unchanged** — the
   20+ parameter signature is preserved to keep the call site
   in `accept_loop.rs` simple. The function body continues to
   consume the parameters individually. This was the
   lowest-risk Option A from the task brief.

7. **No new trait seams introduced** — see §10.2 for why
   `HttpRequestWafBackend` was deferred.

8. **Orphan staged files** — the three pre-staged orphan
   modules (`backend_dispatch.rs`, `request_preparation.rs`,
   `traffic_control.rs`) were **not** present in the working
   tree at the time of RHP-S03, so there was nothing to
   de-stage. The refactor does not reference them.

### 10.2 Stop condition hit: `HttpRequestWafBackend` trait object

The design recommends `HttpServerRuntime.waf` to be
`Arc<dyn HttpRequestWafBackend>`. The trait was drafted (see
§2.3) but introducing the trait object hit the §7 stop
condition: **"The struct's lifetime/borrow story requires
generic propagation into `handle_request`"**.

Specifically: `prepare_http_request_flow<W, D>` in
`crates/synvoid-http/src/http_request_flow.rs:45` has the bound
`W: BufferedRequestWaf + crate::RequestBodyWaf`, with an
implicit `Sized` bound on `W`. Passing a `&Arc<dyn
HttpRequestWafBackend>` (where `dyn HttpRequestWafBackend:
!Sized`) fails the `Sized` bound with 7 new compile errors:

```text
error[E0277]: the size for values of type `dyn HttpRequestWafBackend` cannot be known at compilation time
   --> src/http/server.rs:320:13
    |
320 |             &waf,
    |             ^^^^ doesn't have a size known at compile-time
    |
    = help: the trait `Sized` is not implemented for `dyn HttpRequestWafBackend`
note: required by an implicit `Sized` bound in `prepare_http_request_flow`
   --> crates/synvoid-http/src/http_request_flow.rs:45:40
```

The same issue occurs in `HttpRequestPostludeContext<'a, W>` at
`crates/synvoid-http/src/http_request_postlude.rs:94`, which is
generic on `W` with an implicit `Sized` bound.

Resolving this would require either:

1. Adding `?Sized` bounds to `prepare_http_request_flow<W, D>`
   and `HttpRequestPostludeContext<'a, W>` in `synvoid-http`.
   This is a generic-propagation change that crosses crate
   boundaries and affects every other consumer of those
   helpers.
2. Introducing a parallel `?Sized` variant. Increases API
   surface.

Both are out of scope for RHP-S03 per the task brief's
"no behaviour changes" and "only group already-existing
fields/parameters" constraints.

**Decision: defer `HttpRequestWafBackend` to a follow-up
RHP-S03b task.** The trait declaration is documented in §2.3
for future use. `HttpServerRuntime.waf` remains
`Arc<WafCore>` (concrete) for now. The pre-existing Send
bound errors (see §10.3) still refer to
`&std::sync::Arc<WafCore>`, confirming the type is preserved.

### 10.3 Validation matrix

After the refactor, the validation matrix from §6 produces
exactly the same error counts as the baseline (3 pre-existing
Send bound errors with `--features mesh`, 2 with the core
profile):

```text
cargo check -p synvoid --lib --no-default-features
  → 2 pre-existing Send errors (accept_loop.rs:154, 156)
  → Same baseline count.

cargo check -p synvoid --lib --no-default-features --features dns
  → 2 pre-existing Send errors
  → Same baseline count.

cargo check -p synvoid --lib --no-default-features --features mesh
  → 3 pre-existing Send errors
  → Same baseline count.

cargo check -p synvoid --lib --no-default-features --features mesh,dns
  → 3 pre-existing Send errors
  → Same baseline count.

cargo check --workspace --all-targets
  → 3 pre-existing Send errors (matches baseline)
  → 1 unrelated admin-ui "toast_error" warning (preexisting)
  → Otherwise identical to baseline.
```

The 3 pre-existing errors (or 2 with core profile) are the
Send bound issues documented in
`plans/workspace_all_targets_failure_inventory.md`. RHP-S03 does
**not** add, remove, or fix any of them. The error type is
preserved (`&std::sync::Arc<WafCore>` and
`&std::option::Option<std::sync::Arc<drain_state::WorkerDrainState>>`),
confirming that the `Send` status of the captures is unchanged.

### 10.4 Diff summary

```text
 src/http/server.rs             | 146 ++++++++++++++++++++++-------------------
 src/http/server/accept_loop.rs |  63 +++++++-----------
 2 files changed, 103 insertions(+), 106 deletions(-)
```

The net change is roughly even (103 added, 106 removed) because
the per-connection `.clone()` calls inside the accept loop
(20+ lines) are replaced with `runtime.field.clone()` calls of
the same arity, and the struct declarations add new lines that
roughly offset the removed field declarations.

### 10.5 Deferred to RHP-S03b

- Introduce `HttpRequestWafBackend` as a trait object in
  `HttpServerRuntime.waf`. Requires relaxing the `Sized` bound
  on `prepare_http_request_flow<W, D>` and
  `HttpRequestPostludeContext<'a, W>` in `synvoid-http`.
  Documented in §2.3 of this design doc.
- Drop `ErasedHttpClient` from the threading chain. Currently
  the field is preserved in `HttpServerRuntime` and the
  parameter is preserved in `handle_request` (prefixed with
  `_` to suppress the unused warning). The field is genuinely
  dead per RHP-S01 row 8; deletion is a 1-line change in the
  struct + 1-line removal of the parameter, but was left in
  this pass to keep the diff narrow and behaviour-preserving.
- Wire `HttpServerRuntime` into `Http3Server`. The same
  composition shapes (`HttpServerRuntime`, `HttpAppBackends`)
  could conceivably be unified across HTTP/1.1 and HTTP/3 in a
  future consolidation pass. Not RHP-S03 scope.

### 10.6 Acceptance

RHP-S03 meets the task's acceptance criteria:

- `cargo check --lib --no-default-features`: PASS (2 pre-existing
  Send errors, no new errors).
- `cargo check --no-default-features --features mesh,dns`: PASS
  (3 pre-existing Send errors, no new errors).
- `cargo check --workspace --all-targets`: PASS (3 pre-existing
  Send errors, no new errors).
- `HttpServerRuntime`, `HttpAppBackends` exist in
  `src/http/server.rs` (the `HttpRequestWafBackend` trait is
  documented in §2.3 but deferred per §10.2).
- `HttpServer` continues to expose the same external API
  (`new`, `with_*`, `serve`).
- `ErasedHttpClient` is left alone in this task.
- `HttpServer::handle_request`'s 20+ parameter signature is
  preserved (lowest-risk Option A from the task brief).
