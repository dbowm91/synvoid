# SynVoid Remaining HTTP Runtime and Schema Path Plan

> Status: proposed next-path handoff after the workspace-green and HTTP/3 WAF trait-object passes.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: continue from the now-stable modular architecture by addressing the remaining root-owned HTTP/3 and HTTP runtime seams, while preserving the current green validation baseline.

## 0. Current state

The repo is now validation-clean and modularized enough that further work should be surgical.

Known-good baseline:

```text
cargo fmt                                                PASS
cargo check --lib --no-default-features                  PASS
cargo check --no-default-features --features dns         PASS
cargo check --no-default-features --features mesh        PASS
cargo check --no-default-features --features mesh,dns    PASS
cargo check -p synvoid-http                              PASS
cargo check -p synvoid-http3                             PASS
cargo check -p synvoid-upload                            PASS
cargo check --workspace --all-targets                    PASS
cargo test --workspace --no-run                          PASS
```

Major completed architecture work:

```text
- root proxy is a compatibility shim over synvoid-proxy
- canonical ProxyServer lives in synvoid-proxy
- synvoid-http owns most reusable HTTP request-flow/dispatch/helper logic
- synvoid-static-files owns static file/image-rights logic
- synvoid-upload owns upload/YARA scanning runtime
- root yara-x removed
- dead root upload duplicate files removed
- internal upload submodule imports now use synvoid_upload directly
- HTTP/3 no longer stores concrete Arc<WafCore>
- Http3Server now stores Arc<dyn Http3WafBackend>
- WafAccess is object-safe and narrow
```

Remaining root-owned surfaces:

```text
src/http/server.rs       main HTTP server and TCP accept loop
src/http3/server.rs      HTTP/3 server and QUIC accept loop
src/waf/mod.rs           WafCore and root WAF orchestration
src/worker/**            worker orchestration, drain state, CPU/offload wiring
src/supervisor/**        supervisor orchestration
src/admin/**             admin/OpenAPI/schema export surface
src/mesh/** / crates/synvoid-mesh  mesh and Raft remain together intentionally
```

This plan covers the remaining items that are plausibly worth working on next.

## 1. Strategic rule

Do not restart broad crate-splitting. The repo is already modular and green.

Proceed only when a task does at least one of these:

```text
1. removes a concrete root dependency from an otherwise movable subsystem
2. improves server/runtime context clarity
3. preserves or improves validation reliability
4. clarifies ownership of schema/admin/runtime surfaces
5. reduces accidental coupling without changing behavior
```

## 2. Non-goals

Do not do these in this pass:

```text
Do not create new crates unless a later inventory proves it is necessary.
Do not move src/http/server.rs in one step.
Do not move src/http3/server.rs unless all remaining blockers are explicitly resolved.
Do not move WafCore into synvoid-waf.
Do not move worker or supervisor.
Do not split Raft from mesh.
Do not change IPC wire names such as PoisonImage.
Do not remove image_poisoning compatibility shims.
Do not weaken the validation baseline.
```

## 3. Hard constraints

1. Preserve runtime behavior.
2. Keep every task small enough to review independently.
3. Run validation after each task.
4. If a change threatens the green workspace baseline, stop and document the blocker.
5. Prefer traits/adapters over moving orchestration code.
6. Prefer import cleanup and dependency-boundary clarification over broad rewrites.
7. Do not introduce dependencies from extracted crates back to root `synvoid`.
8. Do not make `synvoid-core` depend on heavy runtime crates.

## 4. Validation matrix

After each task, run task-specific checks.

At the end of each wave, run:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http
cargo check -p synvoid-http3
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

## 5. Wave H3: HTTP/3 remaining root blockers

Purpose: reduce or explicitly classify the remaining reasons `src/http3/server.rs` is still root-owned.

Current known state:

```text
- WAF coupling is solved: Http3Server.waf is Arc<dyn Http3WafBackend>.
- Remaining root-specific pieces include WorkerDrainState and platform UDP socket binding.
- The server remains root-owned for now.
```

### Task RHP-H301: refresh HTTP/3 root dependency inventory

Update:

```text
plans/http3_server_dependency_inventory.md
```

Inspect:

```text
src/http3/server.rs
crates/synvoid-http3/src/lib.rs
crates/synvoid-http/src/http3_request_dispatch.rs
crates/synvoid-http/src/http3_request_flow.rs
```

Run:

```bash
rg -n "crate::|WorkerDrainState|bind_udp_reuse|WafCore|Http3WafBackend|WafAccess" src/http3/server.rs crates/synvoid-http3 crates/synvoid-http/src/http3_*.rs
```

Record:

```text
Dependency | Current owner | Existing seam | Needed seam | Move blocker? | Notes
```

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

Do not change source code except the inventory.

### Task RHP-H302: decide whether WorkerDrainState needs an HTTP/3 seam

Inspect current `drain_state` usage in:

```text
src/http3/server.rs
src/worker/drain_state.rs
src/http/server/connection_types.rs
```

Determine whether HTTP/3 actually uses `WorkerDrainState` behavior or merely stores it.

Decision options:

```text
REMOVE_UNUSED_FIELD
USE_DRAINSTATE_TRAIT_OBJECT
KEEP_ROOT_ONLY_FOR_NOW
```

If the field is unused and no behavior depends on it, remove the field and builder method in a separate implementation task. If used, prefer a trait-object seam using `synvoid_core::drain::DrainState` or a narrow HTTP/3-specific drain trait.

Update:

```text
plans/http3_server_dependency_inventory.md
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task RHP-H303: implement WorkerDrainState decision if trivial

Only implement if RHP-H302 selects `REMOVE_UNUSED_FIELD` or a small trait-object change.

Allowed changes:

```text
- remove unused drain_state field and with_drain_state method from Http3Server if truly unused
- or change field to Option<Arc<dyn DrainState>> if call sites remain simple
```

Do not touch worker internals.

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

Stop condition:

If this propagates into worker/supervisor/server construction broadly, stop and document.

### Task RHP-H304: classify platform UDP binding seam

Inspect:

```text
src/platform/socket.rs
src/http3/server.rs
crates/synvoid-platform/src/**
```

Determine whether `bind_udp_reuse` should remain root-owned or move/re-export through `synvoid-platform`.

Decision options:

```text
MOVE_TO_SYNVOID_PLATFORM
REEXPORT_FROM_SYNVOID_PLATFORM
KEEP_ROOT_PLATFORM_FOR_NOW
```

Default recommendation:

```text
If synvoid-platform already owns related socket helpers, move or re-export bind_udp_reuse there. If not, keep root-owned and document.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task RHP-H305: implement platform UDP binding move only if low-risk

Only implement if RHP-H304 selects `MOVE_TO_SYNVOID_PLATFORM` or `REEXPORT_FROM_SYNVOID_PLATFORM` and the function is self-contained.

Expected shape:

```rust
// crates/synvoid-platform/src/socket.rs
pub fn bind_udp_reuse(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> { ... }

// root compatibility shim if needed
pub use synvoid_platform::socket::bind_udp_reuse;
```

Acceptance:

```bash
cargo check -p synvoid-platform
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
cargo check --workspace --all-targets
```

Stop condition:

If the platform function depends on root-only config/runtime state, keep it root-owned.

### Task RHP-H306: decide HTTP/3 server move readiness

Update:

```text
plans/http3_server_dependency_inventory.md
plans/next_modularization_recommendation.md
```

Decision options:

```text
MOVE_READY
KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER
KEEP_ROOT_UNTIL_PLATFORM_SOCKET_MOVE
KEEP_ROOT_UNTIL_DRAIN_SEAM
DEFER_LOW_VALUE
```

Recommended bias:

```text
Even if technically move-ready, keep src/http3/server.rs root-owned if it primarily wires QUIC endpoint setup, root shutdown, and platform sockets. Moving it should have a measured benefit, not just satisfy aesthetic modularity.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 6. Wave S: server-runtime context design

Purpose: reduce concrete parameter threading in HTTP server/request flow without moving the main server.

Current known issue:

```text
src/http/server.rs and synvoid-http helper functions pass many concrete services around:
router, WAF backend, metrics, drain, HTTP client, upstream registry, configs, plugin manager, serverless manager, app-server supervisor map, mesh pools, IPC logging, etc.
```

This wave should design and possibly introduce small context structs. Do not move the server yet.

### Task RHP-S01: refresh HTTP server dependency inventory after latest cleanup

Update:

```text
plans/http_server_dependency_inventory.md
```

Inspect:

```text
src/http/server.rs
src/http/server/accept_loop.rs
src/http/server/connection_types.rs
src/http/server/observability.rs
crates/synvoid-http/src/*request* crates/synvoid-http/src/*dispatch* crates/synvoid-http/src/*postlude*
```

Run:

```bash
rg -n "WorkerMetrics|WorkerDrainState|HttpClient|UpstreamClientRegistry|PluginManager|ServerlessManager|GranianSupervisor|MainConfig|HttpConfig|Arc<" src/http/server.rs src/http/server crates/synvoid-http/src
```

Record:

```text
Dependency | Passed where | Existing owner crate | Could belong in context? | Notes
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

### Task RHP-S02: design server-runtime context structs

Create or update:

```text
plans/server_runtime_context_design.md
```

Propose small structs, for example:

```rust
pub struct HttpServerRuntime {
    pub router: Arc<Router>,
    pub waf: Arc<dyn HttpRequestWafBackend>,
    pub metrics: Option<Arc<WorkerMetrics>>, // or trait if worthwhile
    pub drain: Option<Arc<dyn DrainState>>,
    pub client: HttpClient,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
}

pub struct HttpAppBackends {
    pub serverless: Option<Arc<ServerlessManager>>,
    pub app_servers: HashMap<String, Arc<GranianSupervisor>>,
    pub plugin_manager: Option<Arc<dyn Any + Send + Sync>>,
}
```

Do not implement yet. Classify whether each struct should live in:

```text
root only
synvoid-http
synvoid-core
```

Default recommendation:

```text
Keep structs in synvoid-http only if they do not depend on root-only types.
Keep root-only composition structs in root until worker/server boundaries stabilize.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task RHP-S03: introduce root-only context struct if low-risk

Only implement if RHP-S02 identifies a root-only context struct that reduces argument threading without crossing crate boundaries.

Target likely files:

```text
src/http/server.rs
src/http/server/*.rs
```

Rules:

```text
- no behavior changes
- no new crates
- no moving server.rs
- only group already-existing fields/parameters
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo check --workspace --all-targets
```

Stop condition:

If this requires generic propagation or lifetime redesign, document and defer.

### Task RHP-S04: decide whether a later server-runtime crate is justified

Update:

```text
plans/server_runtime_context_design.md
plans/next_modularization_recommendation.md
```

Decision options:

```text
KEEP_ROOT_RUNTIME_CONTEXT
MOVE_CONTEXT_TO_SYNVOID_HTTP
CREATE_SYNVOID_RUNTIME_API_LATER
DEFER_LOW_VALUE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 7. Wave A: admin/schema ownership cleanup

Purpose: clarify admin/OpenAPI/schema ownership without prematurely splitting schema crates.

### Task RHP-A01: refresh admin/schema ownership audit

Update or create:

```text
plans/admin_schema_ownership.md
```

Search:

```bash
rg -n "utoipa|ToSchema|OpenApi|schemars|JsonSchema|swagger|export-openapi|export-api-spec" src crates admin-ui Cargo.toml
```

Record:

```text
File | Current owner | Dependency | User-facing? | Candidate owner | Notes
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task RHP-A02: decide whether root schema deps remain justified

Update:

```text
plans/admin_schema_ownership.md
plans/root_dependency_ownership.md
plans/next_modularization_recommendation.md
```

Decision options:

```text
KEEP_ROOT_FOR_BINARY_EXPORT
MOVE_TO_SYNVOID_ADMIN
FEATURE_GATE_SCHEMA_DERIVES
CREATE_SYNVOID_SCHEMA_LATER
DEFER_LOW_VALUE
```

Default recommendation:

```text
Keep root schema export if it is used only by binary flags such as --export-openapi / --export-api-spec and does not dominate compile timing. Move only if measurements show schemars/utoipa are a hot path.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task RHP-A03: cleanup stale schema imports only

Only replace imports where extracted crates already own the item.

Do not move schema definitions.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 8. Wave R: root dependency ownership refresh

Purpose: keep dependency ownership accurate after the last passes.

### Task RHP-R01: refresh root dependency ownership matrix

Update:

```text
plans/root_dependency_ownership.md
```

Focus on dependencies still in root:

```text
hyper / hyper-util / hyper-rustls
tower / tower-http
axum / axum-extra
rusqlite
tokio-rustls / rustls / x509-parser / aws-lc-rs
quinn / h3 / h3-quinn
schemars / utoipa / utoipa-swagger-ui / prost / prost-build
openraft / openraft-legacy
libloading
walkdir / flate2 / tar
tempfile / sha2 if root-only or dev-only
```

For each, classify:

```text
KEEP_ROOT_FOR_NOW
REMOVE_FROM_ROOT
MOVE_TO_EXISTING_CRATE
FEATURE_FORWARD_ONLY
UNKNOWN_INVESTIGATE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task RHP-R02: prune only obviously unused dependencies

Only remove root dependencies marked `REMOVE_FROM_ROOT` by RHP-R01.

Rules:

```text
1-3 dependencies per commit
no code movement in same commit
if removal fails, restore and mark KEEP_ROOT_FOR_NOW
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

## 9. Wave F: final validation and next recommendation

### Task RHP-F01: run final validation matrix

Run:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

Update:

```text
plans/workspace_all_targets_failure_inventory.md
plans/next_modularization_recommendation.md
```

Acceptance:

All commands pass, or any failure is documented with exact cause and whether it was introduced by this pass.

### Task RHP-F02: update next-path recommendation

Update:

```text
plans/next_modularization_recommendation.md
```

Include:

```text
- HTTP/3 move-readiness decision
- server-runtime context decision
- admin/schema ownership decision
- root dependency pruning results
- whether broader modularization should remain deferred
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 10. Recommended task order

Use this exact order:

```text
RHP-H301  refresh HTTP/3 root dependency inventory
RHP-H302  decide whether WorkerDrainState needs an HTTP/3 seam
RHP-H303  implement WorkerDrainState decision if trivial
RHP-H304  classify platform UDP binding seam
RHP-H305  implement platform UDP binding move only if low-risk
RHP-H306  decide HTTP/3 server move readiness
RHP-S01   refresh HTTP server dependency inventory
RHP-S02   design server-runtime context structs
RHP-S03   introduce root-only context struct if low-risk
RHP-S04   decide whether a later server-runtime crate is justified
RHP-A01   refresh admin/schema ownership audit
RHP-A02   decide whether root schema deps remain justified
RHP-A03   cleanup stale schema imports only
RHP-R01   refresh root dependency ownership matrix
RHP-R02   prune only obviously unused dependencies
RHP-F01   run final validation matrix
RHP-F02   update next-path recommendation
```

## 11. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid remaining HTTP/runtime/schema task RHP-XX from plans/remaining_http_runtime_and_schema_path.md.
Scope is limited to this task. Preserve behavior. Do not create new crates unless a task explicitly instructs it. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code unless this task explicitly allows it. Keep the workspace-green baseline intact. Prefer inventories, small trait/object seams, root-only context grouping, import cleanup, and dependency ownership updates over broad rewrites. Run the task acceptance commands and report exact failures.
```

## 12. Success criteria

This pass is successful when:

```text
1. HTTP/3 remaining root blockers are current and classified.
2. WorkerDrainState HTTP/3 usage is either removed, trait-backed, or explicitly kept root-owned.
3. Platform UDP binding ownership is decided.
4. Server-runtime context design is documented and optionally introduced only if low-risk.
5. Admin/schema ownership is refreshed.
6. Root dependency ownership is current.
7. Workspace validation remains green.
8. The next recommendation is evidence-based and avoids broad crate-splitting by default.
```
