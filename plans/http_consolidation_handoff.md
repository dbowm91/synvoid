# SynVoid HTTP Consolidation Handoff Plan

> Status: proposed next-pass handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: consolidate the partially extracted `synvoid-http` crate, reduce root `src/http` duplication, preserve runtime behavior, and prepare for eventual main HTTP server and HTTP/3 migration.

## 0. Current state

Proxy consolidation has succeeded. Root `src/proxy/mod.rs` is now a compatibility shim over `synvoid-proxy`, and the authoritative `ProxyServer<W: WafProcessor>` lives in `crates/synvoid-proxy/src/server.rs`.

HTTP is now the main remaining data-plane extraction target. The extracted `synvoid-http` crate has grown substantially and owns many request-flow, backend-dispatch, WAF-dispatch, HTTP/3-flow helper, streaming, response, and validation modules.

Root `src/http/mod.rs` still declares many modules directly, including modules that likely now have extracted equivalents in `synvoid-http`. Root still also owns the main HTTP server and several root-specific feature surfaces.

Current rough split:

```text
crates/synvoid-http
  owns many reusable HTTP helper/flow modules:
    app_server_backend_dispatch
    axum_dynamic_dispatch
    backend_dispatch
    body_policy
    buffered_request_waf_dispatch
    cgi_backend_dispatch
    challenge_paths
    early_parse
    fastcgi_php_backend_dispatch
    headers
    http3_* helper modules
    http_request_flow
    http_request_postlude
    internal_endpoint_dispatch
    internal_handlers
    listener
    mesh_backend_dispatch
    request_frontdoor
    request_parse
    request_preparation
    response_builder
    response_helpers
    response_transform
    runtime
    serverless_backend_dispatch
    shared_handler
    special_request_paths
    spin_backend_dispatch
    static_backend_dispatch
    streaming_request_fast_path
    streaming_request_pass
    streaming_waf_decision
    streaming_waf_upstream_dispatch
    traffic_control
    upload_validation_dispatch
    upstream_* dispatch/transform modules
    validation_helpers
    waf_decision
    wasm_filter_dispatch
    websocket_dispatch
    websocket_upgrade_dispatch

root src/http
  still declares direct modules:
    app_server_backend_dispatch
    axum_dynamic_dispatch
    body_policy
    buffered_request_waf_dispatch
    cgi_backend_dispatch
    challenge_paths
    directory_viewer
    early_parse
    fastcgi_php_backend_dispatch
    file_manager
    file_manager_ui
    headers
    image_poisoning
    internal_endpoint_dispatch
    internal_handlers
    mesh_backend_dispatch
    request_parse
    response_builder
    response_helpers
    response_transform
    server
    serverless_backend_dispatch
    shared_handler
    special_request_paths
    spin_backend_dispatch
    static_backend_dispatch
    streaming_request_fast_path
    streaming_waf_decision
    streaming_waf_upstream_dispatch
    upload_validation_dispatch
    upstream_buffered_dispatch
    upstream_proxy_dispatch
    upstream_proxy_dispatch_plan
    upstream_response_transform
    upstream_streaming_dispatch
    validation_helpers
    waf_decision
    wasm_filter_dispatch
    webdav
    websocket_dispatch
    websocket_upgrade_dispatch
```

This pass should not create new crates. It should consolidate root HTTP modules into compatibility shims where the extracted implementation already exists.

## 1. Primary objective

Make root `src/http` look more like root `src/proxy`:

```rust
//! Compatibility shim for the extracted synvoid-http crate.

pub use synvoid_http::*;

// Only root-specific modules remain here temporarily.
pub mod server;
pub mod directory_viewer;
pub mod file_manager;
pub mod file_manager_ui;
pub mod image_poisoning;
pub mod webdav;
```

The exact final shape may differ, but the rule is:

```text
If a module has a complete equivalent in synvoid-http, root should re-export it rather than duplicate it.
If a module still depends on root-only server/worker/supervisor state, keep it in root and document why.
```

## 2. Hard constraints

1. Do not create new crates in this pass.
2. Do not move worker or supervisor.
3. Do not move HTTP/3 server yet.
4. Do not move root `src/http/server.rs` until concrete root imports are resolved.
5. Do not move root-only UI/file/WebDAV modules unless their dependencies are clearly trait-clean.
6. Do not add dependencies from `synvoid-http` back to root `synvoid`.
7. Prefer compatibility shims over behavior rewrites.
8. Preserve public import paths where practical.
9. Preserve behavior. This is consolidation, not semantic redesign.
10. Keep task diffs small enough for smaller agents.

## 3. Validation matrix

After each task, run the task-specific checks. After each wave, run:

```bash
cargo fmt
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
```

If full workspace clippy is too noisy, use targeted clippy:

```bash
cargo clippy -p synvoid-http --all-targets -- -D warnings
cargo clippy -p synvoid --lib -- -D warnings
```

## 4. Wave H0: inventory root/extracted HTTP overlap

### Task HTC-H00: generate HTTP module overlap matrix

Create:

```text
plans/http_module_overlap_matrix.md
```

Compare module names in:

```text
src/http/mod.rs
crates/synvoid-http/src/lib.rs
```

Create a table:

```text
Module | Exists in root? | Exists in synvoid-http? | Root imports concrete root state? | Action | Notes
```

Action values:

```text
REEXPORT_SHIM_NOW
KEEP_ROOT_ONLY
MOVE_TO_SYNVOID_HTTP
VERIFY_PARITY
DELETE_ROOT_DUPLICATE
UNKNOWN_INVESTIGATE
```

Initial expected categories:

Likely `REEXPORT_SHIM_NOW` or `VERIFY_PARITY`:

```text
app_server_backend_dispatch
axum_dynamic_dispatch
body_policy
buffered_request_waf_dispatch
cgi_backend_dispatch
challenge_paths
early_parse
fastcgi_php_backend_dispatch
headers
internal_endpoint_dispatch
internal_handlers
mesh_backend_dispatch
request_parse
response_builder
response_helpers
response_transform
serverless_backend_dispatch
shared_handler
special_request_paths
spin_backend_dispatch
static_backend_dispatch
streaming_request_fast_path
streaming_waf_decision
streaming_waf_upstream_dispatch
upload_validation_dispatch
upstream_buffered_dispatch
upstream_proxy_dispatch
upstream_proxy_dispatch_plan
upstream_response_transform
upstream_streaming_dispatch
validation_helpers
waf_decision
wasm_filter_dispatch
websocket_dispatch
websocket_upgrade_dispatch
```

Likely `KEEP_ROOT_ONLY` for now:

```text
server
directory_viewer
file_manager
file_manager_ui
image_poisoning
webdav
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

## 5. Wave H1: convert root duplicate modules into shims

Purpose: eliminate duplicate source ownership without moving the main server.

### Task HTC-H01: convert low-risk parser/header/response modules to shims

Target files likely:

```text
src/http/early_parse.rs
src/http/headers.rs
src/http/request_parse.rs
src/http/response_builder.rs
src/http/response_helpers.rs
src/http/response_transform.rs
src/http/validation_helpers.rs
```

For each module where parity is confirmed, replace the root file with:

```rust
pub use synvoid_http::<module_name>::*;
```

Do not delete files unless the module is removed from `src/http/mod.rs`; shims are safer for public path stability.

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If a root module has extra root-only functions not present in `synvoid-http`, do not overwrite it. Mark it `VERIFY_PARITY` in `plans/http_module_overlap_matrix.md`.

### Task HTC-H02: convert WAF/body/request-flow helper modules to shims

Target files likely:

```text
src/http/body_policy.rs
src/http/buffered_request_waf_dispatch.rs
src/http/challenge_paths.rs
src/http/request_preparation.rs if present
src/http/streaming_request_fast_path.rs
src/http/streaming_waf_decision.rs
src/http/waf_decision.rs
```

Use shim pattern:

```rust
pub use synvoid_http::<module_name>::*;
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If the root module still imports concrete `crate::waf::WafCore` or root-only request services while the extracted version does not fully replace it, keep root module temporarily and update the matrix.

### Task HTC-H03: convert backend dispatch modules to shims

Target files likely:

```text
src/http/app_server_backend_dispatch.rs
src/http/axum_dynamic_dispatch.rs
src/http/cgi_backend_dispatch.rs
src/http/fastcgi_php_backend_dispatch.rs
src/http/internal_endpoint_dispatch.rs
src/http/mesh_backend_dispatch.rs
src/http/serverless_backend_dispatch.rs
src/http/spin_backend_dispatch.rs
src/http/static_backend_dispatch.rs
src/http/upload_validation_dispatch.rs
src/http/wasm_filter_dispatch.rs
src/http/websocket_dispatch.rs
src/http/websocket_upgrade_dispatch.rs
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If a backend dispatch root module depends on root-only app/file/plugin/server state not represented in `synvoid-http`, keep it and record the exact blocker in the matrix.

### Task HTC-H04: convert upstream dispatch modules to shims

Target files likely:

```text
src/http/streaming_waf_upstream_dispatch.rs
src/http/upstream_buffered_dispatch.rs
src/http/upstream_proxy_dispatch.rs
src/http/upstream_proxy_dispatch_plan.rs
src/http/upstream_response_transform.rs
src/http/upstream_streaming_dispatch.rs
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If the root module still depends on root `crate::proxy::ProxyServer` in a way not compatible with the extracted proxy type, update imports to use the root proxy type alias or `synvoid_proxy::ProxyServer`. Do not reintroduce concrete `WafCore`.

### Task HTC-H05: simplify root `src/http/mod.rs`

After H01-H04, simplify `src/http/mod.rs` to re-export `synvoid_http` broadly while keeping root-only modules explicit.

Preferred shape:

```rust
pub use synvoid_http::*;

pub mod directory_viewer;
pub mod file_manager;
pub mod file_manager_ui;
pub mod image_poisoning;
pub mod server;
pub mod webdav;

pub use server::HttpServer;
```

If public path stability requires module shims, keep lines such as:

```rust
pub mod request_parse;
pub mod response_builder;
```

but those files should contain only:

```rust
pub use synvoid_http::request_parse::*;
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

Stop condition:

If simplifying `mod.rs` breaks many imports, keep explicit shim modules and do not collapse `mod.rs` yet.

## 6. Wave H2: root-only HTTP module classification

Purpose: avoid vague “root owns HTTP” state by documenting each remaining root-only module.

### Task HTC-H06: inventory root-only HTTP modules

Create:

```text
plans/http_root_only_modules.md
```

For each remaining root-only module, document:

```text
Module | Why root-owned | Root dependencies | Candidate target crate | Next seam needed | Priority
```

Initial modules to classify:

```text
src/http/server.rs
src/http/directory_viewer.rs
src/http/file_manager.rs
src/http/file_manager_ui.rs
src/http/image_poisoning.rs
src/http/webdav.rs
```

Candidate target crates:

```text
synvoid-http
synvoid-static-files
synvoid-upload
synvoid-theme
synvoid-admin
root-only for now
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task HTC-H07: decide file-manager/image/webdav ownership

Update `plans/http_root_only_modules.md` with a decision:

```text
file_manager/file_manager_ui -> likely synvoid-admin or root-only admin surface
image_poisoning -> likely synvoid-upload or static-files/security image pipeline
webdav -> likely synvoid-static-files or app-handlers
```

Do not move code in this task. This is a boundary decision task.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 7. Wave H3: main HTTP server readiness check

Purpose: determine whether `src/http/server.rs` can move soon or must stay root-owned.

### Task HTC-H08: inventory `src/http/server.rs` concrete root dependencies

Create or update:

```text
plans/http_server_dependency_inventory.md
```

Run searches:

```bash
rg "crate::waf::WafCore|WafCore" src/http/server.rs
rg "crate::router::Router|Router" src/http/server.rs
rg "crate::worker|WorkerMetrics|WorkerDrain|WorkerDrainState" src/http/server.rs
rg "crate::supervisor|crate::server|crate::startup" src/http/server.rs
rg "crate::proxy::ProxyServer|synvoid_proxy::ProxyServer" src/http/server.rs
rg "crate::http::" src/http/server.rs
```

Record:

```text
Concrete dependency | Location | Existing trait/seam | Can replace now? | Required adapter | Notes
```

Existing seams to prefer:

```text
WafCore -> synvoid_waf::traits::WafProcessor / RootWafProcessor
Router -> synvoid_proxy::routing::RouteResolver / RouterRouteResolver
WorkerMetrics -> synvoid_core::metrics::MetricsSink
WorkerDrainState -> synvoid_core::drain::DrainState
ProxyServer -> synvoid_proxy::ProxyServer or root proxy alias
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task HTC-H09: replace obvious concrete imports in `src/http/server.rs`

Only do replacements that are already supported by existing adapters and do not require broad generic rewrites.

Examples:

```text
crate::proxy::ProxyServer -> synvoid_proxy::ProxyServer or root alias
crate::proxy::* helpers -> synvoid_proxy::* helpers
crate::http::<module>::* -> synvoid_http::<module>::* where module has moved
```

Do not move `server.rs` yet.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If replacing WafCore/Router/WorkerMetrics requires generifying the entire `HttpServer`, stop and record the blocker. That should be a separate server-runtime context pass.

### Task HTC-H10: decide whether to move `src/http/server.rs`

Update `plans/http_server_dependency_inventory.md` with one of these decisions:

```text
MOVE_NOW
KEEP_ROOT_UNTIL_WORKER_CONTEXT_REWORK
KEEP_ROOT_UNTIL_HTTP3_REWORK
KEEP_ROOT_AS_COMPOSITION_LAYER
```

Do not move code in this task.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 8. Wave Q: HTTP/3 blocker follow-through

Purpose: turn the updated HTTP/3 blocker note into actionable tasks without moving HTTP/3 prematurely.

### Task HTC-Q01: inventory `src/http3/server.rs` concrete root dependencies

Create:

```text
plans/http3_server_dependency_inventory.md
```

Search:

```bash
rg "WafCore|Router|WorkerMetrics|WorkerDrainState|UpstreamClientRegistry|HttpClient|FloodProtector|FloodDecision" src/http3/server.rs
rg "crate::" src/http3/server.rs
```

Record:

```text
Concrete dependency | Location | Existing seam | Missing seam | Action | Notes
```

Known existing seams:

```text
WafCore -> WafProcessor
Router -> RouteResolver
WorkerMetrics -> MetricsSink
WorkerDrainState -> DrainState
```

Known missing/unclear seams:

```text
UpstreamClientRegistry -> maybe use synvoid_proxy::UpstreamClientRegistry directly or define trait later
HttpClient -> maybe use synvoid_http_client::HttpClient directly
FloodProtector/FloodDecision -> maybe move/alias through synvoid-waf or define traffic-control trait
```

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
```

### Task HTC-Q02: update `crates/synvoid-http3/src/lib.rs` from inventory

Refresh the blocker note based on `plans/http3_server_dependency_inventory.md`.

Acceptance:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

### Task HTC-Q03: do not move HTTP/3 server yet unless dependencies are trait-clean

Guard task.

If `src/http3/server.rs` still imports concrete root worker/server/WAF/router state, leave it in root.

If all concrete imports are replaced with extracted crates or traits, move:

```text
src/http3/server.rs -> crates/synvoid-http3/src/server.rs
```

Acceptance if not moved:

```bash
cargo check --no-default-features --features mesh,dns
```

Acceptance if moved:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features mesh,dns
```

## 9. Wave R: root dependency cleanup after HTTP shims

Purpose: prune dependencies only after root HTTP modules no longer own the code that requires them.

### Task HTC-R01: update root dependency ownership matrix

Create or update:

```text
plans/root_dependency_ownership.md
```

Focus on dependencies affected by proxy/http extraction:

```text
hyper
hyper-util
hyper-rustls
tower
tower-http
axum
axum-extra
http-body
http-body-util
tokio-util
fastcgi-client
wasmtime
yara-x
lightningcss
minify-html
minify-js
brotli
walkdir
infer
maxminddb
rusqlite
metrics-exporter-prometheus
schemars
utoipa
utoipa-swagger-ui
quinn
h3
h3-quinn
```

Action categories:

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

### Task HTC-R02: prune root dependencies in small batches

Only remove dependencies marked `REMOVE_FROM_ROOT` or `FEATURE_FORWARD_ONLY` in the ownership matrix.

Rules:

```text
3-8 dependencies per commit maximum.
Do not combine pruning with module movement.
If removal causes broad unrelated failures, restore and mark KEEP_ROOT_FOR_NOW.
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo check --no-default-features --features mesh,dns
```

## 10. Explicitly deferred work

Do not do these in this pass:

```text
Do not move worker.
Do not move supervisor.
Do not split Raft/consensus from mesh.
Do not move WafCore into synvoid-waf.
Do not create new crates.
Do not move HTTP/3 before its dependency inventory says it is trait-clean.
Do not move src/http/server.rs before its dependency inventory says it is ready.
```

## 11. Recommended task order

Use this order:

```text
HTC-H00  generate HTTP module overlap matrix
HTC-H01  shim low-risk parser/header/response modules
HTC-H02  shim WAF/body/request-flow helper modules
HTC-H03  shim backend dispatch modules
HTC-H04  shim upstream dispatch modules
HTC-H05  simplify root src/http/mod.rs
HTC-H06  inventory root-only HTTP modules
HTC-H07  decide file-manager/image/webdav ownership
HTC-H08  inventory src/http/server.rs concrete dependencies
HTC-H09  replace obvious concrete imports in src/http/server.rs
HTC-H10  decide whether to move src/http/server.rs
HTC-Q01  inventory src/http3/server.rs concrete dependencies
HTC-Q02  update synvoid-http3 blocker note
HTC-Q03  defer or move HTTP3 based on dependency cleanliness
HTC-R01  update root dependency ownership matrix
HTC-R02  prune root dependencies in small batches
```

## 12. Subagent prompt template

Use this for smaller agents:

```text
You are implementing SynVoid HTTP consolidation task HTC-XX from plans/http_consolidation_handoff.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not add dependencies from extracted crates back to root synvoid. Prefer root compatibility shims over rewrites. Do not move worker, supervisor, WafCore, Raft, HTTP3 server, or root http/server.rs unless the task explicitly allows it. Run the task acceptance commands and report exact failures.
```

## 13. Success criteria

This pass is successful when:

```text
1. Root src/http no longer duplicates modules already owned by synvoid-http.
2. Root src/http/mod.rs is mostly a compatibility shim plus a small explicit root-only set.
3. Root-only HTTP modules are documented with target crate/seam decisions.
4. src/http/server.rs has a concrete dependency inventory and a move/defer decision.
5. HTTP3 has a concrete dependency inventory and an updated blocker note.
6. Root dependencies are pruned only after verified ownership changes.
7. Proxy consolidation remains intact.
8. Worker/supervisor/mesh remain stable.
```
