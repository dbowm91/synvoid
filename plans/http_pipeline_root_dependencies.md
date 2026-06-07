# HTTP Pipeline Root Dependencies

> Generated: 2026-06-07
> Purpose: Record which root HTTP/server/worker modules still depend on concrete root types and which trait-based replacements already exist.

## Legend

- `Yes`: the file already uses the trait-based replacement or can be updated without structural work
- `Partial`: the replacement exists, but the file still carries concrete root types
- `No`: the file still depends on concrete root types and should not be moved yet

## Inventory

| File | Concrete root dependency | Existing trait replacement | Can change now? | Notes |
|---|---|---|---|---|
| `src/http/server.rs` | `WafCore`, `Router`, `WorkerMetrics`, `WorkerDrainState` | `synvoid_http::runtime::HttpRuntimeContext`, `RootWafProcessor`, `RouterRouteResolver`, `WorkerMetricsSink`, `WorkerDrainStateAdapter` | `No` | Main HTTP pipeline still owns concrete root types; the front-door ingress preamble and request postlude are now wrapper-oriented and delegate buffered WAF, backend dispatch, and the `fastcgi`/`php`, `cgi`, `spin`, `serverless`, `mesh`, `axum`, `static`, `upload`, and WASM branches into `synvoid-http`. |
| `src/http3/server.rs` | `WafCore`, `Router`, `WorkerMetrics`, `WorkerDrainState` | No direct `HttpRuntimeContext` wiring in this file yet | `No` | HTTP/3 server still uses concrete root request/runtime types, but request dispatch now delegates request resolution, the connection guard, the request prelude, body scan, WAF decisioning, terminal handling, and found-route dispatch into `synvoid-http` via shared resolver/stream traits. |
| `src/server/mod.rs` | `WafCore`, `Router`, `WorkerMetrics`, `WorkerDrainState` | `HttpRuntimeContext` plus `RootWafProcessor`, `RouterRouteResolver`, `WorkerMetricsSink`, `WorkerDrainStateAdapter` | `Yes` | Boundary wiring is already complete here; this is the canonical example of the trait-based composition path. |
| `src/worker/unified_server/mod.rs` | `WorkerMetrics`, `WorkerDrainState` | `WorkerMetricsSink`, `WorkerDrainStateAdapter` | `Yes` | Provider side only; it constructs the runtime state that `src/server/mod.rs` consumes. |
| `src/tls/server.rs` | `WafCore` (via `RootWafProcessor`), `ProxyServer`, `WorkerDrainState` | `synvoid_proxy::ProxyServer`, `RootWafProcessor` | `Partial` | Uses the extracted proxy through the root compatibility alias; not part of the main HTTP pipeline boundary. |

## Summary

- The trait adapters needed for the root/server boundary already exist.
- `src/server/mod.rs` is already constructing `HttpRuntimeContext`.
- The remaining concrete dependencies are concentrated in `src/http/server.rs` and `src/http3/server.rs`.
- In `src/http3/server.rs`, the request resolution, connection guard, request prelude, body scan, WAF decisioning, terminal response handling, and found-route dispatch are now extracted behind `synvoid-http`; the root file is now just transport glue and tracing.
- Within `src/http/server.rs`, the remaining root-specific work is orchestration and wrapper glue; the streaming request pass helper, request postlude, backend-dispatch coordinator, and concrete branch handlers are all behind `synvoid-http` shims.
