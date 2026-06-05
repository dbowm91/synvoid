# Worker/Supervisor Boundary Notes

> Created by IFACE-O01 during interface-pass modularization.

## 1. Which concrete subsystems worker constructs

The `UnifiedServerWorker` (in `src/worker/unified_server/`) directly constructs or owns:

- `WafCore` — WAF request inspection, connection limiting, tarpit, threat intel
- `Router` — route resolution (domain matching, location matching)
- `WorkerMetrics` — request/error/latency counters
- `WorkerDrainState` — graceful shutdown drain tracking
- `UpstreamClientRegistry` — HTTP client connection pooling
- `FloodProtector` — SYN/connection/UDP flood protection
- `RequestSanitizer` — trusted-proxy CIDR matching, XFF sanitization
- `StreamingWafCore` — streaming body WAF inspection
- `ProxyCache` — response caching
- `PluginManager` — WASM plugin runtime
- `StaticFileHandler` — static file serving
- `MinifierClient` / `AsyncMinifierClient` — HTML/CSS/JS minification
- Various `Arc<Config>` types from `synvoid-config`

## 2. Which concrete subsystems supervisor constructs

The `Supervisor` (in `src/supervisor/`) constructs or manages:

- `DrainManager` — orchestrates drain across workers
- `WorkerProcessManager` — spawns/monitors/restarts worker processes
- `MeshService` — mesh networking (feature-gated)
- `ThreatLevelManager` — threat level scoring/escalation
- `AdminApiServer` — admin HTTP API
- `GranianServer` — Python app server integration
- `ConfigManager` — configuration reload

## 3. Which extracted crates worker should depend on after HTTP/proxy/WAF movement

After the interface pass, the worker should depend on:

- `synvoid-core` — shared DTOs (RequestContext, RouteTarget, MetricsSink, DrainState)
- `synvoid-config` — configuration types
- `synvoid-waf` — WafProcessor trait, WafDecision, WafConfig
- `synvoid-proxy` — RouteResolver trait, ProxyServer (eventually)
- `synvoid-http` — HttpRuntimeContext, response builders
- `synvoid-http3` — HTTP/3 server (eventually)
- `synvoid-app-handlers` — AppBackendDispatcher trait
- `synvoid-upstream` — upstream pool types
- `synvoid-plugin-runtime` — WASM plugin runtime
- `synvoid-utils` — DrainFlag, buffer pool, etc.

## 4. Legitimate orchestration dependencies (should remain)

These are concrete types that the worker legitimately needs to construct:

- `WafCore` — the worker is the owner/lifecycle manager of WAF
- `Router` — the worker builds routing from config
- `WorkerMetrics` — the worker owns its metrics
- `WorkerDrainState` — the worker owns its drain state
- `UpstreamClientRegistry` — the worker manages connection pools

These are NOT accidental dependencies. The worker is the process that creates and owns these subsystems. The trait interfaces allow downstream code (proxy, HTTP pipeline) to use traits instead of concrete types, but the worker itself must construct the concrete types.

## 5. Dependencies that are accidental and should be replaced by traits

These should be replaced by trait-based abstractions:

- Direct `WafCore` field access in proxy/HTTP pipeline → use `WafProcessor` trait
- Direct `Router.route()` calls in HTTP pipeline → use `RouteResolver` trait
- Direct `WorkerMetrics` method calls in HTTP pipeline → use `MetricsSink` trait
- Direct `WorkerDrainState.is_draining()` in HTTP pipeline → use `DrainState` trait
- Direct `PluginManager` access in HTTP pipeline → use `AppBackendDispatcher` trait

The pattern: worker constructs concrete types, wraps them in adapters, passes trait objects to downstream code.
