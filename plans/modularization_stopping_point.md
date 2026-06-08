# SynVoid Modularization Stopping Point

> Status: final cleanup / stopping-point record.
> Purpose: document the current stable architecture after the modularization campaign, preserve the green validation baseline, and define when future modularization work should resume.

## 0. Summary

The modularization campaign is considered complete for now.

SynVoid has moved from a root-heavy monolith into a modular workspace with clear subsystem ownership, compatibility shims where needed, and a green validation baseline. Further crate splitting should stop unless driven by measured rebuild cost, a concrete feature need, or a specific dependency boundary problem.

This file is not a new implementation plan. It is a stopping-point record and a guardrail for future agents.

## 1. Current expected validation baseline

Before starting future structural work, preserve this baseline:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http
cargo check -p synvoid-http3
cargo check -p synvoid-upload
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

Expected result at stopping point:

```text
All pass. Warnings only are acceptable if already present and unrelated.
```

If any command fails later, treat that as validation drift and fix it before restarting architectural work.

## 2. Completed high-level outcomes

Completed outcomes:

```text
- root proxy is a compatibility shim over synvoid-proxy
- canonical ProxyServer lives in synvoid-proxy
- synvoid-http owns reusable HTTP request-flow, dispatch, streaming, WAF-decision, and response helpers
- src/http/server.rs remains root-owned intentionally
- src/http3/server.rs remains root-owned intentionally as QUIC composition
- Http3Server no longer stores concrete Arc<WafCore>
- Http3Server stores Arc<dyn Http3WafBackend>
- WafAccess is object-safe and narrow
- synvoid-static-files owns static-file helpers and image-rights marking
- image-rights terminology is canonical
- old image_poisoning names remain only as compatibility/wire/historical debt
- synvoid-upload owns upload/YARA scanning runtime
- synvoid-mesh owns distributed YARA rules manager and mesh/Raft surfaces
- dead duplicate root upload files are deleted
- root direct yara-x is removed
- upload submodule imports are direct to synvoid_upload where practical
- root dependency pruning removed known unused deps such as x509-parser, openraft-legacy, prost-build
- admin/schema ownership is explicitly classified as KEEP_ROOT_FOR_BINARY_EXPORT
- server-runtime context grouping was introduced in root
```

## 3. Current subsystem ownership map

### Root crate

Root owns composition, binaries, startup, and integration:

```text
src/main.rs
src/http/server.rs
src/http3/server.rs
src/waf/mod.rs / WafCore
src/worker/**
src/supervisor/**
src/admin/** root admin handlers and OpenAPI composer
src/startup/**
src/process/**
compatibility shims such as src/proxy/mod.rs and src/upload/mod.rs
```

This is intentional. Root is now a composition crate, not merely a dumping ground.

### Extracted subsystem crates

Current major owners:

```text
synvoid-core              shared request/routing/metrics/drain/streaming primitives
synvoid-config            config DTOs and serde compatibility
synvoid-waf               WAF primitives, traits, WafAccess, flood/traffic primitives
synvoid-proxy             canonical ProxyServer and proxy helpers
synvoid-http              reusable HTTP flow/dispatch/helper logic
synvoid-http3             HTTP/3 helper crate; server remains root-owned
synvoid-static-files      static-file helpers, minification, image-rights marking
synvoid-upload            upload validation, malware/YARA scanning, quarantine
synvoid-ipc               IPC messages and framing
synvoid-dns               DNS/DoH/DoQ/authoritative DNS surfaces
synvoid-mesh              mesh, DHT, distributed YARA rules, Raft remains here
synvoid-tls               TLS/ACME/cert support
synvoid-admin             partial admin/API support
synvoid-platform          platform helpers; socket bind helper re-exported here
synvoid-metrics           metrics helpers
synvoid-http-client       HTTP client stack and post-quantum/http-local ownership
synvoid-plugin-runtime    plugin/runtime support
synvoid-serverless        serverless support
synvoid-app-handlers      CGI/FastCGI/PHP/app handler support
synvoid-block-store       block store ownership
synvoid-tunnel            WireGuard/tunnel/VPN support
```

## 4. Explicit deferred decisions

These are intentionally deferred, not forgotten.

### HTTP server movement

Decision:

```text
KEEP_ROOT_AS_COMPOSITION_LAYER for now.
```

Reason:

```text
src/http/server.rs wires WafCore, WorkerDrainState, metrics, IPC, app backends,
plugin manager, mesh cfg-gated state, HTTP client, upstream registry, and root
accept-loop orchestration. Moving it now would mostly move root composition into
another crate without removing complexity.
```

Future trigger:

```text
Revisit only if compile timings show src/http/server.rs or root HTTP runtime is a dominant hot path, or if a feature requires a reusable standalone HTTP server crate.
```

### HTTP/3 server movement

Decision:

```text
KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER.
```

Resolved blockers:

```text
- WAF trait-object storage is complete: Arc<dyn Http3WafBackend>
- WorkerDrainState removed from Http3Server
- bind_udp_reuse is re-exported via synvoid-platform
```

Remaining preconditions before moving:

```text
1. WafCore extracted to synvoid-waf, or HTTP/3 construction no longer depends on root-created WafCore value.
2. handle_http3_request_dispatch signature changed from generic Waf parameter to &dyn Http3RequestWaf if that still simplifies the call site.
3. QUIC dependency declarations unified between root and synvoid-http3.
```

Until all three are true, moving the file is not worth it.

### WafCore extraction

Decision:

```text
DEFER.
```

Reason:

```text
WafCore remains a high-level root integration object over auth, block store,
challenge manager, GeoIP, request services, streaming WAF, metrics, and threat
tracking. Many interfaces exist now, but full movement is still cross-cutting.
```

Future trigger:

```text
Revisit only if WAF iteration still forces root builds frequently or if root WAF dependencies block another concrete feature.
```

### Worker/supervisor extraction

Decision:

```text
DEFER / probably keep root-owned.
```

Reason:

```text
Worker and supervisor are legitimate orchestration layers. Moving them would likely
produce god traits or simply move composition elsewhere.
```

Future trigger:

```text
Revisit only if there is a planned daemon/frontend split or if worker runtime is reused outside root.
```

### Mesh/Raft split

Decision:

```text
DEFER; keep Raft inside synvoid-mesh.
```

Reason:

```text
Raft is still fused to mesh transport and mesh trust/distribution concerns.
Splitting it without a proven ConsensusTransport boundary would add churn.
```

Future trigger:

```text
Revisit only after a small internal mesh ConsensusTransport trait exists and is stable.
```

### Admin/schema ownership

Decision:

```text
KEEP_ROOT_FOR_BINARY_EXPORT.
```

Reason:

```text
The root binary owns --export-openapi and --export-api-spec. The OpenAPI composer
is root-owned and crosses admin, mesh, WAF, config, and site subsystems.
```

Future trigger:

```text
Run cargo build --timings. If utoipa/schemars macro expansion dominates root compile time,
reopen the decision and consider moving more schema generation into synvoid-admin.
```

## 5. Compatibility shims to keep

Do not remove these without a dedicated compatibility-removal pass:

```text
src/proxy/mod.rs                  re-export shim over synvoid-proxy
src/upload/mod.rs                 re-export shim over synvoid-upload
src/http/image_poisoning.rs       deprecated compatibility shim
crates/synvoid-static-files/src/image_poisoning.rs deprecated compatibility shim
SiteImagePoisonConfig             deprecated compatibility alias
old image_poison serde alias      config compatibility
IPC PoisonImage wire names        protocol compatibility debt
```

These are intentional compatibility surfaces, not accidental leftovers.

## 6. Future work trigger policy

Future structural work should start only if one of these is true:

```text
1. cargo build --timings identifies a concrete hot path.
2. a feature requires a reusable subsystem outside root.
3. a root dependency blocks a target profile or feature set.
4. a compatibility shim becomes unnecessary and can be removed safely.
5. a workspace validation failure appears and must be corrected.
```

Otherwise, do not split more crates.

## 7. Recommended future measurement task

If more work is desired later, the first task should be measurement, not movement.

Run:

```bash
cargo build --timings
cargo check -p synvoid
cargo check --workspace --all-targets
cargo check -p synvoid-http
cargo check -p synvoid-waf
cargo check -p synvoid-proxy
cargo check -p synvoid-mesh --features mesh
```

Then update:

```text
plans/compile_time_measurements.md
plans/root_dependency_ownership.md
plans/next_modularization_recommendation.md
```

Focus questions:

```text
- Does root still dominate common iteration?
- Are utoipa/schemars compile costs material?
- Is HTTP server runtime a hot path?
- Is mesh/Raft compile time significant enough to justify a ConsensusTransport investigation?
- Are any root dependencies now unused after recent pruning?
```

## 8. Guardrails for future agents

Use this prompt for future structural work:

```text
You are working after the SynVoid modularization stopping point recorded in plans/modularization_stopping_point.md. Preserve the green validation baseline. Do not create new crates or move root-owned composition layers unless compile measurements or a concrete feature justify it. Prefer small dependency pruning, compatibility maintenance, and targeted trait seams. If validation fails, stop and fix validation drift before continuing.
```

## 9. Stopping-point success criteria

This stopping point is valid if:

```text
1. full validation remains green
2. root remains a deliberate composition crate
3. extracted subsystem crates own their canonical runtime logic
4. compatibility shims are documented and intentional
5. deferred items have explicit revisit triggers
6. future work is measurement-driven rather than aesthetic crate splitting
```

At this point, the modularization campaign should be considered complete.
