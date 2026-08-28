# SynVoid Architecture Overview

SynVoid is a high-performance, multi-process Web Application Firewall (WAF) and reverse proxy written in Rust. It provides Layer 7 request filtering, attack detection, load balancing, TLS termination, and optional mesh networking — designed for 1M+ RPS with millions of tenants.

**Key Capabilities:**
- Layer 7 WAF with **16 attack detectors**, normalization (incl. overlong UTF-8), bot detection, rate limiting, anomaly scoring, traffic shaping
- Reverse proxy with **6 load-balancing algorithms** (RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash), retries/backoff, circuit breaking, response caching
- TLS termination with ACME (HTTP-01/DNS-01), SNI peeking, JA4 fingerprinting, post-quantum-preferred rustls
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC); WebSocket; WebDAV; FastCGI/CGI/PHP; Granian (Python ASGI/RSGI/WSGI); static files
- WASM plugin/serverless runtime (wasmtime-based) with trust tiers, capabilities, ABI frames, instance pooling
- Mesh networking with DHT, Raft consensus, trust domains, hybrid Ed25519+ML-DSA-44 signatures, ML-KEM-768 KEM
- Authoritative + recursive DNS with DNSSEC signing/validation, DoT/DoH/DoQ, TSIG, RPZ, dynamic updates
- Multi-platform OS abstraction and process sandboxing (Linux, macOS, BSDs, Windows)

---

## Repository Layout

```
synvoid/
├── src/                    # Root crate (binary + library): composition roots + legacy facades
├── crates/                 # 37 dedicated synvoid-* library crates
├── pqc/                    # Post-quantum crypto (ML-KEM-768/1024, ML-DSA-44)
├── admin-ui/               # Yew/WASM admin frontend (Trunk build)
├── tools/                  # xtask runner + repo-guard helpers
├── fuzz/                   # 17 fuzz targets
├── examples/               # dynamic-plugin, embedded-app, dns examples
├── architecture/           # This documentation tree (~125 docs)
├── .opencode/skills/       # Per-subsystem skill guides (32)
├── docs/                   # User/operator docs, testing contracts, releasing
├── plans/                  # Implementation tracking artifacts
├── proto/                  # Protobuf definitions (gRPC control plane)
├── config/                 # Default configuration (main.toml + sites/)
├── rules/                  # WAF rules
└── scripts/                # CI/build scripts
```

**Workspace**: 44 members — root app, 36 `synvoid-*` crates, `pqc`, `admin-ui`, 2 examples, `fuzz`, `tools/{xtask,synvoid-repo-guards}`.

Binaries: `synvoid` (`src/main.rs`, the supervisor/worker entry), plus standalone `synvoid-vpn` and a reserved VPN-dashboard `server` binary under `src/bin/`.

---

## Process Architecture

Two-tier model: a Supervisor-owned control plane and a data plane built around one UnifiedServerWorker plus bounded CPU offload workers. Workers are NOT process-per-tenant.

```
┌─────────────────────────────────────────────────────┐
│                   Supervisor Process                 │
│  • Zero-downtime upgrades (drain protocol)          │
│  • Worker lifecycle management                      │
│  • gRPC control-plane API                           │
│  • Mesh agent mode                                  │
│  • IPC orchestrator                                 │
└──────────┬──────────────────────────────────────────┘
           │ IPC (Unix domain socket, HMAC-signed messages)
           ▼
┌──────────────────────────────┐
│    UnifiedServerWorker       │
│  • HTTP/HTTPS/HTTP3          │
│  • WAF pipeline              │
│  • Routing and proxy path    │
│  • Cheap request-path work   │
└──────────┬───────────────────┘
           │ bounded IPC task offload
           ▼
┌──────────────────────────────┐
│    CPU Offload Worker        │
│  • minify/compress           │
│  • image transforms          │
│  • YARA scanning             │
│  • WASM execution            │
└──────────┬───────────────────┘
           ▼
┌──────────────────────────────┐
│         Upstream Apps        │
│  • Static Files              │
│  • PHP-FPM / FastCGI / CGI   │
│  • Granian (ASGI/RSGI/WSGI)  │
│  • WASM Serverless / Spin    │
│  • QUIC/WireGuard tunnels    │
└──────────────────────────────┘
```

| Process | Flag | Purpose | Default |
|---------|------|---------|---------|
| **Supervisor** | (default) | Control plane, lifecycle, gRPC API | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Latency-sensitive HTTP/HTTPS/HTTP3 + WAF + proxy | 1 |
| **CPU Offload Worker** | `--cpu-worker` | Bounded heavy transforms | 1 |
| **BaseWorkerProcess** | `--worker` | Legacy raw TCP/UDP worker (deprecated for HTTP) | — |

Deep dives: [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) · [`worker_deep_dive.md`](./worker_deep_dive.md) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md)

---

## Request Flow

```
Client ──► TLS Termination ──► HTTP Server ──► WAF Pipeline ──► Proxy Dispatch ──► Upstream Pool ──► Backend
                                     │               │              │
                                     │          ┌────▼────┐    ┌────▼─────┐
                                     │          │ Attack  │    │ WASM     │
                                     │          │Detection│    │ Filters  │
                                     │          │ Bot Det.│    │(plugin/  │
                                     │          │ Rate Lim│    │serverless│
                                     │          └─────────┘    └──────────┘
                                     │
                               ┌─────▼──────┐
                               │ Static File │
                               │ FastCGI/PHP │
                               │ CGI         │
                               │ Spin/WASM   │
                               └─────────────┘
```

### HTTP Pipeline (7 Stages)

Every request flows through `synvoid-http`'s staged pipeline ([`http_request_pipeline.md`](./http_request_pipeline.md)):

1. **Metadata Normalization** (`request_frontdoor.rs`) — client IP sanitization, internal endpoint dispatch, mesh special paths
2. **Route Resolution** (`request_preparation.rs`) — domain/path matching, connection limits, early WAF decision, WebSocket upgrade validation
3. **Body Policy** (`body_policy.rs`) — body collection; chunked WAF scanning for large bodies (64KB chunks, 256KB threshold, 1MB cap)
4. **WAF Evaluation** (`waf_decision.rs`) — full attack detection, anomaly scoring, bot detection, challenge/tarpit/stall decisions
5. **Terminal Response** (`internal_endpoint_dispatch.rs`) — health/ready/drain endpoints, mesh key exchange
6. **Backend Dispatch** (`backend_dispatch.rs`) — 11 backend types: Upstream, FastCGI, PHP, CGI, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin (+ separate WebSocket upgrade path)
7. **Accounting** (`http_request_postlude.rs`) — metrics, bandwidth tracking, error pages

HTTP/3 reuses these stages behind an `Http3WafBackend` trait boundary (see [`http3_request_waf_boundary.md`](./http3_request_waf_boundary.md)).

---

## Feature Gates

From the root `Cargo.toml`. All four compile profiles must build (`cargo check --no-default-features [--features mesh|dns|mesh,dns]`; see [`release_profile_matrix.md`](./release_profile_matrix.md)).

| Feature | Default | Purpose |
|---------|---------|---------|
| `socket-handoff` | ✅ | Socket FD transfer between processes |
| `mesh` | ✅ | Mesh networking, DHT, Raft consensus (`openraft`) |
| `dns` | ✅ | DNS server: DNSSEC, DoT/DoH/DoQ (`hickory`, `cryptoki` HSM) |
| `erased_pool` | ✅ | Type-erased HTTP client pool |
| `swagger-ui` | ✅ | OpenAPI/Swagger UI for admin API |
| `post-quantum` | — | Marker: PQ TLS via rustls `prefer-post-quantum` (upstream connections) |
| `origin_key_exchange` | — | Signed origin session keys (`synvoid-integrity`) |
| `wireguard` | — | WireGuard tunnel transport (`boringtun`) |
| `tun-rs` | — | TUN interface backend for tunnels |
| `icmp-filter` | — | ICMP flood filtering (`nftables`/eBPF/pf/WFP backends) |
| `flood-ebpf` | — | eBPF SYN-level flood dropping (Linux, `aya`) |
| `macos-sandbox` | — | macOS Seatbelt sandbox enforcement |
| `fastcgi_streaming` | — | Streaming FastCGI response handling |
| `buffer` / `rkyv` / `audit` / `verify-pq` / `test-utils` | — | Buffer pool, zero-copy serialization, audit, PQ verify, test helpers |

---

## Component Index

Each component links to its deep-dive or summary document in this directory. Deep dives cover implementation internals, state machines, and integration points.

### Layer 0 — Entry Points & Composition Roots

Root-owned orchestration code (see [`root_module_ledger.md`](./root_module_ledger.md)).

| Component | Location | Purpose | Doc |
|-----------|----------|---------|-----|
| **Command Dispatch** | `src/main.rs`, `src/commands/` | Parse args → pure plan → execute; one-shot commands (configtest, tokens); Tokio runtime launch | [`cli_supervisor_command_dispatch.md`](./cli_supervisor_command_dispatch.md) |
| **Supervisor** | `src/supervisor/` | Process supervision, worker spawn/restart, drain coordination, gRPC control plane, mesh agent mode | [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) · [`supervisor_lifecycle.md`](./supervisor_lifecycle.md) |
| **UnifiedServer composition root** | `src/server/` | Validated startup plan, resource construction (WAF/TLS/listeners), runtime handles, RAII plugin owner | [`unified_server_startup.md`](./unified_server_startup.md) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) |
| **Worker data plane** | `src/worker/` | UnifiedServerWorker event loop (HTTP+WAF+proxy), task registry, mesh supervision, drain adapter | [`worker_deep_dive.md`](./worker_deep_dive.md) · [`worker_task_lifecycle.md`](./worker_task_lifecycle.md) |
| **CPU offload** | `src/worker/cpu_task/` | Bounded heavy transforms off the request loop | [`worker_architecture.md`](./worker_architecture.md) |
| **Bootstrap/daemon/sandbox stub** | `src/startup/`, `src/process/`, `src/sandbox/` | Daemonize + PID files, IPC manager root-side code, jail-process stub | [`process_lifecycle.md`](./process_lifecycle.md) |

> Note on the root crate: many `src/*` paths are thin re-export facades over crates (e.g., `src/proxy/`, `src/dns/`, `src/mesh/`, `src/router.rs`). Others still hold **real root-owned code**: `src/admin/`, `src/worker/`, `src/process/` (~10K lines beside its facade `mod.rs`), `src/waf/` (rate limiting, rule feeds, threat level), `src/http/` (dispatch/WebDAV/file manager), `src/platform/`, `src/tcp/`+`src/udp/`, `src/tls/` (HttpsServer), `src/honeypot_port/` (responders/controller). Check [`root_module_ledger.md`](./root_module_ledger.md) before assuming a path is a shim.

### Layer 1 — Core Infrastructure

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **Configuration** | `synvoid-config` | Strongly-typed TOML config (`main.toml` + `sites/`), validation, reload, theme/mesh/site/protection sections | [`config_deep_dive.md`](./config_deep_dive.md) |
| **Core Types** | `synvoid-core` | Dependency-light shared types: admin mutation authority, provenance kinds, verdicts, time, URL utils | [`core_types.md`](./core_types.md) |
| **Utils** | `synvoid-utils` | Sharded buffer pool, ArcStr, RunningFlag/DrainFlag, safe timestamps, ReDoS checks | [`utils.md`](./utils.md) |
| **Platform** | `synvoid-platform` | OS detection/capability queries, sandbox trait + backends, secure dirs, reuse-port binds | [`platform_deep_dive.md`](./platform_deep_dive.md) |
| **IPC & Process** | `synvoid-ipc` + `src/process/` | Unix-socket transport, FD passing, HMAC-SHA3-signed frames, rate limiting, pools, versioned sockets | [`ipc_deep_dive.md`](./ipc_deep_dive.md) · [`ipc_process.md`](./ipc_process.md) |
| **CLI parsing** | `synvoid-cli` | Clap `Args` extraction (mode flags: supervisor/worker/cpu/mesh-agent/jails) | [`cli_supervisor_command_dispatch.md`](./cli_supervisor_command_dispatch.md) |
| **Drain** | `src/drain/` + `synvoid-core::drain` | Graceful-drain state shared across processes | [`drain.md`](./drain.md) |
| **Filter primitives** | `synvoid-filter` | Generic allowlist/denylist protocol filter core (used by ICMP filter, TCP/UDP listeners) | [`filter.md`](./filter.md) |

### Layer 2 — Security & WAF

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **WAF Engine** | `synvoid-waf` + `src/waf/` | 16 attack detectors, normalizer (overlong UTF-8, homoglyphs…), bot detection, narrow traits (`WafProcessor`, `BlockListStore`), rate limiting, threat level, rule feeds | [`waf_deep_dive.md`](./waf_deep_dive.md) |
| **Auth** | `src/auth/` | Users, bcrypt sessions, brute-force lockout, CSRF, HTTP Basic | [`auth_deep_dive.md`](./auth_deep_dive.md) |
| **Challenge** | `synvoid-challenge` | SHA-256 PoW (constant-time verify), CSS fingerprinting, adaptive difficulty, honeypot fields | [`challenge_deep_dive.md`](./challenge_deep_dive.md) |
| **Browser PoW module** | `synvoid-wasm-pow` | WASM solver served to clients; hybrid X25519+ML-KEM key exchange; request signing | [`wasm_pow.md`](./wasm_pow.md) |
| **Block Store** | `synvoid-block-store` | Persistent IP/mesh-ID blocklists, 64-shard LRU, provenance tracking, sequence-numbered event log for peer catch-up | [`block_store_deep_dive.md`](./block_store_deep_dive.md) · [`block_store.md`](./block_store.md) |
| **Tarpit** | `synvoid-tarpit` | Markov-chain HTML trap, per-IP/global admission semaphores, session budgets | [`tarpit_deep_dive.md`](./tarpit_deep_dive.md) |
| **Honeypot** | `synvoid-honeypot` + `src/honeypot_port/` | Multi-protocol deception, AI responders (Anthropic/OpenAI/Ollama/static), intel extraction, port rotation | [`honeypot_deep_dive.md`](./honeypot_deep_dive.md) |
| **Upload Security** | `synvoid-upload` | MIME validation, YARA scanning (multi-source rules incl. signed mesh feeds), archive inspection, quarantine | [`upload_deep_dive.md`](./upload_deep_dive.md) |
| **GeoIP** | `synvoid-geoip` | MaxMind country/ASN lookup, auto-update; wrapped as `ErasedGeoIp` for WAF | [`geoip_deep_dive.md`](./geoip_deep_dive.md) |
| **Integrity** | `synvoid-integrity` | Ed25519(+ML-DSA) message signing, X25519+ML-KEM session keys, attestation | [`integrity_deep_dive.md`](./integrity_deep_dive.md) |
| **ICMP Filter** | `synvoid-icmp-filter` | ICMP flood filtering via nftables/eBPF/pf/WFP backends with privilege detection | [`icmp_filter.md`](./icmp_filter.md) |
| **Threat Intel governance** | mesh + block-store | Consumer classes, actionability rules, enforcement ownership | [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) · [`manual_enforcement_ownership.md`](./manual_enforcement_ownership.md) |

### Layer 3 — Networking & Proxy

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **HTTP Server pipeline** | `synvoid-http` | HTTP/1.1+HTTP/2, 7-stage pipeline, WebSocket, streaming WAF bodies | [`http_deep_dive.md`](./http_deep_dive.md) · [`http_request_pipeline.md`](./http_request_pipeline.md) |
| **HTTP/3** | `synvoid-http3` | QUIC server (quinn/h3), trait-bound WAF backend, shared dispatch stages | [`http3_deep_dive.md`](./http3_deep_dive.md) · [`http3_request_waf_boundary.md`](./http3_request_waf_boundary.md) |
| **HTTP Client** | `synvoid-http-client` | Pooled upstream clients (moka, 100/TTL300s), erased bodies, UDS support, PQ TLS option | [`http_client_deep_dive.md`](./http_client_deep_dive.md) |
| **Proxy** | `synvoid-proxy` | Routing (matchit wildcard domains), header hygiene (hop-by-hop/XFF chains), retries w/ idempotency, cache tee | [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| **Upstream pools** | `synvoid-upstream` | Backend registry, 6 LB algorithms, health checking (HEAD/GET/TCP), tunnel connector trait | [`upstream_deep_dive.md`](./upstream_deep_dive.md) |
| **TLS** | `synvoid-tls` + `src/tls/` | Cert resolver w/ hot-reload, ACME (HTTP-01/DNS-01), SNI peeking, JA4 | [`tls_deep_dive.md`](./tls_deep_dive.md) |
| **Routing** | `synvoid-proxy::router` | Domain/path routing, radix trees, location semantics | [`routing_deep_dive.md`](./routing_deep_dive.md) · [`location_matcher.md`](./location_matcher.md) |
| **Listeners / L3–L5** | `src/tcp/`, `src/udp/` | Raw listener pools, protocol detection, port filtering before admission | [`listener.md`](./listener.md) · [`layer_3_5_deep_dive.md`](./layer_3_5_deep_dive.md) |
| **Streaming** | `synvoid-proxy::bidirectional` | Bidirectional proxy streaming with inline WAF scanning | [`streaming.md`](./streaming.md) |
| **Proxy Cache** | `synvoid-proxy-cache` | Two-tier memory+disk cache, stale-while-revalidate/if-error, inflight dedup, circuit breaker | [`proxy_cache.md`](./proxy_cache.md) |
| **Static Files** | `synvoid-static-files` | Range/conditional requests, pre-compressed + on-the-fly gzip/brotli, minification, traversal prevention | [`static_files.md`](./static_files.md) |
| **Tunnel transport** | `synvoid-tunnel` | QUIC + WireGuard tunnels, TUN devices, UDP forwarding, session registry | [`tunnel_deep_dive.md`](./tunnel_deep_dive.md) |
| **VPN Client** | `synvoid-vpn-client` | Standalone QUIC/WireGuard client, local port mapping, jittered auto-reconnect | [`vpn_client_deep_dive.md`](./vpn_client_deep_dive.md) |

### Layer 4 — Application Handlers & Serving

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **App Handlers** | `synvoid-app-handlers` | Generic backend dispatcher trait; CGI/FastCGI/PHP sub-modules; MIME registry | [`app_handlers.md`](./app_handlers.md) |
| **FastCGI / CGI / PHP** | (via app-handlers) | FastCGI client + pool + streaming; classic CGI exec; PHP dispatch | [`fastcgi.md`](./fastcgi.md) · [`cgi.md`](./cgi.md) |
| **App Server (Granian)** | `synvoid-app-server` | Managed Python ASGI/RSGI/WSGI processes, health monitoring, restart | [`app_server.md`](./app_server.md) |
| **MIME** | `synvoid-app-handlers::mime` | Type registry and content detection | [`mime.md`](./mime.md) |
| **Theme** | `synvoid-theme` | CSS generation (glassmorphism vars), challenge/error/login/captcha templates, stealth timestamps | [`theme.md`](./theme.md) |

### Layer 5 — WASM & Plugin Runtime

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|--------|-----|
| **Plugin Runtime** | `synvoid-plugin-runtime` + `src/plugin/` | Sandboxed WASM plugins: trust tiers, capabilities, canonical ABI frames, instance pooling, generation-aware hot-reload | [`plugin_deep_dive.md`](./plugin_deep_dive.md) · [`plugin_runtime_sandbox.md`](./plugin_runtime_sandbox.md) |
| **Native Extensions** | (via plugin-runtime) | Unsafe native loading: risk acknowledgement, path allowlist, hash pinning, Arc-retained handles | [`unsafe_native_extensions.md`](./unsafe_native_extensions.md) |
| **Serverless** | `synvoid-serverless` | WASM function registry/routing, autoscaling instance pools, async compilation, mesh invocation, pub/sub | [`serverless_deep_dive.md`](./serverless_deep_dive.md) |
| **Spin runtime** | `synvoid-plugin-runtime::spin` | Fermyon Spin WASM integration | [`spin.md`](./spin.md) |

### Layer 6 — Distributed Systems

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|--------|-----|
| **Mesh** | `synvoid-mesh` | DHT (signed records, Merkle sync), transports (QUIC/WireGuard), openraft consensus, org keys/trust domains, reputation, behavioral intel | [`mesh_deep_dive.md`](./mesh_deep_dive.md) · [`mesh_trust_domains.md`](./mesh_trust_domains.md) · [`mesh_transport_lifecycle.md`](./mesh_transport_lifecycle.md) |
| **DNS** | `synvoid-dns` | Authoritative+recursive, DNSSEC sign/validate, DoT/DoH/DoQ, TSIG, RPZ, RFC2136 updates, zone trie, anycast sync | [`dns_deep_dive.md`](./dns_deep_dive.md) · [`dns_zone_lifecycle.md`](./dns_zone_lifecycle.md) |
| **Post-Quantum Crypto** | `pqc` | ML-KEM-768/1024, ML-DSA-44 primitives (aws-lc-rs / libcrux) | [`pqc.md`](./pqc.md) |
| **Org key trust chain** | `synvoid-mesh` | Hierarchical organization/node key management | [org_key_trust_chain skill](../.opencode/skills/org_key_trust_chain/SKILL.md) |

### Layer 7 — Observability & Admin

| Component | Crate(s)/Path | Purpose | Doc |
|-----------|--------------|---------|-----|
| **Admin API (backend)** | `src/admin/` + `synvoid-admin` | Axum REST API, session cookie+CSRF auth, typed mutation results, audit events, alerting, Prometheus exporter, OpenAPI/Swagger | [`admin_deep_dive.md`](./admin_deep_dive.md) · [`admin_control_plane_authority.md`](./admin_control_plane_authority.md) |
| **Admin UI (frontend)** | `admin-ui/` | Yew/WASM dashboard (~21 pages), Trunk build | [`admin_ui.md`](./admin_ui.md) |
| **Metrics** | `synvoid-metrics` | Atomic per-site counters, bandwidth EMA tracker, scheduler-delay health monitor, global collection counters | [`metrics.md`](./metrics.md) |
| **Logging** | `src/log_controller.rs`, `src/common/` | Dynamic log levels, syslog integration, panic handler | [`log_controller.md`](./log_controller.md) · [`common.md`](./common.md) |
| **Security observability** | cross-cutting | Audit trails, alert correlation, dropped-event accounting | [`security_observability.md`](./security_observability.md) |

### Tooling & Quality

| Component | Path | Purpose | Doc |
|-----------|------|---------|-----|
| **xtask** | `tools/xtask` | `cargo xtask verify[-full|-release]`, focused test lanes | [`developer_tooling.md`](./developer_tooling.md) |
| **Repo guards** | `tools/synvoid-repo-guards` + root `tests/` | ~12 static guard suites enforcing boundaries/invariants | [`developer_tooling.md`](./developer_tooling.md) · [`root_module_ledger.md`](./root_module_ledger.md) |
| **Fuzzing** | `fuzz/` | 17 targets; smoke runs need nightly | [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md) |

---

## Key Integration Patterns

### IPC Message Categories (60+ types)

| Category | Examples | Direction |
|----------|----------|-----------|
| Worker Lifecycle | Spawn, Ready, Shutdown, Drain | Supervisor → Worker |
| Configuration | ConfigReload, SiteUpdate | Supervisor → Worker |
| Health | HealthCheck, Heartbeat | Bidirectional |
| Metrics | MetricsReport, BandwidthReport | Worker → Supervisor |
| Socket | SocketHandoff, SocketRelease | Supervisor → Worker |
| Security | ThreatUpdate, BlockNotify | Supervisor → Worker |
| WASM | PluginLoad, PluginUnload | Supervisor → Worker |
| Blocklist | BlocklistRequest/Update/EventUpdate (sequence-numbered catch-up) | Bidirectional |
| CPU Offload | CpuTaskKind/Payload/Result | Worker ↔ CPU Worker |

### WAF Decision Variants

| Decision | Behavior | Response |
|----------|----------|----------|
| `Pass` | Allow request | Forward to backend |
| `Drop` | Blackhole (silent drop) | 404 Not Found |
| `Stall` | Concurrency-capped delay | 408 Timeout |
| `Block` | Active block | Themed error page |
| `Challenge` / `ChallengeWithCookie` | Browser verification (PoW/CSS) | HTML challenge page (+Set-Cookie) |
| `Tarpit` | Slow-response trap | Streamed infinite HTML |

### Security Patterns

| Pattern | Implementation |
|---------|---------------|
| Constant-time comparison | `subtle::ConstantTimeEq` everywhere secrets/MACs/tokens are compared (incl. PoW verification) |
| IPC authentication | HMAC-SHA3-256 signed frames, constant-time verify (`synvoid-ipc::ipc_signed`) |
| Admin authority | Typed `AdminMutationResult` + `AdminMutationAuthority`; hashed actor IDs in audit logs |
| Browser sessions | HttpOnly cookie + CSRF token; bearer only for session exchange; WS via cookie only |
| Path traversal prevention | Canonicalize + prefix check (`synvoid-static-files`, `synvoid-upload`) |
| ReDoS prevention | Regex complexity screening (`synvoid-utils::regex_utils`) |
| Sandboxing | Per-platform backends behind `ProcessSandbox` trait (`synvoid-platform`) |
| WAF normalization | Overlong UTF-8 decoding + `OVERLONG` flag; strict mode rejects risky inputs |
| Private key material | Mode `0o600` files; zeroize-on-drop signing keys |

### Serialization Strategy

| Path | Format | Reason |
|------|--------|--------|
| DHT/Mesh/Persistence | Postcard | Compact, deterministic |
| IPC Messages | Postcard | Performance, type safety |
| High-perf hot paths | Rkyv | Zero-copy access |
| Admin API | JSON (+utoipa OpenAPI) | Human-readable tooling |
| DNS wire format | hickory-proto | RFC compliance |

---

## Documentation Map

Start here, then descend:

| Topic | Docs |
|-------|------|
| Request path end-to-end | [`http_request_pipeline.md`](./http_request_pipeline.md) → [`http_deep_dive.md`](./http_deep_dive.md) → [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| Boundaries (must-know) | [`root_module_ledger.md`](./root_module_ledger.md) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) · [`request_path_capability_boundary.md`](./request_path_capability_boundary.md) · [`root_dependency_ownership.md`](./root_dependency_ownership.md) |
| Admin & authority | [`admin_control_plane_authority.md`](./admin_control_plane_authority.md) → [`admin_deep_dive.md`](./admin_deep_dive.md) → [`admin_ui.md`](./admin_ui.md) |
| Threat intel enforcement | [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) · [`block_store_deep_dive.md`](./block_store_deep_dive.md) · [`manual_enforcement_ownership.md`](./manual_enforcement_ownership.md) |
| Mesh internals | [`mesh_trust_domains.md`](./mesh_trust_domains.md) → [`mesh_transport_lifecycle.md`](./mesh_transport_lifecycle.md) → [`mesh_deep_dive.md`](./mesh_deep_dive.md) |
| Lifecycle & ops | [`process_lifecycle.md`](./process_lifecycle.md) · [`supervisor_lifecycle.md`](./supervisor_lifecycle.md) · [`worker_task_lifecycle.md`](./worker_task_lifecycle.md) · [`drain.md`](./drain.md) · [`runtime_operations_drill.md`](./runtime_operations_drill.md) |
| Verification | `docs/testing/verification-contract.md` · [`developer_tooling.md`](./developer_tooling.md) · [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md) · [`release_profile_matrix.md`](./release_profile_matrix.md) |

External: [`AGENTS.md`](../AGENTS.md) (agent guide) · [`.opencode/skills/`](../.opencode/skills/) (32 subsystem guides) · [`docs/releasing.md`](../docs/releasing.md) · [`SECURITY.md`](../SECURITY.md)
