# SynVoid Architecture Overview

SynVoid is a high-performance, multi-process Web Application Firewall (WAF) and reverse proxy written in Rust. It provides Layer 7 request filtering, attack detection, load balancing, TLS termination, and optional mesh networking — designed for 1M+ RPS with millions of tenants.

**Key Capabilities:**
- Layer 7 WAF with **13 policy detectors + HeaderValidator + behavioral engine + fast-path prefilter**, normalization (incl. overlong UTF-8), bot detection, rate limiting, anomaly scoring, traffic shaping
- Reverse proxy with **6 load-balancing algorithms** (RoundRobin, Random, LeastConnections, PeakEwma, WeightedRoundRobin, IpHash), retries/backoff, circuit breaking, response caching
- TLS termination with ACME (HTTP-01/DNS-01), SNI peeking, JA4 fingerprinting, post-quantum-preferred rustls
- HTTP/1.1, HTTP/2, HTTP/3 (QUIC); WebSocket; WebDAV; FastCGI/CGI/PHP; Granian (Python ASGI/RSGI/WSGI); static files
- WASM plugin/serverless runtime (wasmtime-based) with trust tiers, capabilities, ABI frames, instance pooling
- Mesh networking with DHT, Raft consensus, trust domains, hybrid Ed25519+ML-DSA-44 signatures, ML-KEM-768 KEM
- Authoritative + recursive DNS with DNSSEC signing/validation, DoT/DoH/DoQ, TSIG (deferred: RPZ, prefetch, zone transfers, dynamic updates, NOTIFY, EDNS padding, QNAME privacy — enabling them fails `DnsConfig::validate()` with typed `Unsupported`, Phase 45)
- Multi-platform OS abstraction and process sandboxing (Linux, macOS, BSDs, Windows)

This document is the **birds-eye view** of how everything fits together and the **index** for focused review: every discrete module/component below links to its deep-dive document in this directory.

---

## Repository Layout

```
synvoid/
├── src/                    # Root crate (binary + library): composition roots + legacy facades
│   ├── commands/           # CLI plan → execute dispatch
│   ├── supervisor/         # Supervisor process (lifecycle, IPC, gRPC, drain)
│   ├── worker/             # UnifiedServerWorker data plane + CPU offload
│   ├── server/             # UnifiedServer composition root (startup plan, resources)
│   ├── admin/              # Admin Axum transport (routes, auth, WS, alerting)
│   ├── waf/                # Root WAF composition (rate limit, rule feeds, threat level)
│   ├── http/               # HTTP dispatch / WebDAV / file-manager adapter
│   ├── tcp/ udp/           # Raw listener pools + L3–L5 filtering
│   ├── platform/ sandbox/  # Platform composition, jail supervision
│   ├── tls/                # HttpsServer (cert resolver use lives in synvoid-tls)
│   ├── honeypot_port/      # Facade-only re-export over synvoid-honeypot (controller/runner canonical)
│   ├── app_server/ metrics/ theme/ tunnel/ vpn_client/  # App-service, counters, theming, tunnels, VPN wiring
│   ├── bin/                  # `synvoid-vpn`, `server` binaries
│   └── {proxy,dns,mesh,…}/ # Thin re-export facades over crates/synvoid-*
├── crates/                 # 43 dedicated synvoid-* library crates (canonical logic)
├── pqc/                    # Post-quantum crypto (ML-KEM-768/1024, ML-DSA-44)
├── admin-ui/               # Yew/WASM admin frontend (Trunk build → dist/, ~22 pages)
├── tools/                  # xtask runner + repo-guard helpers
├── proto/                  # gRPC control-plane definitions (control.proto)
├── fuzz/                   # 21 fuzz targets (see `architecture/ci_fuzz_failure_injection.md`)
├── ebpf-flood/ ebpf-icmp/  # Kernel XDP/TC programs (SYN flood, ICMP filter)
├── clients/                # Browser-side helpers (integrity-client.js)
├── examples/               # dynamic-plugin, embedded-app, dns configs
├── config/                 # Default configuration (main.toml + sites/)
├── rules/                  # YARA rules (default.yar)
├── benches/ benchmarks/    # Criterion hot-path benches (16 files) + historical results
├── architecture/           # This documentation tree (~150 docs)
├── .opencode/skills/       # Per-subsystem skill guides (48)
├── docs/                   # User/operator docs, testing contracts, releasing
├── plans/                  # Implementation tracking artifacts
└── scripts/                # CI/build/dns helper scripts
```

**Workspace**: 51 members — root app, 43 `synvoid-*` crates under `crates/`, `pqc`, `admin-ui`, 2 examples, `fuzz`, `tools/{xtask,synvoid-repo-guards}`.

### Binaries

| Binary | Entry | Purpose |
|--------|-------|---------|
| `synvoid` | `src/main.rs` → `src/commands/` | Supervisor/worker entry; normal invocation starts the Supervisor, which spawns workers |
| `synvoid-vpn` | `src/bin/synvoid-vpn.rs` | Standalone QUIC/WireGuard VPN client (see [`vpn_client_deep_dive.md`](./vpn_client_deep_dive.md)) |
| `server` | `src/bin/server.rs` | Reserved VPN-dashboard binary |

Deep dive on dispatch: [`cli_supervisor_command_dispatch.md`](./cli_supervisor_command_dispatch.md).

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

Plus two supervised **sandbox jail** processes (dedicated `synvoid-wasm-jail` / `synvoid-yara-jail` binaries from `synvoid-jail-runtime`, Phase 29; legacy `--wasm-jail` / `--yara-jail` flags are forwarding shims): parent-created stdio pipes, deterministic exe-dir binary resolution (no CWD/PATH search), versioned length-bounded typed protocol, no secrets in argv/env — see [`sandbox_jail_protocol.md`](./sandbox_jail_protocol.md).

| Process | Flag | Purpose | Default |
|---------|------|---------|---------|
| **Supervisor** | (default) | Control plane, lifecycle, gRPC API | 1 |
| **UnifiedServerWorker** | `--unified-server-worker` | Latency-sensitive HTTP/HTTPS/HTTP3 + WAF + proxy | 1 (code default; shipped `config/main.toml` sets 4) |
| **CPU Offload Worker** | `--cpu-worker` | Bounded heavy transforms | 1 |
| **Supervisor (legacy `--worker` alias)** | `--worker` | Deprecated alias for Supervisor (compat only; no `plan.rs` dispatch branch — falls through to Supervisor) | — |

Deep dives: [`supervisor.md`](./supervisor.md) · [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) · [`supervisor_lifecycle.md`](./supervisor_lifecycle.md) · [`worker_deep_dive.md`](./worker_deep_dive.md) · [`worker_architecture.md`](./worker_architecture.md) · [`worker_task_lifecycle.md`](./worker_task_lifecycle.md) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) · [`process_lifecycle.md`](./process_lifecycle.md)

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

Cross-cutting enforcement notes: worker admission reads the BlockStore (not the threat-intel manager); the WAF pipeline itself queries no block/threat state and mutates none; new block writes use `block_ip_with_provenance`. See [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) · [`manual_enforcement_ownership.md`](./manual_enforcement_ownership.md) · [`enforcement_decision_contract.md`](./enforcement_decision_contract.md).

### HTTP Pipeline (7 Stages)

Every request flows through `synvoid-http`'s staged pipeline ([`http_request_pipeline.md`](./http_request_pipeline.md)):

1. **Metadata Normalization** (`request_frontdoor.rs`) — client IP sanitization, internal endpoint dispatch, mesh special paths
2. **Route Resolution** (`request_preparation.rs`) — domain/path matching, connection limits, trust-token bypass, WebSocket upgrade validation
3. **Body Policy** (`body_policy.rs`) — body collection; chunked WAF scanning for large bodies (64KB chunks, 256KB threshold, 1MB cap)
4. **WAF Evaluation** (`waf_decision.rs`) — full attack detection, anomaly scoring, bot detection, challenge/tarpit/stall decisions
5. **Terminal Response** (`internal_endpoint_dispatch.rs`) — health/ready/drain endpoints, mesh key exchange
6. **Backend Dispatch** (`backend_dispatch.rs`) — 11 backend types: Upstream, FastCGI, PHP, CGI, AxumDynamic, AppServer, Static, QuicTunnel, Serverless, Mesh, Spin (+ separate WebSocket upgrade path)
7. **Accounting** (`http_request_postlude.rs`) — metrics, bandwidth tracking, error pages

HTTP/3 reuses these stages behind an `Http3WafBackend` trait boundary (see [`http3_request_waf_boundary.md`](./http3_request_waf_boundary.md)).

Related: [`http_deep_dive.md`](./http_deep_dive.md) · [`http_server.md`](./http_server.md) · [`http_shared.md`](./http_shared.md) · [`http_ownership_convergence.md`](./http_ownership_convergence.md) · [`EggServe H1 qualification (retained at Phase 65)`](./eggserve_0_2_2_h1_compatibility_matrix.md) · [`H1 runtime truthfulness (Phase 70)`](./http_h1_runtime_truthfulness_phase70.md) · [`HTTP config runtime semantics (Phase 71)`](./http_config_runtime_semantics_matrix.md) · [`streaming.md`](./streaming.md) · [`networking_deep_dive.md`](./networking_deep_dive.md)

---

## Feature Gates

From the root `Cargo.toml`. All four compile profiles must build (`cargo check --no-default-features [--features mesh|dns|mesh,dns]`; see [`release_profile_matrix.md`](./release_profile_matrix.md)).

| Feature | Default | Purpose |
|---------|---------|---------|
| `socket-handoff` | ✅ | Socket FD transfer between processes |
| `mesh` | ✅ | Mesh networking, DHT, Raft consensus (`openraft`) |
| `dns` | ✅ | DNS server: DNSSEC, DoT/DoH/DoQ (`hickory`; private-key custody in `synvoid-dnssec-keystore`, HSM via opt-in `dns-hsm`) |
| `dns-hsm` | — | Opt-in PKCS#11/HSM backing for DNSSEC via the keystore custody boundary (implies `dns`; off by default, no silent software fallback) |
| `erased_pool` | ✅ | Type-erased HTTP client pool |
| `swagger-ui` | ✅ | OpenAPI/Swagger UI for admin API |
| `post-quantum` | — | Marker: PQ TLS via rustls `prefer-post-quantum` (upstream connections) |
| `origin_key_exchange` | — | Signed origin session keys (`synvoid-integrity`) |
| `wireguard` | — | WireGuard tunnel transport (`boringtun`) |
| `tun-rs` | — | TUN interface backend for tunnels |
| `icmp-filter` | — | ICMP flood filtering (`nftables`/eBPF/pf/WFP backends). Backend selection uses crate-level sub-features of `synvoid-icmp-filter` (not root flags): `icmp-ebpf` (Linux, `aya`), `icmp-pf` (macOS/FreeBSD), `icmp-winfw` / `icmp-wfp` (Windows) |
| `flood-ebpf` | — | eBPF SYN-level flood dropping (Linux, `aya`) |
| `macos-sandbox` | — | macOS Seatbelt (experimental, deprecated `sandbox_init`; not App Sandbox) |
| `unsafe-native-extensions` | — | Opt-in in-process native-extension loader (`synvoid-native-extension`; off by default + runtime gates: risk acknowledgement, path allowlist, hash pinning) |
| `fastcgi_streaming` | — | Streaming FastCGI response handling |
| `buffer` / `rkyv` / `audit` / `verify-pq` / `test-utils` | — | Buffer pool, zero-copy serialization, audit, PQ verify, test helpers |

---

## Component Index

Each component links to its deep-dive or summary document in this directory. Deep dives cover implementation internals, state machines, and integration points. Start a focused review at the linked doc.

### Layer 0 — Entry Points & Composition Roots

Root-owned orchestration code (see [`root_module_ledger.md`](./root_module_ledger.md) · [`facade_disposition_matrix.md`](./facade_disposition_matrix.md) · [`request_path_capability_boundary.md`](./request_path_capability_boundary.md) · [`root_dependency_ownership.md`](./root_dependency_ownership.md)).

| Component | Location | Purpose | Doc |
|-----------|----------|---------|-----|
| **Command Dispatch** | `src/main.rs`, `src/commands/` | Parse args → pure plan → execute; one-shot commands (configtest, tokens); Tokio runtime launch | [`cli_supervisor_command_dispatch.md`](./cli_supervisor_command_dispatch.md) |
| **Supervisor** | `src/supervisor/` | Process supervision, worker spawn/restart, drain coordination, gRPC control plane, mesh agent mode | [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) · [`supervisor_lifecycle.md`](./supervisor_lifecycle.md) · [`supervisor.md`](./supervisor.md) |
| **UnifiedServer composition root** | `src/server/` | Validated startup plan, resource construction (WAF/TLS/listeners), runtime handles, RAII plugin owner | [`unified_server_startup.md`](./unified_server_startup.md) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) |
| **Worker data plane** | `src/worker/` | UnifiedServerWorker event loop (HTTP+WAF+proxy), task registry, mesh supervision, drain adapter | [`worker_deep_dive.md`](./worker_deep_dive.md) · [`worker_task_lifecycle.md`](./worker_task_lifecycle.md) · [`worker_architecture.md`](./worker_architecture.md) |
| **CPU offload** | `src/worker/cpu_task/` | Bounded heavy transforms off the request loop | [`worker_architecture.md`](./worker_architecture.md) |
| **Bootstrap/daemon/sandbox jail** | `src/startup/`, `src/sandbox/` (parent policy) + `synvoid-jail-runtime` (child execution) + `synvoid-ipc` (canonical protocol/supervision/binary resolution; `src/process/` is a facade-only re-export) | Daemonize + PID files, supervised WASM/YARA jail processes (dedicated binaries, framed stdio IPC) | [`process_lifecycle.md`](./process_lifecycle.md) · [`sandbox_jail_protocol.md`](./sandbox_jail_protocol.md) |

> Note on the root crate: many `src/*` paths are thin re-export facades over crates (e.g., `src/proxy/`, `src/dns/`, `src/mesh/`, `src/process/` (facade-only over `synvoid-ipc`), `src/honeypot_port/` (facade-only over `synvoid-honeypot`), `src/router.rs`). Others still hold **real root-owned code**: `src/admin/` (Axum transport composition; per-handler matrix in [`admin_root_ownership.md`](./admin_root_ownership.md)), `src/worker/`, `src/waf/` (rate limiting, rule feeds, threat level), `src/http/` (dispatch/WebDAV/file manager), `src/platform/`, `src/tcp/`+`src/udp/`, `src/tls/` (HttpsServer). Check [`root_module_ledger.md`](./root_module_ledger.md) before assuming a path is a shim.

### Layer 1 — Core Infrastructure

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **Configuration** | `synvoid-config` | Strongly-typed TOML config (`main.toml` + `sites/`), validation, reload, theme/mesh/site/protection sections | [`config.md`](./config.md) · [`config_deep_dive.md`](./config_deep_dive.md) · [`dns_config_runtime_matrix.md`](./dns_config_runtime_matrix.md) · [`config_feature_contract.md`](./config_feature_contract.md) |
| **Core Types** | `synvoid-core` | Dependency-light shared types: admin mutation authority, provenance kinds, verdicts, time, URL utils | [`core_types.md`](./core_types.md) |
| **Utils** | `synvoid-utils` | Sharded buffer pool, ArcStr, RunningFlag/DrainFlag, safe timestamps, ReDoS checks | [`utils.md`](./utils.md) |
| **Common** | `src/common/` | Panic handler + shared runtime glue | [`common.md`](./common.md) |
| **Platform** | `synvoid-platform` | OS detection/capability queries, sandbox trait + backends, secure dirs, reuse-port binds | [`platform.md`](./platform.md) · [`platform_deep_dive.md`](./platform_deep_dive.md) |
| **IPC & Process** | `synvoid-ipc` (canonical; `src/process/` is a facade-only 6-line re-export) | Unix-socket transport, FD passing, HMAC-SHA3-signed frames, rate limiting, pools, versioned sockets | [`ipc_deep_dive.md`](./ipc_deep_dive.md) · [`ipc_process.md`](./ipc_process.md) |
| **Jail runtime (child side)** | `synvoid-jail-runtime` + `synvoid-ipc` (jail protocol, exe-dir binary resolution) + `src/sandbox/` (parent policy) | Sandboxed WASM/YARA jail execution in dedicated `synvoid-wasm-jail` / `synvoid-yara-jail` binaries; parent-created stdio pipes, versioned length-bounded typed protocol | [`sandbox_jail_protocol.md`](./sandbox_jail_protocol.md) · [`plugin_runtime_sandbox.md`](./plugin_runtime_sandbox.md) |
| **CLI parsing** | `synvoid-cli` | Clap `Args` extraction (mode flags: supervisor/worker/cpu/mesh-agent/jails) | [`cli_supervisor_command_dispatch.md`](./cli_supervisor_command_dispatch.md) |
| **Drain** | `src/drain/` + `synvoid-core::drain` | Graceful-drain state shared across processes | [`drain.md`](./drain.md) |
| **Filter primitives** | `synvoid-filter` | Generic allowlist/denylist protocol filter core (used by ICMP filter, TCP/UDP listeners) | [`filter.md`](./filter.md) |
| **Rate limiting** | `synvoid-rate-limit` | Shared sliding-window mechanism (`AtomicSlidingWindow`, neutral `RateLimitResult`/`IpRateLimiter`/`KeyedRateLimiter`, `ip_to_slot`); only class-3 public crate (0.1.0, MSRV 1.81) — WAF/policy decisions stay root-owned | [`public_crate_release_readiness_phase47.md`](./public_crate_release_readiness_phase47.md) |
| **Metrics core** | `synvoid-metrics` | Atomic per-site counters, bandwidth EMA tracker, scheduler-delay health monitor | [`metrics.md`](./metrics.md) |
| **Logging** | `src/log_controller.rs`, `src/common/` | Dynamic `EnvFilter` levels + stderr variant, panic handler (no syslog sink) | [`log_controller.md`](./log_controller.md) · [`common.md`](./common.md) |

### Layer 2 — Security & WAF

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **WAF Engine** | `synvoid-waf` + `src/waf/` | 13 policy detectors + HeaderValidator + behavioral engine + fast-path prefilter, normalizer (overlong UTF-8, homoglyphs…), bot detection, narrow traits (`WafProcessor`, `BlockListStore`), rate limiting, threat level, rule feeds | [`waf.md`](./waf.md) · [`waf_deep_dive.md`](./waf_deep_dive.md) · [`waf_ownership_convergence.md`](./waf_ownership_convergence.md) |
| **Enforcement decisions** | `synvoid-waf` + `synvoid-core` | Pass/Drop/Stall/Block/Challenge/Tarpit verdict contract | [`enforcement_decision_contract.md`](./enforcement_decision_contract.md) |
| **Auth** | `synvoid-auth` | Users, bcrypt sessions, brute-force lockout, CSRF, HTTP Basic | [`auth.md`](./auth.md) · [`auth_deep_dive.md`](./auth_deep_dive.md) |
| **Challenge** | `synvoid-challenge` | SHA-256 PoW (constant-time verify), CSS fingerprinting, adaptive difficulty, honeypot fields | [`challenge.md`](./challenge.md) · [`challenge_deep_dive.md`](./challenge_deep_dive.md) |
| **Browser PoW module** | `synvoid-wasm-pow` | WASM solver served to clients; hybrid X25519+ML-KEM key exchange; request signing | [`wasm_pow.md`](./wasm_pow.md) |
| **Block Store** | `synvoid-block-store` | Persistent IP/mesh-ID blocklists, 64-shard LRU, provenance tracking, sequence-numbered event log for peer catch-up | [`block_store.md`](./block_store.md) · [`block_store_deep_dive.md`](./block_store_deep_dive.md) · [`blocklist_provenance_preservation.md`](./blocklist_provenance_preservation.md) · [`blocklist_reconciliation.md`](./blocklist_reconciliation.md) · [`blocklist_remove_consistency.md`](./blocklist_remove_consistency.md) |
| **Tarpit** | `synvoid-tarpit` | Markov-chain HTML trap, per-IP/global admission semaphores, session budgets | [`tarpit.md`](./tarpit.md) · [`tarpit_deep_dive.md`](./tarpit_deep_dive.md) |
| **Honeypot** | `synvoid-honeypot` (canonical controller/runner; `src/honeypot_port/` is a facade-only re-export) | Multi-protocol deception, AI responders (Anthropic/OpenAI/Ollama/static), intel extraction, port rotation | [`honeypot.md`](./honeypot.md) · [`honeypot_deep_dive.md`](./honeypot_deep_dive.md) |
| **Upload Security** | `synvoid-upload` (policy) + `synvoid-yara` (canonical engine, Phase 26) | MIME validation, YARA scanning via `synvoid-yara` engine (multi-source rules incl. signed mesh feeds), archive inspection, quarantine | [`upload.md`](./upload.md) · [`upload_deep_dive.md`](./upload_deep_dive.md) |
| **YARA engine** | `synvoid-yara` | Canonical YARA-X execution boundary: rule compilation, artifact-bound execution, metrics; consumed by upload scanning and jail `yara_service` | [`upload_deep_dive.md`](./upload_deep_dive.md) · [`sandbox_jail_protocol.md`](./sandbox_jail_protocol.md) |
| **DNSSEC keystore** | `synvoid-dnssec-keystore` | Private-key/HSM custody boundary: key generation, `SealedSigningKey::sign()`, PKCS#11 opt-in (`dns-hsm`); query/transport code never touches private material | [`dnssec_keystore.md`](./dnssec_keystore.md) · [`dns_deep_dive.md`](./dns_deep_dive.md) |
| **GeoIP** | `synvoid-geoip` | MaxMind country/ASN lookup, auto-update; wrapped as `ErasedGeoIp` for WAF | [`geoip.md`](./geoip.md) · [`geoip_deep_dive.md`](./geoip_deep_dive.md) |
| **Integrity** | `synvoid-integrity` | Ed25519(+ML-DSA) message signing, X25519+ML-KEM session keys, attestation; browser client in `clients/` | [`integrity.md`](./integrity.md) · [`integrity_deep_dive.md`](./integrity_deep_dive.md) |
| **ICMP Filter** | `synvoid-icmp-filter` (canonical; `src/icmp_filter/` is a facade-only 1-line re-export) | ICMP flood filtering via nftables/eBPF/pf/WFP backends with privilege detection | [`icmp_filter.md`](./icmp_filter.md) |
| **Threat Intel governance** | mesh + block-store | Consumer classes, actionability rules, enforcement ownership, request-path audit | [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) · [`manual_enforcement_ownership.md`](./manual_enforcement_ownership.md) · [`threat_intel_request_waf_audit.md`](./threat_intel_request_waf_audit.md) |

### Layer 3 — Networking & Proxy

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **HTTP Server pipeline** | `synvoid-http` | HTTP/1.1+HTTP/2, 7-stage pipeline, WebSocket, streaming WAF bodies | [`http_deep_dive.md`](./http_deep_dive.md) · [`http_request_pipeline.md`](./http_request_pipeline.md) · [`http_server.md`](./http_server.md) · [`http_shared.md`](./http_shared.md) |
| **HTTP/3** | `synvoid-http3` | QUIC server (quinn/h3), trait-bound WAF backend, shared dispatch stages | [`http3_deep_dive.md`](./http3_deep_dive.md) · [`http3_request_waf_boundary.md`](./http3_request_waf_boundary.md) |
| **HTTP Client** | `synvoid-http-client` | Policy-free egress transport: pooled upstream clients (moka, 100/TTL300s), erased bodies, UDS support, PQ TLS option; site→TLS in upstream, WAF bodies in `synvoid-http` (Phase 34) | [`http_client_deep_dive.md`](./http_client_deep_dive.md) · [`egress_client_decision_phase34.md`](./egress_client_decision_phase34.md) |
| **Proxy** | `synvoid-proxy` | Routing (matchit wildcard domains), header hygiene (hop-by-hop/XFF chains), retries w/ idempotency, cache tee | [`proxy.md`](./proxy.md) · [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
| **Upstream pools** | `synvoid-upstream` | Backend registry, 6 LB algorithms, health checking (HEAD/GET/TCP), tunnel connector trait, site→TLS adapter (Phase 34), hardened shm unsafe boundary (Phase 42) | [`upstream.md`](./upstream.md) · [`upstream_deep_dive.md`](./upstream_deep_dive.md) · [`shared_memory_atomic_contract.md`](./shared_memory_atomic_contract.md) |
| **TLS** | `synvoid-tls` + `src/tls/` | Cert resolver w/ hot-reload, ACME (HTTP-01/DNS-01), SNI peeking, JA4 | [`tls.md`](./tls.md) · [`tls_deep_dive.md`](./tls_deep_dive.md) |
| **Routing** | `synvoid-proxy::router` | Domain/path routing, radix trees, location semantics | [`routing_deep_dive.md`](./routing_deep_dive.md) · [`location_matcher.md`](./location_matcher.md) |
| **Listeners / L3–L5** | `src/tcp/`, `src/udp/`, `src/listener/` | Raw listener pools, protocol detection, port filtering before admission | [`listener.md`](./listener.md) · [`layer_3_5_deep_dive.md`](./layer_3_5_deep_dive.md) · [`networking_deep_dive.md`](./networking_deep_dive.md) |
| **Protocol helpers** | `synvoid-proxy::protocol` | L7 detection framework (gRPC/WS handlers, DNS sniffing, first-line extraction; no PROXY-protocol v1/v2 parsing) | [`protocol.md`](./protocol.md) |
| **Streaming** | `synvoid-proxy::streaming` (`TeeBody`) + `bidirectional` | Cache-tee body (`TeeBody` lives in `streaming.rs`) + bidirectional copy with inline WAF scanning | [`streaming.md`](./streaming.md) |
| **Proxy Cache** | `synvoid-proxy-cache` | Two-tier memory+disk cache, stale-while-revalidate/if-error, inflight dedup, circuit breaker | [`proxy_cache.md`](./proxy_cache.md) |
| **Static Files** | `synvoid-static-files` | Range/conditional requests, pre-compressed br/gzip + gzip-only on-the-fly (brotli is precompressed-only), minification, traversal prevention | [`static_files.md`](./static_files.md) |
| **Tunnel transport** | `synvoid-tunnel` | QUIC + WireGuard tunnels, availability-gated TUN/userspace packet path (`tun.rs` stub returns `Unsupported`; platform TUN in `wireguard/tun.rs`), UDP forwarding, session registry | [`tunnel_deep_dive.md`](./tunnel_deep_dive.md) |
| **VPN Client** | `synvoid-vpn-client` | Standalone QUIC/WireGuard client, local port mapping, jittered auto-reconnect | [`vpn_client_deep_dive.md`](./vpn_client_deep_dive.md) |

### Layer 4 — Application Handlers & Serving

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|---------|-----|
| **App Handlers** | `synvoid-app-handlers` | Generic backend dispatcher trait; CGI/FastCGI/PHP sub-modules; MIME registry | [`app_handlers.md`](./app_handlers.md) |
| **FastCGI / CGI / PHP** | (via app-handlers) | FastCGI client + pool + streaming; classic CGI exec; PHP dispatch | [`fastcgi.md`](./fastcgi.md) · [`cgi.md`](./cgi.md) · [`php.md`](./php.md) |
| **App Server (Granian)** | `synvoid-app-server` | Managed Python ASGI/RSGI/WSGI processes, health monitoring, restart | [`app_server.md`](./app_server.md) |
| **MIME** | `synvoid-app-handlers::mime` | Type registry and content detection | [`mime.md`](./mime.md) |
| **Theme** | `synvoid-theme` | CSS generation (glassmorphism vars), challenge/error/login/captcha templates, stealth timestamps | [`theme.md`](./theme.md) |

### Layer 5 — WASM & Plugin Runtime

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|--------|-----|
| **Plugin Runtime** | `synvoid-plugin-runtime` + `src/plugin/` | Sandboxed WASM plugins: trust tiers, capabilities, canonical ABI frames, instance pooling, generation-aware hot-reload | [`plugin_deep_dive.md`](./plugin_deep_dive.md) · [`plugin_runtime_sandbox.md`](./plugin_runtime_sandbox.md) · [`plugin_wasm.md`](./plugin_wasm.md) · [`plugin_loader_trust_audit.md`](./plugin_loader_trust_audit.md) |
| **Native Extensions** | (via synvoid-native-extension, opt-in) | Explicit unsafe loader behind `unsafe-native-extensions` (off by default) + runtime gates: risk acknowledgement, path allowlist, hash pinning, Arc-retained handles | [`unsafe_native_extensions.md`](./unsafe_native_extensions.md) |
| **Serverless** | `synvoid-serverless` | WASM function registry/routing, autoscaling instance pools, async compilation, mesh invocation, pub/sub | [`serverless.md`](./serverless.md) · [`serverless_deep_dive.md`](./serverless_deep_dive.md) |
| **Spin runtime** | `synvoid-plugin-runtime::spin` | Fermyon Spin WASM integration | [`spin.md`](./spin.md) |

### Layer 6 — Distributed Systems

| Component | Crate(s) | Purpose | Doc |
|-----------|----------|--------|-----|
| **Mesh** | `synvoid-mesh` + `synvoid-mesh-protocol` (Phase 27) | DHT (signed records, Merkle sync), transports (QUIC; WireGuard port-advertising only here — real WG in `synvoid-tunnel`), openraft consensus, org keys/trust domains, reputation, behavioral intel; low-capability wire/identity vocabulary (`HybridSignature`, `ProtocolSigner`, threat taxonomy, framing) in `synvoid-mesh-protocol` | [`distributed_state_contract.md`](./distributed_state_contract.md) (binding) · [`mesh.md`](./mesh.md) · [`mesh_deep_dive.md`](./mesh_deep_dive.md) · [`mesh_trust_domains.md`](./mesh_trust_domains.md) · [`mesh_transport_lifecycle.md`](./mesh_transport_lifecycle.md) |
| **DNS** | `synvoid-dns` | Authoritative+recursive, DNSSEC sign/validate, DoT/DoH/DoQ, TSIG, zone trie; RPZ / RFC2136 updates / transfers / anycast are Deferred-fail-closed (`DnsConfig::validate` rejects activation with `Unsupported`) | [`dns.md`](./dns.md) · [`dns_deep_dive.md`](./dns_deep_dive.md) · [`dns_zone_lifecycle.md`](./dns_zone_lifecycle.md) · [`dns_operations_diagnostics.md`](./dns_operations_diagnostics.md) · [`dns_production_profiles.md`](./dns_production_profiles.md) |
| **Post-Quantum Crypto** | `pqc` | ML-KEM-768/1024, ML-DSA-44 primitives (aws-lc-rs / libcrux) | [`pqc.md`](./pqc.md) |

### Layer 7 — Observability & Admin

| Component | Crate(s)/Path | Purpose | Doc |
|-----------|--------------|---------|-----|
| **Admin API (backend)** | `src/admin/` + `synvoid-admin` | Axum REST API, session cookie+CSRF auth, typed mutation results, audit events, alerting, Prometheus exporter, OpenAPI/Swagger | [`admin_deep_dive.md`](./admin_deep_dive.md) · [`admin_control_plane_authority.md`](./admin_control_plane_authority.md) · [`admin_root_ownership.md`](./admin_root_ownership.md) |
| **Admin UI (frontend)** | `admin-ui/` | Yew/WASM dashboard (~22 pages + shared components/hooks/services), Trunk build, REST + WS (`/api/ws/metrics`, `/api/ws/logs`); note: `pages/tcp_udp.rs` exists but is unwired (no export in `pages/mod.rs`, no route in `app.rs`) | [`admin_ui.md`](./admin_ui.md) |
| **Metrics** | `synvoid-metrics` | Atomic per-site counters, bandwidth EMA tracker, scheduler-delay health monitor, global collection counters | [`metrics.md`](./metrics.md) |
| **Logging** | `src/log_controller.rs`, `src/common/` | Dynamic `EnvFilter` levels + stderr variant, panic handler (no syslog sink) | [`log_controller.md`](./log_controller.md) · [`common.md`](./common.md) |
| **Security observability** | cross-cutting | Audit trails, alert correlation, dropped-event accounting, blockstore admin observability | [`security_observability.md`](./security_observability.md) · [`blockstore_admin_observability.md`](./blockstore_admin_observability.md) |

### Tooling, Capabilities & Auxiliary Services

These are discrete review surfaces in their own right — build/verify tooling, kernel programs, client helpers, and shipped assets.

| Component | Path | Purpose | Doc |
|-----------|------|---------|-----|
| **xtask** | `tools/xtask` | `cargo xtask verify[-full|-release]`, focused test lanes (`test package`, `test guards`) | [`developer_tooling.md`](./developer_tooling.md) |
| **Repo guards** | `tools/synvoid-repo-guards` + root `tests/` | Static guard suites enforcing boundaries/invariants (composition, threat-intel, ownership) | [`developer_tooling.md`](./developer_tooling.md) · [`root_module_ledger.md`](./root_module_ledger.md) |
| **Fuzzing** | `fuzz/` | 21 targets; smoke runs need nightly (`cargo +nightly fuzz run <target>`) | [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md) |
| **Control-plane proto** | `proto/control.proto` | gRPC `ControlPlane` service (status, reload, stop, block/unblock) | [`supervisor_deep_dive.md`](./supervisor_deep_dive.md) · [`ipc_deep_dive.md`](./ipc_deep_dive.md) |
| **eBPF flood guard** | `ebpf-flood/` | XDP TCP-SYN-only flood-drop program (`filter_syn`; no UDP path) + maps/token buckets (Linux, nightly `bpfel` build) | [`layer_3_5_deep_dive.md`](./layer_3_5_deep_dive.md) |
| **eBPF ICMP guard** | `ebpf-icmp/` | XDP+TC ICMP filter program (type/code filter, rate limit, exempt IPs, v4+v6) | [`icmp_filter.md`](./icmp_filter.md) |
| **Integrity browser client** | `clients/integrity-client.js` | X25519+ML-KEM key exchange, Ed25519 signing, PoW solving for frontends | [`integrity_deep_dive.md`](./integrity_deep_dive.md) |
| **Shipped config** | `config/` | `main.toml` + `sites/`, error pages, `mime.types`, honeypot paths | [`config.md`](./config.md) |
| **YARA rules** | `rules/default.yar` | 14 upload/content rules (executables, macros, webshells, bombs) | [`upload_deep_dive.md`](./upload_deep_dive.md) |
 | **Benches** | `benches/` + `benchmarks/` | Criterion hot-path benches (16 files: attack detection ×2, normalization, proxy cache ×2, proxy headers, ratelimit, routing, broadcast, DNS, WASM, upstream selection, metrics hot-path, buffer pool, honeypot persistence + `run_benchmarks.rs` runner; 12 registered `[[bench]]` targets) + historical result tracking; `benchmarks/http_transport/` is the Phase 63 manual-only eggfetch/legacy comparison harness (never CI) | [`track3_performance_report.md`](./track3_performance_report.md) · [`performance_optimization_baseline.md`](./performance_optimization_baseline.md) · [`performance_optimization_closeout.md`](./performance_optimization_closeout.md) · [`performance_optimization_corrective_closeout.md`](./performance_optimization_corrective_closeout.md) · [`eggfetch_0_2_transport_performance_requalification.md`](./eggfetch_0_2_transport_performance_requalification.md) |
| **Examples** | `examples/` | Embedded-app, dynamic-plugin, DNS profile configs | [`plugin_wasm.md`](./plugin_wasm.md) · [`dns_production_profiles.md`](./dns_production_profiles.md) |
| **Scripts** | `scripts/` | `verify_architecture.sh`, DNS conformance/stress/bench, import checks | [`developer_tooling.md`](./developer_tooling.md) |

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
| `Allow` | Non-terminal permit (never erases a terminal claim) | Forward to backend |
| `Observe` | Log-only telemetry (never erases a terminal claim) | Forward to backend |
| `Drop` | Silent drop (highest precedence; terminal) | No response (transport-local adapters degrade to Block, fail-closed) |
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

Start here, then descend into a discrete review track. For the review workflow itself see [`review_plan.md`](./review_plan.md) (module-by-module review procedure, completed 2026-05-28 with findings consolidated in `plans/plan.md`) and [`deep_dive_review.md`](./deep_dive_review.md) (layer 1/2/3/7 findings):

| Topic | Docs |
|-------|------|
| Request path end-to-end | [`http_request_pipeline.md`](./http_request_pipeline.md) → [`http_deep_dive.md`](./http_deep_dive.md) → [`proxy_deep_dive.md`](./proxy_deep_dive.md) |
 | Boundaries (must-know) | [`root_module_ledger.md`](./root_module_ledger.md) (owner) → [`facade_disposition_matrix.md`](./facade_disposition_matrix.md) (Phase 03 delta) → [`root_dependency_ownership.md`](./root_dependency_ownership.md) (dependency entitlement) · [`worker_data_plane_composition_root.md`](./worker_data_plane_composition_root.md) · [`request_path_capability_boundary.md`](./request_path_capability_boundary.md) · [`egress_client_decision_phase34.md`](./egress_client_decision_phase34.md) · [`crate_boundary_reuse_closeout.md`](./crate_boundary_reuse_closeout.md) (Phase 35 closeout; supersedes `crate_granularity_audit.md`) · [`public_crate_release_policy.md`](./public_crate_release_policy.md) (binding; only `synvoid-rate-limit` is class 3) · [`runtime_truthfulness_security_publication_closeout.md`](./runtime_truthfulness_security_publication_closeout.md) (Phase 41–48 campaign closeout) · perf campaign: [`performance_optimization_closeout.md`](./performance_optimization_closeout.md) + [`performance_optimization_corrective_closeout.md`](./performance_optimization_corrective_closeout.md) (Phases 49–57) · eggfetch transport: [`eggfetch_0_2_transport_corrective_closeout.md`](./eggfetch_0_2_transport_corrective_closeout.md) (Phase 62 runtime authority) + [`eggfetch_0_2_transport_performance_requalification.md`](./eggfetch_0_2_transport_performance_requalification.md) (Phase 63 final performance authority as corrected by Phase 64 docs/evidence-truth correction; Phases 58–64 closed) |
| Admin & authority | [`admin_control_plane_authority.md`](./admin_control_plane_authority.md) → [`admin_deep_dive.md`](./admin_deep_dive.md) → [`admin_ui.md`](./admin_ui.md) |
| Threat intel enforcement | [`threat_intel_consumer_actionability.md`](./threat_intel_consumer_actionability.md) · [`block_store_deep_dive.md`](./block_store_deep_dive.md) · [`manual_enforcement_ownership.md`](./manual_enforcement_ownership.md) |
| Mesh internals | [`mesh_trust_domains.md`](./mesh_trust_domains.md) → [`mesh_transport_lifecycle.md`](./mesh_transport_lifecycle.md) → [`mesh_deep_dive.md`](./mesh_deep_dive.md) |
| Lifecycle & ops | [`process_lifecycle.md`](./process_lifecycle.md) · [`supervisor_lifecycle.md`](./supervisor_lifecycle.md) · [`worker_task_lifecycle.md`](./worker_task_lifecycle.md) · [`drain.md`](./drain.md) · [`runtime_operations_drill.md`](./runtime_operations_drill.md) |
| Verification | `docs/testing/verification-contract.md` · [`developer_tooling.md`](./developer_tooling.md) · [`ci_fuzz_failure_injection.md`](./ci_fuzz_failure_injection.md) · [`release_profile_matrix.md`](./release_profile_matrix.md) |
| Historical / closure reports (never cite as current behavior) | [`phase_1_5_verification_report.md`](./phase_1_5_verification_report.md) · [`phase_8_verification_report.md`](./phase_8_verification_report.md) · [`phase_9_observability_report.md`](./phase_9_observability_report.md) · [`phase_11_ci_verification_report.md`](./phase_11_ci_verification_report.md) · [`phase_14_fuzz_execution_report.md`](./phase_14_fuzz_execution_report.md) · [`track3_performance_report.md`](./track3_performance_report.md) + [`track3_post_closure_corrective_report.md`](./track3_post_closure_corrective_report.md) (superseded by perf closeouts) · [`track4_dependency_security_closeout.md`](./track4_dependency_security_closeout.md) + [`track4_post_closure_corrective_report.md`](./track4_post_closure_corrective_report.md) · [`crate_granularity_audit.md`](./crate_granularity_audit.md) (superseded by `crate_boundary_reuse_closeout.md`; fuzz count 20→21 stale) · [`root_module_burndown_report.md`](./root_module_burndown_report.md) (superseded by ledger) · [`crate_boundary_reuse_closeout.md`](./crate_boundary_reuse_closeout.md) · [`release_hardening_report.md`](./release_hardening_report.md) · [`final_verification_cleanup_report.md`](./final_verification_cleanup_report.md) · [`runtime_operations_drill_report.md`](./runtime_operations_drill_report.md) (run log for `runtime_operations_drill.md`) · [`unified_server_lifecycle_closure_report.md`](./unified_server_lifecycle_closure_report.md) |

External: [`AGENTS.md`](../AGENTS.md) (agent guide) · [`.opencode/skills/`](../.opencode/skills/) (48 subsystem guides) · [`docs/releasing.md`](../docs/releasing.md) · [`SECURITY.md`](../SECURITY.md)
