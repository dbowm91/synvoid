# Final Public Surface Audit

Phase 10 closure audit. Classifies every public surface of the SynVoid codebase as stable, internal, transitional, test-only, or deprecated.

## 1. Root Crate Exports (`src/lib.rs`)

### Root-Owned Composition Modules

| Module | Classification | Stability | Owner | Notes |
|--------|---------------|-----------|-------|-------|
| `commands` | `keep_app_root` | internal | root | Typed CLI dispatch; plan/execute/runtime-launch boundary |
| `common` | `keep_app_root` | internal | root | Panic handler setup (53 lines) |
| `drain` | `keep_app_root` | internal | root | Connection drain state for graceful shutdown |
| `log_controller` | `keep_app_root` | internal | root | Runtime log level management |
| `sandbox` | `keep_app_root` | internal | root | Process sandbox entry points (mostly TODO stubs) |
| `server` | `keep_app_root` | internal | root | UnifiedServer composition root (1344 lines) |
| `startup` | `keep_app_root` | internal | root | Process startup and bootstrap |
| `supervisor` | `keep_app_root` | internal | root | Supervisor process lifecycle (re-exports submodules) |
| `tcp` | `keep_app_root` | internal | root | TCP proxy with protocol detection |
| `udp` | `keep_app_root` | internal | root | UDP proxy |
| `worker` | `keep_app_root` | internal | root | Worker process runtime and composition |

### Mixed Application/Domain Modules (split_required)

| Module | Classification | Stability | Owner | Notes |
|--------|---------------|-----------|-------|-------|
| `admin` | `split_required` | transitional | root (composition) + synvoid-admin | Admin API routes, auth, CORS; inventory in progress |
| `auth` | `split_required` | transitional | potential synvoid-auth | Real implementation (1135 lines); extraction candidate |
| `challenge` | `split_required` | transitional | root (orchestration) + synvoid-challenge | Hybrid: re-exports + local ChallengeManager |
| `http` | `split_required` | transitional | root (composition) + synvoid-http | 43 submodules; large module needs targeted extraction |
| `http_client` | `split_required` | transitional | synvoid-http-client + root | QUIC tunnel dispatch depends on root infra |
| `platform` | `split_required` | transitional | synvoid-platform + root | Mixed: re-exports + platform detection code |
| `plugin` | `split_required` | transitional | root (composition) + synvoid-plugin-runtime | Plugin lifecycle management root-owned |
| `tarpit` | `split_required` | transitional | root (handler) + synvoid-tarpit | Handler depends on root; Markov chain extracted |
| `tls` | `split_required` | transitional | synvoid-tls + root | Local HttpsServer depends on root HTTP infra |
| `utils` | `split_required` | transitional | synvoid-utils + root | Some utils root-specific; shared in synvoid-utils |
| `waf` | `split_required` | transitional | synvoid-waf + root | WafCore and adapters are root-owned (1056 lines) |

### Compatibility Facades (facade_existing_crate)

| Module | Classification | Stability | Target Crate | Notes |
|--------|---------------|-----------|-------------|-------|
| `app_server` | `facade_existing_crate` | transitional | synvoid-app-server | Pure re-export facade |
| `block_store` | `facade_existing_crate` | transitional | synvoid-block-store | Pure re-export facade |
| `buffer` | `facade_existing_crate` | transitional | synvoid-utils | Inline re-export |
| `cgi` | `facade_existing_crate` | transitional | synvoid-app-handlers | Pure re-export facade |
| `config` | `facade_existing_crate` | transitional | synvoid-config | Facade with compat submodules |
| `dns` | `facade_existing_crate` | transitional | synvoid-dns | Feature-gated re-export |
| `fastcgi` | `facade_existing_crate` | transitional | synvoid-app-handlers | Pure re-export facade |
| `filter` | `facade_existing_crate` | transitional | synvoid-filter | Pure re-export facade |
| `geoip` | `facade_existing_crate` | transitional | synvoid-geoip | Root re-export (`pub use`) |
| `honeypot_port` | `facade_existing_crate` | transitional | synvoid-honeypot | Pure re-export facade |
| `http3` | `facade_existing_crate` | transitional | synvoid-http3 | Pure re-export facade |
| `icmp_filter` | `keep_app_root` | internal | root | Feature-gated; network-level filtering |
| `integrity` | `facade_existing_crate` | transitional | synvoid-integrity | Root re-export (`pub use`) |
| `listener` | `facade_existing_crate` | transitional | synvoid-http | Pure re-export facade |
| `location_matcher` | `facade_existing_crate` | transitional | synvoid-proxy | Pure re-export facade |
| `mesh` | `facade_existing_crate` | transitional | synvoid-mesh | Pure re-export facade; feature-gated |
| `metrics` | `facade_existing_crate` | transitional | synvoid-metrics | Facade with local tests |
| `mime` | `facade_existing_crate` | transitional | synvoid-app-handlers | Pure re-export facade |
| `php` | `facade_existing_crate` | transitional | synvoid-app-handlers | Pure re-export facade |
| `process` | `facade_existing_crate` | transitional | synvoid-ipc | Pure re-export facade |
| `protocol` | `facade_existing_crate` | transitional | synvoid-proxy | Pure re-export facade |
| `proxy` | `facade_existing_crate` | transitional | synvoid-proxy | Facade with local adapter |
| `proxy_cache` | `facade_existing_crate` | transitional | synvoid-proxy-cache | Root re-export (`pub use`) |
| `router` | `facade_existing_crate` | transitional | synvoid-proxy | Pure re-export facade |
| `router_adapter` | `facade_existing_crate` | transitional | synvoid-proxy | Pure re-export facade |
| `serialization` | `facade_existing_crate` | transitional | synvoid-utils | Root re-export (`pub use`) |
| `serverless` | `facade_existing_crate` | transitional | synvoid-serverless | Pure re-export facade |
| `spin` | `facade_existing_crate` | transitional | synvoid-plugin-runtime | Pure re-export facade |
| `static_files` | `facade_existing_crate` | transitional | synvoid-static-files | Facade with local adapter |
| `streaming` | `facade_existing_crate` | transitional | synvoid-proxy | Pure re-export facade |
| `theme` | `facade_existing_crate` | transitional | synvoid-theme | Pure re-export facade |
| `tunnel` | `facade_existing_crate` | transitional | synvoid-tunnel | Pure re-export facade |
| `upload` | `facade_existing_crate` | transitional | synvoid-upload | Pure re-export facade |
| `upstream` | `facade_existing_crate` | transitional | synvoid-upstream | Root re-export (`pub use`) |
| `vpn_client` | `facade_existing_crate` | transitional | synvoid-vpn-client | Pure re-export facade |

### Legacy/Stale Modules

| Module | Classification | Stability | Notes |
|--------|---------------|-----------|-------|
| `serder` | `legacy_or_stale` | deprecated | 98% doc comments, 2 lines of code; candidate for removal |

### Top-Level Re-exports

| Re-export | Source | Classification | Stability | Notes |
|-----------|--------|---------------|-----------|-------|
| `ConfigManager` | `config::ConfigManager` | `compat_facade` | transitional | Compatibility path |
| `errors` | `utils::errors` | `internal_public_for_crate_boundary` | stable_within_workspace | Shared error types |
| `urlencoding_decode` | `utils::urlencoding_decode` | `internal_public_for_crate_boundary` | stable_within_workspace | Utility function |
| `DrainFlag` | `utils::DrainFlag` | `internal_public_for_crate_boundary` | stable_within_workspace | Shared drain flag |
| `OptionExt` | `utils::OptionExt` | `internal_public_for_crate_boundary` | stable_within_workspace | Extension trait |
| `ResultExt` | `utils::ResultExt` | `internal_public_for_crate_boundary` | stable_within_workspace | Extension trait |
| `RunningFlag` | `utils::RunningFlag` | `internal_public_for_crate_boundary` | stable_within_workspace | Shared running flag |
| `WafCore` | `waf::WafCore` | `internal_public_for_crate_boundary` | stable_within_workspace | Root-owned WAF core |
| `WafCoreConfig` | `waf::WafCoreConfig` | `internal_public_for_crate_boundary` | stable_within_workspace | Root-owned WAF config |

## 2. Binary Targets

| Binary | Path | Classification | Stability | Notes |
|--------|------|---------------|-----------|-------|
| `synvoid` | `src/main.rs` | `stable_public` | stable | Main CLI entrypoint |
| `synvoid-vpn` | `src/bin/synvoid-vpn.rs` | `stable_internal` | stable | VPN client binary |
| `server` | `src/bin/server.rs` | `stable_internal` | stable | Server binary |

## 3. CLI Commands

| Command | Classification | Side Effects | Auth | Runtime Dependency | Tests |
|---------|---------------|-------------|------|-------------------|-------|
| Default (no flags) | runtime launch | starts supervisor | none | supervisor process | plan tests |
| `--configtest` | one-shot local | reads config files | none | filesystem only | plan tests |
| `--export-openapi` | one-shot local | stdout JSON | none | none | plan tests |
| `--export-api-spec` | one-shot local | stdout JSON | none | none | plan tests |
| `--genesis` | one-shot local | generates key | none | mesh feature | plan tests |
| `--show-node-info` | one-shot local | reads config | none | mesh feature | plan tests |
| `--generatetoken` | one-shot local | stdout token | none | none | plan tests |
| `--generatenewtoken` | one-shot local | writes config | none | filesystem | plan tests |
| `--hash-token` | one-shot local | stdout hash | none | none | plan tests |
| `--check-regex` | one-shot local | stdout result | none | none | plan tests |
| `--status` | supervisor control | IPC query | IPC auth | running supervisor | plan tests |
| `--stop` | supervisor control | IPC stop | IPC auth | running supervisor | plan tests |
| `--rehash` | supervisor control | IPC reload | IPC auth | running supervisor | plan tests |
| `--export-threat-feed` | supervisor control | IPC export | IPC auth | mesh feature | plan tests |
| `--restart` | pre-action + runtime | IPC stop + launch | IPC auth | running supervisor | plan tests |
| `--cpu-worker` | runtime launch | starts CPU worker | none | IPC to supervisor | plan tests |
| `--unified-server-worker` | runtime launch | starts unified worker | none | IPC to supervisor | plan tests |
| `--mesh-agent` | runtime launch | starts mesh agent | none | mesh feature | plan tests |
| `--wasm-jail` | runtime launch | starts WASM jail | none | none | plan tests |
| `--yara-jail` | runtime launch | starts YARA jail | none | none | plan tests |

## 4. Admin Endpoints Summary

~240 distinct endpoint registrations across 22 handler files. See `src/admin/mod.rs` for route tree.

### By Category

| Category | Endpoints | Method Mix | Feature Gate |
|----------|-----------|------------|-------------|
| Config (main + sub-sections) | ~97 | GET/PUT | none |
| Sites | 11 | GET/POST/PUT/DELETE | none |
| Upstreams | 3 | GET/POST | none |
| Stats | 7 | GET | none |
| Logs | 4 | GET/PUT | none |
| System | 12 | GET/POST | none |
| Probes | 11 | GET/POST/DELETE | none |
| Threat Level | 11 | GET/POST/DELETE | none |
| Rule Feed | 4 | GET/POST | none |
| Observability | 6 | GET | none |
| Auth | 3 | POST/GET/DELETE | none |
| Theme | 4 | GET/PUT | none |
| TCP/UDP | 4 | GET/POST/DELETE | none |
| Alerting | 3 | GET/PUT/POST | none |
| API Discovery | 1 | GET | none |
| Plugins | 5 | GET/POST | none |
| Mesh Admin | 20 | GET/POST/DELETE | mesh |
| Mesh Topology | 2 | GET | mesh |
| Mesh Threat-Intel Policy | 2 | GET | mesh |
| Behavioral Intel | 2 | GET | mesh |
| YARA Rules | 10 | GET/POST/DELETE | mesh |
| ICMP Filter | 6 | GET/PUT/POST | mesh |
| Serverless | 5 | GET/PUT | mesh |
| Spin | 5 | GET/POST/DELETE | mesh |
| Honeypot | 4 | GET/POST/PUT | mesh |
| WebSocket | 2 | WS | none |

### Authority Classification

| Endpoint Type | Authority | Mutation Result | Audit | Propagation |
|--------------|-----------|----------------|-------|-------------|
| Config read | read-only diagnostic | N/A | no | N/A |
| Config write | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| Site CRUD | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| Block/Unblock | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| Mesh ban | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| Worker restart | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | local only |
| Threat level | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| YARA approve | AdminMutationAuthority::Admin | AdminMutationResult | AdminAuditEvent | QueuedBestEffort |
| Auth session | session-based | simple response | no | N/A |
| Stats/logs | read-only diagnostic | N/A | no | N/A |

## 5. Feature Profile Support Matrix

| Profile | Command | Supported | CI Gated | Runtime Behavior |
|---------|---------|-----------|----------|-----------------|
| default | `cargo build` | Yes | Yes | socket-handoff + mesh + dns + erased_pool + swagger-ui |
| no-default-features | `--no-default-features` | Yes | Yes | Core only; no mesh, DNS, socket-handoff |
| mesh | `--features mesh` | Yes | Yes | Mesh networking enabled |
| dns | `--features dns` | Yes | Yes | DNS server with DNSSEC |
| mesh,dns | `--features mesh,dns` | Yes | Yes | Full feature set |
| post-quantum | `--features post-quantum` | Yes | No | PQ TLS key exchange |
| wireguard | `--features wireguard` | Yes | No | WireGuard VPN tunnel |
| icmp-filter | `--features icmp-filter` | Yes | No | ICMP flood filtering |
| flood-ebpf | `--features flood-ebpf` | Yes | No | eBPF flood protection (Linux) |
| buffer | `--features buffer` | Yes | No | Buffer pool in synvoid-utils |
| erased_pool | `--features erased_pool` | Yes | Default | Type-erased HTTP client pool |
| swagger-ui | `--features swagger-ui` | Yes | Default | OpenAPI docs UI |
| socket-handoff | `--features socket-handoff` | Yes | Default | Socket transfer between processes |

## 6. Guardrail Completeness

| Guard | Invariant | Strength | Known Gaps | Required for Release |
|-------|-----------|----------|------------|---------------------|
| `root_facade_boundary_guard` | Domain crates don't import root `synvoid::` | Strong (fail-closed) | None | Yes |
| `root_module_ledger_guard` | Root modules in lib.rs are in ledger | Strong (fail-closed) | None | Yes |
| `root_dependency_ownership_guard` | Root deps have ledger entries | Strong (fail-closed) | None | Yes |
| `unified_server_lifecycle_ownership_guard` | No mem::forget, registered spawns | Strong (fail-closed) | None | Yes |
| `supervisor_task_ownership_guard` | Spawns only in allowlisted locations | Strong (fail-closed) | None | Yes |
| `request_path_capability_boundary_guard` | Request path uses narrow traits | Strong (fail-closed) | None | Yes |
| `data_plane_composition_boundary_guard` | Request path doesn't import concrete infra | Strong (fail-closed) | None | Yes |
| `http_request_pipeline_boundary_guard` | HTTP dispatch doesn't import lifecycle | Strong (fail-closed) | None | Yes |
| `http3_waf_boundary_guard` | HTTP/3 uses narrow traits only | Strong (fail-closed) | None | Yes |
| `mesh_id_boundary_guard` | Mesh-ID blocks admin-only | Strong (fail-closed) | None | Yes |
| `threat_intel_boundary_guard` | No raw lookups in enforcement | Strong (fail-closed) | None | Yes |
| `threat_intel_consumer_actionability_guard` | 7 enforcement rules | Strong (fail-closed) | None | Yes |
| `admin_mutation_response_guard` | Typed AdminMutationResult | Moderate (pattern scan) | None | Yes |
| `plugin_capability_boundary_guard` | 4 sandbox invariants | Strong (fail-closed) | None | Yes |
| `docs_path_reference_guard` | Markdown links valid | Strong (fail-closed) | None | Yes |
| `security_observability_guard` | Metric labels, registry signals | Strong (fail-closed) | None | Yes |
| `background_task_ownership_guard` | Background tasks registered | Strong (fail-closed) | None | Yes |
| `cli_command_dispatch_guard` | main.rs thin, dispatch in commands/ | Strong (fail-closed) | None | Yes |
| `manual_enforcement_provenance_guard` | block_ip_with_provenance used | Strong (fail-closed) | None | Yes |
| `unified_worker_composition_root_guard` | Composition root ≤80 lines | Strong (fail-closed) | None | Yes |
| `worker_mesh_supervision_boundary_guard` | Mesh supervision structural invariants | Strong (fail-closed) | None | Yes |
| `mesh_task_ownership_guard` | Mesh tasks registered/cancelled | Strong (fail-closed) | None | Yes |
| `admin_mutation_blocklist` | Blocklist mutation consistency | Strong (fail-closed) | None | Yes |
| `admin_auth_boundary` | Auth authority boundary | Strong (fail-closed) | None | Yes |
| `mesh_admin_edge_cases` | Mesh admin edge cases | Strong (fail-closed) | None | Yes |
| `plugin_failure_does_not_poison_manager` | Plugin failure isolation | Strong (fail-closed) | None | Yes |

## 7. Plugin API Surface

### Manifest Schema (declared in `synvoid-plugin.toml`)

| Item | File | Classification | Stability | Notes |
|------|------|---------------|-----------|-------|
| `PluginManifest` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:318` | stable_within_workspace | stable | Top-level manifest: name, version, entry, trust_tier, capabilities, limits, signature |
| `PluginTrustTier` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:16` | stable_within_workspace | stable | 5 variants: Disabled, LocalTrusted, LocalSandboxed (default), SignedSandboxed, DevelopmentHotReload |
| `PluginCapabilities` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:79` | stable_within_workspace | stable | Default-deny capability set; 11 fields |
| `PluginCapability` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:52` | stable_within_workspace | stable | 11 fine-grained capability tokens |
| `PluginLimits` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:220` | stable_within_workspace | stable | Per-plugin resource limits: timeout_ms, max_input/output_bytes, max_concurrency, memory_pages, fuel |
| `SigningPolicy` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:636` | stable_within_workspace | stable | RequireSigned (default), AllowUnsignedWithWarning, Disabled |

### Runtime Types (host-side, used by composition roots)

| Item | File | Classification | Stability | Notes |
|------|------|---------------|-----------|-------|
| `WasmRuntime` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:86` | internal_public_for_crate_boundary | stable | Core WASM runtime wrapping wasmtime Engine/Module/Linker |
| `WasmPluginManager` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:102` | internal_public_for_crate_boundary | stable | Multi-plugin manager: load, unload, reload, filter, transform |
| `WasmResourceLimits` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:50` | internal_public_for_crate_boundary | stable | Resource limits: max_memory_mb, max_cpu_fuel, timeout_seconds |
| `WasmFilterResult` | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:1925` | internal_public_for_crate_boundary | stable | Filter decision: Pass, Block, Challenge |
| `PluginInvocationGuard` | `crates/synvoid-plugin-runtime/src/sandbox/types.rs:741` | internal_public_for_crate_boundary | stable | Per-plugin invocation guard: capability checks, input size, concurrency, timeout |
| `GlobalPluginManager` | `crates/synvoid-plugin-runtime/src/global.rs:117` | internal_public_for_crate_boundary | stable | Singleton wrapping WasmPluginManager + GlobalWasmMemoryBudget |
| `PluginManager` | `crates/synvoid-plugin-runtime/src/plugin_manager.rs:16` | internal_public_for_crate_boundary | stable | Unified manager for WASM + Axum plugins |
| `PluginManagerLifecycle` | `crates/synvoid-plugin-runtime/src/plugin_manager.rs:169` | internal_public_for_crate_boundary | stable | Lifecycle manager with file watching and hot reload |

### WASM Guest ABI (provided to WASM plugins)

| Item | File | Classification | Stability | Notes |
|------|------|---------------|-----------|-------|
| `filter_request` (export) | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:31` | stable_within_workspace | stable | filter_request(method, uri, headers, body) -> i32 |
| `transform_response` (export) | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:35` | stable_within_workspace | stable | transform_response(status, body, out, max) -> i32 |
| `handle_request` (export) | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:41` | stable_within_workspace | stable | Serverless handler |
| Host functions | `crates/synvoid-plugin-runtime/src/wasm_runtime.rs:726+` | stable_within_workspace | stable | abort, check_timeout, get_env, mesh_query_dht, mesh_check_threat, mesh_emit_event, synvoid_read_body_chunk |

### Axum Native Plugin ABI (libloading)

| Item | File | Classification | Stability | Notes |
|------|------|---------------|-----------|-------|
| `synvoid_abi_version` | `crates/synvoid-plugin-runtime/src/axum_loader.rs:109` | stable_within_workspace | stable | ABI version check; plugin .so must export matching CARGO_PKG_VERSION |
| `create_router` | `crates/synvoid-plugin-runtime/src/axum_loader.rs:126` | stable_within_workspace | stable | Factory function returning *mut Router<()> |

### Spin Compatibility Layer

| Item | File | Classification | Stability | Notes |
|------|------|---------------|-----------|-------|
| `SpinManifest` | `crates/synvoid-plugin-runtime/src/spin/manifest.rs:7` | internal_public_for_crate_boundary | stable | Spin v2 manifest parser |
| `SpinAppsManager` | `crates/synvoid-plugin-runtime/src/spin/handler.rs:177` | internal_public_for_crate_boundary | stable | Registry for Spin app runtimes |

## 8. Config Keys (Top-Level TOML Sections)

### Core Server

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[server]` | `ServerConfig` | `crates/synvoid-config/src/server.rs:8` | None | host, port, host_v6, trusted_proxies. Default: 0.0.0.0:8080 |
| `[fallback]` | `FallbackConfig` | `crates/synvoid-config/src/server.rs:63` | None | mode ("return_404" or "proxy"), upstream |
| `[http]` | `HttpConfig` | `crates/synvoid-config/src/http.rs:8` | None | header_read_timeout, keep_alive, max_headers, max_request_size, pipeline_limit, waf_stall_timeout, max_connections |
| `[http3]` | `Http3Config` | `crates/synvoid-config/src/http.rs:133` | None | enabled, port, host_v6, alt_svc_max_age |
| `tokio` | `TokioConfig` | `crates/synvoid-config/src/http.rs:158` | None | Worker thread count; integer or "auto" |
| `[tls]` | `TlsConfig` | `crates/synvoid-config/src/tls.rs:12` | None | cert/key paths, ACME, post-quantum, OCSP, client_auth |

### Admin & Auth

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[admin]` | `AdminConfig` | `crates/synvoid-config/src/admin.rs:36` | None | enabled, port, bind_address, token, bcrypt_cost, trusted_proxies |
| `[admin.cors]` | `AdminCorsConfig` | `crates/synvoid-config/src/admin.rs:26` | None | allow_origin, allow_methods, allow_headers |
| `[admin.rate_limit]` | `AdminRateLimitConfig` | `crates/synvoid-config/src/admin.rs:57` | None | requests_per_minute (60), burst (10) |

### Security & Defaults

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[security]` | `MainSecurityConfig` | `crates/synvoid-config/src/security.rs:14` | None | sanitize_forwarded_headers, ipc_enforce_signing, strict_tls_passthrough_policy |
| `[defaults]` | `DefaultsConfig` | `crates/synvoid-config/src/defaults.rs:15` | None | Nested: ratelimit, blocked, honeypot, bot, challenge, auth, worker_pool, persistence, proxy_limits, blocklist_limits, tcp, udp, tarpit, upload, theme, traffic_shaping |
| `[threat_level]` | `ThreatLevelConfig` | `crates/synvoid-config/src/protection.rs:8` | None | initial, auto_scale, ban_durations, escalation |
| `[ip_feeds]` | `IpFeedConfig` | `crates/synvoid-config/src/protection.rs:230` | None | enabled, update_interval_hours, url |
| `[rule_feed]` | `RuleFeedConfig` | `crates/synvoid-config/src/protection.rs` | None | Rule feed configuration |
| `[yara_feed]` | `YaraRuleFeedConfig` | `crates/synvoid-config/src/protection.rs` | None | YARA rule feed configuration |

### Limits

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[rate_limit_memory]` | `RateLimitMemoryConfig` | `crates/synvoid-config/src/limits.rs:6` | None | max_ip_entries (100K), num_shards (256) |
| `[proxy_limits]` | `ProxyLimitsConfig` | `crates/synvoid-config/src/limits.rs:36` | None | max_response_size (10MB), connection_pool_size (100) |
| `[blocklist_limits]` | `BlocklistLimitsConfig` | `crates/synvoid-config/src/limits.rs:60` | None | max_entries (500K), persist_interval, target_state_ttl |

### Network

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[tcp]` | `TcpDefaults` | `crates/synvoid-config/src/network.rs:7` | None | enabled, worker_pool_size, protocols, syn_rate, connection_rate |
| `[udp]` | `UdpDefaults` | `crates/synvoid-config/src/network.rs` | None | UDP protocol configuration |
| `[tarpit]` | `TarpitDefaults` | `crates/synvoid-config/src/network.rs` | None | Tarpit configuration |
| `[traffic_shaping]` | `TrafficShapingConfig` | `crates/synvoid-config/src/traffic.rs` | None | Connection limits, bandwidth config |
| `[icmp_filter]` | `IcmpFilterConfig` | `crates/synvoid-config/src/icmp_filter.rs` | `icmp-filter` | ICMP filter configuration |
| `[honeypot_port]` | `HoneypotPortConfig` | `crates/synvoid-config/src/honeypot_port.rs:7` | None | enabled, ports, protocols, site_scope |

### Plugins & Serverless

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[plugins]` | `PluginConfig` | `crates/synvoid-config/src/plugins.rs:6` | None | wasm section: max_memory_mb, max_cpu_fuel, timeout_seconds, per-plugin instances |
| `[serverless]` | `ServerlessConfig` | `crates/synvoid-config/src/serverless.rs:6` | None | enabled, functions, default_memory_mb, default_cpu_fuel, waf_mode |

### Mesh & Tunnel (feature-gated)

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `mesh` | `MeshConfig` | `crates/synvoid-config/src/mesh.rs:663` | `mesh` | node_id, role, seeds, peers, tls, threat_intel, yara_rules, supervision |
| `[tunnel]` | `TunnelConfig` | `crates/synvoid-config/src/tunnel.rs:8` | None | enabled, vpn (WireGuard), quic, mesh |
| `[dns]` | `DnsConfig` | `crates/synvoid-config/src/dns/mod.rs` | `dns` | enabled, mode, listen, zones, dnssec, rate_limit |

### Process & Logging

| Key/Section | Type | File | Feature Gate | Notes |
|-------------|------|------|-------------|-------|
| `[process_manager]` | `ProcessManagerConfig` | `crates/synvoid-config/src/process.rs:161` | None | min/max_workers, unified_server_workers, restart_cooldown, control_api_addr |
| `[logging]` | `LoggingConfig` | `crates/synvoid-config/src/logging.rs:10` | None | level, access_log, retention_days, exporter |
| `[metrics]` | `MetricsConfig` | `crates/synvoid-config/src/admin.rs:212` | None | enabled, port. Default: true:9090 |
| `persistence` | `PersistenceConfig` | `crates/synvoid-config/src/defaults.rs:1011` | None | enabled, data_dir, persist_interval_secs |

## 9. Protocol and Serialization Surface

### IPC Protocol

| Component | Format | Trust Boundary | Fuzz Coverage | Panic Risk |
|-----------|--------|---------------|---------------|------------|
| IPC framing (4-byte BE + payload) | postcard | IPC channel (Unix socket/named pipe) | `fuzz_ipc` | Low (validated) |
| IPC message validation | struct fields | IPC channel | `fuzz_ipc` | Low (explicit validation) |
| Signed IPC | HMAC-SHA3-256 | IPC channel + file-based keys | `fuzz_ipc` | Low (constant-time) |

### Mesh Protocol

| Component | Format | Trust Boundary | Fuzz Coverage | Panic Risk |
|-----------|--------|---------------|---------------|------------|
| MeshMessage protobuf | prost | Mesh transport (TLS) | `fuzz_raft_response`, `fuzz_raft_commit_notification` | Low (prost decode) |
| Proto decode (130+ variants) | Rust enum | Mesh transport | `fuzz_protocol_proto_decode` | Low (TryFrom) |
| Mesh signing | Ed25519 + ML-DSA-44 | Mesh transport | none | Low |

### Config Parsing

| Component | Format | Trust Boundary | Fuzz Coverage | Panic Risk |
|-----------|--------|---------------|---------------|------------|
| MainConfig | TOML | Filesystem | none | Low (serde) |
| SiteConfig | TOML | Filesystem | none | Low (serde) |
| PluginManifest | TOML | Filesystem | `plugin_manifest` | Low (explicit error) |

### DNS

| Component | Format | Trust Boundary | Fuzz Coverage | Panic Risk |
|-----------|--------|---------------|---------------|------------|
| DNS wire format | hickory-proto | Network (UDP/TCP/QUIC) | `dns_message_decode` | Low |

### HTTP

| Component | Format | Trust Boundary | Fuzz Coverage | Panic Risk |
|-----------|--------|---------------|---------------|------------|
| Early HTTP parse | bytes | Network | `fuzz_early_parse` | Low |
| Path normalization | URL-encoded | Network | `http_path_normalization` | Low |
| WAF attack detection | synthetic HTTP | Network | `fuzz_attack_detection` | Low |

## 10. Stability Posture

### Semver Status

SynVoid is pre-1.0. Semver is not yet meaningful for external consumers. All crates are internal workspace implementation details unless explicitly documented otherwise.

### Public API Intent

| Crate | Public Intent | Stability |
|-------|--------------|-----------|
| `synvoid` (root) | Internal application crate | transitional (facades) |
| `synvoid-config` | Internal | stable within workspace |
| `synvoid-core` | Internal (admin types) | stable within workspace |
| `synvoid-waf` | Internal | stable within workspace |
| `synvoid-proxy` | Internal | stable within workspace |
| `synvoid-http` | Internal | stable within workspace |
| `synvoid-mesh` | Internal | stable within workspace |
| All other `synvoid-*` | Internal | stable within workspace |

### Deprecation Process

1. Root facade modules are transitional; new code should import dedicated crates directly.
2. `serder` module is deprecated and removable.
3. Compatibility re-exports (`ConfigManager`, etc.) remain for transitional API compatibility.
4. No compatibility promises for root facades until 1.0.

### Residual Risks

| Risk | Severity | Mitigation | Status |
|------|----------|-----------|--------|
| Pre-1.0 semver | Medium | Documented; no external API promises | Accepted |
| `split_required` modules still in root | Low | Extraction plan exists; 11 modules tracked | In progress |
| Mesh protocol has ~130 message types | Low | Fuzz coverage exists for decode paths | Accepted |
| Config fuzzing not implemented | Medium | Listed in ci_fuzz_failure_injection.md | Deferred |
| `serder` module is stale | Low | Candidate for removal | Accepted |
| Duplicate admin route registrations | Low | Investigate in Phase 11 | Known |
| No domain crate root imports | None | Guard passes | Clean |
| No request-path control-plane imports | None | Guard passes | Clean |
| No raw threat-intel enforcement | None | Guard passes | Clean |
| No mem::forget lifecycle leaks | None | Guard passes | Clean |
