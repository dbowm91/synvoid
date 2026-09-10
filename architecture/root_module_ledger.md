# Root Module Ownership Ledger

This ledger records the intended ownership of modules exported by the root `synvoid` crate. It exists to prevent the root crate from silently remaining the canonical owner of domain implementation code after dedicated crates have been introduced.

Classification values:

- `keep_app_root`: root application/runtime composition remains the owner;
- `facade_existing_crate`: compatibility facade over a dedicated crate; new code should prefer the dedicated crate;
- `split_required`: mixed module that needs a targeted extraction plan;
- `legacy_or_stale`: candidate for deletion or collapse after verification.

Status vocabulary:

- **pure re-export facade**: the root module only re-exports a dedicated crate or crate submodule;
- **facade with local adapter/submodule**: the root module mostly re-exports a crate but still contains root-specific adapters, aliases, or submodules;
- **mixed implementation**: the root module contains real implementation that needs a targeted extraction plan;
- **root runtime owner**: the root module remains the current owner of process/runtime composition behavior;
- **stale candidate**: the module appears removable or collapsible after verification.

## Module Ledger

| Root module | Current responsibility | Classification | Target owner | Current status | Blocker / next step |
|-------------|------------------------|----------------|--------------|----------------|---------------------|
| admin | Admin API transport: Axum router/middleware composition plus thin adapters over typed manager operations | keep_app_root | root app crate (composition) + synvoid-admin (reusable handler logic/DTOs) | root application composition — transport, route registration, middleware ordering, operator-identity extraction, response adaptation, explicit typed service wiring; reusable handler logic canonical in synvoid-admin | Full matrix: `architecture/admin_root_ownership.md` (Phase 21) |
| commands | CLI and supervisor command dispatch (plan + execute + runtime-launch boundary + typed result boundary + one-shot adapter) | keep_app_root | root app crate | typed command plan, execution layer, runtime-launch boundary, supervisor-control adapter, and one-shot adapter with typed outcomes/errors | Thin dispatch module; delegates to existing runtime/supervisor modules via typed adapters |
| app_server | Granian app-server integration | facade_existing_crate | synvoid-app-server | pure re-export facade | Prefer `synvoid_app_server` in domain crates |
| auth | Authentication, session management, CSRF, brute-force lockout | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Module removed; canonical `synvoid_auth` — see `architecture/facade_disposition_matrix.md` §4 |
| block_store | Block-store re-exports | facade_existing_crate | synvoid-block-store / synvoid-core | pure re-export facade | Prefer `synvoid_block_store` in domain crates |
| buffer | Buffer pool re-export from synvoid-utils | facade_existing_crate | synvoid-utils | inline re-export | Prefer `synvoid_utils::buffer` in domain crates |
| captcha | SVG captcha generation and verification | legacy_or_stale | none | removed (dead code, zero consumers) | Module removed; CaptchaPageTemplate in synvoid-theme is independent |
| cgi | CGI handler | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Module removed; canonical `synvoid_app_handlers::cgi` — see `architecture/facade_disposition_matrix.md` §4 |
| challenge | Challenge orchestration (PoW, CSS, honeypot, mesh-PoW) | legacy_or_stale | none | removed (Phase 03; zero workspace consumers since Phase 18) | Module removed; canonical `synvoid_challenge` — see `architecture/facade_disposition_matrix.md` §4 |
| common | Panic handler setup | keep_app_root | root app crate | small utility (53 lines) | Process-level panic hook; root-owned |
| config | Configuration types and loaders | facade_existing_crate | synvoid-config | facade with compat submodules | Prefer `synvoid_config` in domain crates; compat shims (`main`, `site`, `dns`, `protection`, `traffic`) provide legacy paths |
| dns | DNS server with DNSSEC (feature-gated) | facade_existing_crate | synvoid-dns | feature-gated re-export | Prefer `synvoid_dns` in domain crates |
| drain | Connection drain state for graceful shutdown | keep_app_root | root app crate | real implementation (94 lines) | Process-level shutdown coordination; root-owned |
| fastcgi | FastCGI handler | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::fastcgi` in domain crates |
| filter | Protocol filtering traits and config | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Module removed; canonical `synvoid_filter` — see `architecture/facade_disposition_matrix.md` §4 |
| geoip | GeoIP lookups | facade_existing_crate | synvoid-geoip | root re-export (`pub use`) | Prefer `synvoid_geoip` in domain crates |
| honeypot_port | Honeypot port detection | facade_existing_crate | synvoid-honeypot | pure re-export facade | Prefer `synvoid_honeypot` in domain crates |
| http | HTTP server application composition (42 submodules) | keep_app_root | root app crate (composition) + synvoid-http (shared) | root application composition — 24 thin facades + 11 narrow-trait adapters + 5 application handlers + HttpServer composition root; shared parsing/normalization/dispatch canonical in synvoid-http | Full matrix: `architecture/http_ownership_convergence.md` (Phase 20) |
| http3 | HTTP/3 QUIC server | facade_existing_crate | synvoid-http3 | pure re-export facade — only `Http3Server` and `Http3WafBackend` re-exported | Prefer `synvoid_http3` in domain crates |
| http_client | HTTP client + QUIC tunnel dispatch | facade_existing_crate | synvoid-http-client (pool/client) + root (QUIC dispatch) | facade with local adapter — re-exports crate + root-owned `quic_tunnel_dispatch`; `streaming_waf_body` is a pure re-export shim | QUIC tunnel dispatch depends on root tunnel/QUIC infra; cannot fully extract |
| icmp_filter | ICMP filtering (feature-gated) | keep_app_root | root app crate | feature-gated | Network-level filtering; root-owned |
| integrity | Integrity checking | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Re-export removed; canonical `synvoid_integrity` — see `architecture/facade_disposition_matrix.md` §4 |
| listener | Connection listener | facade_existing_crate | synvoid-http | pure re-export facade | Prefer `synvoid_http::listener` in domain crates |
| location_matcher | URL location matching | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::location_matcher` in domain crates |
| log_controller | Log controller | keep_app_root | root app crate | log management | Process-level logging; root-owned |
| logging | Syslog configuration | legacy_or_stale | none | removed (dead code, zero consumers) | Module removed; config::logging in synvoid-config is the active logging config |
| mesh | Mesh networking | facade_existing_crate | synvoid-mesh | pure re-export facade | Prefer `synvoid_mesh` in domain crates; feature-gated `mesh` |
| metrics | Metrics re-exports | facade_existing_crate | synvoid-metrics | facade with local tests — glob re-export plus root-level test module | Prefer `synvoid_metrics` in domain crates |
| mime | MIME type handling | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::mime` in domain crates |
| php | PHP handler | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Module removed; canonical `synvoid_app_handlers::php` — see `architecture/facade_disposition_matrix.md` §4 |
| platform | Platform abstraction (OS detection, IPC, sandbox) | keep_app_root | root app crate (composition) + synvoid-platform (core) | facade with local submodules — thin facade re-exports Platform/PlatformError/fs from synvoid-platform crate; root-owned sandbox/socket/ipc/process/service modules | Duplicate fs.rs removed; Platform enum and detection re-exported from crate |
| plugin | Plugin lifecycle/application composition plus facade over the canonical runtime | keep_app_root | root app crate (composition) + synvoid-plugin-runtime (runtime) | facade with local adapter — re-exports crate `PluginManager`/`PluginManagerLifecycle`; root-owned mesh-aware byte resolution; watcher/epoch owned by `PluginRuntimeOwner` | Full matrix: `architecture/admin_root_ownership.md` §D (Phase 21) |
| process | IPC/process-mode integration | facade_existing_crate | synvoid-ipc | pure re-export facade | Prefer `synvoid_ipc` in domain crates |
| protocol | Protocol detection types | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::protocol` in domain crates |
| proxy | Reverse proxy and routing | facade_existing_crate | synvoid-proxy | facade with local adapter — glob re-export + root trait-bound `ProxyServer` type alias | Prefer `synvoid_proxy` in domain crates; type alias `ProxyServer` has root trait bound |
| proxy_cache | Proxy caching | legacy_or_stale | none | removed (Phase 03; zero workspace consumers) | Re-export removed; canonical `synvoid_proxy_cache` — see `architecture/facade_disposition_matrix.md` §4 |
| router | URL routing | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::router` in domain crates |
| router_adapter | Router adapter | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::router_adapter` in domain crates |
| sandbox | Sandbox process modes (WASM/YARA jails) | keep_app_root | root app crate | real implementation — jail entry points + WASM/YARA execution services + policy client; protocol DTOs/supervision in synvoid-ipc | Phase 22 operational; spec `architecture/sandbox_jail_protocol.md` |
| serialization | Serialization re-export from synvoid-utils | facade_existing_crate | synvoid-utils | root re-export (`pub use`) | Prefer `synvoid_utils::serialization` in domain crates |
| server | UnifiedServer composition root | keep_app_root | root app crate | real implementation (modular: `startup_plan` + `resources` + `runtime_handles` + `plugin_runtime` + `service_assembly` + `listener_tasks` + `waf_handler`; Phase 04 `run()` orchestrates narrow subsystem/family builders) | Heavy composition root wiring all subsystems |
| serverless | Serverless runtime | facade_existing_crate | synvoid-serverless | pure re-export facade | Prefer `synvoid_serverless` in domain crates |
| spin | Spin WASM runtime | facade_existing_crate | synvoid-plugin-runtime | pure re-export facade | Prefer `synvoid_plugin_runtime::spin` in domain crates |
| startup | Process startup and bootstrap | keep_app_root | root app crate | real implementation | Supervisor-level startup orchestration |
| static_files | Static file handling | facade_existing_crate | synvoid-static-files | pure re-export facade | Prefer `synvoid_static_files` in domain crates; `FileManager` canonical in crate with injected `FileManagerSecurityBackend` (Phase 02) |
| streaming | Bidirectional streaming proxy | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::bidirectional` in domain crates |
| supervisor | Supervisor process lifecycle | keep_app_root | root app crate | facade over submodules | Process-level supervision; root-owned |
| tarpit | Tarpit response generation | keep_app_root | root app crate (handler) + synvoid-tarpit (Markov chain) | facade with local submodules — re-exports MarkovChain/TarpitConfig from synvoid-tarpit crate; root-owned TarpitHandler/TarpitManager | Dead generator.rs removed; facade documentation added |
| tcp | TCP proxy with protocol detection | keep_app_root | root app crate | real implementation | Network-level proxy; root-owned |
| theme | Theme/rendering | facade_existing_crate | synvoid-theme | pure re-export facade | Prefer `synvoid_theme` in domain crates |
| tls | TLS termination and ACME | keep_app_root | synvoid-tls (core) + root (server integration) | root runtime owner — re-exports + local `server` submodule (`HttpsServer` listener/integration depends on root HTTP infra); core TLS canonical in dedicated crate | `HttpsServer` request-flow convergence complete (Phase 01): canonical `prepare_http_request_flow` + `handle_http_request_postlude` with `ForwardedProtocol::Https` + JA4; see `http_ownership_convergence.md` §4 and `http_request_pipeline.md` stage matrix |
| tunnel | Tunnel backend routing | facade_existing_crate | synvoid-tunnel | pure re-export facade | Prefer `synvoid_tunnel` in domain crates |
| udp | UDP proxy | keep_app_root | root app crate | real implementation | Network-level proxy; root-owned |
| upload | Upload handling | legacy_or_stale | none | removed (Phase 03; single test consumer migrated) | Module removed; canonical `synvoid_upload` — see `architecture/facade_disposition_matrix.md` §4 |
| upstream | Upstream proxy | facade_existing_crate | synvoid-upstream | root re-export (`pub use`) | Prefer `synvoid_upstream` in domain crates |
| utils | Utility types and helpers | keep_app_root | root app crate (composition) + synvoid-utils (shared) | facade with local helpers — re-exports shared types from synvoid-utils crate; root-only ResultExt/OptionExt/errors/urlencoding/HotHashMap | Duplicate ArcStr, parse_duration, timestamp functions, etc. removed; re-exported from crate |
| vpn_client | VPN client | facade_existing_crate | synvoid-vpn-client | pure re-export facade | Prefer `synvoid_vpn_client` in domain crates |
| waf | WAF application composition over the canonical synvoid-waf engine | keep_app_root | root app crate (composition: WafCore/AppWaf, adapters, threat-level, rule/threat feeds, ASN, rate-limit core, traffic global) + synvoid-waf (detectors/policy/traits) | facade with local composition — reusable detectors are crate-owned thin facades; WafCore is documented composition (AppWaf alias); duplicates and hot-path placeholders removed (Phase 19) | Full WafCore move blocked: would pull GeoIP facade, tarpit handler, theme error pages, upload-validator static, traffic metrics, threat-level sqlite persistence, and worker RequestServices into the domain crate |
| worker | Worker process runtime and composition | keep_app_root | root app crate | real implementation + re-exports | Worker process entry points and composition root |

## Re-export Summary

The following root paths are direct crate re-exports (not module declarations):

| Root path | Re-exported crate | Classification |
|-----------|-------------------|----------------|
| `geoip` | `synvoid_geoip` | facade_existing_crate |
| `serialization` | `synvoid_utils::serialization` | facade_existing_crate |
| `upstream` | `synvoid-upstream` | facade_existing_crate |
| `buffer` | `synvoid_utils::buffer` | facade_existing_crate |

(`integrity` and `proxy_cache` re-exports removed in Phase 03; see disposition matrix §4.)

## Top-Level Re-exports from `src/lib.rs`

| Re-export | Source | Notes |
|-----------|--------|-------|
| `ConfigManager` | `config::ConfigManager` | Compatibility path |
| `errors` | `utils::errors` | Shared error types |
| `urlencoding_decode` | `utils::urlencoding_decode` | Utility function |
| `DrainFlag` | `utils::DrainFlag` | Shared drain flag |
| `OptionExt` | `utils::OptionExt` | Extension trait |
| `ResultExt` | `utils::ResultExt` | Extension trait |
| `RunningFlag` | `utils::RunningFlag` | Shared running flag |
| `WafCore` | `waf::WafCore` | Root-owned WAF application composition (`AppWaf` alias) |
| `WafCoreConfig` | `waf::WafCoreConfig` | Root-owned composition constructor (`AppWafConfig` alias) |

## Feature-Gated Modules

| Module | Feature gate | Classification |
|--------|-------------|----------------|
| `mesh` | `mesh` | facade_existing_crate → synvoid-mesh |
| `dns` | `dns` | facade_existing_crate → synvoid-dns |
| `icmp_filter` | `icmp-filter` | keep_app_root |
| `test_utils` | `test` or `test-utils` | keep_app_root (test support) |
