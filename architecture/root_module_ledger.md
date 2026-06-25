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
| admin | Admin API routes, auth, CORS, metrics endpoints | split_required | root app crate (composition) + potential synvoid-admin | mixed — root-owned Axum router wiring WAF, config, mesh, metrics | Inventory admin submodules for domain types that could move to a crate |
| commands | CLI and supervisor command dispatch (plan + execute) | keep_app_root | root app crate | typed command plan + execution layer | Thin dispatch module; delegates to existing runtime/supervisor modules |
| app_server | Granian app-server integration | facade_existing_crate | synvoid-app-server | pure re-export facade | Prefer `synvoid_app_server` in domain crates |
| auth | Authentication, session management, CSRF, brute-force lockout | split_required | potential synvoid-auth crate | real implementation (1135 lines) | Only depends on `DrainFlag`; good extraction candidate. Verify no circular deps before moving |
| block_store | Block-store re-exports | facade_existing_crate | synvoid-block-store / synvoid-core | pure re-export facade | Prefer `synvoid_block_store` in domain crates |
| buffer | Buffer pool re-export from synvoid-utils | facade_existing_crate | synvoid-utils | inline re-export | Prefer `synvoid_utils::buffer` in domain crates |
| captcha | SVG captcha generation and verification | split_required | potential synvoid-captcha or root | real implementation (197 lines) | Self-contained; depends on synvoid-theme. Good extraction candidate |
| cgi | CGI handler | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::cgi` in domain crates |
| challenge | Challenge orchestration (PoW, CSS, honeypot, mesh-PoW) | split_required | root app crate (orchestration) + synvoid-challenge (primitives) | hybrid — re-exports from synvoid-challenge + local ChallengeManager | Local orchestration depends on root infra; primitives already extracted |
| common | Panic handler setup | keep_app_root | root app crate | small utility (53 lines) | Process-level panic hook; root-owned |
| config | Configuration types and loaders | facade_existing_crate | synvoid-config | facade with compat submodules | Prefer `synvoid_config` in domain crates; compat shims (`main`, `site`, `dns`, `protection`, `traffic`) provide legacy paths |
| dns | DNS server with DNSSEC (feature-gated) | facade_existing_crate | synvoid-dns | feature-gated re-export | Prefer `synvoid_dns` in domain crates |
| drain | Connection drain state for graceful shutdown | keep_app_root | root app crate | real implementation (94 lines) | Process-level shutdown coordination; root-owned |
| fastcgi | FastCGI handler | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::fastcgi` in domain crates |
| filter | Protocol filtering traits and config | split_required | root app crate or potential synvoid-filter | real implementation (159 lines) | Generic protocol filtering used by TCP/UDP proxy; investigate if shared with synvoid-proxy |
| geoip | GeoIP lookups | facade_existing_crate | synvoid-geoip | root re-export (`pub use`) | Prefer `synvoid_geoip` in domain crates |
| honeypot_port | Honeypot port detection | facade_existing_crate | synvoid-honeypot | pure re-export facade | Prefer `synvoid_honeypot` in domain crates |
| http | HTTP server modules (43 submodules) | split_required | root app crate (composition) + synvoid-http (shared) | mixed — submodule hub with real root-owned code | Large module; inventory submodules for domain types that could move |
| http3 | HTTP/3 QUIC server | facade_existing_crate | synvoid-http3 | pure re-export facade — only `Http3Server` and `Http3WafBackend` re-exported | Prefer `synvoid_http3` in domain crates |
| http_client | HTTP client + QUIC tunnel dispatch | split_required | synvoid-http-client (pool/client) + root (QUIC dispatch) | facade with local adapter — re-exports crate + root-owned `quic_tunnel_dispatch` and `streaming_waf_body` submodules | QUIC tunnel dispatch depends on root tunnel/QUIC infra; cannot fully extract yet |
| icmp_filter | ICMP filtering (feature-gated) | keep_app_root | root app crate | feature-gated | Network-level filtering; root-owned |
| integrity | Integrity checking | facade_existing_crate | synvoid-integrity | root re-export (`pub use`) | Prefer `synvoid_integrity` in domain crates |
| listener | Connection listener | facade_existing_crate | synvoid-http | pure re-export facade | Prefer `synvoid_http::listener` in domain crates |
| location_matcher | URL location matching | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::location_matcher` in domain crates |
| log_controller | Log controller | keep_app_root | root app crate | log management | Process-level logging; root-owned |
| logging | Syslog configuration | split_required | potential config/syslog module or root | real implementation (205 lines) | Self-contained syslog types; could merge into synvoid-config |
| mesh | Mesh networking | facade_existing_crate | synvoid-mesh | pure re-export facade | Prefer `synvoid_mesh` in domain crates; feature-gated `mesh` |
| metrics | Metrics re-exports | facade_existing_crate | synvoid-metrics | facade with local tests — glob re-export plus root-level test module | Prefer `synvoid_metrics` in domain crates |
| mime | MIME type handling | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::mime` in domain crates |
| php | PHP handler | facade_existing_crate | synvoid-app-handlers | pure re-export facade | Prefer `synvoid_app_handlers::php` in domain crates |
| platform | Platform abstraction (OS detection, IPC, sandbox) | split_required | synvoid-platform (core) + root (app-level integration) | mixed — re-exports from 6 submodules + real platform detection code | Platform enum and detection methods are root-owned; could extract to synvoid-platform |
| plugin | WASM plugin runtime | split_required | root app crate (composition) + synvoid-plugin-runtime | mixed | Plugin lifecycle management is root-owned; runtime in dedicated crate |
| process | IPC/process-mode integration | facade_existing_crate | synvoid-ipc | pure re-export facade | Prefer `synvoid_ipc` in domain crates |
| protocol | Protocol detection types | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::protocol` in domain crates |
| proxy | Reverse proxy and routing | facade_existing_crate | synvoid-proxy | facade with local adapter — glob re-export + root trait-bound `ProxyServer` type alias | Prefer `synvoid_proxy` in domain crates; type alias `ProxyServer` has root trait bound |
| proxy_cache | Proxy caching | facade_existing_crate | synvoid-proxy-cache | root re-export (`pub use`) | Prefer `synvoid_proxy_cache` in domain crates |
| router | URL routing | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::router` in domain crates |
| router_adapter | Router adapter | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::router_adapter` in domain crates |
| sandbox | Sandbox process modes (WASM/YARA jails) | keep_app_root | root app crate | stub implementation (54 lines) | Process entry points for sandbox modes; mostly TODO stubs |
| serder | Rkyv migration documentation stub | legacy_or_stale | none | stale — 98% doc comments, 2 lines of code | Candidate for removal; actual serialization lives in synvoid-utils |
| serialization | Serialization re-export from synvoid-utils | facade_existing_crate | synvoid-utils | root re-export (`pub use`) | Prefer `synvoid_utils::serialization` in domain crates |
| server | UnifiedServer composition root | keep_app_root | root app crate | real implementation (1344 lines) | Heavy composition root wiring all subsystems |
| serverless | Serverless runtime | facade_existing_crate | synvoid-serverless | pure re-export facade | Prefer `synvoid_serverless` in domain crates |
| spin | Spin WASM runtime | facade_existing_crate | synvoid-plugin-runtime | pure re-export facade | Prefer `synvoid_plugin_runtime::spin` in domain crates |
| startup | Process startup and bootstrap | keep_app_root | root app crate | real implementation | Supervisor-level startup orchestration |
| static_files | Static file handling | facade_existing_crate | synvoid-static-files | facade with local adapter — re-exports crate + root-owned `file_manager` submodule | Prefer `synvoid_static_files` in domain crates; local `file_manager` needs investigation |
| streaming | Bidirectional streaming proxy | facade_existing_crate | synvoid-proxy | pure re-export facade | Prefer `synvoid_proxy::bidirectional` in domain crates |
| supervisor | Supervisor process lifecycle | keep_app_root | root app crate | facade over submodules | Process-level supervision; root-owned |
| tarpit | Tarpit response generation | split_required | root app crate (handler) + synvoid-tarpit (Markov chain) | hybrid — re-exports Markov chain + local handler | Handler depends on root request infra; Markov chain already extracted |
| tcp | TCP proxy with protocol detection | keep_app_root | root app crate | real implementation | Network-level proxy; root-owned |
| theme | Theme/rendering | facade_existing_crate | synvoid-theme | pure re-export facade | Prefer `synvoid_theme` in domain crates |
| tls | TLS termination and ACME | split_required | synvoid-tls (core) + root (server integration) | mixed — re-exports + local `server` submodule | Local `HttpsServer` depends on root HTTP infra; core TLS in dedicated crate |
| tunnel | Tunnel backend routing | facade_existing_crate | synvoid-tunnel | pure re-export facade | Prefer `synvoid_tunnel` in domain crates |
| udp | UDP proxy | keep_app_root | root app crate | real implementation | Network-level proxy; root-owned |
| upload | Upload handling | facade_existing_crate | synvoid-upload | pure re-export facade | Prefer `synvoid_upload` in domain crates |
| upstream | Upstream proxy | facade_existing_crate | synvoid-upstream | root re-export (`pub use`) | Prefer `synvoid_upstream` in domain crates |
| utils | Utility types and helpers | split_required | synvoid-utils (shared) + root (app-level utils) | mixed | Some utils are root-specific; shared utils in synvoid-utils |
| vpn_client | VPN client | facade_existing_crate | synvoid-vpn-client | pure re-export facade | Prefer `synvoid_vpn_client` in domain crates |
| waf | WAF engine and adapters | split_required | synvoid-waf (core) + root (WafCore, adapters) | mixed — massive real implementation (1056 lines) + re-exports | WafCore and root adapters are the dominant code; core WAF traits/primitives in synvoid-waf |
| worker | Worker process runtime and composition | keep_app_root | root app crate | real implementation + re-exports | Worker process entry points and composition root |

## Re-export Summary

The following root paths are direct crate re-exports (not module declarations):

| Root path | Re-exported crate | Classification |
|-----------|-------------------|----------------|
| `geoip` | `synvoid_geoip` | facade_existing_crate |
| `integrity` | `synvoid-integrity` | facade_existing_crate |
| `proxy_cache` | `synvoid-proxy-cache` | facade_existing_crate |
| `serialization` | `synvoid_utils::serialization` | facade_existing_crate |
| `upstream` | `synvoid-upstream` | facade_existing_crate |
| `buffer` | `synvoid_utils::buffer` | facade_existing_crate |

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
| `WafCore` | `waf::WafCore` | Root-owned WAF core |
| `WafCoreConfig` | `waf::WafCoreConfig` | Root-owned WAF config |

## Feature-Gated Modules

| Module | Feature gate | Classification |
|--------|-------------|----------------|
| `mesh` | `mesh` | facade_existing_crate → synvoid-mesh |
| `dns` | `dns` | facade_existing_crate → synvoid-dns |
| `icmp_filter` | `icmp-filter` | keep_app_root |
| `test_utils` | `test` or `test-utils` | keep_app_root (test support) |
