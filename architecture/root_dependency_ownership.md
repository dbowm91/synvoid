# Root Dependency Ownership Ledger

This file records why each direct dependency in the root `synvoid` package exists. The root crate may depend on a crate only when the dependency is needed by a root-owned composition/runtime module, a temporary compatibility facade, or a documented migration blocker.

Classification values:

- `composition_runtime`: needed by root-owned startup/server/supervisor/worker/process code.
- `compat_facade`: retained for root compatibility paths only.
- `migration_blocker`: should move to a dedicated crate after blocker is resolved.
- `test_or_tooling`: needed only for tests, examples, or developer tooling.
- `remove_candidate`: appears removable after verification.

`Allowed root paths` is the mechanically checked entitlement: top-level `src/`
paths (file stems for root files, directory names otherwise) where root code may
reference the dependency, measured 2026-09-12 and enforced by
`root_dependency_entitlement_guard` in `tools/synvoid-repo-guards/tests/module_ownership.rs`.
`tests/, benches/` means test/tooling use only; `—` means no root consumer is
entitled (any new `use` must reclassify the row first). `test_or_tooling` rows are
exempt from the production-consumer requirement but must have a test/bench consumer.
`migration_blocker` rows with `—` are additionally fail-closed: a new production
reference fails the guard until the row is reclassified with a reason.

## Dependency Ledger

| Dependency | Root owner module(s) | Classification | Feature gate | Reason | Next action | Allowed root paths |
|------------|----------------------|----------------|--------------|--------|-------------|--------------------|
| tokio | server, supervisor, worker, startup, commands | composition_runtime | default | async runtime and task orchestration | keep | admin, bin, commands, honeypot_port, http, http_client, platform, process, sandbox, server, serverless, startup, supervisor, tarpit, tcp, test_utils, tls, udp, waf, worker |
| hyper | http, http_client | composition_runtime | default | HTTP/1 and HTTP/2 server and client | keep | http, tls |
| hyper-util | http, http_client | composition_runtime | default | HTTP connection pooling and utilities | keep | http, tls |
| hyper-rustls | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| tower | tests | test_or_tooling | default | Production use moved to domain crates (tower-http stack); root references only in tests/ | keep | tests/, benches/ |
| tower-http | http, admin | composition_runtime | default | HTTP middleware (filesystem, CORS) | keep | admin |
| axum | admin, http | composition_runtime | default | REST API framework for admin endpoints | keep | admin, bin, http |
| axum-extra | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| http-body | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| http-body-util | http, http_client | composition_runtime | default | HTTP body adapter utilities | keep | honeypot_port, http, server, tls |
| bytes | utils, buffer | composition_runtime | default | Efficient byte buffer management | keep | honeypot_port, http, http_client, mesh, server, serverless, tarpit, tls, waf, worker |
| serde | config, throughout | composition_runtime | default | Serialization framework | keep | admin, bin, honeypot_port, http, icmp_filter, mesh, platform, process, waf, worker |
| serde_json | config, admin, logging | composition_runtime | default | JSON serialization | keep | admin, bin, commands, honeypot_port, http, icmp_filter, platform, process, sandbox, server, serverless, supervisor, waf, worker |
| postcard | utils, mesh | composition_runtime | default | Compact binary serialization for distributed state | keep | supervisor, worker |
| rkyv | — | migration_blocker | default | No direct root consumer in src/ (last refs were Phase 25-removed facade copies; direct rkyv 0.8 use in domain crates); retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| toml | config | composition_runtime | default | TOML config file parsing | keep | admin, bin |
| anyhow | throughout | composition_runtime | default | Error context and chaining | keep | http_client, server |
| bitflags | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| tracing | throughout | composition_runtime | default | Structured logging framework | keep | admin, bin, commands, common, honeypot_port, http, icmp_filter, log_controller, mesh, platform, plugin, process, sandbox, server, serverless, startup, supervisor, tcp, tls, udp, utils, waf, worker |
| tracing-subscriber | startup | composition_runtime | default | Log output formatting and filtering | keep | bin, log_controller |
| tracing-appender | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| stegoeggo | worker | composition_runtime | default | Steganography detection in worker image-rights admission (src/worker/image_rights.rs), not WAF | keep | worker |
| regex | waf, logging, admin | composition_runtime | default | Pattern matching for WAF rules and log parsing | keep | admin, honeypot_port |
| parking_lot | throughout | composition_runtime | default | Fast mutex and RwLock implementations | keep | admin, honeypot_port, http, log_controller, process, serverless, supervisor, tarpit, tcp, tls, udp, waf, worker |
| dashmap | http_client, mesh | composition_runtime | default | Concurrent hash map for connection pools | keep | mesh, process, udp, waf, worker |
| arc-swap | config, http_client | composition_runtime | default | Atomic Arc pointer swapping for hot config | keep | waf |
| moka | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| memmap2 | block_store | composition_runtime | default | Memory-mapped file I/O for block store | keep | waf |
| metrics | metrics | composition_runtime | default | Metrics facade for observability | keep | admin, honeypot_port, http, icmp_filter, process, server, supervisor, tarpit, tcp, tls, udp, waf, worker |
| metrics-exporter-prometheus | metrics | composition_runtime | default | Prometheus metrics endpoint | keep | admin |
| http | http, http_client | composition_runtime | default | HTTP type definitions | keep | admin, honeypot_port, http, http_client, server, serverless, theme, tls, waf, worker |
| ipnetwork | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| rand | admin, commands, honeypot_port, process, supervisor, tarpit, waf | composition_runtime | default | Random number generation (admin tokens, PoW challenges, request IDs) | keep | admin, commands, honeypot_port, process, supervisor, tarpit, waf |
| base64 | utils, mesh | composition_runtime | default | Base64 encoding/decoding | keep | admin, commands, waf |
| sha2 | admin, process, supervisor, waf, worker | composition_runtime | default | SHA-256 hashing | keep | admin, process, supervisor, waf, worker |
| hex | admin, commands, honeypot_port, waf | composition_runtime | default | Hex encoding/decoding | keep | admin, commands, honeypot_port, waf |
| futures | http_client, proxy | composition_runtime | default | Async stream and future utilities | keep | admin, http, tarpit, waf, worker |
| sysinfo | admin, startup | composition_runtime | default | System resource monitoring | keep | admin, process, worker |
| nix | platform, process | composition_runtime | default | Unix system calls (signals, sockets, process) | keep | platform, process, tls, worker |
| chrono | config, logging | composition_runtime | default | Date/time handling with serde support | keep | admin, http, serverless, waf |
| notify | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| aho-corasick | — | migration_blocker | default | No direct root consumer in src/ (last ref was a Phase 25-removed honeypot_port facade copy; canonical WAF use in synvoid-waf); retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| unicode-normalization | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| libinjectionrs | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| serde_bytes | — | migration_blocker | default | No direct root consumer in src/ (last ref was the Phase 25-removed src/process/ipc_signed.rs facade copy; canonical use in synvoid-ipc); retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| synvoid-cli | commands | composition_runtime | default | CLI argument parsing definitions | keep | commands, main |
| synvoid-config | config | composition_runtime | default | Configuration types and ConfigManager | keep | admin, commands, config, http, static_files, supervisor, waf, worker |
| synvoid-dns | dns | composition_runtime | dns | DNS server with DNSSEC validation | keep | dns |
| synvoid-icmp-filter | icmp_filter | composition_runtime | icmp-filter | ICMP filtering | keep | icmp_filter |
| synvoid-honeypot | honeypot_port | composition_runtime | default | Honeypot port detection | keep | honeypot_port |
| synvoid-upload | http, waf, worker | composition_runtime | default | File upload handling in synvoid_upload; root upload/ removed Phase 03 | keep | http, waf, worker |
| synvoid-yara | worker, supervisor | composition_runtime | default | Canonical YARA engine for CPU worker + mesh validator injection (Phase 26 single yara-x owner; Phase 29 jail service lives in synvoid-jail-runtime) | keep | supervisor, worker |
| synvoid-ipc | process | composition_runtime | default | IPC transport abstractions | keep | http, process, sandbox, supervisor, worker |
| synvoid-http-client | http_client | composition_runtime | default | HTTP client pool and QUIC dispatch | keep | http, http_client, tls |
| synvoid-platform | platform | composition_runtime | default | Platform detection and OS abstractions | keep | platform |
| synvoid-upstream | upstream | composition_runtime | default | Upstream server selection | keep | lib |
| synvoid-tunnel | tunnel | composition_runtime | default | Tunnel backend routing | keep | tunnel |
| hickory-proto | — | migration_blocker | dns | No direct root consumer in src/ (measured 2026-09-12); retained for dns feature-surface wiring (dep:hickory-proto) | Phase 31 removal audit | — |
| hickory-resolver | — | migration_blocker | dns | No direct root consumer in src/ (measured 2026-09-12); retained for dns feature-surface wiring (dep:hickory-resolver) | Phase 31 removal audit | — |
| thiserror | throughout | composition_runtime | default | Derive macro for error types | keep | admin, honeypot_port, icmp_filter, mesh, platform, process, server, serverless |
| getrandom | — | migration_blocker | dns | No direct root consumer in src/ (measured 2026-09-12); retained for dns feature-surface wiring (dep:getrandom) | Phase 31 removal audit | — |
| clap | commands | composition_runtime | default | CLI subcommand parsing | keep | bin, main |
| tempfile | tests | test_or_tooling | default | Test fixtures (integration suites + src unit tests); last production ref was the Phase 25-removed src/process/manager.rs facade copy | keep | tests/, benches/ |
| uuid | config, tests | composition_runtime | default | UUID generation for request IDs | keep | admin, serverless |
| pin-project-lite | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| bcrypt | admin | composition_runtime | default | Password hashing for admin auth | keep | admin |
| dirs | — | migration_blocker | default | No direct root consumer in src/ (last ref was a Phase 25-removed src/process facade copy; canonical use in domain crates); retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| flate2 | worker (unit tests) | test_or_tooling | default | Gzip fixtures for worker minifier unit tests (src/worker/mod.rs); production bundles moved to synvoid-serverless | keep | tests/, benches/ |
| tar | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| mime_guess | admin | composition_runtime | default | MIME type detection for SPA static file serving | keep | admin |
| pqc | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| zeroize | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| walkdir | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| rusqlite | block_store | composition_runtime | default | SQLite for block store persistence | keep | honeypot_port, waf |
| tokio-rustls | http_client, tls | composition_runtime | default | TLS stream integration with Tokio | keep | tls |
| rustls | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); retained for workspace TLS feature unification (prefer-post-quantum, aws-lc-rs); direct use in synvoid-tls | Phase 31 per-crate feature audit | — |
| rustls-pki-types | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| aws-lc-rs | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); retained for workspace TLS feature unification (unstable for ML-DSA); direct use in synvoid-tls | Phase 31 per-crate feature audit | — |
| subtle | admin, bin, process, waf | composition_runtime | default | Constant-time comparisons for security | keep | admin, bin, process, waf |
| cryptoki | — | remove_candidate | — | Phase 30: removed from root (no `dep:cryptoki` edge). PKCS#11/HSM ownership moved to `synvoid-dnssec-keystore` behind its opt-in `pkcs11`/`hsm` features (root `dns-hsm`); normal builds carry no PKCS#11 provider surface | Phase 30 extraction | — |
| quinn | http3, tunnel | composition_runtime | default | QUIC protocol implementation | keep | tcp |
| zip | serverless | composition_runtime | default | ZIP archive handling for WASM bundles | keep | platform |
| libloading | platform (Windows Wintun only) | composition_runtime | windows-target only | Independent platform use only (src/platform/windows/wintun.rs, `#[cfg(windows)]`). Must NOT be used for plugin loading: plugin loader authority moved to synvoid-native-extension in Phase 28 | keep | platform |
| synvoid-native-extension | plugin | composition_runtime | unsafe-native-extensions (opt-in, off by default) | Explicit unsafe in-process native extension loader (Phase 28): ABI/version checks, path/hash/permission validation, library lifetime, narrow backend trait | keep | plugin |
| aya | worker | composition_runtime | flood-ebpf | eBPF program loading for SYN flood detection | keep | icmp_filter, waf |
| synvoid-utils | throughout | composition_runtime | default | Shared utilities (DrainFlag, buffer, IP utils) | keep | admin, http, lib, utils, waf, worker |
| synvoid-core | waf, proxy | composition_runtime | default | Core WAF and proxy types | keep | admin, supervisor, waf, worker |
| synvoid-tarpit | tarpit | composition_runtime | default | Tarpit Markov chain generation | keep | tarpit, waf |
| synvoid-auth | waf | compat_facade | default | Canonical AuthManager/session/CSRF/lockout in synvoid_auth; root auth/ removed Phase 03; consumed from src/waf | keep | waf |
| synvoid-challenge | server, waf | compat_facade | default | Canonical ChallengeManager/ChallengeConfig/mesh-PoW in synvoid_challenge; root challenge/ removed Phase 03; consumed from src/server, src/waf | keep | server, waf |
| synvoid-waf | waf | composition_runtime | default | WAF rule engine and detection | keep | http, server, waf |
| synvoid-plugin-runtime | plugin | composition_runtime | default | WASM plugin runtime and instance pooling | keep | admin, plugin, sandbox, spin, worker |
| synvoid-jail-runtime | sandbox | composition_runtime | default | Child-side jail execution package (Phase 29): WASM/YARA services + sandbox-entry sequencing + dedicated binaries; root sandbox facades/shims delegate to it | keep | sandbox |
| synvoid-tls | tls | composition_runtime | default | TLS termination and ACME | keep | supervisor, tls |
| synvoid-proxy-cache | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); root proxy_cache/ removed Phase 03; canonical synvoid_proxy_cache | Phase 31 removal audit | — |
| synvoid-admin | admin | composition_runtime | default | Admin API handler types | keep | admin |
| synvoid-proxy | proxy | composition_runtime | default | Reverse proxy routing and location matching | keep | http, location_matcher, protocol, proxy, router, router_adapter, streaming, tls, waf |
| synvoid-http | http | composition_runtime | default | Canonical HTTP parsing/normalization/body-policy/dispatch; root `http` is application composition over it (Phase 20) | keep | http, listener, server, tls, waf, worker |
| synvoid-http3 | http3 | composition_runtime | default | HTTP/3 QUIC server | keep | http3 |
| synvoid-serverless | serverless | composition_runtime | default | Serverless WASM function runtime | keep | serverless, worker |
| synvoid-geoip | geoip | composition_runtime | default | GeoIP database lookups | keep | admin, lib |
| synvoid-integrity | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); retained for origin_key_exchange feature-surface wiring (synvoid-integrity/origin_key_exchange) | Phase 31 removal audit | — |
| synvoid-mesh | mesh | composition_runtime | mesh | Mesh networking, DHT, transport, Raft | keep | admin, http, mesh, supervisor, worker |
| synvoid-mesh-protocol | waf | composition_runtime | mesh | Low-capability wire/identity verification vocabulary (Phase 27); feed signature + threat value types without DHT/Raft/SQLite/YARA | keep | waf |
| synvoid-app-handlers | fastcgi, mime | composition_runtime | default | Application protocol handlers; root cgi/ + php/ removed Phase 03 (canonical synvoid_app_handlers::cgi/php); root facades remain for fastcgi/mime | keep | fastcgi, mime |
| synvoid-metrics | metrics | composition_runtime | default | Metrics collection and export | keep | admin, http, metrics, supervisor, tls, worker |
| synvoid-theme | theme | composition_runtime | default | Theme rendering and templates | keep | theme |
| synvoid-block-store | block_store | composition_runtime | default | Block store persistence and export | keep | admin, block_store, process, supervisor, waf, worker |
| synvoid-app-server | app_server | composition_runtime | default | Granian app-server integration | keep | app_server, worker |
| synvoid-vpn-client | vpn_client | composition_runtime | default | VPN client tunnel management | keep | vpn_client |
| synvoid-filter | tcp, udp | composition_runtime | default | Protocol filtering traits and engine; root filter/ removed Phase 03; consumed from src/tcp, src/udp | keep | tcp, udp |
| synvoid-static-files | static_files | composition_runtime | default | Static file serving and directory listing | keep | http, static_files, tls, worker |
| url | config, http | composition_runtime | default | URL parsing and manipulation | keep | admin, http |
| syslog | logging | remove_candidate | default | Syslog transport (dead module - logging removed) | removed with logging module | — |
| log | — | migration_blocker | default | Prior claim of src/waf/endpoints.rs use is stale (no log:: reference repo-wide, measured 2026-09-12); logging facade use moved to domain crates | Phase 31 removal audit | — |
| schemars | config | composition_runtime | default | JSON Schema generation for config | keep | admin, commands, mesh |
| utoipa | admin | composition_runtime | default | OpenAPI schema generation | keep | admin |
| utoipa-swagger-ui | admin | composition_runtime | swagger-ui | Swagger UI for API docs | keep | admin |
| prost | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| lru_time_cache | http_client | composition_runtime | default | Time-expiring LRU cache | keep | waf |
| indexmap | config, http | composition_runtime | default | Insertion-ordered hash map | keep | waf |
| ahash | http_client, mesh | composition_runtime | default | Fast hashing for concurrent maps | keep | utils |
| smallvec | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| aes-gcm | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| async-trait | throughout | composition_runtime | default | Async trait support | keep | honeypot_port, http, mesh, waf, worker |
| daemonize2 | startup | composition_runtime | default | Process daemonization | keep | platform, startup |
| digest | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| ed25519-dalek | supervisor, waf | composition_runtime | default | Ed25519 signatures | keep | supervisor, waf |
| rsa | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| rand_core_06 | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| hkdf | supervisor, worker | composition_runtime | default | HKDF key derivation | keep | supervisor, worker |
| hmac | process, waf | composition_runtime | default | HMAC message authentication | keep | process, waf |
| socket2 | platform | composition_runtime | default | Low-level socket options | keep | process, tcp, udp |
| sha1 | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| sha3 | — | migration_blocker | default | No direct root consumer in src/ (last ref was a Phase 25-removed src/process facade copy; canonical use in domain crates); retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| x25519-dalek | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| base32 | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| libc | platform, process | composition_runtime | default | Raw libc bindings for Unix syscalls | keep | icmp_filter, platform, process, tcp |
| windows-sys | platform | composition_runtime | default | Windows API bindings | keep | icmp_filter, platform, process |
| tonic | admin | composition_runtime | default | gRPC framework for supervisor control | keep | supervisor |
| tonic-reflection | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| tonic-prost | — | migration_blocker | default | No direct root consumer in src/ (measured 2026-09-12); canonical use in domain crates; retained pending Phase 31 per-crate feature audit | Phase 31 removal audit | — |
| openraft | — | migration_blocker | mesh | No direct root consumer in src/ (measured 2026-09-12); retained for mesh feature-surface wiring (dep:openraft); mesh Raft lives in synvoid-mesh | Phase 31 removal audit | — |
| async-stream | http_client, mesh | composition_runtime | default | Async stream macro | keep | tarpit |

## Build Dependencies

| Dependency | Root owner module(s) | Classification | Feature gate | Reason | Next action | Allowed root paths |
|------------|----------------------|----------------|--------------|--------|-------------|--------------------|
| tonic-prost-build | admin (protobuf codegen) | composition_runtime | default | Protobuf code generation for gRPC admin/control APIs | keep | build.rs |
| chrono | admin (protobuf codegen) | composition_runtime | default | Timestamp types in protobuf code generation | keep | build.rs |
