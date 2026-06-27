# Root Dependency Ownership Ledger

This file records why each direct dependency in the root `synvoid` package exists. The root crate may depend on a crate only when the dependency is needed by a root-owned composition/runtime module, a temporary compatibility facade, or a documented migration blocker.

Classification values:

- `composition_runtime`: needed by root-owned startup/server/supervisor/worker/process code.
- `compat_facade`: retained for root compatibility paths only.
- `migration_blocker`: should move to a dedicated crate after blocker is resolved.
- `test_or_tooling`: needed only for tests, examples, or developer tooling.
- `remove_candidate`: appears removable after verification.

## Dependency Ledger

| Dependency | Root owner module(s) | Classification | Feature gate | Reason | Next action |
|------------|----------------------|----------------|--------------|--------|-------------|
| tokio | server, supervisor, worker, startup, commands | composition_runtime | default | async runtime and task orchestration | keep |
| hyper | http, http_client | composition_runtime | default | HTTP/1 and HTTP/2 server and client | keep |
| hyper-util | http, http_client | composition_runtime | default | HTTP connection pooling and utilities | keep |
| hyper-rustls | http_client | composition_runtime | default | TLS for outbound HTTP/2 connections | keep |
| tower | http | composition_runtime | default | middleware and service abstractions | keep |
| tower-http | http, admin | composition_runtime | default | HTTP middleware (filesystem, CORS) | keep |
| axum | admin, http | composition_runtime | default | REST API framework for admin endpoints | keep |
| axum-extra | admin | composition_runtime | default | Typed header support for admin routes | keep |
| http-body | http, http_client | composition_runtime | default | HTTP body trait definitions | keep |
| http-body-util | http, http_client | composition_runtime | default | HTTP body adapter utilities | keep |
| bytes | utils, buffer | composition_runtime | default | Efficient byte buffer management | keep |
| serde | config, throughout | composition_runtime | default | Serialization framework | keep |
| serde_json | config, admin, logging | composition_runtime | default | JSON serialization | keep |
| postcard | utils, mesh | composition_runtime | default | Compact binary serialization for distributed state | keep |
| rkyv | utils, config | composition_runtime | default | Zero-copy deserialization for hot paths | keep |
| toml | config | composition_runtime | default | TOML config file parsing | keep |
| anyhow | throughout | composition_runtime | default | Error context and chaining | keep |
| bitflags | platform, sandbox | composition_runtime | default | Bitflag types for capabilities | keep |
| tracing | throughout | composition_runtime | default | Structured logging framework | keep |
| tracing-subscriber | startup | composition_runtime | default | Log output formatting and filtering | keep |
| tracing-appender | startup | composition_runtime | default | Log file rotation | keep |
| stegoeggo | waf | composition_runtime | default | Steganography detection in WAF | keep |
| regex | waf, logging, admin | composition_runtime | default | Pattern matching for WAF rules and log parsing | keep |
| parking_lot | throughout | composition_runtime | default | Fast mutex and RwLock implementations | keep |
| dashmap | http_client, mesh | composition_runtime | default | Concurrent hash map for connection pools | keep |
| arc-swap | config, http_client | composition_runtime | default | Atomic Arc pointer swapping for hot config | keep |
| moka | proxy_cache | composition_runtime | default | High-performance concurrent cache | keep |
| memmap2 | block_store | composition_runtime | default | Memory-mapped file I/O for block store | keep |
| metrics | metrics | composition_runtime | default | Metrics facade for observability | keep |
| metrics-exporter-prometheus | metrics | composition_runtime | default | Prometheus metrics endpoint | keep |
| http | http, http_client | composition_runtime | default | HTTP type definitions | keep |
| ipnetwork | platform, network | composition_runtime | default | IP network/CIDR calculations | keep |
| rand | challenge, captcha, throughout | composition_runtime | default | Random number generation | keep |
| base64 | utils, mesh | composition_runtime | default | Base64 encoding/decoding | keep |
| sha2 | challenge, auth, ipc | composition_runtime | default | SHA-256 hashing | keep |
| hex | utils, challenge | composition_runtime | default | Hex encoding/decoding | keep |
| futures | http_client, proxy | composition_runtime | default | Async stream and future utilities | keep |
| sysinfo | admin, startup | composition_runtime | default | System resource monitoring | keep |
| nix | platform, process | composition_runtime | default | Unix system calls (signals, sockets, process) | keep |
| chrono | config, logging | composition_runtime | default | Date/time handling with serde support | keep |
| notify | config | composition_runtime | default | Filesystem watch for config hot-reload | keep |
| aho-corasick | waf | composition_runtime | default | Multi-pattern string matching for WAF rules | keep |
| unicode-normalization | waf | composition_runtime | default | Unicode normalization for WAF input processing | keep |
| libinjectionrs | waf | composition_runtime | default | SQL/XSS injection detection | keep |
| serde_bytes | mesh, config | composition_runtime | default | Efficient byte array serialization | keep |
| synvoid-cli | commands | composition_runtime | default | CLI argument parsing definitions | keep |
| synvoid-config | config | composition_runtime | default | Configuration types and ConfigManager | keep |
| synvoid-dns | dns | composition_runtime | dns | DNS server with DNSSEC validation | keep |
| synvoid-icmp-filter | icmp_filter | composition_runtime | icmp-filter | ICMP filtering | keep |
| synvoid-honeypot | honeypot_port | composition_runtime | default | Honeypot port detection | keep |
| synvoid-upload | upload | composition_runtime | default | File upload handling | keep |
| synvoid-ipc | process | composition_runtime | default | IPC transport abstractions | keep |
| synvoid-http-client | http_client | composition_runtime | default | HTTP client pool and QUIC dispatch | keep |
| synvoid-platform | platform | composition_runtime | default | Platform detection and OS abstractions | keep |
| synvoid-upstream | upstream | composition_runtime | default | Upstream server selection | keep |
| synvoid-tunnel | tunnel | composition_runtime | default | Tunnel backend routing | keep |
| hickory-proto | dns | composition_runtime | dns | DNS protocol types for DNSSEC | keep |
| hickory-resolver | dns | composition_runtime | dns | DNS resolver with recursive support | keep |
| thiserror | throughout | composition_runtime | default | Derive macro for error types | keep |
| getrandom | dns | composition_runtime | dns | Cryptographic random for DNSSEC | keep |
| tokio-dstip | dns | composition_runtime | dns | Dual-stack IPv4/IPv6 socket support | keep |
| clap | commands | composition_runtime | default | CLI subcommand parsing | keep |
| tempfile | test_or_tooling | test_or_tooling | default | Temporary files for tests | keep |
| uuid | config, tests | composition_runtime | default | UUID generation for request IDs | keep |
| pin-project-lite | http, http_client | composition_runtime | default | Pin projection for async streams | keep |
| bcrypt | auth | composition_runtime | default | Password hashing for admin auth | keep |
| dirs | startup | composition_runtime | default | Platform directory resolution | keep |
| flate2 | serverless | composition_runtime | default | Gzip compression for serverless bundles | keep |
| tar | serverless | composition_runtime | default | Tar archive extraction for WASM bundles | keep |
| pqc | mesh, auth | composition_runtime | default | Post-quantum cryptography primitives | keep |
| zeroize | auth, ipc | composition_runtime | default | Secure memory zeroing for secrets | keep |
| walkdir | serverless, static_files | composition_runtime | default | Recursive directory traversal | keep |
| rusqlite | block_store | composition_runtime | default | SQLite for block store persistence | keep |
| tokio-rustls | http_client, tls | composition_runtime | default | TLS stream integration with Tokio | keep |
| rustls | http_client, tls | composition_runtime | default | TLS implementation | keep |
| rustls-pki-types | tls | composition_runtime | default | TLS certificate type definitions | keep |
| aws-lc-rs | tls | composition_runtime | default | Cryptographic backend for rustls | keep |
| subtle | auth, challenge, ipc | composition_runtime | default | Constant-time comparisons for security | keep |
| cryptoki | dns | composition_runtime | dns | PKCS#11 HSM support for DNSSEC keys | keep |
| quinn | http3, tunnel | composition_runtime | default | QUIC protocol implementation | keep |
| zip | serverless | composition_runtime | default | ZIP archive handling for WASM bundles | keep |
| libloading | plugin_runtime | composition_runtime | default | Dynamic library loading for native plugins | keep |
| aya | worker | composition_runtime | flood-ebpf | eBPF program loading for SYN flood detection | keep |
| synvoid-utils | throughout | composition_runtime | default | Shared utilities (DrainFlag, buffer, IP utils) | keep |
| synvoid-core | waf, proxy | composition_runtime | default | Core WAF and proxy types | keep |
| synvoid-tarpit | tarpit | composition_runtime | default | Tarpit Markov chain generation | keep |
| synvoid-challenge | challenge | composition_runtime | default | Challenge primitives (PoW, CSS, honeypot) | keep |
| synvoid-waf | waf | composition_runtime | default | WAF rule engine and detection | keep |
| synvoid-plugin-runtime | plugin | composition_runtime | default | WASM plugin runtime and instance pooling | keep |
| synvoid-tls | tls | composition_runtime | default | TLS termination and ACME | keep |
| synvoid-proxy-cache | proxy_cache | composition_runtime | default | Proxy response caching | keep |
| synvoid-admin | admin | composition_runtime | default | Admin API handler types | keep |
| synvoid-proxy | proxy | composition_runtime | default | Reverse proxy routing and location matching | keep |
| synvoid-http | http | composition_runtime | default | HTTP server listener and shared handler | keep |
| synvoid-http3 | http3 | composition_runtime | default | HTTP/3 QUIC server | keep |
| synvoid-serverless | serverless | composition_runtime | default | Serverless WASM function runtime | keep |
| synvoid-geoip | geoip | composition_runtime | default | GeoIP database lookups | keep |
| synvoid-integrity | integrity | composition_runtime | default | Integrity checking for mesh distribution | keep |
| synvoid-mesh | mesh | composition_runtime | mesh | Mesh networking, DHT, transport, Raft | keep |
| synvoid-app-handlers | cgi, fastcgi, mime, php | composition_runtime | default | Application protocol handlers | keep |
| synvoid-metrics | metrics | composition_runtime | default | Metrics collection and export | keep |
| synvoid-theme | theme | composition_runtime | default | Theme rendering and templates | keep |
| synvoid-block-store | block_store | composition_runtime | default | Block store persistence and export | keep |
| synvoid-app-server | app_server | composition_runtime | default | Granian app-server integration | keep |
| synvoid-vpn-client | vpn_client | composition_runtime | default | VPN client tunnel management | keep |
| synvoid-filter | filter | composition_runtime | default | Protocol filtering traits and generic filter engine for TCP/UDP | keep |
| synvoid-static-files | static_files | composition_runtime | default | Static file serving and directory listing | keep |
| url | config, http | composition_runtime | default | URL parsing and manipulation | keep |
| syslog | logging | remove_candidate | default | Syslog transport (dead module - logging removed) | removed with logging module |
| log | waf/endpoints | composition_runtime | default | Log facade — kept because `src/waf/endpoints.rs` still uses it | keep |
| schemars | config | composition_runtime | default | JSON Schema generation for config | keep |
| utoipa | admin | composition_runtime | default | OpenAPI schema generation | keep |
| utoipa-swagger-ui | admin | composition_runtime | swagger-ui | Swagger UI for API docs | keep |
| prost | admin | composition_runtime | default | Protocol buffer serialization for gRPC | keep |
| lru_time_cache | http_client | composition_runtime | default | Time-expiring LRU cache | keep |
| indexmap | config, http | composition_runtime | default | Insertion-ordered hash map | keep |
| ahash | http_client, mesh | composition_runtime | default | Fast hashing for concurrent maps | keep |
| smallvec | waf, http | composition_runtime | default | Stack-allocated small vectors | keep |
| aes-gcm | auth, ipc | composition_runtime | default | AES-GCM encryption for sessions/IPC | keep |
| async-trait | throughout | composition_runtime | default | Async trait support | keep |
| daemonize2 | startup | composition_runtime | default | Process daemonization | keep |
| digest | auth, challenge | composition_runtime | default | Cryptographic digest traits | keep |
| ed25519-dalek | auth, mesh | composition_runtime | default | Ed25519 signatures | keep |
| rsa | auth | composition_runtime | default | RSA encryption for legacy auth | keep |
| rand_core_06 | auth, challenge | composition_runtime | default | Core random traits (v0.6 compat) | keep |
| hkdf | auth, ipc | composition_runtime | default | HKDF key derivation | keep |
| hmac | auth, ipc | composition_runtime | default | HMAC message authentication | keep |
| socket2 | platform | composition_runtime | default | Low-level socket options | keep |
| sha1 | auth | composition_runtime | default | SHA-1 for legacy auth protocols | keep |
| sha3 | ipc | composition_runtime | default | SHA-3 for IPC HMAC | keep |
| x25519-dalek | auth, mesh | composition_runtime | default | X25519 key exchange | keep |
| base32 | auth | composition_runtime | default | Base32 encoding for TOTP secrets | keep |
| libc | platform, process | composition_runtime | default | Raw libc bindings for Unix syscalls | keep |
| windows-sys | platform | composition_runtime | default | Windows API bindings | keep |
| tonic | admin | composition_runtime | default | gRPC framework for supervisor control | keep |
| tonic-reflection | admin | composition_runtime | default | gRPC server reflection | keep |
| tonic-prost | admin | composition_runtime | default | gRPC prost integration | keep |
| openraft | mesh | composition_runtime | mesh | Raft consensus for mesh control plane | keep |
| async-stream | http_client, mesh | composition_runtime | default | Async stream macro | keep |
| bincode | mesh, utils | composition_runtime | default | Binary serialization for mesh state | keep |

## Build Dependencies

| Dependency | Root owner module(s) | Classification | Feature gate | Reason | Next action |
|------------|----------------------|----------------|--------------|--------|-------------|
| tonic-prost-build | admin (protobuf codegen) | composition_runtime | default | Protobuf code generation for gRPC admin/control APIs | keep |
| chrono | admin (protobuf codegen) | composition_runtime | default | Timestamp types in protobuf code generation | keep |
