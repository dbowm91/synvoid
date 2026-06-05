# Root Dependency Ownership Matrix

> Status: Created as part of Wave A (CONT-A01)
> Last updated: 2026-06-05

## Summary

This matrix classifies each dependency in root `Cargo.toml` by its true owner.
Actions: `KEEP_ROOT`, `MOVE_TO_EXISTING_CRATE`, `REMOVE_FROM_ROOT`, `FEATURE_FORWARD_ONLY`, `UNKNOWN_INVESTIGATE`

## Hyper/Tower/Axum Stack

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| tokio | Core async runtime | ROOT (shared) | KEEP_ROOT | 994 uses in root; all crates share via workspace |
| hyper | HTTP server/client | ROOT (server) | KEEP_ROOT | 96 uses in root; http server pipeline still in root |
| hyper-util | HTTP server helpers | ROOT (server) | KEEP_ROOT | 13 uses in root; server-auto, server-graceful |
| hyper-rustls | TLS HTTP connector | synvoid-http-client | MOVE_TO_EXISTING_CRATE | 4 uses in root; synvoid-http-client already owns |
| tower | Middleware framework | ROOT (server) | KEEP_ROOT | 4 uses in root; server pipeline |
| tower-http | HTTP middleware | ROOT (server) | KEEP_ROOT | 2 uses in root; fs, cors |
| axum | Admin API framework | ROOT (admin) | KEEP_ROOT | 165 uses in root; admin handlers |
| axum-extra | Axum extensions | ROOT (admin) | KEEP_ROOT | 1 use in root |
| http-body | Body trait | ROOT (shared) | KEEP_ROOT | 99 uses in root |
| http-body-util | Body utilities | ROOT (shared) | KEEP_ROOT | 111 uses in root |
| tokio-util | IO utilities | ROOT (shared) | KEEP_ROOT | 0 direct uses but transitive |
| bytes | Byte buffers | ROOT (shared) | KEEP_ROOT | 106 uses in root |
| hyperlocal | Unix domain sockets | synvoid-http-client | REMOVE_FROM_ROOT | 0 uses in root; already in synvoid-http-client |

## TLS/Crypto

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| rustls | TLS implementation | synvoid-tls | KEEP_ROOT_FOR_NOW | 36 uses in root; TLS server still root-owned |
| tokio-rustls | Async TLS | synvoid-tls | KEEP_ROOT_FOR_NOW | 9 uses in root; TLS server |
| rustls-native-certs | OS cert store | synvoid-tls | REMOVE_FROM_ROOT | 0 uses in root; already in synvoid-http-client |
| rustls-pki-types | TLS types | synvoid-tls | KEEP_ROOT_FOR_NOW | 5 uses in root |
| rustls-post-quantum | PQ TLS | synvoid-tls | REMOVE_FROM_ROOT | 0 direct uses; optional dep never imported |
| x509-parser | Certificate parsing | synvoid-tls | KEEP_ROOT_FOR_NOW | 3 uses in root |
| instant-acme | ACME certs | synvoid-tls | REMOVE_FROM_ROOT | 0 uses in root; already in synvoid-tls |
| aws-lc-rs | Crypto backend | synvoid-tls | KEEP_ROOT_FOR_NOW | 2 uses in root |
| rcgen | Certificate gen | synvoid-tls | KEEP_ROOT_FOR_NOW | 22 uses in root; mesh cert code |
| webpki-roots | WebPKI roots | synvoid-http-client | KEEP_ROOT_FOR_NOW | 1 use in root http_client/typed_pool.rs |
| subtle | Constant-time ops | synvoid-core/waf/challenge | KEEP_ROOT_FOR_NOW | 24 uses in root |
| zeroize | Secret zeroing | synvoid-integrity | KEEP_ROOT_FOR_NOW | 3 uses in root |
| ed25519-dalek | Ed25519 | synvoid-integrity | KEEP_ROOT_FOR_NOW | 101 uses in root; mesh crypto |
| x25519-dalek | X25519 | synvoid-integrity | KEEP_ROOT_FOR_NOW | 4 uses in root |
| aes-gcm | AES-GCM | synvoid-config | KEEP_ROOT_FOR_NOW | 7 uses in root |
| hkdf | HKDF | synvoid-config | KEEP_ROOT_FOR_NOW | 9 uses in root |
| hmac | HMAC | synvoid-tunnel | KEEP_ROOT_FOR_NOW | 5 uses in root |
| rsa | RSA | synvoid-tls | KEEP_ROOT_FOR_NOW | 14 uses in root |
| pqc | Post-quantum | synvoid-integrity/config | KEEP_ROOT_FOR_NOW | 26 uses in root; mesh PQ |
| bcrypt | Password hashing | ROOT (admin) | KEEP_ROOT | 5 uses in root; admin auth |
| digest | Crypto digest | ROOT (crypto) | KEEP_ROOT | transitive |

## WAF/Detection

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| isbot | Bot detection | synvoid-waf | REMOVE_FROM_ROOT | 0 uses in root; already in synvoid-waf |
| regex | Pattern matching | ROOT (shared) | KEEP_ROOT | 25 uses in root |
| aho-corasick | String matching | ROOT (shared) | KEEP_ROOT | 14 uses in root; WAF detection |
| unicode-normalization | Unicode norms | ROOT (shared) | KEEP_ROOT | 2 uses in root |
| libinjectionrs | SQL/XSS injection | ROOT (waf) | KEEP_ROOT_FOR_NOW | Root waf/attack_detection still uses directly |
| bloomfilter | Bloom filter | ROOT (mesh) | KEEP_ROOT | 4 uses in root; mesh |
| yara-x | YARA rules | ROOT (upload) | KEEP_ROOT | 0 direct uses but feature-gated |
| stegoeggo | Steganography | ROOT (upload) | KEEP_ROOT | 1 use in root; image_poisoning |

## Storage/Cache

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| rusqlite | SQLite | ROOT (block_store) | KEEP_ROOT | 66 uses in root |
| moka | Cache | ROOT (shared) | KEEP_ROOT | 12 uses in root |
| dashmap | Concurrent map | ROOT (shared) | KEEP_ROOT | 23 uses in root |
| parking_lot | Mutexes | ROOT (shared) | KEEP_ROOT | 168 uses in root |
| memmap2 | Memory maps | ROOT (shared) | KEEP_ROOT | 2 uses in root |
| lru_time_cache | LRU cache | ROOT (shared) | KEEP_ROOT | 11 uses in root |
| linked-hash-map | Linked hash map | UNKNOWN | REMOVE_FROM_ROOT | 0 uses in root or extracted crates |
| indexmap | Index map | ROOT (shared) | KEEP_ROOT | 1 use in root |
| ahash | Fast hash | ROOT (shared) | KEEP_ROOT | 9 uses in root |
| smallvec | Small vectors | ROOT (shared) | KEEP_ROOT | 0 direct uses but transitive |

## Networking/Control Plane

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| quinn | QUIC | ROOT (mesh/http3) | KEEP_ROOT | 45 uses in root |
| h3 | HTTP/3 | ROOT (http3) | KEEP_ROOT | 2 uses in root |
| h3-quinn | H3 Quinn bridge | ROOT (http3) | KEEP_ROOT | 2 uses in root |
| tokio-tungstenite | WebSocket | ROOT (proxy) | KEEP_ROOT | 32 uses in root |
| tonic | gRPC | ROOT (mesh) | KEEP_ROOT | 9 uses in root |
| tonic-reflection | gRPC reflection | ROOT (mesh) | KEEP_ROOT | 0 uses but gRPC server |
| tonic-prost | gRPC prost | ROOT (mesh) | KEEP_ROOT | 0 uses but gRPC |
| openraft | Raft consensus | ROOT (mesh) | KEEP_ROOT | 54 uses in root; mesh Raft |
| socket2 | Socket options | ROOT (shared) | KEEP_ROOT | 9 uses in root |
| ipnetwork | IP networks | ROOT (shared) | KEEP_ROOT | 4 uses in root |
| httparse | HTTP parsing | ROOT (shared) | KEEP_ROOT | 4 uses in root |

## App Handlers/Runtime

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| fastcgi-client | FastCGI | ROOT (fastcgi) | KEEP_ROOT | 1 use in root |
| wasmtime | WASM runtime | synvoid-plugin-runtime | KEEP_ROOT_FOR_NOW | 1 use in root; plugin loading |
| libloading | Dynamic loading | ROOT (plugin) | KEEP_ROOT | 9 uses in root |
| lightningcss | CSS parsing | ROOT (static_files) | KEEP_ROOT | 2 uses in root |
| minify-html | HTML minify | ROOT (static_files) | KEEP_ROOT | 1 use in root |
| minify-js | JS minify | ROOT (static_files) | KEEP_ROOT | 1 use in root |
| brotli | Brotli compression | ROOT (shared) | KEEP_ROOT | 2 uses in root |
| flate2 | Gzip compression | ROOT (shared) | KEEP_ROOT | 12 uses in root |
| tar | Tar archives | ROOT (shared) | KEEP_ROOT | 2 uses in root |
| walkdir | Directory walking | ROOT (shared) | KEEP_ROOT | 3 uses in root |
| infer | File type detection | ROOT (shared) | KEEP_ROOT | 1 use in root |

## Observability/Admin/Schema

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| metrics | Metrics facade | ROOT (shared) | KEEP_ROOT | 227 uses in root |
| metrics-exporter-prometheus | Prometheus exporter | ROOT (admin) | KEEP_ROOT | 1 use in root |
| tracing | Logging facade | ROOT (shared) | KEEP_ROOT | 2979 uses in root |
| tracing-subscriber | Log subscriber | ROOT (admin) | KEEP_ROOT | 4 uses in root |
| tracing-appender | Log appender | ROOT (admin) | KEEP_ROOT | 0 uses but init code |
| log | Log facade | ROOT (shared) | KEEP_ROOT | 38 uses in root |
| syslog | Syslog support | ROOT (admin) | KEEP_ROOT | 3 uses in root |
| sd-notify | systemd notify | ROOT (admin) | REMOVE_FROM_ROOT | 0 uses in root |
| schemars | JSON schema | synvoid-config | KEEP_ROOT_FOR_NOW | 13 uses in root |
| utoipa | OpenAPI | synvoid-config | KEEP_ROOT_FOR_NOW | 319 uses in root; admin API |
| utoipa-swagger-ui | Swagger UI | ROOT (admin) | KEEP_ROOT | 1 use in root; feature-gated |
| prost | Protobuf | ROOT (mesh) | KEEP_ROOT | 4 uses in root |
| prost-build | Protobuf build | ROOT (build) | KEEP_ROOT | 0 uses but build.rs |

## Platform/System

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| nix | Unix APIs | ROOT (platform) | KEEP_ROOT | 152 uses in root |
| libc | C bindings | ROOT (platform) | KEEP_ROOT | 72 uses in root |
| windows-sys | Windows API | ROOT (platform) | KEEP_ROOT | 75 uses in root |
| sysinfo | System info | ROOT (admin) | KEEP_ROOT | 5 uses in root |
| notify | File watching | synvoid-tls | KEEP_ROOT_FOR_NOW | 10 uses in root; config reload |
| daemonize2 | Daemonize | ROOT (supervisor) | KEEP_ROOT | 2 uses in root |
| dirs | Directory paths | ROOT (shared) | KEEP_ROOT | 5 uses in root |
| tempfile | Temp files | ROOT (shared) | KEEP_ROOT | 15 uses in root |

## Other

| Dependency | Current root reason | True owner crate | Action | Notes |
|---|---|---|---|---|
| serde | Serialization | ROOT (shared) | KEEP_ROOT | 221 uses in root |
| serde_json | JSON | ROOT (shared) | KEEP_ROOT | 456 uses in root |
| postcard | Binary ser | ROOT (shared) | KEEP_ROOT | 57 uses in root |
| rkyv | Zero-copy ser | ROOT (shared) | KEEP_ROOT | 50 uses in root |
| toml | TOML parsing | ROOT (config) | KEEP_ROOT | 27 uses in root |
| anyhow | Error handling | ROOT (shared) | KEEP_ROOT | 23 uses in root |
| bitflags | Bit flags | ROOT (shared) | KEEP_ROOT | 1 use in root |
| http | HTTP types | ROOT (shared) | KEEP_ROOT | 822 uses in root |
| rand | RNG | ROOT (shared) | KEEP_ROOT | 123 uses in root |
| base64 | Base64 | ROOT (shared) | KEEP_ROOT | 141 uses in root |
| sha2 | SHA-2 | ROOT (shared) | KEEP_ROOT | 63 uses in root |
| hex | Hex encoding | ROOT (shared) | KEEP_ROOT | 92 uses in root |
| futures | Futures | ROOT (shared) | KEEP_ROOT | 24 uses in root |
| chrono | DateTime | ROOT (shared) | KEEP_ROOT | 70 uses in root |
| uuid | UUIDs | ROOT (shared) | KEEP_ROOT | 75 uses in root |
| url | URL parsing | ROOT (shared) | KEEP_ROOT | 4 uses in root |
| thiserror | Error derive | ROOT (shared) | KEEP_ROOT | 49 uses in root |
| async-trait | Async trait | ROOT (shared) | KEEP_ROOT | 8 uses in root |
| clap | CLI parsing | ROOT (cli) | KEEP_ROOT | CLI args |
| async-stream | Async stream | ROOT (mesh) | KEEP_ROOT | 1 use in root |
| bincode | Binary ser | ROOT (mesh) | KEEP_ROOT | 0 uses but raft |

## Dependencies Owned by Extracted Crates (Root Re-exports)

| Dependency | Root re-export location | True owner | Action | Notes |
|---|---|---|---|---|
| synvoid-config | `pub mod config` | synvoid-config | KEEP_ROOT | Root depends on extracted crate |
| synvoid-http-client | `pub mod http_client` | synvoid-http-client | KEEP_ROOT | Root re-exports |
| synvoid-upstream | `pub use synvoid_upstream` | synvoid-upstream | KEEP_ROOT | Root re-exports |
| synvoid-tunnel | root dep | synvoid-tunnel | KEEP_ROOT | Root depends on extracted crate |
| synvoid-utils | `pub mod buffer` | synvoid-utils | KEEP_ROOT | Root re-exports |
| synvoid-core | root dep | synvoid-core | KEEP_ROOT | Root depends on extracted crate |
| synvoid-tarpit | root dep | synvoid-tarpit | KEEP_ROOT | Root depends on extracted crate |
| synvoid-challenge | root dep | synvoid-challenge | KEEP_ROOT | Root depends on extracted crate |
| synvoid-waf | root dep | synvoid-waf | KEEP_ROOT | Root depends on extracted crate |
| synvoid-plugin-runtime | root dep | synvoid-plugin-runtime | KEEP_ROOT | Root depends on extracted crate |
| synvoid-tls | root dep | synvoid-tls | KEEP_ROOT | Root depends on extracted crate |
| synvoid-proxy-cache | `pub use synvoid_proxy_cache` | synvoid-proxy-cache | KEEP_ROOT | Root re-exports |
| synvoid-serverless | root dep | synvoid-serverless | KEEP_ROOT | Root depends on extracted crate |
| synvoid-geoip | `pub use synvoid_geoip` | synvoid-geoip | KEEP_ROOT | Root re-exports |
| synvoid-integrity | `pub use synvoid_integrity` | synvoid-integrity | KEEP_ROOT | Root re-exports |
| synvoid-testkit | dev-dep | synvoid-testkit | KEEP_ROOT | Root dev-dep |
