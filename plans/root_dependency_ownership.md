# Root Dependency Ownership Inventory

This file tracks which dependencies are owned by root vs. extracted crates.
Root should be the composition/binary integration layer; extracted crates own their protocol/runtime deps.

## Ownership Table

| Dependency | Current owner | Root direct? | Reason / next action |
|------------|---------------|--------------|----------------------|
| quinn | root (DNS DOQ, TCP detection) | yes | `src/dns/doq.rs` (QUIC DNS server), `src/tcp/listener.rs` (protocol detection) |
| webpki-roots | synvoid-http-client | no | Used by `crates/synvoid-http-client/src/lib.rs` as fallback when native certs are empty. Root no longer depends on it directly (typed_pool removed in iteration 5). |
| h3 | synvoid-http3 | no | Fully owned by http3 crate |
| h3-quinn | synvoid-http3 | no | Fully owned by http3 crate |
| tokio | root + workspace | yes | Core async runtime; workspace dep |
| hyper / hyper-util | root | yes | HTTP server/client foundation |
| axum / axum-extra | root | yes | HTTP routing framework |
| rustls / tokio-rustls | root | yes | TLS foundation; also declared in synvoid-tls |
| aws-lc-rs | root | yes | Post-quantum crypto |
| subtle | root | yes | Constant-time comparison |
| rusqlite | root | yes | SQLite database |
| postcard | root | yes | Binary serialization |
| rkyv | root | yes | High-perf serialization |
| hickory-proto / hickory-resolver | root (optional, dns feature) | yes | DNS resolution; owned by synvoid-dns when dns feature enabled |
| cryptoki | root (optional, dns feature) | yes | HSM/PKCS#11 for DNSSEC |
| wasmtime | root (patch.crates-io) | yes | Workspace-level patch for yara-x transitive vuln |
| openraft | root (optional, mesh feature) | yes | Raft consensus; mesh feature gate |
| libloading | root | yes | Dynamic plugin loading |
| aya | root (optional, flood-ebpf) | yes | eBPF support |

## Moved/Removed Dependencies (Historical)

| Dependency | Moved to | Reference |
|------------|----------|-----------|
| rustls-native-certs | synvoid-http-client | plans/root_dependency_ownership.md |
| tokio-util | synvoid-static-files | plans/root_dependency_ownership.md |
| isbot | synvoid-waf | plans/root_dependency_ownership.md |
| infer | synvoid-app-handlers | plans/root_dependency_ownership.md |
| minification deps | synvoid-static-files | plans/root_dependency_ownership.md |
| rustls-post-quantum | removed (rustls prefer-post-quantum) | plans/root_dependency_ownership.md |
| instant-acme | synvoid-tls | plans/root_dependency_ownership.md |
| maxminddb | synvoid-geoip | plans/root_dependency_ownership.md |
| wasmtime (direct) | synvoid-plugin-runtime | plans/root_dependency_ownership.md |
| defguard_boringtun | synvoid-tunnel | plans/root_dependency_ownership.md |
| hyperlocal | synvoid-http-client | plans/root_dependency_ownership.md |
| sd-notify | removed | plans/root_dependency_ownership.md |
| linked-hash-map | removed | plans/root_dependency_ownership.md |

## Iteration 2 Changes

- Updated `quinn` comment to clarify root ownership (DNS DOQ + TCP detection)
- Updated `webpki-roots` comment to clarify root ownership (http_client typed_pool)
- Updated `h3`/`h3-quinn` comment to reference http3 crate ownership
- Removed stale "HTTP/3 + QUIC" section header that implied root owns HTTP/3 deps

## Iteration 5 Changes

- Removed root `webpki-roots` dependency (was only used by dead `typed_pool.rs`)
- Updated `webpki-roots` ownership to `synvoid-http-client` (root direct: no)
- Removed dead `TypedConnectionPool`, `TypedHttpClient`, `TypedPoolKey` from codebase
- Removed dead `src/http_client/typed_pool.rs`, `src/http_client/erased_pool.rs`, `crates/synvoid-http-client/src/typed_pool.rs`
