# Root Dependency Ownership Matrix

> Status: Refreshed as part of MDM-R01 (measurement-driven modularization pass).
> Last updated: 2026-06-07
> Scope: Every direct dependency in root `Cargo.toml` plus the
> "focus first" / "heavy root" lists in
> `plans/measurement_driven_modularization_cleanup.md` § 5.
>
> This document is the source of truth for MDM-R02. Removal of any
> dependency from root `Cargo.toml` requires an `Action` of
> `REMOVE_FROM_ROOT` (or `FEATURE_FORWARD_ONLY` for feature wiring) and a
> validated follow-up compile check, per the rules in
> `plans/measurement_driven_modularization_cleanup.md` § 5.

## Action legend

```text
KEEP_ROOT_FOR_NOW       Cannot remove today; concrete root code still uses it.
REMOVE_FROM_ROOT        Safe to drop from [dependencies] in a tiny batch.
MOVE_TO_EXISTING_CRATE  A target crate already owns the type, but the move
                        requires moving the call site (out of MDM-R02 scope).
FEATURE_FORWARD_ONLY    Root only forwards a feature flag to a sub-crate;
                        the dependency itself can be removed.
UNKNOWN_INVESTIGATE     Owner is unclear from grep; needs deeper read.
```

## Focus-first list (already moved in HTC-R01 / HTC-R02)

These dependencies were the focus of the earlier consolidation passes.
All of them are already removed from root `[dependencies]`. The comments
left in root `Cargo.toml` are documented here so they can be replaced
with one-line pointers in MDM-R03.

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `isbot` | KEEP_REMOVED | `synvoid-waf` | `crates/synvoid-waf/src/bot.rs:1` `use isbot::Bots;` | Removed in HTC-R02 batch; root `Cargo.toml` has comment "isbot moved to synvoid-waf" |
| `rustls-native-certs` | KEEP_REMOVED | `synvoid-http-client` | `crates/synvoid-http-client/src/lib.rs` 2 uses; dep in `crates/synvoid-http-client/Cargo.toml` | Removed in HTC-R02; root comment "rustls-native-certs moved to synvoid-http-client" |
| `tokio-util` | KEEP_REMOVED | `synvoid-static-files` | 0 root uses | Removed in HTC-R02; root comment "tokio-util removed (0 uses in root; synvoid-static-files owns this)" |
| `lightningcss` | KEEP_REMOVED | `synvoid-static-files` | `crates/synvoid-static-files/src/minifier.rs:1` `use lightningcss::stylesheet::{MinifyOptions, ParserOptions, PrinterOptions};` | Removed in HTC-R02 |
| `minify-html` | KEEP_REMOVED | `synvoid-static-files` | `crates/synvoid-static-files/src/minifier.rs:2` `use minify_html::{minify, Cfg};` | Removed in HTC-R02 |
| `minify-js` | KEEP_REMOVED | `synvoid-static-files` | `crates/synvoid-static-files/src/minifier.rs:1` `use minify_js::{minify, Session, TopLevelMode};` | Removed in HTC-R02 |
| `brotli` | KEEP_REMOVED | `synvoid-static-files` | `crates/synvoid-static-files/src/minifier.rs:1` `use brotli::CompressorWriter;`; dep in `crates/synvoid-static-files/Cargo.toml` | Root `Cargo.toml` comment is "brotli removed from root (0 uses in prod code; synvoid-static-files owns this dep)"; root code only references the `enable_brotli` / `brotli_level` config fields, not the crate |
| `maxminddb` | KEEP_REMOVED | `synvoid-geoip` | `crates/synvoid-geoip/src/lookup.rs:1` `use maxminddb::{PathElement, Reader};`; `crates/synvoid-geoip/src/manager.rs` | Removed in HTC-R02 |
| `wasmtime` | KEEP_REMOVED | `synvoid-plugin-runtime` | `crates/synvoid-plugin-runtime/Cargo.toml: wasmtime = "42.0.2"`; 5 files in `crates/synvoid-plugin-runtime/src/` use it | Only present in root as `[patch.crates-io]` for transitive yara-x fix; comment in root `Cargo.toml` "wasmtime moved to synvoid-plugin-runtime" |
| `hyperlocal` | KEEP_REMOVED | `synvoid-http-client` | `crates/synvoid-http-client/src/lib.rs:1` `use hyperlocal::{UnixConnector, Uri as HyperlocalUri};`; dep in `crates/synvoid-http-client/Cargo.toml` | Removed; comment "hyperlocal moved to synvoid-http-client" |
| `infer` | KEEP_REMOVED | `synvoid-app-handlers` | 0 root uses; dep moved to `crates/synvoid-app-handlers/Cargo.toml` | Removed in HTC-R02; comment "infer removed (0 uses in root; synvoid-app-handlers owns this dep)" |
| `sd-notify` | KEEP_REMOVED | n/a | 0 uses anywhere in `src/` or `crates/` | Removed earlier; root comment "sd-notify removed (0 uses in root)" |
| `linked-hash-map` | KEEP_REMOVED | n/a | 0 uses; only `Cargo.lock` and a deprecated plan doc mention it | Removed; comment "linked-hash-map removed (0 uses in root or extracted crates)" |
| `instant-acme` | KEEP_REMOVED | `synvoid-tls` | `crates/synvoid-tls/src/acme.rs:1` `use instant_acme::{...};`; dep in `crates/synvoid-tls/Cargo.toml` | Removed; comment "instant-acme moved to synvoid-tls" |
| `rustls-post-quantum` | KEEP_REMOVED | n/a | 0 uses; PQ handled by `rustls` `prefer-post-quantum` feature on `aws-lc-rs` | Removed; comment "rustls-post-quantum removed (0 direct uses; prefer-post-quantum feature on rustls handles PQ)" |
| `defguard_boringtun` | KEEP_REMOVED | `synvoid-tunnel` | `crates/synvoid-tunnel/src/wireguard/userspace.rs` 2 uses; dep in `crates/synvoid-tunnel/Cargo.toml` | Removed; comment "defguard_boringtun moved to synvoid-tunnel" |

## Still-heavy root dependencies

Each row was re-validated by `rg`-ing for the dep's name in
`src/` and `crates/`. Counts are direct `use` statements + macros +
attribute uses.

### Hyper / Tower / Axum stack

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `hyper` | KEEP_ROOT_FOR_NOW | root | 55 uses across `src/http/websocket_*`, `src/http/server*`, `src/dns/doh.rs`, `src/tls/server.rs`, `src/http_client/*`; also used heavily in `synvoid-http`, `synvoid-http-client`, `synvoid-proxy` | Cannot remove while `src/http/server.rs`, `src/dns/doh.rs`, `src/tls/server.rs`, and `src/http_client/*` are root-owned. Plan rule "Do not prune hyper/tower/axum while root HTTP server/admin still require them" applies. |
| `hyper-util` | KEEP_ROOT_FOR_NOW | root | 8 uses in `src/http_client/typed_pool.rs`, `src/http_client/erased_pool.rs`, `src/http/server/connection_types.rs`, `src/dns/doh.rs`, `src/tls/server.rs`; also in `synvoid-http`, `synvoid-http-client` | Required by `http_client/` and `http/server/connection_types.rs`. Same constraint as `hyper`. |
| `hyper-rustls` | KEEP_ROOT_FOR_NOW | `synvoid-http-client` | Only 3 direct uses in `src/http_client/typed_pool.rs`; dep already in `crates/synvoid-http-client/Cargo.toml` | Move would require moving the http_client tree (out of scope for MDM-R02). |
| `tower` | KEEP_ROOT_FOR_NOW | root | 1 `use` + 32 occurrences of `tower::` macros/derives in `src/admin/handlers/*`, `src/admin/middleware.rs`, `src/admin/mod.rs`, `src/admin/ws/*`, `src/http/directory_viewer.rs`, `src/http/file_manager*.rs`, `src/http/webdav.rs`, `src/plugin/*` | Plan rule prevents pruning while admin uses it. |
| `tower-http` | KEEP_ROOT_FOR_NOW | root | `src/admin/mod.rs` (CORS + ServeDir) | Tied to admin server. |
| `axum` | KEEP_ROOT_FOR_NOW | root + `synvoid-admin` | 49 `use` lines + many macros in 32 root files; also used in `synvoid-admin`, `synvoid-app-handlers`, `synvoid-plugin-runtime` | Cannot move while root `src/admin/handlers/*` (23 files) and `src/plugin/mod.rs` use it. |
| `axum-extra` | KEEP_ROOT_FOR_NOW | root | 1 use in `src/admin/handlers/common.rs` (typed headers) | Tied to admin handlers. |
| `http-body` | KEEP_ROOT_FOR_NOW | root | 26 uses in `src/http/body_policy.rs`, `src/http_client/erased_pool.rs`, `src/http_client/typed_pool.rs`, `src/tls/server.rs`; also in `synvoid-http`, `synvoid-proxy`, `synvoid-http3` | Required by `http/server.rs` and `http_client/`. |
| `http-body-util` | KEEP_ROOT_FOR_NOW | root | 11+ uses in `src/tls/server.rs`, `src/honeypot_port/responders/ai.rs`, `src/server/waf_handler.rs`, `src/http/*_dispatch.rs`, `src/http/challenge_paths.rs`, `src/http_client/*`, `src/dns/doh.rs`; also in `synvoid-http`, `synvoid-proxy`, `synvoid-http3` | Body utilities used in many root dispatch modules. |

### HTTP/3 + QUIC

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `quinn` | KEEP_ROOT_FOR_NOW | root + `synvoid-http3` | 3 root modules: `src/dns/doq.rs`, `src/http3/server.rs`, `src/tcp/listener.rs`; also in `synvoid-http3` | Plan rule: "Do not prune quinn/h3/h3-quinn while HTTP3 server remains root-owned." |
| `h3` | KEEP_ROOT_FOR_NOW | root | 2 uses in `src/http3/server.rs`; also in `synvoid-http3` | Same constraint. |
| `h3-quinn` | KEEP_ROOT_FOR_NOW | root | 1 use in `src/http3/server.rs` | Same constraint. |

### TLS / Post-quantum / Crypto

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `tokio-rustls` | KEEP_ROOT_FOR_NOW | root | Used in `src/tls/server.rs`, `src/dns/hsm.rs`, `src/dns/doh.rs`; also in `synvoid-tls`, `synvoid-http-client` | Cannot remove while `src/tls/server.rs` is root-owned. |
| `rustls` | KEEP_ROOT_FOR_NOW | root | `src/tls/*` and `src/http3/server.rs`; also in `synvoid-tls`, `synvoid-http-client`, `synvoid-mesh`, `synvoid-block-store` | Same. |
| `aws-lc-rs` | KEEP_ROOT_FOR_NOW | root | 0 direct root uses, but root pulls in `yara-x` which uses `aws-lc-rs` (via patch) | Pure transitive for root; the patch in `[patch.crates-io]` keeps it pinned. Cannot remove while `yara-x` is in root. |

### HSM / PKCS#11

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `cryptoki` | KEEP_ROOT_FOR_NOW | root | 5 uses in `src/dns/hsm.rs`; also in `synvoid-dns` | Tied to root `src/dns/hsm.rs`. Optional via the `dns` feature. |

### Database / GeoIP

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `rusqlite` | KEEP_ROOT_FOR_NOW | root | 4 root modules use it: `src/dns/store.rs`, `src/dns/trust_anchor.rs`, `src/honeypot_port/storage.rs`, `src/waf/threat_level/persistence/sqlite.rs`; also in `synvoid-dns`, `synvoid-honeypot`, `synvoid-block-store` | Cannot remove until the root sqlite sites are consolidated. Tracked in MDM-S02. |

### YARA / Scanning

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `yara-x` | KEEP_ROOT_FOR_NOW | root + `synvoid-upload` | 2 uses in `src/upload/yara_scanner.rs`; also 2 uses in `crates/synvoid-upload/src/yara_scanner.rs` | Root upload module uses directly for YARA scanning. Tracked in MDM-S01. |

### Schema / OpenAPI

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `schemars` | KEEP_ROOT_FOR_NOW | root | 2 uses in `src/admin/handlers/config.rs`, `src/mesh/dht/mod.rs`; also in `synvoid-config`, `synvoid-mesh`, `synvoid-metrics` | Root mesh DHT (shim) and config schema derive use it. |
| `utoipa` | KEEP_ROOT_FOR_NOW | root + `synvoid-admin` | 257 uses across 23 root files in `src/admin/handlers/*`, `src/admin/openapi.rs`, `src/admin/schema.rs`, `src/admin/state.rs`, `src/admin/mod.rs`; also in `synvoid-admin`, `synvoid-metrics`, `synvoid-config`, `synvoid-app-handlers` | Heavy root admin usage; cannot move without moving the 23 root admin handler files. Tracked in MDM-A01/A02. |
| `utoipa-swagger-ui` | KEEP_ROOT_FOR_NOW (FEATURE_FORWARD_ONLY candidate) | root | 1 use in `src/admin/mod.rs: use utoipa_swagger_ui::SwaggerUi;`; feature-gated by the `swagger-ui` feature | Root-only, but tied to the admin server which is root-owned. Tracked in MDM-A01. |

### Protobuf / gRPC

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `prost` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | 0 direct root uses; 1 use in `crates/synvoid-mesh/src/mesh/protocol.rs: use prost::Message;` | Mesh crate owns the wire format. Root only enables it because `synvoid-mesh` is in root's `[dependencies]`. |
| `prost-build` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | Build dep for protobuf message definitions | Build-script side of `prost`; same constraint. |
| `tonic` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | 0 direct root uses; used in `synvoid-mesh` | gRPC stack lives in mesh crate. |
| `tonic-reflection` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | Same | |
| `tonic-prost` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | Same | |
| `tonic-prost-build` (build-dep) | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | Same | |
| `async-stream` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | 0 direct root uses; used in `synvoid-mesh` | |
| `bincode` | KEEP_ROOT_FOR_NOW | root + `synvoid-mesh` | 0 direct root uses; used in `synvoid-mesh` and likely root via mesh re-exports | |

### Raft consensus

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `openraft` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | 0 direct root uses; 16+ uses in `crates/synvoid-mesh/src/mesh/raft/*.rs`; optional via `mesh` feature | Plan rule: "Do not prune openraft while root mesh feature still directly enables it." |
| `openraft-legacy` | KEEP_ROOT_FOR_NOW | `synvoid-mesh` | 0 direct root uses; pinned for legacy | Required by synvoid-mesh's `Cargo.toml`. |

### Dynamic plugin loading

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `libloading` | KEEP_ROOT_FOR_NOW | root + `synvoid-plugin-runtime` | 1 use in `src/plugin/axum_loader.rs: use libloading::{Library, Symbol};`; same use in `crates/synvoid-plugin-runtime/src/axum_loader.rs` | Root `src/plugin/mod.rs` is the canonical `PluginManager`, not a shim. |

### Other root dependencies (re-validated)

These are the rest of the direct deps in root `Cargo.toml`. Rows marked
`REMOVE_FROM_ROOT` are queued for MDM-R02 batch 1; the rest are
`KEEP_ROOT_FOR_NOW` with a concrete blocker.

| Dependency | Action | True owner | Evidence | Notes |
|---|---|---|---|---|
| `httparse` | REMOVE_FROM_ROOT | `synvoid-http` | 0 real root uses (only doc-comment references in `src/waf/attack_detection/request_smuggling.rs`); 1 import + 3 path uses in `crates/synvoid-http/src/early_parse.rs`; dep declared in `crates/synvoid-http/Cargo.toml` | Pulled in transitively from `synvoid-http`. Safe to drop from root. |
| `matchit` | REMOVE_FROM_ROOT | `synvoid-proxy` | 0 root uses; 1 use in `crates/synvoid-proxy/src/router.rs: use matchit::Router as MatchRouter;`; dep declared in `crates/synvoid-proxy/Cargo.toml` | Pulled in transitively from `synvoid-proxy`. Safe to drop from root. |
| `pbkdf2` | REMOVE_FROM_ROOT | `synvoid-mesh` (also `synvoid-config`) | 0 root uses; uses in `crates/synvoid-mesh/src/mesh/config_identity.rs`; dep declared in both `synvoid-mesh` and `synvoid-config` `Cargo.toml` | Pulled in transitively from `synvoid-mesh`. Safe to drop from root. |
| `rcgen` | REMOVE_FROM_ROOT | `synvoid-mesh`, `synvoid-tunnel` | 0 root uses; 25 uses in `crates/synvoid-mesh/src/mesh/cert.rs` and `crates/synvoid-tunnel/src/quic/tls.rs`; dep declared in both `Cargo.toml`s | Pulled in transitively. Safe to drop from root. |
| `bloomfilter` | REMOVE_FROM_ROOT | `synvoid-mesh` | 0 root uses; 5 uses in `crates/synvoid-mesh/src/mesh/hierarchical_routing.rs`; dep declared in `crates/synvoid-mesh/Cargo.toml` | Pulled in transitively. Safe to drop from root. |
| `tokio` | KEEP_ROOT_FOR_NOW | root | Used by virtually every root module; also in many extracted crates | Foundation runtime, not removable. |
| `bytes` | KEEP_ROOT_FOR_NOW | root | Body/buffer primitive used across root and crates | Foundation primitive. |
| `serde` / `serde_json` / `serde_bytes` | KEEP_ROOT_FOR_NOW | root | Used by every config / IPC / DHT type | Foundation serialisation. |
| `postcard` / `rkyv` | KEEP_ROOT_FOR_NOW | root | Distributed state (DHT, Mesh, Persistence) per AGENTS.md | Foundation serialisation. |
| `toml` | KEEP_ROOT_FOR_NOW | root | Config loading | Foundation. |
| `anyhow` / `thiserror` | KEEP_ROOT_FOR_NOW | root + crates | Error handling | Foundation. |
| `bitflags` | KEEP_ROOT_FOR_NOW | root + crates | Bit flags | Foundation. |
| `tracing` / `tracing-subscriber` / `tracing-appender` | KEEP_ROOT_FOR_NOW | root | Logging bootstrap in `src/main.rs`, `src/bin/server.rs` | Foundation logging. |
| `regex` | KEEP_ROOT_FOR_NOW | root + crates | WAF rules, etc. | Foundation. |
| `parking_lot` / `dashmap` / `arc-swap` | KEEP_ROOT_FOR_NOW | root + crates | Concurrency primitives | Foundation. |
| `moka` | KEEP_ROOT_FOR_NOW | root + crates | Cache | Foundation. |
| `memmap2` | KEEP_ROOT_FOR_NOW | root | 2 uses in `src/waf/ratelimit/core.rs` (used by IP rate limiter) | Required by root WAF. |
| `metrics` / `metrics-exporter-prometheus` | KEEP_ROOT_FOR_NOW | root | `src/admin/prometheus_exporter.rs` | Required for metrics export. |
| `http` | KEEP_ROOT_FOR_NOW | root + crates | HTTP types | Foundation. |
| `ipnetwork` | KEEP_ROOT_FOR_NOW | root | 3 uses in `src/dns/transfer.rs`, `src/dns/rpz.rs`, `src/dns/update.rs` | Required by root DNS modules. |
| `rand` | KEEP_ROOT_FOR_NOW | root + crates | Randomness | Foundation. |
| `base64` | KEEP_ROOT_FOR_NOW | root + crates | Encoding | Foundation. |
| `sha2` / `sha1` / `sha3` | KEEP_ROOT_FOR_NOW | root + crates | Hashing | Foundation. |
| `hex` | KEEP_ROOT_FOR_NOW | root + crates | Encoding | Foundation. |
| `futures` | KEEP_ROOT_FOR_NOW | root + crates | Async primitives | Foundation. |
| `sysinfo` | KEEP_ROOT_FOR_NOW | root | Process metrics in supervisor | Foundation. |
| `nix` | KEEP_ROOT_FOR_NOW | root | Unix syscalls in supervisor/worker | Foundation. |
| `notify` | KEEP_ROOT_FOR_NOW | root + crates | File system watcher | Used in root `src/plugin/mod.rs` and `synvoid-plugin-runtime`. |
| `aho-corasick` | KEEP_ROOT_FOR_NOW | root + crates | Pattern matching (WAF) | Foundation. |
| `unicode-normalization` | KEEP_ROOT_FOR_NOW | root | Unicode normalization in WAF | Foundation. |
| `libinjectionrs` | KEEP_ROOT_FOR_NOW | root | SQLi detection | Required by root WAF. |
| `tempfile` | KEEP_ROOT_FOR_NOW | root | 3 root uses in `src/process/socket_fd.rs`, `src/upload/sandbox.rs`, `src/worker/cpu_task/payload.rs` | Required by root. |
| `uuid` | KEEP_ROOT_FOR_NOW | root + crates | Unique IDs | Foundation. |
| `pin-project-lite` | KEEP_ROOT_FOR_NOW | root + crates | Pin projection | Foundation. |
| `bcrypt` | KEEP_ROOT_FOR_NOW | root | Password hashing in challenge | Required. |
| `dirs` | KEEP_ROOT_FOR_NOW | root | Path discovery in supervisor | Required. |
| `flate2` | KEEP_ROOT_FOR_NOW | root + crates | gzip | Used in root `src/static_files/file_manager.rs` and crates. |
| `tar` | KEEP_ROOT_FOR_NOW | root | 2 uses in `src/static_files/file_manager.rs` | Required by root. |
| `pqc` (path) | KEEP_ROOT_FOR_NOW | root | Used in `src/mesh/`, `src/auth/`, etc. via the `pqc` workspace member | Foundation for PQ. |
| `zeroize` | KEEP_ROOT_FOR_NOW | root + crates | Secret zeroing | Foundation. |
| `walkdir` | KEEP_ROOT_FOR_NOW | root | 1 use in `src/static_files/file_manager.rs` | Required. |
| `socket2` | KEEP_ROOT_FOR_NOW | root | Socket options in `src/process/`, `src/tcp/` | Required. |
| `hickory-proto` / `hickory-resolver` | KEEP_ROOT_FOR_NOW | root | DNS server in `src/dns/`; optional via `dns` feature | Required. |
| `tokio-dstip` | KEEP_ROOT_FOR_NOW | root | DNS resolver helper | Required. |
| `getrandom` | KEEP_ROOT_FOR_NOW | root | Random sampling | Required. |
| `clap` | KEEP_ROOT_FOR_NOW | root | CLI parsing in `src/main.rs`, `src/bin/server.rs` | Required. |
| `cryptoki` | KEEP_ROOT_FOR_NOW | root | `src/dns/hsm.rs`; optional via `dns` feature | Required. |
| `webpki-roots` | KEEP_ROOT_FOR_NOW | root | TLS root store in `src/tls/`, `src/http3/server.rs` | Required. |
| `zip` | KEEP_ROOT_FOR_NOW | root | 0 direct Rust uses in `src/`; included for the geoip updater (which lives in `synvoid-geoip`) | The dep is only used by the geoip updater crate. UNKNOWN_INVESTIGATE — possibly removable but unverified. |
| `aya` | KEEP_ROOT_FOR_NOW | root | eBPF (Linux only) | Required. |
| `libc` | KEEP_ROOT_FOR_NOW | root | Unix syscalls | Foundation. |
| `windows-sys` | KEEP_ROOT_FOR_NOW | root | Win32 bindings | Foundation. |
| `url` | KEEP_ROOT_FOR_NOW | root | URL parsing in `src/`, `src/auth/`, etc. | Required. |
| `syslog` | KEEP_ROOT_FOR_NOW | root | Syslog sink in `src/logging/`, `src/supervisor/` | Required. |
| `log` | KEEP_ROOT_FOR_NOW | root + crates | Re-exported from `synvoid-config` and used in `src/` logging macros | Foundation. |
| `daemonize2` | KEEP_ROOT_FOR_NOW | root | Daemonization in `src/main.rs`, `src/bin/server.rs` | Required. |
| `aes-gcm` | KEEP_ROOT_FOR_NOW | root + crates | Authenticated encryption | Foundation. |
| `async-trait` | KEEP_ROOT_FOR_NOW | root + crates | Async trait sugar | Foundation. |
| `digest` | KEEP_ROOT_FOR_NOW | root | 119 root uses | Foundation. |
| `rsa` | KEEP_ROOT_FOR_NOW | root + crates | RSA operations | Foundation. |
| `rand_core_06` | KEEP_ROOT_FOR_NOW | root | RNG core (compat) | Foundation. |
| `hkdf` / `hmac` | KEEP_ROOT_FOR_NOW | root + crates | KDF/MAC | Foundation. |
| `x25519-dalek` | KEEP_ROOT_FOR_NOW | root + crates | X25519 ECDH | Foundation. |
| `base32` | KEEP_ROOT_FOR_NOW | root | Base32 encoding in `src/auth/` | Required. |
| `indexmap` / `ahash` / `smallvec` | KEEP_ROOT_FOR_NOW | root + crates | Collection primitives | Foundation. |
| `lru_time_cache` | KEEP_ROOT_FOR_NOW | root | 2 uses in `src/dns/cookie.rs`; also in `synvoid-dns` | Required by root. |
| `chrono` | KEEP_ROOT_FOR_NOW | root + crates | Timestamps | Foundation. |
| `stegoeggo` | KEEP_ROOT_FOR_NOW | root | Steganography library in `src/waf/` | Required by root WAF. |
| `ed25519-dalek` | KEEP_ROOT_FOR_NOW | root | 4+ uses in `src/dns/dnssec_signing.rs`, `src/dns/dnssec_key_mgmt.rs`, `src/dns/hsm.rs`, `src/supervisor/cli_commands.rs`, `src/waf/rule_feed.rs` | Required by root. |
| `rustls-pki-types` | KEEP_ROOT_FOR_NOW | root | TLS types in `src/tls/`, `src/http3/` | Required. |
| `x509-parser` | KEEP_ROOT_FOR_NOW | root | X.509 cert parsing in `src/tls/`, `src/waf/` | Required. |

## Removed from root (history)

This sub-section is appended to in MDM-R02; earlier passes already
removed the focus-first items above.

### MDM-R02 batch 1 — 2026-06-07

| Dependency | Reason | Already in extracted crate |
|---|---|---|
| `httparse` | 0 real root uses (only doc-comment references); pulled in transitively | `synvoid-http` |
| `matchit` | 0 root uses; pulled in transitively | `synvoid-proxy` |
| `pbkdf2` | 0 root uses; pulled in transitively | `synvoid-mesh`, `synvoid-config` |
| `rcgen` | 0 root uses; pulled in transitively | `synvoid-mesh`, `synvoid-tunnel` |
| `bloomfilter` | 0 root uses; pulled in transitively | `synvoid-mesh` |

Verification (after removal):

```text
cargo check -p synvoid-waf            OK
cargo check -p synvoid-proxy          OK
cargo check -p synvoid-http           OK
cargo check -p synvoid-static-files   OK
cargo check -p synvoid-ipc            OK
cargo check -p synvoid-core           OK
cargo check --lib --no-default-features   OK
cargo check --no-default-features --features mesh,dns  OK
```

No items failed and needed `KEEP_ROOT_FOR_NOW` restoration. The
pre-existing mesh and admin-ui compile errors observed before the batch
were unchanged.

### MDM-R03 — 2026-06-07

17 historical "moved to" / "removed" comments in root `Cargo.toml` were
replaced with brief one-liners that point at this document. The
substantive content already lives in the focus-first table above. The
Cargo.toml history went from 20 historical comment lines (across 17
dependencies) to 14 brief one-liner references.

## Verification

```bash
cargo check -p synvoid-waf
cargo check -p synvoid-proxy
cargo check -p synvoid-http
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
cargo check --workspace --all-targets
```

Pre-existing failures (not introduced by MDM-R01):

* `cargo check --no-default-features --features mesh` — E0425 in
  `src/worker/unified_server/init_mesh.rs` (`backend_pool`,
  `signer_for_mesh`).
* `cargo check --workspace --all-targets` — `admin-ui` lib + lib-test
  have 5 errors (E0277/E0282/E0609) plus missing `tempfile`/`sha2`
  imports in yew pages.
