# SynVoid Consolidated Implementation Plan

> **Note**: This is the single source of truth for all planned work.
> Completed items have been pruned. See git history for completed item details.
> All items verified against source code by review subagents (2026-05-28).

---

## Priority Key

- **P0**: Critical security/regression bugs
- **P1**: High-impact bugs or architectural issues
- **P2**: Medium-priority improvements
- **P3**: Low-priority documentation/accuracy fixes

---

## Execution Waves

Items are organized into waves that can be parallelized. Within each wave, tasks are grouped by domain so multiple agents can work simultaneously. **Within a wave, all tasks are independent** — assign one task per agent.

### Wave 1: Security-Critical Code Fixes (P0)

Each task is independent and can be assigned to a separate agent. All verified present in source code.

| ID | Task | Location | Description | Effort |
|----|------|----------|-------------|--------|
| **SEC-1** | ~~Fix filter allow/deny priority~~ | `src/filter/common.rs:74-96` | ~~Documentation says "allowlist first, then denylist" — actual code checks **denylist first** (`:74-84`), then allowlist (`:86-96`). Update `architecture/filter.md:53-54` to match actual behavior.~~ **RESOLVED**: `architecture/filter.md:68` already correctly states "Denylist checked first, then allowlist (deny takes precedence for security)". | Low |
| **SEC-2** | ~~Fix SSRF bypass via HTTPS~~ | `src/admin/alerting/mod.rs:143-154` | ~~SSRF check is inline in `AlertConfig::validate()` (not a named function). Line 143: `if url_lower.starts_with("http://")` — only `http://` URLs get private IPs checked. An `https://` URL to `https://127.0.0.1/admin` bypasses the check entirely.~~ **RESOLVED**: Added HTTPS URL validation to SSRF check. Both `http://` and `https://` URLs now checked for private IPs. Commit: `988c0498`. | Low |
| **SEC-3** | ~~Fix FastCGI semaphore bypass~~ | `src/fastcgi/pool.rs:229` | ~~`execute_stream()` acquires semaphore permit at line 224, then immediately `drop(permit)` at line 229 before any work. Concurrency limiting is completely bypassed.~~ **RESOLVED**: Removed `drop(permit)`, permit now held for full function scope. Commit: `4b49a371`. | Low |
| **SEC-4** | ~~Fix cert strength validation bypass~~ | `src/tls/cert_resolver.rs:215-253` | ~~`load_certs_from_dir()` does NOT call `validate_key_strength()` (which ends at line 213). Certs loaded from watch directory completely bypass RSA key strength checks.~~ **RESOLVED**: Added `validate_key_strength()` call in `load_certs_from_dir()`. Commit: `ba513c0b`. | Low |

### Wave 2: Code Bug Fixes (P1)

Independent bug fixes, each assignable to a separate agent.

| ID | Task | Location | Description | Effort |
|----|------|----------|-------------|--------|
| **BUG-1** | ~~Fix CGI thread pool blocking~~ | `src/cgi/mod.rs:342-358` | ~~`execute_script()` uses `spawn_blocking` wrapping `std::process::Command` + `wait_with_output()`. The entire CGI execution (stdin write + wait) runs in a single blocking task, which could starve the Tokio blocking thread pool under high concurrency.~~ **RESOLVED**: Converted to `tokio::process::Command` for async process management. Commit: `180fc20b`. | Medium |
| **BUG-2** | ~~Fix static file double-read~~ | `src/static_files/mod.rs:867-880` | ~~`into_response()` at line 877-878 does `Bytes::from(std::fs::read(&path).unwrap_or_default())` — synchronous re-read of file already read when creating `StaticResponse::Buffered`. Negates zero-copy.~~ **RESOLVED**: Changed `Buffered` variant from `PathBuf` to `Bytes`, eliminating double-read. Commit: `ad2eb28a`. | Medium |
| **BUG-3** | ~~Fix StreamingFastCgiClient buffering~~ | `src/fastcgi/streaming.rs:258-273` | ~~Buffers entire request body into `stdin_buffer: Vec<u4>` before sending (line 275: `build_stdin_records(&stdin_buffer)`). Not truly streaming.~~ **RESOLVED**: Implemented true streaming body forwarding with chunked FastCGI STDIN records. Commit: `63b07e03`. | Medium |
| **BUG-4** | ~~Fix admin session race window~~ | `src/admin/state.rs:830-852` | ~~TOCTOU race: read lock acquired at line 838, dropped at line 842, write lock acquired at line 843. Between drop and write, another thread could modify the session.~~ **RESOLVED**: Single write lock for atomic validate+update. Commit: `3134182a`. | Low |
| **BUG-5** | ~~Fix cert file reload debounce~~ | `src/tls/cert_resolver.rs:484-498` | ~~Debounce sleeps 500ms then drains events (line 487-488). New events arriving after drain but before `load_certificates()` finishes are lost.~~ **RESOLVED**: Restructured loop with inner `needs_reload` flag to re-check after load. Commit: `7ca09fa1`. | Low |
| **BUG-6** | ~~Fix macOS zero_copy path~~ | `src/zero_copy.rs:128-133` | ~~`FilePath::path()` on Unix uses `/proc/self/fd/{fd}` — Linux-only. `#[cfg(unix)]` should be `#[cfg(target_os = "linux")]` since macOS doesn't have procfs.~~ **RESOLVED**: Changed to `#[cfg(target_os = "linux")]`. Commit: `bed70c72`. | Medium |
| **BUG-7** | ~~Fix ACME non-Unix permissions~~ | `src/tls/acme.rs:190-193` | ~~Unix path (lines 178-181) sets `0o600` permissions. Non-Unix path (lines 190-193) uses `std::fs::write` with default permissions (typically `0o644`), making credentials file world-readable on Windows.~~ **RESOLVED**: Added atomic write + Windows ACLs for restrictive permissions. Commit: `55937d18`. | Low |
| **BUG-8** | ~~Fix request_body_size double assignment~~ | `src/http/server.rs:1633` | ~~Line 1633: `request_body_size = len;` overwrites WAF-computed body size with raw `Content-Length` header value after WAF scanning.~~ **RESOLVED**: Removed overwriting line. Commit: `82ed83bf`. | Low |

### Wave 3: Dead Code Cleanup (P1)

Remove or wire dead code. Each task is independent.

| ID | Task | Location | Description | Effort |
|----|------|----------|-------------|--------|
| **DEAD-1** | Remove dead zero_copy module | `src/zero_copy.rs` | Declared in `lib.rs:101` but has ZERO external callers anywhere in the codebase. Remove file and `lib.rs` declaration. | Low |
| **DEAD-2** | Remove dead listener/common.rs types | `src/listener/common.rs` | `SocketOptionsBase`, `ListenerConfigBase`, `ListenerInstance<C>` are defined but never instantiated. `ConnectionContext` IS used (re-exported in `tcp/mod.rs:12`/`udp/mod.rs:9`) — keep it. Remove only the dead types. | Medium |
| **DEAD-3** | Wire or remove pqc-mesh feature | `Cargo.toml` + all `src/**/*.rs` | `pqc-mesh` feature flag defined at `Cargo.toml:37` but has zero `#[cfg(feature = "pqc-mesh")]` usages. Either wire it to gate ML-DSA-44 post-quantum signatures or remove the flag. | Medium |
| **DEAD-4** | Remove dead ProxyServer wrappers | `src/proxy/mod.rs:929,1143,1148,1153,1158` | All marked `#[allow(dead_code)]`. Remove or implement. | Low |
| **DEAD-5** | Remove dead HttpProtocol/PooledConnection stubs | `src/http_client/erased_pool.rs` | `HttpProtocol` enum, `PooledConnection` trait, `Http2PooledConnection` are empty stubs. Remove or implement. | Low |
| **DEAD-6** | Remove CacheEntryInner::validate() | `src/proxy/cache/store.rs:139-141` | Dead code. Remove. | Low |
| **DEAD-7** | Remove honeypot_unified dead module | `src/honeypot_unified/` | 215 lines exist but NOT declared in `lib.rs`. Dead module — remove directory. | Low |
| **DEAD-8** | Remove orphaned serialization_rkyv.rs | `src/serder/serialization_rkyv.rs` | File exists but NOT declared in `lib.rs`. Remove or wire. | Low |
| **DEAD-9** | Remove dead RequestContext trait | `src/http/shared_handler.rs:133` | `RequestContext` trait is `#[allow(dead_code)]`. Remove or implement. | Low |

### Wave 4: Feature Wiring (P1-P2)

Wire or properly configure partially-implemented features.

| ID | Task | Location | Description | Effort |
|----|------|----------|-------------|--------|
| **FEAT-1** | Wire pqc-mesh feature flag | Multiple `#[cfg(feature = "pqc-mesh")]` locations | Feature is defined in Cargo.toml but has zero cfg usages. Investigate what it should gate (ML-DSA-44 post-quantum signatures) and wire it. (Cross-references DEAD-3) | High |
| **FEAT-2** | Fix health_check() validation | `src/fastcgi/pool.rs:283-294` | `health_check()` only validates socket format, not actual connectivity. Add real connection test. | Low |
| **FEAT-3** | Fix collect_body_with_chunk_waf duplication | `src/http/server.rs:4665` + `src/tls/server.rs:2086` | Two implementations with different signatures. Consolidate into single shared implementation. | Medium |
| **FEAT-4** | Export ServerlessScheduler | `src/serverless/scheduler.rs` + `src/serverless/mod.rs` | `scheduler.rs` exists but not `pub mod` in `mod.rs`. Wire or remove. | Low |

### Wave 5: Documentation Updates (P2-P3)

Organized by domain for parallel execution. **Each domain can be handled by a separate agent.** Within a domain, tasks can be batched (one agent per domain).

#### Wave 5A: Admin/Observability Docs (11 items)

| ID | File | Fix |
|----|------|-----|
| DOC-A1 | `architecture/admin_deep_dive.md` | Fix middleware order: actual is `Request→Rate Limit→YARA Rate Limit→CSRF→Auth→Client IP` |
| DOC-A2 | `architecture/admin_deep_dive.md` | Update handler count: 28 (24 always + 4 mesh-gated), not 26 |
| DOC-A3 | `architecture/admin_deep_dive.md` | Fix `build_router_from_state()` line: 173, not 806 |
| DOC-A4 | `architecture/metrics.md` | Expand SiteMetrics: 13 fields, not 6 |
| DOC-A5 | `architecture/metrics.md` | Fix BandwidthTracker: 11+ fields, not 2 |
| DOC-A6 | `architecture/metrics.md` | Fix WorkerMetrics: 13+ fields, not 3 |
| DOC-A7 | `architecture/metrics.md` | Expand global counters: 50+ `LazyLock<AtomicU64>`, not 4 statics |
| DOC-A8 | `architecture/protocol.md` | Fix ProtocolHandler trait return types and ProtocolDetectionResult field types |
| DOC-A9 | `architecture/admin_deep_dive.md` | Fix SyslogLogger struct: actual uses `_backend: ()` on Unix, `app_name: String`, `_phantom: ()` — no `syslog` field |
| DOC-A10 | `architecture/admin_deep_dive.md` | Document audit log per-write permissions at `audit.rs:131-139` (redundant — already set in `with_audit_dir()`) |
| DOC-A11 | `architecture/admin_deep_dive.md` | Document email alerting stub: `send_email_internal()` at `mod.rs:349-373` logs message then returns `Ok(())` without sending |

#### Wave 5B: App Handler Docs (9 items)

| ID | File | Fix |
|----|------|-----|
| DOC-B1 | `architecture/static_files.md:30-36` | Fix NormalizedLocation: `index: Option<String>`, `cache_ttl: Option<u64>`, add `theme` field |
| DOC-B2 | `architecture/static_files.md:22-28` | Fix StaticFileHandler: 16 fields (add `gzip_types`, `max_file_size`, `gzip_level`, etc.) |
| DOC-B3 | `architecture/static_files.md:38-50` | Fix StaticResponse/StaticResponseBody/StaticError variant structures |
| DOC-B4 | `architecture/fastcgi.md:19-29` | Fix FastCgiClient fields (`socket_path`, `is_tcp`) and FastCgiPool structure (`RwLock<VecDeque<PooledConnection>>`) |
| DOC-B5 | `architecture/mime.md:19-28` | Fix MimeRegistry type (`HashMap<String, String>`) and remove MimeTypeInfo field reference |
| DOC-B6 | `architecture/theme.md:47-53` | Fix DirectoryEntry: `modified: String`, `size: String`, add `modified_timestamp`/`size_bytes` |
| DOC-B7 | `architecture/app_handlers.md:71` | Fix SpinHttpHandler line reference |
| DOC-B8 | `architecture/fastcgi.md` | Document health_check() socket-format-only limitation |
| DOC-B9 | `architecture/streaming.md` | Fix ProxyError variant types and ProxyConfig.waf_scanner type |

#### Wave 5C: Config Docs (7 items)

| ID | File | Fix |
|----|------|-----|
| DOC-C1 | `architecture/config.md:200` | Fix MeshNodeRole: struct(u8) bitflag with 8 values, not enum |
| DOC-C2 | `architecture/config.md:131` | Fix MainConfig: `supervisor_compat: SupervisorConfig`, not `overseer: OverseerConfig` |
| DOC-C3 | `architecture/config_deep_dive.md:91-117` | Expand SiteConfig hierarchy (missing `worker_pool`, `logging`, `proxy`, `tcp`, `udp`, `tarpit`, `upload`, `auth`, `tunnel`, `whitelist`, `serverless_only`); `site_id` is method not field |
| DOC-C4 | `architecture/config_deep_dive.md:329` | Fix DNS validation condition: requires `dns.enabled == true`, not just feature compile |
| DOC-C5 | `architecture/config.md:662-707` | Add missing appendix files: `site/misc.rs`, `icmp_filter.rs`, 10 DNS submodules |
| DOC-C6 | `architecture/config.md:85-87` | Fix default port function line references: `default_dns_port` at `dns/mod.rs:144` (not 145), `default_wg_port` at `tunnel.rs:87` (not 86) |
| DOC-C7 | `architecture/config.md` | Expand feature flag table to list ALL effects of each feature. `dns` feature also enables `hickory-proto`, `hickory-resolver`, `tokio-dstip`, `cryptoki`, `getrandom`. Add missing gates: `origin_key_exchange`, `audit`, `verify-pq`, `tun-rs`, `buffer`, `rkyv`, `test-utils` |

#### Wave 5D: DNS Docs (12 items)

| ID | File | Fix |
|----|------|-----|
| DOC-D1 | `architecture/dns.md:107` | Fix syntax error: `Arc<RwLock<BTreeMap>>` missing angle brackets |
| DOC-D2 | `architecture/dns.md:226` | Add `#[cfg(feature = "dns")]` to `with_cookie_server` |
| DOC-D3 | `architecture/dns.md:341` | Fix cookie validation location: method at `cookie.rs:66-86`, call site at `server/query.rs:645-662` |
| DOC-D4 | `architecture/dns.md:790` | Remove stale DNS-2 reference (`_max_wait_ms` is now used) |
| DOC-D5 | `architecture/dns.md:246` | Fix HickoryRecursor `new()` line: 629 (method), not 628 (impl block start) |
| DOC-D6 | `architecture/dns.md:224` | Fix `with_acme_dns_challenges` line: 855, not 573 |
| DOC-D7 | `architecture/dns.md:3.1` | Expand DnsServer struct: ~30 fields (add `zone_index_dirty`, `geoip_lookup`, `shutdown_tx`, etc.) |
| DOC-D8 | `architecture/dns.md:3.5` | Add `key_size: Option<u32>` to ZoneSigningKey |
| DOC-D9 | `architecture/dns_deep_dive:39` | Fix RFC reference: DNS cookies are RFC 7873, not RFC 8905 |
| DOC-D10 | `architecture/dns_deep_dive:70` | Remove stale DNS-2 reference |
| DOC-D11 | `architecture/dns.md` | Document missing modules: `mesh_dnssec.rs`, `platform.rs`, `prefetch.rs`, `secure_server.rs`, `sharded_cache.rs`, `config.rs`, `zone_manager.rs` |
| DOC-D12 | `architecture/dns.md` | Document missing types: `DsDigestType`, `DnsSecKeyStatus`, `KeyInfo`, `KeyRotationResult`, `RolloverState`, `CryptoRngAdapter`, `ShardedDnsCache`, `SecureDnsServerBase`, `DnsSettings`, `PrefetchConfig` |

#### Wave 5E: HTTP Server Docs (5 items)

| ID | File | Fix |
|----|------|-----|
| DOC-E1 | `architecture/http_server.md:23` | Fix line count: 4907, not 4908 |
| DOC-E2 | `architecture/http_shared.md:176` | Fix function name: `send_request_with_timeout_and_headers`, not `send_request_with_headers` |
| DOC-E3 | `architecture/http_server.md:340-341` | Clarify HTTP-01 challenge is behind `mesh` feature, not `dns` |
| DOC-E4 | `architecture/http_shared.md:324-325` | Fix `WebPkiServerVerifier` description: uses `with_root_certificates`, not explicit `WebPkiServerVerifier` |
| DOC-E5 | `architecture/http_shared.md:129` | Fix `StreamingWafBody`: implements `hyper::body::Body`, not `http_body::Body` |

#### Wave 5F: Mesh Docs (8 items)

| ID | File | Fix |
|----|------|-----|
| DOC-F1 | `architecture/mesh.md` | Fix QuorumVerifier reference: `QuorumVerifierContext` at `dht/signed.rs:12`, not `quorum.rs` |
| DOC-F2 | `architecture/mesh.md` | Fix NodeInfo location: `dht/mod.rs:342`, not `dht/keys.rs` |
| DOC-F3 | `architecture/mesh.md` | Fix TierKeyStore location: `dht/mod.rs:850`, not `dht/store.rs` |
| DOC-F4 | `architecture/mesh.md` | Fix DhtAccessControl location: `dht/mod.rs:689`, not `capability_access.rs:7` |
| DOC-F5 | `architecture/mesh.md` | Add `AuthorizedGlobalNodes` variant to Namespace (4 variants, not 3) |
| DOC-F6 | `architecture/mesh.md` | Document MeshNodeRole bitmask: 8 values including `GLOBAL_EDGE`, `GLOBAL_ORIGIN`, `EDGE_ORIGIN`, `ALL`, `SERVERLESS_ORIGIN` |
| DOC-F7 | `architecture/mesh.md` | Add `record_store_persist.rs` to file tree |
| DOC-F8 | `architecture/mesh.md` | Fix RaftInstance field reference: `MeshTransport.raft_instance` at `transport.rs:159`, not `RaftInstance.raft` |

#### Wave 5G: Networking Docs (10 items)

| ID | File | Fix |
|----|------|-----|
| DOC-G1 | `architecture/networking_deep_dive.md` | Fix 0-RTT config path: `tls.quic_enable_0rtt`, not `mesh.config.quic.enable_0rtt` |
| DOC-G2 | `architecture/networking_deep_dive.md` | Fix ACME DNS TXT line numbers: `query.rs:698-721` |
| DOC-G3 | `architecture/networking_deep_dive.md` | Remove `SiteConnectionLimiter` reference (struct removed) |
| DOC-G4 | `architecture/networking_deep_dive.md` | Fix `mesh.ml_kem` → `mesh.mlkem` (no underscore) |
| DOC-G5 | `architecture/networking_deep_dive.md` | Fix `http_client/mod.rs:893` → line 878 |
| DOC-G6 | `architecture/listener.md` | Rewrite entire file — documented structs don't match actual source code at all |
| DOC-G7 | `architecture/listener.md` | Fix bind_addresses: `bind_address: String` + `bind_address_v6: Option<String>` (not `Vec<String>`) |
| DOC-G8 | `architecture/listener.md` | Fix expected_protocol: `String` (not `ProtocolType` enum) |
| DOC-G9 | `architecture/listener.md` | Fix upstream_address: `String` + `upstream_address_v6: Option<String>` (not `Option<String>`) |
| DOC-G10 | `architecture/listener.md` | Fix filter_config: `filter_enabled: bool` + `strict_mode: bool` (no `FilterConfig` type) |

#### Wave 5H: Proxy/Routing Docs (21 items)

| ID | File | Fix |
|----|------|-----|
| DOC-H1 | `architecture/proxy.md:57-63` | Fix BackendType: actual is `router.rs:66-78` with 11 variants: `Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin` |
| DOC-H2 | `architecture/proxy.md:210-215` | Fix calculate_backoff() pseudocode: remove jitter that doesn't exist in code |
| DOC-H3 | `architecture/proxy.md` | Fix RetryConfig: field is `retry_on_error` (not `retry_on_connection_error`), add `retry_non_idempotent` |
| DOC-H4 | `architecture/proxy.md` | Add `proxy_headers_config: Option<Arc<ProxyHeadersConfig>>` to ProxyServer |
| DOC-H5 | `architecture/proxy.md` | Fix `with_upstream_pool()` signature: add `retry_config` and `buffering_config` parameters |
| DOC-H6 | `architecture/proxy.md` | Remove named constants `DEFAULT_POOL_MAX_IDLE` etc. (values are inline) |
| DOC-H7 | `architecture/proxy.md` | Fix `http2`: struct field, not feature gate |
| DOC-H8 | `architecture/proxy_deep_dive.md` | Fix revalidation semaphore default: 100, not 32; field name is `max_concurrent_revalidations` |
| DOC-H9 | `architecture/proxy_cache.md` | **Major rewrite needed** — nearly every struct definition is wrong |
| DOC-H10 | `architecture/proxy_cache.md` | Fix ProxyCacheEntry: `HashMap` → `HeaderMap`, `u64` → `Instant` |
| DOC-H11 | `architecture/proxy_cache.md` | Fix CacheKey.site_id: `String` not `Option<String>` |
| DOC-H12 | `architecture/proxy_cache.md` | Fix CacheHit: no associated data on variants |
| DOC-H13 | `architecture/proxy_cache.md` | Fix ProxyCacheSettings: `max_memory_size` not `max_memory_entries`, `inactive` not `default_ttl` |
| DOC-H14 | `architecture/proxy_cache.md` | Fix ProxyCache: uses `CacheKey` not `String`, no `disk_cache` field |
| DOC-H15 | `architecture/streaming.md` | Fix ProxyError variants: `ReadError`/`WriteError` take `String` not `io::Error` |
| DOC-H16 | `architecture/location_matcher.md` | Fix LocationMatch: `exact_matches` → `exact_locations` with tuple values, `compiled_regex` → `regex` |
| DOC-H17 | `architecture/upstream.md` | Fix field types: `cpu_percent`/`memory_percent` are `Arc<AtomicU32>` |
| DOC-H18 | `architecture/routing_deep_dive.md` | Replace external GitHub URLs with local file paths |
| DOC-H19 | `architecture/proxy.md` | Document SharedConnectionTable layout: `[16 + max_workers * 8..]` not `[N+1..]` |
| DOC-H20 | `architecture/proxy.md` | Document CacheKey.uri contains hash-prefixed value: `format!("{}:{}", hash, uri_str)` |
| DOC-H21 | `architecture/proxy.md` | Document `ErasedHttpClient::new(100)` hardcodes pool size instead of using parameter |

#### Wave 5I: TLS/Crypto Docs (7 items)

| ID | File | Fix |
|----|------|-----|
| DOC-I1 | `architecture/layer_3_5_deep_dive.md` | Fix post-quantum provider location: `src/mesh/cert.rs:87-139`, not `src/startup/master.rs:210-234` |
| DOC-I2 | `architecture/layer_3_5_deep_dive.md` | Fix TunnelBackend location: `src/tunnel/router.rs:200`, not `src/tunnel/upstream.rs` |
| DOC-I3 | `architecture/tls.md` | Fix CertResolver.certs: `Arc<RwLock<HashMap<...>>>` (missing `RwLock` wrapper) |
| DOC-I4 | `architecture/tls.md` | Fix `watch_for_cert_changes`: free function, not method |
| DOC-I5 | `architecture/tls.md` | Expand SniError: 7 variants, not 4 (add `InvalidHostname`, `ConnectionClosed`, `Io(String)`) |
| DOC-I6 | `architecture/tls.md` | Add undocumented `config: InternalTlsConfig` field to CertResolver docs |
| DOC-I7 | `architecture/layer_3_5_deep_dive.md` | Fix rustls-post-quantum line: `Cargo.toml:157` not 156 |

#### Wave 5J: Utilities Docs (8 items)

| ID | File | Fix |
|----|------|-----|
| DOC-J1 | `architecture/filter.md:53-54` | **SECURITY**: ~~Fix priority — denylist checked first, then allowlist (doc has it reversed)~~ **RESOLVED**: `architecture/filter.md:68` already correct |
| DOC-J2 | `architecture/filter.md` | Fix `Protocol::from_str` return type: `Self` (infallible), not `Option<Self>` |
| DOC-J3 | `architecture/filter.md` | Fix `BaseFilterConfig` allowlist/denylist: `Vec<String>` (stringly-typed), not `Vec<P>` |
| DOC-J4 | `architecture/zero_copy.md` | Fix `sendfile_to_socket` description: returns `Err` on unsupported platforms, not userspace fallback |
| DOC-J5 | `architecture/serder.md` | Clarify Postcard: single-allocation encoding but NOT cross-version/platform determinism. Only `no_std` with explicit endianness is deterministic |
| DOC-J6 | `architecture/filter.md` | Fix PhantomData field name: `_marker` not `_phantom` |
| DOC-J7 | `architecture/filter.md` | Document trait bounds: both traits have `Clone + PartialEq + Eq + Debug + Send + Sync + 'static` |
| DOC-J8 | `architecture/filter.md` | Document missing `PortConfigBase` type (public API exported from `src/filter/mod.rs:4`) |

#### Wave 5K: WAF/Security Docs (18 items)

| ID | File | Fix |
|----|------|-----|
| DOC-K1 | `architecture/waf.md` | Expand WafCore struct: ~30 fields (add `auth_manager`, `attack_detection_config`, `block_store`, `config`, `whitelist`, `tarpit_generator`, `rate_limiter`, `captcha_manager`, `challenge_config`, `icmp_filter`, `threat_intel`, `behavioral_intel`, `integrity_checker`, etc.) |
| DOC-K2 | `architecture/waf.md:180` | Remove `SiteConnectionLimiter` reference (struct does not exist) |
| DOC-K3 | `architecture/waf.md` | Fix WafCoreConfig: 22 fields, not 11 |
| DOC-K4 | `architecture/waf.md` | Fix default features: `flood-ebpf` is NOT in default features |
| DOC-K5 | `architecture/waf_deep_dive.md:24` | Remove `SiteConnectionLimiter` reference |
| DOC-K6 | `architecture/block_store.md:20-36` | Fix BlockStore: 64-shard `Vec<RwLock<AHashMap>>`, not `Arc<RwLock<HashMap>>` |
| DOC-K7 | `architecture/block_store.md` | Fix BlockEntry: `ip: String`, `blocked_at: u64`, `ban_expire_seconds: u64`, `site_scope: String`, add `access_count`/`last_access` |
| DOC-K8 | `architecture/challenge.md` | Remove non-existent `rate_limiter: RateLimiter` field |
| DOC-K9 | `architecture/captcha.md` | Fix CaptchaManager.challenges type: uses `CaptchaStore` wrapper; fix `verification_window_secs`: `u32` not `u64` |
| DOC-K10 | `architecture/icmp_filter.md` | Remove `FilterBackend::PfBsd` variant (does not exist) |
| DOC-K11 | `architecture/icmp_filter.md` | Fix feature gates: `icmp-ebpf` not `flood-ebpf`, `icmp-pf` not `icmp-filter` |
| DOC-K12 | `architecture/integrity.md` | Fix SignedHttpMessage: add missing fields (`integrity_header`, `method`, `path`, `query`, `body_hash`); fix `signature` and `timestamp` types |
| DOC-K13 | `architecture/tarpit.md` | Fix TarpitManager.chain: add `Arc<RwLock<>>` wrapper; fix field types `usize` → `u32` |
| DOC-K14 | `architecture/upload.md` | Fix UploadValidationError: add missing variants (`InvalidMultipart`, `NoData`, `EmptyFilename`, `IoError`, `YaraError`, `SandboxError`) |
| DOC-K15 | `architecture/upload.md` | Fix UploadValidator struct: different field names/types from documented |
| DOC-K16 | `architecture/upload.md` | Fix UploadConfig: incomplete documentation |
| DOC-K17 | `architecture/honeypot.md` | Fix PortHoneypotController: only `runner` and `config` fields |
| DOC-K18 | `architecture/honeypot.md` | Fix IpHoneypotProfile: `AtomicU64` not `AtomicU32`, `RwLock<Vec<String>>` not `HashSet` |

#### Wave 5L: WASM/Plugin Docs (7 items)

| ID | File | Fix |
|----|------|-----|
| DOC-L1 | `architecture/spin.md` | Clarify `Manifest` vs `SpinManifest` — shown struct is `SpinManifest`, actual `Manifest` is simplified |
| DOC-L2 | `architecture/plugin_deep_dive.md:108` | Fix stale claim: `PooledInstance::prepare_for_request` DOES reset `body_receiver` and DHT prefixes |
| DOC-L3 | `architecture/serverless.md` | Fix FunctionDefinition: `require_trusted_caller: bool` (not `Option<bool>`), `allowed_dht_prefixes: Vec<String>` (not `Option<Vec<String>>`), `path: String` (not `Option<String>`), add `handler: String` field |
| DOC-L4 | `architecture/plugin_deep_dive.md:109` | Fix host function count: 7, not 6 |
| DOC-L5 | `architecture/serverless.md` | Remove incorrect `#[cfg(feature = "mesh")]` from `handle_serverless_function_streaming` |
| DOC-L6 | `architecture/spin.md` | Remove false claim: "Runs a supervisor task for idle eviction and health checks" — no such task exists |
| DOC-L7 | `architecture/serverless.md` | Document Spin idle instance eviction: `instances` HashMap keyed by UUID grows indefinitely — old entries never cleaned up |

#### Wave 5M: Process Infrastructure Docs (10 items)

| ID | File | Fix |
|----|------|-----|
| DOC-M1 | `architecture/process_lifecycle.md` | Remove all `src/overseer/`, `src/master/`, `src/startup/master.rs` references |
| DOC-M2 | `architecture/supervisor.md` | Update `ProcessManagerConfig`: add 8 missing fields, rename `master_socket_path` → `supervisor_socket_path` |
| DOC-M3 | `architecture/supervisor.md` | Fix `run_supervisor_mode()` line: 531-537, not 541-546 |
| DOC-M4 | `architecture/worker_architecture.md` | Fix buffer pool tiers: 4 tiers (small/medium/large/jumbo), not 3 |
| DOC-M5 | `architecture/ipc_process.md` | Fix MessageCategory count: 18, not 17 |
| DOC-M6 | `architecture/ipc_process.md` | Replace `Overseer*` message variants with `Supervisor*` prefix |
| DOC-M7 | `architecture/drain.md` | Expand DrainStatus/WorkerDrainState with all actual fields |
| DOC-M8 | `architecture/platform.md` | Remove non-existent `supports_seatbelt()` method; document feature gate instead |
| DOC-M9 | `architecture/process_lifecycle.md` | Fix CPU pinning claim: requires `--cpu-affinity` flag, not "automatic" |
| DOC-M10 | `architecture/process_lifecycle.md` | Fix drain coordination claim: `drain_aware_shutdown()` exists at `process.rs:198-272` |

#### Wave 5N: Overview/General Docs (8 items)

| ID | File | Fix |
|----|------|-----|
| DOC-N1 | `architecture/overview.md:269-278` | Update all Key Source File line counts to actual values |
| DOC-N2 | `architecture/overview.md:174` | Create or remove `architecture/tunnel.md` reference |
| DOC-N3 | `architecture/overview.md:210` | Create or remove `architecture/admin.md` reference |
| DOC-N4 | `architecture/overview.md:224` | Fix typo: `serder.md` → `serde.md` |
| DOC-N5 | `architecture/deep_dive_review.md:48` | Remove unverifiable `io_uring` claim or add evidence |
| DOC-N6 | `architecture/overview.md` | Document `StaticResponseBody` location: defined in `src/static_files/mod.rs:96`, not `src/http/server.rs` |
| DOC-N7 | `architecture/overview.md` | Document common.md `setup_panic_handler` claim: NOT called from `main.rs` directly |
| DOC-N8 | `architecture/geoip.md` | Fix GeoIpManager: fields wrapped in `Arc<RwLock<>>` not bare types |

#### Wave 5O: WAF Deep-Dive Doc Gaps (4 items)

| ID | File | Fix |
|----|------|-----|
| DOC-O1 | `architecture/integrity.md` | Fix IntegrityConfig: 17+ fields vs documented 5 |
| DOC-O2 | `architecture/integrity.md` | Fix SessionKey.key: `String` (base64) not `Vec<u8>` |
| DOC-O3 | `architecture/icmp_filter.md` | Fix BackendCapabilities: `supports_block`, `supports_allow` etc., add `requires_admin`, `is_enforcing` |
| DOC-O4 | `architecture/icmp_filter.md` | Fix IcmpFilterManager: `filter: Box<dyn IcmpFilter>` not `Option<Box<dyn IcmpFilter>>`; fix IcmpFilterFactory::create: ownership not reference; fix IcmpFilter::update_config: `Result<()>` not `Result<(), IcmpFilterError>` |

### Wave 6: Cross-Module Conflict Resolution (P2)

Resolve conflicts where multiple documents disagree.

| ID | Conflict | Resolution |
|----|----------|------------|
| **XMOD-1** | MeshNodeRole — config.md says enum, mesh.md says bitmask | Both wrong in different ways — update both to actual bitmask struct |
| **XMOD-2** | DrainStatus/WorkerDrainState — incomplete in drain.md AND supervisor.md | Make drain.md canonical, update supervisor.md to reference it |
| **XMOD-3** | Buffer pool tier count — worker_architecture.md says 3, networking_deep_dive.md says 4 | Actual is 4 — fix worker_architecture.md |
| **XMOD-4** | SiteConnectionLimiter — referenced in 3 files after removal | Delete all three references (waf.md:180, waf_deep_dive.md:24, networking_deep_dive.md:82) |
| **XMOD-5** | Overseer/Master naming — ipc_process.md uses `Overseer*` variants, code uses `Supervisor*` | Real code inconsistency — document the `Master*` → `Supervisor*` rename in process docs |
| **XMOD-6** | request_body_size double assignment — `src/http/server.rs` lines 1517, 4692, 1633 | Line 1633 overwrites WAF-computed body size with Content-Length header value. Fix: remove line 1633 or make it conditional. (Cross-references BUG-8) |
| **XMOD-7** | TunnelBackend location — layer_3_5 says `upstream.rs`, actual is `router.rs:200` | Update path reference |

---

## Deferred Items (Requires Major Architectural Work)

These items require significant architectural work and are correctly deferred:

| ID | Issue | Reason | Effort |
|----|-------|--------|--------|
| **MESH-14** | Source Node ID Binding Validation | Partial validation exists (node_id bound to TLS), but no TLS cert chain validation for global nodes. Requires PKI hierarchy, trust model changes. | VeryHigh |
| **HTTP2-POOL** | ErasedHttpClient HTTP/2 support | `Http2PooledConnection` is empty stub. hyper-util API requires background task management per connection. | VeryHigh |
| **MR-4** | DhtSyncRequest has no auth | Breaking protobuf protocol change - no signature field. Coordinated rollout required. | High |

---

## HTTP/2 Pooling Implementation Plan (When Resolved)

**Status**: DEFERRED - hyper-util API incompatible

When the hyper-util API issue is resolved, implement HTTP/2 pooling:

### Step 1: HTTP2-POOL-1
- Location: `src/http_client/erased_pool.rs:125-127`
- Add connection fields: `io`, `sender`, `driver` task
- Implement proper HTTP/2 connection handshake

### Step 2: HTTP2-POOL-2
- Add `inner_h2` HashMap for HTTP/2 connections
- Update `checkout()` to route based on `key.is_http2`

### Step 3: HTTP2-POOL-3
- Use `is_http2` to select HTTP/1.1 or HTTP/2 pool

### Step 4: HTTP2-POOL-4
- Remove hardcoded `http2_only(false)` or make configurable

---

## Quick Reference: Key Files

| Component | File | Lines |
|-----------|------|-------|
| QuorumManager | `src/mesh/dht/quorum.rs` | 316-437 |
| RaftClient | `src/mesh/raft/client.rs` | 186-213 |
| FastCGI Client | `src/fastcgi/mod.rs` | 98-164 |
| DrainManager | `src/supervisor/process.rs` | 186-257 |
| ProxyServer | `src/proxy/mod.rs` | 73-226 |
| ErasedHttpClient | `src/http_client/erased_pool.rs` | 415-456 |
| ML-KEM Key Exchange | `src/mesh/ml_kem_key_exchange.rs` | 204-265 |
| Spin Runtime | `src/spin/runtime.rs` | 289-303 |
| WafCore | `src/waf/mod.rs` | 172-199 |
| HickoryRecursor DNSSEC | `src/dns/resolver.rs` | 693-702 |
| HTTP/3 Body Collection | `src/http3/server.rs` | 340-398 |
| collect_body_with_chunk_waf | `src/http/server.rs` | 4666-4700 |
| CertResolver | `src/tls/cert_resolver.rs` | 215-253 |
| filter.rs | `src/filter/common.rs` | 74-96 (deny/allow check) |
| BlockStore | `src/waf/block_store.rs` | 64-shard Vec<RwLock<AHashMap>> |
| ListenerConfigBase | `src/listener/common.rs` | Dead code (keep ConnectionContext) |
| zero_copy.rs | `src/zero_copy.rs` | Dead module |

---

## Summary Statistics

| Category | Count |
|----------|-------|
| P0 Security-Critical Items | 4 |
| P1 Code Bug Fixes | 8 |
| P1 Dead Code Cleanup | 9 |
| P1-P2 Feature Wiring | 4 |
| P2-P3 Documentation Updates (by domain) | 148 |
| P2 Cross-Module Conflicts | 7 |
| Deferred Items | 3 |
| **Total Actionable Items** | **183** |

---

## Wave Dependency Map

```
Wave 1 (Security)     ─────┐
Wave 2 (Bug Fixes)    ─────┤── All independent, no cross-dependencies
Wave 3 (Dead Code)    ─────┤
Wave 4 (Features)     ─────┘
                              │
Wave 5 (Docs)         ──────── All doc domains independent, parallelizable
                              │
Wave 6 (Conflicts)    ──────── Depends on Waves 1-5 being complete
```

**Maximum parallelization**: 23+ agents can work simultaneously across Waves 1-5 (4 security + 8 bug + 9 dead code + 4 feature + domains within Wave 5).

---

*Last Updated: 2026-05-28*
*Consolidated from 16 original plan files into single source of truth.*
*All items verified against source code by review subagents.*
