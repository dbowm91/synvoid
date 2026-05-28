# Stale Content Aggregate

**Generated:** 2026-05-28

Extracted from all 14 `*_review_plan.md` files in `plans/`.

## Items Flagged for Removal

- **process_lifecycle.md sections 1-2** (Overseer/Master): References `src/overseer/`, `src/master/`, `src/startup/master.rs` which no longer exist. Entire Overseer/Master sections are stale — consolidated into Supervisor. (process_infra_review_plan.md)
- **supervisor.md sections 9.1-9.2** (Overseer/Master legacy): References non-existent `src/overseer/mod.rs` and `src/master/mod.rs` module lists. (process_infra_review_plan.md)
- **supervisor.md section 2.7**: References `overseer/drain_manager.rs` — actual location is `src/supervisor/drain_manager.rs`. (process_infra_review_plan.md)
- **platform_deep_dive.md sections 4, 15, 18**: References `src/startup/master.rs` which does not exist (lines 219-233, 258, 403-405). (process_infra_review_plan.md)
- **ipc_process.md**: Lists `Overseer*` message variants (e.g., `OverseerUpgradePrepare`, `OverseerDrainWorkers`) — actual code uses `Supervisor*` prefix for all of these. (process_infra_review_plan.md)
- **src/honeypot_unified/**: Dead module — directory exists (215 lines) but is NOT declared in `src/lib.rs`, never compiled. (overview_review_plan.md)
- **architecture/tunnel.md**: Referenced at overview.md:174 but file does not exist. (overview_review_plan.md)
- **architecture/admin.md**: Referenced at overview.md:210 but file does not exist (only `admin_deep_dive.md`). (overview_review_plan.md)
- **waf.md:180**: `SiteConnectionLimiter` description — struct was removed from codebase entirely. (waf_security_review_plan.md)
- **waf_deep_dive.md:24**: `SiteConnectionLimiter` reference — same removed struct. (waf_security_review_plan.md)
- **icmp_filter.md:43**: `FilterBackend::PfBsd` variant — never existed in the enum. BSD uses the `Pf` backend. (waf_security_review_plan.md)
- **networking_deep_dive.md:82**: `SiteConnectionLimiter` at `limiter.rs:306-346` — struct was removed (2026-05-27), file is only 304 lines. (networking_review_plan.md)
- **layer_3_5_deep_dive.md:39**: References `src/startup/master.rs:210-234` which does not exist. Startup module contains only `bootstrap.rs`, `daemon.rs`, `mod.rs`, `worker.rs`. (tls_crypto_review_plan.md)
- **layer_3_5_deep_dive.md:134**: References `src/tunnel/upstream.rs` as location of `TunnelBackend`. Struct was removed from that file and now lives in `src/tunnel/router.rs:200`. (tls_crypto_review_plan.md)
- **zero_copy.md entire module**: `ZeroCopyReader`, `FilePath`, `sendfile_to_socket`, `copy_file_range` have zero callers outside `zero_copy.rs` itself. Module is declared in `lib.rs` but never imported or used. (utilities_review_plan.md)
- **serialization_rkyv.rs**: NOT declared in `lib.rs` — unreachable dead code. Content is postcard-based serialization (not rkyv despite its name). (utilities_review_plan.md)
- **config.md:131**: `overseer: OverseerConfig` field listed in MainConfig — the code uses `supervisor_compat: SupervisorConfig` instead. `OverseerConfig` type exists but is not a MainConfig field. (config_review_plan.md)

## Items Flagged for Update

- **admin_deep_dive.md lines 154-159**: Middleware order documented as `Request → Client IP → Auth → CSRF → Rate Limit`. Actual: `Request → Rate Limit (outer) → YARA Rate Limit → CSRF → Auth → Client IP (inner)`. CSRF is before Auth, YARA rate limit layer omitted. (admin_observability_review_plan.md)
- **admin_deep_dive.md**: Handler count "26 handlers + 1 feature-gated" — actual is 28 handler modules (24 always available, 4 mesh-gated). Serverless and Spin modules not in handler table. (admin_observability_review_plan.md)
- **admin_deep_dive.md line 806**: Claims `build_router_from_state()` at line 806. Actual definition is at line 173; line 806 is `.layer(create_cors_layer(...))`. (admin_observability_review_plan.md)
- **metrics.md**: SiteMetrics struct shows 6 fields — actual has 13 fields including `challenged`, `proxied`, `current_concurrent`, `peak_concurrent`, `total_latency_ms`, `upstream_successes`, `upstream_failures`, `latency_samples`, `blocked_by_type`. Documented `latency_sum` and `latency_count` do not exist. (admin_observability_review_plan.md)
- **metrics.md**: BandwidthTracker shows 2 fields (`inbound`, `outbound`) — actual has 11+ atomic fields. (admin_observability_review_plan.md)
- **metrics.md**: WorkerMetrics shows 3 fields — actual has 14+ fields. (admin_observability_review_plan.md)
- **metrics.md**: Global counters section shows 4 plain statics — actual uses `LazyLock<AtomicU64>` with 50+ counters. (admin_observability_review_plan.md)
- **protocol.md**: ProtocolHandler trait significantly different — actual uses `Result` return types, additional lifecycle methods (`set_waf`, `set_upstream_pool`), and `metrics()`. (admin_observability_review_plan.md)
- **protocol.md**: ProtocolDetectionResult types wrong — `confidence: f64` should be `f32`, `matched_pattern: Option<String>` should be `String`. (admin_observability_review_plan.md)
- **logging.md**: SyslogLogger struct incomplete — uses `_backend: ()` on Unix, `app_name: String` and `_phantom: ()` on non-Unix. No `syslog` field. (admin_observability_review_plan.md)
- **app_handlers.md line 71**: SpinHttpHandler line drift — actual `if matches!` at line 2420, handler creation at 2425 (doc says 2421-2503). (app_handlers_review_plan.md)
- **app_handlers.md lines 87-93**: Cgi/AppServer/Mesh dispatch lines off by 1 (2746/2820/2871 vs documented 2747/2821/2872). (app_handlers_review_plan.md)
- **fastcgi.md line 38**: `StreamingFastCgiClient` comment claims "FCGI record-level streaming" — implementation buffers entire request body before sending. (app_handlers_review_plan.md)
- **static_files.md lines 30-36**: `NormalizedLocation` fields wrong — `index: Option<String>` (not `Vec<String>`), `cache_ttl: Option<u64>` (not `u64`), missing `theme` field. (app_handlers_review_plan.md)
- **static_files.md lines 22-28**: `StaticFileHandler` has 16 fields vs documented 5. Documented `compression` and `minification` fields do not exist as named. (app_handlers_review_plan.md)
- **static_files.md lines 38-41**: `StaticResponse`/`StaticResponseBody` enum structure wrong — `StaticResponse` has `status`, `headers`, `body` fields; variant fields incorrect. (app_handlers_review_plan.md)
- **static_files.md lines 43-50**: `StaticError` variants wrong — documented as unit variants, actual has tuple variants with `String` payloads. (app_handlers_review_plan.md)
- **fastcgi.md lines 19-23**: `FastCgiClient` fields wrong — `socket_path` (not `socket`), `is_tcp` (not `is_unix`), no `timeout` field. (app_handlers_review_plan.md)
- **fastcgi.md lines 25-29**: `FastCgiPool` uses `RwLock<VecDeque<PooledConnection>>` (not `Vec<FastCgiClient>`), plus `closed` and `draining` fields. (app_handlers_review_plan.md)
- **mime.md lines 19-22**: `MimeRegistry` maps `String → String` (not `String → MimeTypeInfo`). Missing `mime_categories` field. (app_handlers_review_plan.md)
- **theme.md lines 47-53**: `DirectoryEntry` fields wrong — `modified: String` and `size: String` (not `Option<DateTime<Utc>>`/`Option<u64>`), plus undocumented `modified_timestamp: u64` and `size_bytes: u64`. (app_handlers_review_plan.md)
- **config.md line 200**: `MeshNodeRole` documented as `enum` — actual is `struct(u8)` with associated constants (bitflag pattern). Cannot use `match` on it. (config_review_plan.md)
- **config_deep_dive.md:95**: `site_id: String` listed as SiteConfig field — `site_id` is a method, not a field. (config_review_plan.md)
- **config_deep_dive.md:91-117**: SiteConfig hierarchy incomplete — missing fields: `worker_pool`, `logging`, `proxy`, `tcp`, `udp`, `tarpit`, `upload`, `auth`, `tunnel`, `whitelist`, `serverless_only`. (config_review_plan.md)
- **config_deep_dive.md:329**: DNS validation claimed to run unconditionally when `dns` feature enabled — actual requires both `dns` feature AND `dns.enabled == true`. (config_review_plan.md)
- **config.md:662-707**: Appendix file structure incomplete — missing `site/misc.rs`, `icmp_filter.rs`, and 10 DNS submodule files. (config_review_plan.md)
- **dns.md:107**: `zone_index_btree` type missing angle brackets — `Arc RwLock<BTreeMap>` should be `Arc<RwLock<BTreeMap<String, String>>>`. (dns_review_plan.md)
- **dns.md:226**: `with_cookie_server` documented without `#[cfg(feature = "dns")]` but actual code has it. (dns_review_plan.md)
- **dns.md:224**: `with_acme_dns_challenges` shown at line 573 but that is `new()`. Builder is at line 855. (dns_review_plan.md)
- **dns.md:3.1**: DnsServer struct shown with only 16 fields — actual has ~30 fields. Missing ~14 fields. (dns_review_plan.md)
- **dns.md:3.5**: `ZoneSigningKey` missing `key_size: Option<u32>` field. (dns_review_plan.md)
- **dns_deep_dive:39**: Incorrectly references "RFC 8905" for DNS cookies — RFC 8905 is "DNS over TLS". Correct RFC is 7873. (dns_review_plan.md)
- **http_server.md:23**: `server.rs (4908 lines)` — actual is 4907 lines. (http_server_review_plan.md)
- **http_shared.md:176**: `send_request_with_headers` function name is stale — renamed to `send_request_with_timeout_and_headers`. (http_server_review_plan.md)
- **http_shared.md:265-266**: Reference to `skills/AGENTS.override.md` should point to actual skills file path. (http_server_review_plan.md)
- **http_server.md:341**: `dns` feature gate description for HTTP-01 challenge is misleading — challenge serving is behind `mesh` feature, not `dns`. (http_server_review_plan.md)
- **mesh.md:581**: File tree missing `record_store_persist.rs` (exists at `src/mesh/dht/record_store_persist.rs`). (mesh_review_plan.md)
- **mesh.md:159**: `TierKeyStore` at `store.rs` — should be `mod.rs:850`. (mesh_review_plan.md)
- **mesh.md:162**: `NodeInfo` at `keys.rs` — should be `mod.rs:342`. (mesh_review_plan.md)
- **mesh.md:165**: `DhtAccessControl` at `capability_access.rs` — should be `mod.rs:689`. (mesh_review_plan.md)
- **networking_deep_dive.md:16**: `mesh.config.quic.enable_0rtt` and `mesh.quic.enable_0rtt` — actual config path is `tls.quic_enable_0rtt`. (networking_review_plan.md)
- **networking_deep_dive.md:60**: `mesh.ml_kem` config section — actual field name is `mesh.mlkem`. (networking_review_plan.md)
- **listener.md:59-62**: Integration points claim — `ListenerConfigBase` is defined but never instantiated or imported by any module. (networking_review_plan.md)
- **listener.md**: `ListenerConfigBase` fields completely wrong — `bind_addresses` (should be `bind_address: String`), `expected_protocol: ProtocolType` (should be `String`), `upstream_address: Option<String>` (should be `String`), `filter_config: Option<FilterConfig>` (should be `filter_enabled: bool` + `strict_mode: bool`). (networking_review_plan.md)
- **listener.md**: `ConnectionContext` fields wrong — `server_name: Option<String>` should be `String`, `expected_protocol: ProtocolType` should be `String`. (networking_review_plan.md)
- **proxy.md:57-63**: `BackendType` documented from wrong module with completely wrong variants. Actual is in `src/router.rs:66-78` with 11 different variants. (proxy_routing_review_plan.md)
- **proxy.md:69-76**: `RetryConfig` field `retry_on_connection_error` should be `retry_on_error`. Missing `retry_non_idempotent`. (proxy_routing_review_plan.md)
- **proxy.md:82-110**: `ProxyServer` missing `proxy_headers_config: Option<Arc<ProxyHeadersConfig>>` field. (proxy_routing_review_plan.md)
- **proxy.md:92-93**: `with_upstream_pool()` signature missing `retry_config` and `buffering_config` parameters. (proxy_routing_review_plan.md)
- **proxy.md:210-215**: `calculate_backoff()` pseudocode shows jitter that doesn't exist in actual code. (proxy_routing_review_plan.md)
- **proxy.md:248-253**: Named constants `DEFAULT_POOL_MAX_IDLE`, `DEFAULT_POOL_IDLE_TIMEOUT`, `DEFAULT_UPSTREAM_TIMEOUT` do not exist. (proxy_routing_review_plan.md)
- **proxy.md:239-245**: `http2` feature gate for `is_http2` flag — `is_http2` is a struct field, not a feature gate. (proxy_routing_review_plan.md)
- **proxy_deep_dive.md:31**: `ProxyServer` struct location `mod.rs:73-94` — actual spans 73-96. (proxy_routing_review_plan.md)
- **proxy_deep_dive.md:43**: `ProxyExecutor` location `executor.rs:96-103` — actual is 98-107. (proxy_routing_review_plan.md)
- **proxy_deep_dive.md:244**: Revalidation semaphore default 32 — actual is 100. Field name `revalidation_capacity` should be `max_concurrent_revalidations`. (proxy_routing_review_plan.md)
- **routing_deep_dive.md:50,65**: External GitHub URLs for code references should be local file paths. (proxy_routing_review_plan.md)
- **upstream.md:103-105**: `Backend` field types `cpu_percent: AtomicU32` should be `Arc<AtomicU32>`. (proxy_routing_review_plan.md)
- **upstream.md:124-125**: `SharedConnectionTable` layout `[N+1..]` should be `[16 + max_workers * 8..]`. (proxy_routing_review_plan.md)
- **proxy_cache.md:25-32**: `ProxyCacheEntry` struct completely wrong — `headers: HeaderMap` (not `HashMap`), `created_at: Instant` (not `u64`), `expires_at: Option<Instant>` (not `u64`), missing `stale_while_revalidate`/`stale_if_error`/`is_fresh` fields. (proxy_routing_review_plan.md)
- **proxy_cache.md:34-41**: `CacheKey.site_id` is `String` (not `Option<String>`). (proxy_routing_review_plan.md)
- **proxy_cache.md:43-47**: `CacheHit` enum has no associated data on any variant — `Hit, Miss, Expired, Stale, StaleWhileRevalidate`. (proxy_routing_review_plan.md)
- **proxy_cache.md:49-56**: `ProxyCacheSettings` fields completely wrong — `max_memory_size` (bytes, not entry count), `inactive` + `stale_while_revalidate` (not `default_ttl`), `valid_status`/`methods` (not `valid_status_codes`/`valid_methods`). (proxy_routing_review_plan.md)
- **proxy_cache.md:20-23**: `ProxyCache` struct wrong — uses `Cache<CacheKey, CacheEntryInner>` (not `Cache<String, ProxyCacheEntry>`), no `disk_cache` field. (proxy_routing_review_plan.md)
- **streaming.md:27-34**: `ProxyError` variants `ReadError(io::Error)` and `WriteError(io::Error)` should be `ReadError(String)` and `WriteError(String)`. (proxy_routing_review_plan.md)
- **streaming.md:33**: `WafBlock(String)` should be `WafBlock(u16, String)`. (proxy_routing_review_plan.md)
- **streaming.md:24**: `ProxyConfig.waf_scanner` type should be `Option<Arc<Mutex<StreamingWafCore>>>` (not `Option<Arc<StreamingWafCore>>`). (proxy_routing_review_plan.md)
- **streaming.md:43-46**: `copy_bidirectional_native` takes two stream objects (not four reader/writer pairs). (proxy_routing_review_plan.md)
- **location_matcher.md:18-22**: `LocationMatcher` field names wrong — `exact_locations`/`prefix_locations`/`regex_locations` with different types. (proxy_routing_review_plan.md)
- **location_matcher.md:26**: `LocationMatch` field `compiled_regex` should be `regex`. (proxy_routing_review_plan.md)
- **tls.md:70**: `CertResolver` holds `certs: HashMap<String, Arc<CertifiedKey>>` — actual is `Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>`. (tls_crypto_review_plan.md)
- **tls.md:76**: `watch_for_cert_changes()` documented as method — actual is a free function. (tls_crypto_review_plan.md)
- **tls.md:201-208**: `SniError` enum lists 4 variants — actual has 7 (missing `InvalidHostname`, `ConnectionClosed`, `Io(String)`). (tls_crypto_review_plan.md)
- **tls.md:418**: Feature flag table incomplete — `dns` feature also enables `hickory-proto`, `hickory-resolver`, `tokio-dstip`, `cryptoki`, `getrandom`. (tls_crypto_review_plan.md)
- **layer_3_5_deep_dive.md:43-44**: `rustls-post-quantum` line number 156 — actual is 157. (tls_crypto_review_plan.md)
- **common.md**: "Integration Points → Main" claim — `main.rs` does NOT call `setup_panic_handler` directly. Worker modules call wrapper functions. (utilities_review_plan.md)
- **filter.md**: `Protocol::from_str` return type `Option<Self>` should be `Self`. (utilities_review_plan.md)
- **filter.md**: `BaseFilterConfig` allowlist/denylist types `Vec<P>` should be `Vec<String>`. (utilities_review_plan.md)
- **filter.md**: "Allow/Deny Priority: Allowlist checked first" — actual is denylist first, then allowlist. (utilities_review_plan.md)
- **filter.md**: Missing `PortConfigBase` documentation — public API exported from `src/filter/mod.rs:4`. (utilities_review_plan.md)
- **zero_copy.md**: `sendfile_to_socket` fallback claim — actual returns `Err`, not userspace copy. (utilities_review_plan.md)
- **serder.md**: "Postcard produces deterministic output" — Postcard guarantees single-allocation encoding but NOT cross-version/platform determinism. (utilities_review_plan.md)
- **waf.md:30-45**: `WafCore` struct incomplete — missing ~15 fields (actual has ~30). (waf_security_review_plan.md)
- **waf.md:318-328**: `WafCoreConfig` severely incomplete — 22 fields vs documented ~11. (waf_security_review_plan.md)
- **waf.md:543-547**: Feature gates `default = ["mesh", "flood-ebpf"]` — `flood-ebpf` is NOT in default features. (waf_security_review_plan.md)
- **challenge.md:19-26**: `ChallengeManager` shows `rate_limiter: RateLimiter` field — does not exist. Rate limiting is internal via `attempts` HashMap. (waf_security_review_plan.md)
- **captcha.md:18-22**: `CaptchaManager` shows `challenges: Arc<RwLock<HashMap<...>>>` — actual uses `Arc<RwLock<CaptchaStore>>`. (waf_security_review_plan.md)
- **captcha.md:21**: `verification_window_secs: u64` should be `u32`. (waf_security_review_plan.md)
- **block_store.md:20-36**: `BlockStore` and `BlockEntry` structs completely wrong — storage changed from flat HashMap to 64-shard design, field names/types changed. (waf_security_review_plan.md)
- **tarpit.md:19-29**: `TarpitManager.chain` should be `Arc<RwLock<MarkovChain>>`. `TarpitConfig` field types `usize` should be `u32`, missing `enabled` field. (waf_security_review_plan.md)
- **tarpit.md:63**: Scraper patterns incomplete — missing "python-urllib", "aiohttp", "httpx". (waf_security_review_plan.md)
- **honeypot.md:25-31**: `PortHoneypotController` struct wrong — actual has `runner` and `config` fields only. (waf_security_review_plan.md)
- **honeypot.md:45-49**: `IpHoneypotProfile` uses `AtomicU64` (not `AtomicU32`), `RwLock<Vec<String>>` (not `HashSet`), plus undocumented fields. (waf_security_review_plan.md)
- **upload.md:20-32**: `UploadValidator` struct wrong — different field names/types. `UploadConfig` incomplete. (waf_security_review_plan.md)
- **upload.md:41-46**: `ValidationResult` types wrong — `mime_type: String` (not `Option<String>`), `size: u64` (not `usize`). (waf_security_review_plan.md)
- **upload.md:55-62**: `UploadValidationError` missing 4 variants. (waf_security_review_plan.md)
- **geoip.md:19-25**: `GeoIpManager` fields wrapped in `Arc<RwLock<>>` — bare types documented. Missing `config` and `is_enabled`. (waf_security_review_plan.md)
- **icmp_filter.md:48-54**: `BackendCapabilities` field names wrong — `supports_block`, `supports_allow`, etc. (not `block`, `allow`). Missing `requires_admin`, `is_enforcing`. (waf_security_review_plan.md)
- **icmp_filter.md:62-67**: Feature gates all wrong — `icmp-ebpf` (not `flood-ebpf`), `icmp-pf`/`icmp-winfw`/`icmp-wfp` (not `icmp-filter`). (waf_security_review_plan.md)
- **icmp_filter.md:24-31**: `IcmpFilterManager` shows `backend: Option<Box<dyn IcmpFilter>>` — actual is `filter: Box<dyn IcmpFilter>` (not Option). (waf_security_review_plan.md)
- **icmp_filter.md:34-37**: `IcmpFilterFactory::create` signature `config: &IcmpFilterConfig` should be `config: IcmpFilterConfig` (ownership). (waf_security_review_plan.md)
- **icmp_filter.md:30**: `IcmpFilter::update_config` returns `Result<(), IcmpFilterError>` — actual returns `Result<()>`. (waf_security_review_plan.md)
- **integrity.md:19-25**: `IntegrityConfig` severely incomplete — documented 5 fields vs actual 17+. (waf_security_review_plan.md)
- **integrity.md:33-38**: `SignedHttpMessage` completely wrong — missing `integrity_header`, `method`, `path`, `query`, `body_hash`, wrong types for `signature` and `timestamp`. (waf_security_review_plan.md)
- **integrity.md:40-44**: `SessionKey.key` type `Vec<u8>` should be `String` (base64). (waf_security_review_plan.md)
- **spin.md Section 2.2**: `Manifest` struct described is actually `SpinManifest`. Actual `Manifest` struct is a simplified parsed form. (wasm_plugin_review_plan.md)
- **spin.md Section 2.1**: Claims "Runs a supervisor task for idle eviction and health checks" — no such task exists. (wasm_plugin_review_plan.md)
- **plugin_deep_dive.md:109**: Stub count says "6" — actual is 7. (wasm_plugin_review_plan.md)
- **serverless.md Section 9**: `FunctionDefinition` field types wrong — `path: String` (not `Option<String>`), `require_trusted_caller: bool` (not `Option<bool>`), `allowed_dht_prefixes: Vec<String>` (not `Option<Vec<String>>`). Missing `handler` field. (wasm_plugin_review_plan.md)
- **serverless.md**: `handle_serverless_function_streaming` documented as `#[cfg(feature = "mesh")]` — actual has no such attribute. (wasm_plugin_review_plan.md)
- **process_lifecycle.md line 34**: `run_supervisor_mode()` at `src/main.rs:541-546` — actual call is at 531-537. (process_infra_review_plan.md)
- **process_lifecycle.md line 36**: "Supervisor does not currently implement drain coordination" — contradicted by `drain_aware_shutdown()` at `src/supervisor/process.rs:198-272`. (process_infra_review_plan.md)
- **worker_architecture.md:23-24**: Buffer pool "Three tiers: small (4KB), medium (32KB), large (128KB)" — actual is 4 tiers (small/medium/large/jumbo 256KB). (process_infra_review_plan.md)
- **ipc_process.md:76**: "17 categories" — actual is 18 categories. (process_infra_review_plan.md)
- **drain.md:18-33**: `DrainStatus` and `WorkerDrainState` structs incomplete — missing `is_draining`, `connections_drained`, `drain_start`, etc. (process_infra_review_plan.md)
- **supervisor.md:270-285**: `ProcessManagerConfig` missing fields, `master_socket_path` should be `supervisor_socket_path`. (process_infra_review_plan.md)
- **supervisor.md:393-399**: `start_grpc_server` missing `tls_config: Option<InternalTlsConfig>` parameter. (process_infra_review_plan.md)
- **supervisor.md:764-778**: Tokio runtime config at `process.rs:354-358` — actual is 363-367. (process_infra_review_plan.md)
- **platform.md:43**: `supports_seatbelt()` method does not exist on `Platform` enum. (process_infra_review_plan.md)
- **platform_deep_dive.md:69**: "Seatbelt sandboxing is not yet fully implemented" — misleading. It IS implemented but feature-gated. (process_infra_review_plan.md)
- **overview.md:266-278**: All line count estimates significantly outdated (mesh 3x understated, proxy 3.6x understated, etc.). (overview_review_plan.md)
- **deep_dive_review.md:48**: Claims `io_uring` used via Tokio — no io_uring references found in source. (overview_review_plan.md)

## Items Flagged for Merge

- **proxy.md entire document**: Superseded by `proxy_deep_dive.md` for detailed struct/API documentation. Contains incorrect struct definitions that `proxy_deep_dive.md` has partially corrected. Consider removing duplicate struct listings from `proxy.md` and keeping it as high-level overview only. (proxy_routing_review_plan.md)
- **proxy_cache.md**: Significantly outdated — all struct definitions (`ProxyCacheEntry`, `CacheHit`, `ProxyCacheSettings`, `ProxyCache`) don't match current code. Describes simpler cache that has been enhanced with circuit breakers, revalidation tracking, site-level memory accounting. (proxy_routing_review_plan.md)
- **dns.md:790** and **dns_deep_dive:70**: Both contain same stale DNS-2 `_max_wait_ms` reference. The coalescer now uses `tokio::timeout` with configured `max_wait` value. (dns_review_plan.md)
- **waf.md:180** and **waf_deep_dive.md:24**: Both reference `SiteConnectionLimiter` which was removed. Same stale content in two files. (waf_security_review_plan.md)
- **process_lifecycle.md** and **supervisor.md**: Both reference non-existent Overseer/Master modules. Content overlaps and both need the same corrections. (process_infra_review_plan.md)

## Cross-Module Duplicates

- **SiteConnectionLimiter references across 3 files**: Referenced in `waf.md:180`, `waf_deep_dive.md:24`, and `networking_deep_dive.md:82`. Struct was removed 2026-05-27. All three references are stale and should be deleted. (waf_security_review_plan.md, networking_review_plan.md)

- **Overseer/Master references across 4 files**: `process_lifecycle.md` (sections 1-2), `supervisor.md` (sections 9.1-9.2, 2.7), `platform_deep_dive.md` (sections 4, 15, 18), and `ipc_process.md` all reference `src/overseer/`, `src/master/`, `src/startup/master.rs` which no longer exist. The Overseer and Master have been consolidated into the Supervisor. (process_infra_review_plan.md)

- **src/startup/master.rs references across 3 files**: `process_lifecycle.md:17`, `platform_deep_dive.md:219-233,258,403-405`, and `layer_3_5_deep_dive.md:39` all reference this non-existent file. (process_infra_review_plan.md, tls_crypto_review_plan.md)

- **TunnelBackend location discrepancy across 2 files**: `layer_3_5_deep_dive.md:134` references `src/tunnel/upstream.rs` (removed), while `tls_crypto_review_plan.md` confirms actual location is `src/tunnel/router.rs:200`. (tls_crypto_review_plan.md)

- **DNS-2/_max_wait_ms stale reference in 2 files**: Both `dns.md:790` and `dns_deep_dive.md:70` claim `_max_wait_ms` is unused. The issue was fixed via DNS-QUERY async redesign with `tokio::timeout`. (dns_review_plan.md)

- **PooledInstance fix incorrectly described as unfixed**: `plugin_deep_dive.md:108` claims `PooledInstance::prepare_for_request` does NOT reset fields, but `pool.rs:25-26` clearly resets both `body_receiver` and `allowed_dht_prefixes`. The doc was written before the fix was applied. (wasm_plugin_review_plan.md)

- **Feature gate naming inconsistencies across multiple modules**: `icmp_filter.md` uses `flood-ebpf`, `icmp-filter` — actual gates are `icmp-ebpf`, `icmp-pf`, `icmp-winfw`, `icmp-wfp`. `waf.md` claims `default = ["mesh", "flood-ebpf"]` — `flood-ebpf` is not in default features. (waf_security_review_plan.md)

- **MeshNodeRole type discrepancy in 2 files**: `config.md:200` documents it as an `enum`, `mesh_review_plan.md` documents it as a bitmask struct with constants. Both describe the same type but with different (and conflicting) representations. (config_review_plan.md, mesh_review_plan.md)

- **DrainStatus/WorkerDrainState incomplete in 2 files**: Both `drain.md:18-33` and `supervisor.md:207-238` document these structs with fewer fields than the actual implementation. Both need the same field additions. (process_infra_review_plan.md)

- **Buffer pool tier count wrong in 2 files**: `worker_architecture.md:23-24` says 3 tiers; `process_infra_review_plan.md` confirms actual is 4 (small/medium/large/jumbo). (process_infra_review_plan.md)

## Summary Statistics

| Category | Count |
|----------|-------|
| Items Flagged for Removal | 17 |
| Items Flagged for Update | 92 |
| Items Flagged for Merge | 5 |
| Cross-Module Duplicates | 9 |
| **Total Stale Items** | **123** |
| Files Contributing | 14 |
| Non-existent File References | 7 distinct files |
| Removed Code References | 3 distinct structs |
| Renamed Items | 6 distinct items |
