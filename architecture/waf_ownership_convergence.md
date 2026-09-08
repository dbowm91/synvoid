# WAF Ownership Convergence (Phase 19)

Status: implemented.

Goal: `synvoid-waf` is the unambiguous owner of reusable WAF policy/detection
logic. `src/waf/` is root application composition: it wires runtime services,
owns control-plane integrations, and exposes thin facades/adapters over the
crate. One owner per concept; root LOC is not the metric.

Non-goals: moving supervisor/admin/mesh transport/filesystem lifecycle into
`synvoid-waf` to reduce root LOC; restoring block-store writes into WAF
convenience methods; changing enforcement precedence.

## 1. File-level ownership matrix

Every entry under `src/waf/` classified against `crates/synvoid-waf/src/`.
Responsibility and callers were compared, not filenames.

| Root path | Lines | Crate counterpart | Classification | Rationale / canonical owner |
|-----------|-------|-------------------|----------------|-----------------------------|
| `mod.rs` (`WafCore`, `WafCoreConfig`, pipeline) | ~1514 | `primitives.rs`, `enforcement.rs`, `traits.rs`, `access.rs` | **application composition (`keep_app_root`)** | `WafCore` wires concrete runtime services (rate limiter, challenge/auth managers, threat-level, feeds, GeoIP, tarpit, traffic shaper, flood, upload validator, `RequestServices`). Reusable policy primitives (`WafDecision`, `WafConfig`, `TestModeConfig`), detector→candidate adapters, and narrow traits (`WafProcessor`, `BlockListStore`, `GeoIpLookup`, `WafAccess`) live in `synvoid-waf`. Full `WafCore` move is blocked: it would pull root GeoIP facade, tarpit handler, theme error pages, upload-validator static, traffic-shaper metrics, threat-level sqlite persistence, and worker `RequestServices` into the domain crate. Root type is documented as composition (`AppWaf` alias). |
| `adapter.rs` (`RootWafProcessor`) | 110 | `traits.rs` (`WafProcessor`) | **root adapter** | Implements the crate's `WafProcessor` trait for `Arc<WafCore>` so request-path code consumes a narrow trait, never the concrete core. Stays root. |
| `adapters.rs` (`BlockStoreAdapter`, `GeoIpAdapter`, `ChallengeServiceAdapter`, `ViolationPersistenceAdapter`) | 134 | `traits.rs` (`BlockListStore`, `GeoIpLookup`, `ChallengeService`, `WafPersistence`) | **root adapter** | Concrete-to-trait bridges (`BlockStore`, `GeoIpManager`, `ChallengeManager`, `ViolationTracker` → crate traits). Composition roots own concrete types per the capability boundary. Stays root. |
| `attack_detection/mod.rs` | 28 | `attack_detection/*` (canonical engine, normalizer, patterns, streaming) | **exact/thin facade** | Root is a compatibility re-export (`pub use synvoid_waf::attack_detection::*`) plus one overlong-UTF8 regression test. No domain logic in root. |
| `endpoints.rs` | 355 | `endpoints/{blocker,sensitive}.rs` | **facade + root composition** | `EndpointBlockerManager` / `SensitiveEndpointManager` re-exported from crate (canonical). `ErrorPageManager` (theme rendering, error-page dirs) is root application composition and stays root. |
| `flood/mod.rs` | 4 | `flood/mod.rs` (canonical `FloodConfig`, `FloodDecision`, `FloodProtector`, backends) | **exact/thin facade** | Root re-exports the crate. |
| `flood/connection_limiter.rs`, `flood/syn_flood.rs`, `flood/udp_flood.rs` | 199/275/346 | `flood/{connection_limiter,syn_flood,udp_flood}.rs` | **stale/dead duplicate — deleted** | Files were not declared as modules in `flood/mod.rs` (which only declares `ebpf_flood`), so they were never compiled. Live code was already the crate versions (modulo import paths `crate::utils` vs `synvoid_utils`). Deleted; crate is canonical. |
| `flood/ebpf_flood.rs` | 426 | none | **application composition (`keep_app_root`)** | Linux-only eBPF/XDP SYN-drop path via `aya`. Depends on kernel/privilege/platform composition, not reusable policy. Gated on `flood-ebpf`. Stays root. |
| `ip_feed.rs` (`IpFeedManager`, background fetch, CIDR matching) | 319+ | stale crate copy (never compiled: `ip_feed` was not declared in `synvoid-waf/src/lib.rs` because it needs `synvoid-http-client`/hyper — deleted) | **root-owned feed integration (`keep_app_root`)** | Background HTTP fetch + in-memory CIDR sets. Control-plane I/O (HTTP client, background tasks); pulling hyper/rustls into the domain crate merely to reduce root LOC is rejected. Wired into `WafCore` by composition; not consulted on the hot path (admission owns enforcement). The crate copy's extra zero-prefix unit test was ported into the root tests before deletion. |
| `probe_tracker.rs` | 1 | `probe_tracker.rs` (canonical) | **exact/thin facade** | Already `pub use synvoid_waf::probe_tracker::*`. |
| `violation_tracker.rs` | 1 | `violation_tracker.rs` (canonical) | **exact/thin facade** | Already `pub use synvoid_waf::violation_tracker::*`. |
| `ratelimit.rs` (`RateLimiterManager`, `RateLimitConfigStore`, `RateLimitResult`) | 477 | none (manager-level) | **application composition (`keep_app_root`)** | Manager wires `SlottedIpRateLimiter`/`GlobalRateLimiter` (root `ratelimit/core.rs`), shared-memory rate-limit table (`upstream::shared_state`), semaphores, LRU eviction, and cleanup tasks. Policy primitives (`sliding::AtomicBucketWindow`, configs) live in the crate. Stays root. |
| `ratelimit/sliding.rs` | 1 | `ratelimit/sliding.rs` (canonical sliding windows) | **exact/thin facade** | Already `pub use synvoid_waf::ratelimit::sliding::*`. |
| `ratelimit/core.rs` (`ShardedRateLimiter`, `SlottedIpRateLimiter`, `GlobalRateLimiter`, `AtomicSlidingWindow`) | 883 | none | **application composition (`keep_app_root`)** | Depends on root-only runtime: `RunningFlag`, `upstream::shared_state::SharedRateLimitTable` (mmap IPC), root rate-limit configs. Moving it would pull process/IPC composition into the domain crate. Consumed by `AsnTracker` and `ThreatMetricsCollector` via narrow root paths. Documented blocker. |
| `rule_feed.rs` (`RuleFeedManager`, `RuleFeedManagerForWaf`, global pattern store) | 1048 | none | **control-plane integration (`keep_app_root`)** | Signed feed fetch/verify/persist/hot-reload with filesystem lifecycle, supervised by `supervisor/process.rs` + `supervisor/state.rs`. Not request-policy; must not move into `synvoid-waf`. |
| `threat_intel/` (`feed_client.rs`, mesh-gated) | 536+5 | none (`threat.rs` holds only DTO/traits, deliberately) | **control-plane integration (`keep_app_root`)** | Mesh threat-feed client (`crate::mesh::protocol`). Mesh enforcement populates `BlockStore`; WAF reads block state at the worker admission boundary, never via raw threat-intel lookups in the request path. |
| `threat_level/` (manager, baseline, collector, scorer, sqlite persistence) | ~1500 total | none (`threat.rs` holds only DTO/traits) | **application composition (`keep_app_root`)** | Threat scoring + sqlite history + admin/diagnostic readers (`admin/handlers/threat_level.rs`). Filesystem lifecycle + admin coupling block crate ownership. WAF consumes it as an owned service inside `WafCore`, not as request-path authority. |
| `traffic_shaper/mod.rs` | 10 | `traffic_shaper/mod.rs` (canonical buckets + `ConnectionLimiter`) | **facade + root composition** | `ConnectionLimiter`/buckets re-exported from crate (canonical, including the ported increment-then-validate fix). `global` submodule stays root (see below). |
| `traffic_shaper/global.rs` (`GlobalTrafficShaper`, site limits) | 285 | none | **application composition (`keep_app_root`)** | Depends on root bandwidth metrics (`metrics::bandwidth`) and root traffic configs. Stays root. |
| `traffic_shaper/limiter.rs` | 320 | `traffic_shaper/limiter.rs` | **stale/dead duplicate — deleted** | Not declared in `traffic_shaper/mod.rs`; never compiled. Contained a newer increment-then-validate fix + `remove_if` release hardening that the live crate version lacked — both ported into the crate before deletion so the canonical implementation is the fixed one. |
| `asn_tracker.rs` | 328 | none | **application composition (`keep_app_root`)** | Distributed ASN scraping detection. Depends on concrete `GeoIpManager`, `proxy::WafDecision`, and root `ratelimit::core::AtomicSlidingWindow`. Extraction would require threading `GeoIpLookup` + sliding primitives through the crate; documented blocker. Queries GeoIP as a capability; mesh announce stays outside the request path. |
| `threat.rs` / `mitigation.rs` / `access.rs` / `enforcement.rs` / `bot.rs` / `request_sanitization.rs` / `primitives.rs` / `traits.rs` (crate-only) | — | — | **canonical domain owner: `synvoid-waf`** | No root counterpart. Request-path code (`synvoid-http`, `synvoid-proxy`, `synvoid-http3`) consumes these via narrow traits. |

## 2. `WafCore` split

`WafCore` was reassessed field-by-field after Phase 18 (auth/challenge now
canonical in `synvoid-auth` / `synvoid-challenge`; `WafCore` imports them
directly, no `crate::auth`/`crate::challenge` remains):

- **Core request-policy engine state (crate-owned types):** `bot_detector`
  (`synvoid_waf::bot`), `endpoint_blocker` + `sensitive_endpoint_manager`
  (`synvoid_waf::endpoints`), `attack_detector` (`synvoid_waf::attack_detection`),
  `config` (`synvoid_waf::primitives::WafConfig`), `violation_tracker` /
  `probe_tracker` / `suspicious_word_tracker` / `upstream_error_tracker`
  (`synvoid_waf::{violation_tracker,probe_tracker}`), `flood_protector`
  (`synvoid_waf::flood`), `connection_limiter` + token buckets
  (`synvoid_waf::traffic_shaper`).
- **External service capabilities (narrow-trait or canonical-crate types):**
  `challenge_manager` (`synvoid_challenge::ChallengeManager`),
  `auth_manager` (`Arc<synvoid_auth::AuthManager>`), `rate_limiter` (root
  manager behind `WafCore` methods, not exposed to request path as concrete
  infrastructure), `BlockStoreAdapter`/`GeoIpAdapter`/`ChallengeServiceAdapter`
  in `adapters.rs` for trait-based consumption.
- **Application lifecycle/composition state (root-owned):** `threat_level`
  (sqlite-backed), `ip_feed` (crate type, root-wired background fetch),
  `probe_tracker` wiring, `traffic_shaper`/`connection_limiter` optionals,
  `asn_tracker` (GeoIP-backed), `whitelist`, `_tarpit_generator` +
  `tarpit_defaults`, `test_mode`, `honeypot_ban_duration_secs`,
  `trust_token_key`, `error_page_manager` (theme/filesystem).
- **Unrelated subsystem state via narrow interface:** `request_services`
  (`ArcSwapOption<RequestServices>` placeholder, thread-through preferred);
  mesh/YARA/threat-intel globals are no-op stubs relegated to the supervisor
  control plane (`set_threat_intel`, `set_yara_rules`, `get_yara_rules`).

End state: `WafCore` stays root-owned **composition** (`pub type AppWaf =
WafCore`, `pub type AppWafConfig = WafCoreConfig`) rather than moving into the
crate. `WafCoreConfig` is documented as a composition constructor: data-only
WAF configuration (`synvoid_waf::primitives::{WafConfig, TestModeConfig}`,
`AttackDetectionConfig`) plus an explicit dependency bundle (auth manager,
threat/ip/probe/traffic/ASN configs, GeoIP handle, data dir). Reusable WAF
logic never touches `WafCoreConfig` (the crate does not import root).

## 3. Hot-path placeholder removal

- `WafCore::check_block_store` (always `None`) removed from
  `check_request_full` and deleted. Worker admission owns the block-store
  request check (`architecture/worker_data_plane_composition_root.md`); the WAF
  pipeline no longer contains an always-`None` stage.
- `WafCore::check_early` (always `Pass`) removed with its
  `EarlyWafHooks::check_early` trait method and the `early_waf_decision`
  helper. The HTTP (`request_preparation.rs`) and TLS (`tls/server.rs`) early
  matches were dead (only `Pass` reachable) and now proceed directly to full
  preparation. `verify_trust_token` remains the only early hook.
- `WafCore::block_ip_for_honeypot` / `block_ip_with_threat_intel` (no-op
  block-store writes) removed with their `ChallengePathWaf` /
  `UploadValidationWaf` trait methods. Production call sites in
  `tls/server.rs`, `challenge_paths.rs`, and `upload_validation_dispatch.rs`
  now deny the immediate request (408/403 + logging) without pretending to
  write block history. Timed blocks remain the worker admission /
  control-plane's job via `block_ip_with_provenance` with `BlockProvenanceKind`.
- Remaining non-hot-path placeholders (`record_suspicious_words`,
  `start_background_tasks`, `reload_attack_detector`, `set_request_services`,
  `set_threat_intel`, `set_yara_rules`, `get_yara_rules`,
  `check_request_body` pass-through) are documented as deprecated no-ops and
  covered by `tests/waf_ownership_guard.rs` (no new production callers).

## 4. Enforcement pipeline (Phase 17 applied)

`check_request_full` stages policy and folds with the canonical reducer
(`synvoid_core::enforcement::reduce`): cheap local checks (rate limit,
endpoint) → challenge/bot/flood candidates → expensive attack inspection
(skipped on interim `Drop`/`Block` as a documented resource-protection
short-circuit) → deterministic reduction → directive rendering at dispatch.
Detector mappings live in `synvoid_waf::enforcement`
(`flood_candidate`, `bot_candidate`, `endpoint_candidate`, `attack_candidate`);
rate-limit/honeypot stages construct the canonical
`EnforcementCandidate` directly (`RateLimit`/`RateLimited`,
`Honeypot`/`HoneypotHit`) since their source types are root-owned.
`record_enforcement_outcome` emits only bounded source/class/reason labels.
Terminal `Drop` outranks `Block` outranks `Stall` per the reducer, covered by
`enforcement_pipeline_tests` + `enforcement_decision_contract_guard`.

## 5. Threat/control-plane decoupling

- Raw lookups are diagnostic-only; enforcement uses strict policy paths.
- WAF reads block state at the worker admission boundary, not via
  `ThreatIntelligenceManager` in the request path.
- New block writes use `block_ip_with_provenance` with `BlockProvenanceKind`
  (`LegacyUnknown` only for compat/tests/mocks).
- No `is_mesh_id_blocked` in WAF/request/proxy/HTTP code (see
  `mesh_id_boundary_guard`).
- Threat-level/violation/feed/ASN state is owned by composition and queried
  through narrow traits or owned manager handles — mesh state is never
  directly authoritative inside request-policy evaluation.

## 6. Guards

- `tests/waf_ownership_guard.rs`: crate never imports root; facade modules stay
  thin; orphan duplicates stay deleted; dead `check_block_store` stays out of
  the pipeline; deprecated no-op shims gain no new production callers.
- Existing `root_facade_boundary_guard` (domain crates must not import root),
  `boundary_composition_guard` (request-path capability boundary),
  `enforcement_decision_contract_guard` (canonical precedence), and
  `mesh_id_boundary_guard` continue to cover adjacent invariants.
- Ledger updates: `root_module_ledger.md` reclassifies `waf` to
  `keep_app_root` (composition over `synvoid-waf`); burn-down, dependency
  ownership, final surface audit, `waf.md`, and `src/waf/AGENTS.override.md`
  reconciled.

## 7. Benchmarks

Relevant benches (`--profile ci -- --quick`, post-change, Apple M-series
dev machine — relative reference for Phase 24, not a CI gate):

- `bench_attack_detection`: normalizer hello_world ~52ns, xss_attempt ~96ns,
  sql_injection ~53ns, path_traversal ~68ns, ssti ~43ns, http_request ~116ns,
  long_text ~263ns; url_decode ~179ns.
- `bench_normalization`: benign check ~296µs, form body ~289µs, 10KB body
  ~423µs.
- `bench_ratelimit`: hashmap_get ~11.9ns, hashset_contains ~11.6ns,
  vec_contains ~310ns, to_lowercase_10kb ~384ns.

No pre-change baseline was captured (the moved code paths are identical
logic modulo import paths; the limiter port only narrows an overshoot race
and hardens map removal, adding no per-request allocation or lock). No hot-path
allocation/lock changes were made. Phase 24 records the final regression
conclusion against these numbers.
