# Phase 02 Plan: Wire `SiteAttackDetectionConfig` into WAF Dispatch

Status: **PROPOSED**.

Registered in: `plans/roadmap.md`.

Campaign: `plans/waf_admin_deployment_truthfulness_roadmap.md`.
Predecessor: Phase 01 (verification cleanliness — Referer traffic must pass
before per-site RFI toggles are observable; otherwise independent).

## The finding

Site `[attack_detection.*]` parses and validates but never reaches the
running detectors. Setting `sites/blog.toml [attack_detection.rfi]
enabled=false` (and the global equivalent) has no effect — `Referer` RFI
still fires after restart.

- Site view: `crates/synvoid-config/src/site/attack_detection.rs`
  (`SiteAttackDetectionConfig` with `enabled: Option<bool>`,
  `paranoia_level`, `action`, plus `sqli/xss/path_traversal/rfi/ssrf`
  subtables; `SiteRfiConfig{enabled: Option<bool>, custom_patterns}`,
  `SiteSsrfConfig` adds `block_private_ips/allowed_domains`).
  `site/mod.rs:100,205` carries and validates it. Tri-state `Option<>`
  merge-ready.
- Running view: `crates/synvoid-waf/src/attack_detection/config.rs`
  `AttackDetectionConfig` (resolved `bool`s, `DetectorConfig`,
  `SsrfConfig`, default all-enabled, `paranoia_level=2`, `action="stall"`).
  `AttackDetector::new` fans `config.rfi.enabled/ssrf.enabled/...` into
  `check_request_sync` / `check_body_only*` (`mod.rs:376-513` and two more
  dispatch sites).
- All construction sites hardcode the default; none merges site:
  `src/server/resources.rs:295`, `src/worker/connection.rs:61`,
  `src/waf/assembly.rs:192,242` (via `Option<AttackDetectionConfig>`),
  `src/waf/mod.rs:1156` + `service_assembly.rs:257` (test helpers).
  `grep SiteAttackDetectionConfig` outside `synvoid-config`, docs, config,
  and `xtask` finds zero production consumers.
- Working per-site precedent exists for bots:
  `Router` carries `Arc<SiteConfig>` (`crates/synvoid-proxy/src/router.rs`),
  `RouteTarget{site_id, site_config}`; `buffered_request_waf_dispatch.rs:50,66-78`
  threads `site_bot_config = Some(&target.site_config.bot)` into
  `WafCore::check_request_full(..., site_bot_config, ...)`
  (`src/waf/mod.rs:674-680`). Attack config has no equivalent parameter —
  `check_attack` uses only `self.attack_detector.load()`, with `site_id`
  used for rate-limit sharding only. Counter-examples with the same gap:
  per-site rate-limit thresholds (sharded by `site_id` in
  `RateLimiterManager`, limits still from `WafCoreConfig.rate_config`),
  `check_endpoint_block` (no `site_id`), `UploadValidator::get_effective_config`
  (path-level merge only; `init_waf.rs:19-73` builds from `main.defaults.upload`
  ignoring `site.upload`).

Note the asymmetry: site config lacks `ssti/cmd_injection/xxe/jwt/smuggling/
ldap/xpath/open_redirect/strict_normalization/limits/allowlist_only_mode`.
Merge must define defaulting for those (use global).

## Goal

`SiteAttackDetectionConfig.enabled=false` (per detector) actually disables
that detector for that site, with global config as the default when the site
key is absent. No per-site `AttackDetector` map in this phase.

## Recommended disposition: per-request gate, single global detector

Thread `Option<&SiteAttackDetectionConfig>` exactly like `site_bot_config`
(`RouteTarget.site_config.attack_detection` → `buffered_request_waf_dispatch.rs`
→ `RootWafProcessor` in `adapter.rs` → `WafCore::check_attack` and the
`streaming()/check_body_only` variants if they take per-site input).

In the gated function, compute effective flags as
`site.<det>.enabled.unwrap_or(global.<det>.enabled)` (plus top-level
`enabled`, and for SSRF `block_private_ips`/`allowed_domains`; union
`custom_patterns` additively; `paranoia_level`/`action` override when set),
and short-circuit before `attack_detector.load()` hits. Keeps one global
`AttackDetector`; `Default` preserves current behavior when site is `None`.

The heavier alternative (per-site `HashMap<site_id, Arc<AttackDetector>>`
built at config load/reload with invalidation on `ConfigManager` update) is
deferred — it needs a memory bound and reload plumbing. Prefer the gate
unless per-site `custom_patterns`/`paranoia_level` need compiled detector
state that the gate cannot express.

Out of scope: RFI regex semantics (Phase 01), admin mounting (Phase 03),
per-site rate-limit thresholds, endpoint-block and upload site gaps (same
bug class, separate phases if pursued).

## Workstreams

- **A — plumbing** (`src/waf/`, `src/http/`, `src/proxy/` adapter only;
  detector crates untouched): add the `site_attack_config` parameter,
  effective-flag helper (pure function, unit-testable), early-return gates.
  No new crate (ledger: detectors stay in `crates/synvoid-waf`, wiring in
  root composition).
- **B — tests**: unit tests for the merge helper (site `Some(false)` beats
  global true; `None` inherits; SSRF `block_private_ips`/`allowed_domains`
  override); integration via existing WAF harness with two sites (one
  disabled detector passes attack traffic — mirror
  `execution_model_parity.rs:346` precedent). New WAF-only tests go in
  `crates/synvoid-waf/tests/`, not root `tests/`.
- **C — docs**: `docs/ATTACK_DETECTION.md` + `docs/CONFIGURATION.md`
  per-site attack-detection section (inheritance rule).

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo test -p synvoid-waf --profile ci
cargo nextest run --cargo-profile ci --profile ci \
  --test boundary_composition_guard --test waf_ownership_guard \
  --test security_guard --test mesh_id_boundary_guard --features mesh
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
```

Manual: with Phase 01 applied, set site `rfi.enabled=false` → IP
`Referer` passes; `rfi.enabled` absent → still blocks. Revert safe:
parameter defaults to `None` → current behavior.
