# Phase 05 Plan: Per-Site WAF Policy

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: none. Phase 06 consumes the policy-resolution seam.

## The finding

`SiteAttackDetectionConfig` parses and validates:

- `enabled`
- `paranoia_level`
- `action` (`stall` | `block` | `log`)
- `sqli`, `xss`, `path_traversal`, `rfi`, `ssrf` enable flags and the
  detector-specific `custom_patterns`/`allowed_domains` fields
- `per_path` log rules.

Only a subset is applied. `src/waf/site_attack_config.rs` implements
`enabled`, the five detector enable flags and `per_path` log-only. `check_attack`
(`src/waf/mod.rs`) does not read `site_attack_config.action` or
`paranoia_level`, and does not merge site `custom_patterns`/SSRF settings into
the detector. It returns `WafDecision::Block(403, "Attack Detected")`
unconditionally.

The global `AttackDetectionConfig` is also fixed at construction:
`src/server/resources.rs::create_waf` passes
`AttackDetectionConfig::default()`, and `WafCore::reload_attack_detector` is a
documented no-op. The default action in the type is `"stall"`, but the running
behavior is `403`.

`docs/CONFIGURATION.md` already admits that site `custom_patterns`,
`paranoia_level` and `action` are parsed but do not alter detection. That is
honest documentation of a defect, not a policy.

## Decision D3/D4

- D3: make the default action **`block`** to preserve current behavior and
  avoid the 5-second stall budget as a DoS lever. Update the docs that claim
  `stall` is the default. Site/global `stall` and `log` remain available.
- D4: implement per-site `paranoia_level` and `custom_patterns` through a
  bounded detector cache. If the cache cannot be bounded to a safe memory
  budget, remove those fields from the schema and document a global-only
  policy instead of accepting them silently.

## Work items

### 05.1 Policy resolution

Create one resolution function in `src/waf/site_attack_config.rs` (or a
neighbouring root composition module) that returns:
```text
ResolvedAttackPolicy {
    enabled: bool,
    action: AttackAction,     // Block | Stall | Log
    detector_config: AttackDetectionConfig,
    log_only: bool,           // existing per-path rule
}
```
Precedence: site value > global value > built-in default. Keep the existing
per-path `log` override as the highest-priority log-only rule.

### 05.2 Action semantics

- In `check_attack`, after a detector result is accepted:
  - `log`: emit the existing warning/metric, do not record a violation by
    default (Phase 06 decides the exact confidence rule), return `None`.
  - `stall`: return `WafDecision::Stall` with an `EnforcementCandidate` whose
    class is `Stall` and source is attack detection.
  - `block`: return `WafDecision::Block(403, "Attack Detected")` as today.
- Add an `attack_candidate_with_class` helper or a small mapping so the
  enforcement contract's class/source/reason stay correct.
- The streaming scanner already applies per-path log-only; ensure its
  `set_log_only` also respects the resolved action and the site/global
  precedence.
- Change `default_action()` to `"block"`; update
  `docs/ATTACK_DETECTION.md`, `docs/SECURITY.md`,
  `docs/CONFIGURATION.md`, `config/sites/example.com.toml` and
  `config/main.toml.example`.

### 05.3 Per-site detector variants

- Build a merged `AttackDetectionConfig` from the global config plus the
  site's `paranoia_level`, detector custom patterns, SSRF allowed domains,
  `block_private_ips` and `allowlist_only_mode`.
- Build an `AttackDetector` per distinct resolved policy, not per request.
  Cache in `WafCore` with a bounded capacity (the workspace already carries
  `lru_time_cache`; use it or a bounded `DashMap` with eviction).
- Key by a stable policy fingerprint (site id + config generation + policy
  hash). On config reload or `reload_attack_detector`, clear the cache and
  rebuild the global detector.
- The default/no-override path must keep using the single global detector;
  do not clone detector state per request.
- Add a metric for cache size, hits, misses and rebuilds. A cache that grows
  with tenant count without a cap is not acceptable.

### 05.4 Reload and rule feed

- Replace the `reload_attack_detector` no-op with a real path that reads the
  effective configuration/rule feed and swaps the global detector. The
  `attack_detector` is already an `ArcSwapOption`; use the same pattern for
  the per-site cache.
- If the rule feed is not ready to drive detector reloads, explicitly remove
  the no-op and document that only a process restart refreshes custom
  patterns. Do not leave a method that looks live but does nothing.
- Ensure the reload path preserves the streaming scanner settings
  (`max_buffered_bytes`, log-only policy, multipart behavior).

### 05.5 Tests

- Action precedence: site `log`/`stall`/`block`, global fallback, default
  `block`; per-path `log` beats site action.
- Paranoia: a payload detected at level 3 but not level 1 changes the decision
  for the same site; the default site is unaffected.
- Custom patterns: a site-only pattern fires only on that site; global patterns
  still apply everywhere.
- SSRF: `allowed_domains`, `block_private_ips` and `allowlist_only_mode`
  overrides are honored per site.
- Cache: bounded eviction, reload invalidation, no shared mutable detector
  across sites, streaming scanner uses the resolved policy.
- Config validation: invalid action/paranoia still fails; absent site keys
  inherit the global values.

## Non-goals

- New detector types.
- A general-purpose rule language.
- Per-request detector construction.
- Changing the enforcement class vocabulary.

## Risks

- Detector construction compiles regex/Aho-Corasick structures; an unbounded
  per-site cache can dwarf the WAF memory budget. The cap and eviction policy
  are part of the security case.
- Changing the default action from the type's `stall` to `block` is a
  behavior/documentation change; call it out in the release notes.
- A real reload path can race with in-flight requests; use the existing
  `ArcSwap`/snapshot pattern and test it under load.

## Exit criteria

- A site's `action = "log"` no longer blocks; `stall` stalls; `block` blocks.
- `paranoia_level` and `custom_patterns` either work per site or are removed
  from the schema with a typed config error.
- No documentation claims a setting is parsed but ignored.

## Completion evidence

Implemented 2026-11-11. `ResolvedAttackPolicy` resolves enabled/action/
per-path log and merged detector config with site > global > built-in
precedence. `check_attack` now honors `log`, `stall` and `block`; the built-in
default is `block`. Per-site paranoia, custom patterns, SSRF allowlists/private
IP/allowlist mode and header scan extensions are built into a bounded 64-entry
LRU detector cache keyed by policy fingerprint and config generation; rule-feed
reload rebuilds the global detector and clears the cache. Streaming scanners
receive the resolved action and the body cap. WAF tests (384) and root WAF tests
pass.

