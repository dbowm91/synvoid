---
name: waf_engine
description: Core WAF engine — 16 attack detectors, normalizer, narrow request-path traits, enforcement verdicts. Use when adding detectors, touching normalization, or wiring WAF capabilities.
---

# Skill: WAF Engine

## Context

The WAF engine lives canonically in `crates/synvoid-waf`; `src/waf/` is
root composition (rate limiting, rule feeds, threat level). Request-path
code consumes narrow traits, never concrete infrastructure — see
`architecture/request_path_capability_boundary.md`. Full reference:
`architecture/waf.md`, `architecture/waf_deep_dive.md`,
`architecture/waf_ownership_convergence.md`,
`architecture/enforcement_decision_contract.md`.

## When to Use

- Adding or tuning an attack detector
- Touching normalization (overlong UTF-8, homoglyphs) or anomaly scoring
- Adding a capability to the request path (new narrow trait)
- Changing enforcement verdicts or rate-limit/threat-level wiring

## Key Files

| File | Purpose |
|------|---------|
| `crates/synvoid-waf/src/traits.rs` | Narrow traits: `BlockListStore`, `WafProcessor`, `WafRequestServices`, `ChallengeService`, `ThreatLevelProvider`, `TarpitService` (+ `GeoIpLookup`, `WafPersistence`) |
| `crates/synvoid-waf/src/attack_detection/` | Detector suite (see `streaming_waf` skill for chunked scanning) |
| `crates/synvoid-waf/src/enforcement.rs` | Pass/Drop/Stall/Block/Challenge/Tarpit verdict contract |
| `crates/synvoid-waf/src/ratelimit/` | Rate limiting (`shared` \| `isolated` modes only) |
| `crates/synvoid-rate-limit/` | Shared mechanism (Phase 33): `AtomicSlidingWindow` (`increment_at`/`count_at` + `WindowClock`), neutral `RateLimitResult`/`IpRateLimiter`/`KeyedRateLimiter`/`RateLimitStats`, `ip_to_slot`. Std-only leaf — no config/metrics/HTTP/WAF-policy. Consumed by root WAF composition and mesh; blackhole/slotted/shm/token-bucket policy stays domain-owned |
| `crates/synvoid-waf/src/bot.rs` | Bot detection (see `waf_bot_detection` skill) |
| `src/waf/` | Root composition: rule feeds, threat level, rate-limit wiring |

## Non-Negotiables

1. **Composition boundary** (guard-enforced): request path consumes
   `Arc<dyn Trait>` built in composition roots (`src/worker/unified_server/`,
   `src/supervisor/`, `src/server/`). To add a capability, define the trait
   in `crates/synvoid-waf/src/traits.rs` or `synvoid-core`, implement it on
   the concrete type in a composition root, pass it down.
2. **Overlong UTF-8**: the normalizer decodes overlong percent-encoded
   sequences and sets `OVERLONG` on `NormalizationFlags`;
   `strict_normalization` rejects them. Never silently drop the flag.
3. **The WAF pipeline queries/mutates no block/threat state** — enforcement
   reads come from BlockStore via the narrow traits (see `block_store` skill).
4. **Rate-limit modes are `shared` | `isolated`** — there is no
   `distributed` mode; config validation rejects anything else.
5. **Constant-time comparison** (`subtle::ConstantTimeEq`) for all
   secret/MAC/token compares, including PoW verification.
6. **Inline execution model** (Phase 50): `AttackDetector::check_request`
    evaluates detectors inline on borrowed inputs via `check_request_sync` —
    no per-request `JoinSet` fanout, no `Arc` snapshots, no
    `NormalizedInputs::into_owned()`. Do not reintroduce task-per-detector
    fanout. Anomaly-enabled scoring/priority semantics and the
    anomaly-disabled early-terminal path are pinned by
    `crates/synvoid-waf/tests/execution_model_parity.rs`.
    Known cost (Phases 56–57 requalified, incl. immutable concurrency
    1/8/32/128): isolated single 10 KiB-body latency regressed while all
    concurrent batches improved; whole-stage offload stays deferred pending
    event-loop evidence. See
    `architecture/performance_optimization_corrective_closeout.md` §6/§7.

## Verification

```bash
cargo nextest run -p synvoid-waf --cargo-profile ci --profile ci
cargo nextest run --test boundary_composition_guard --cargo-profile ci --profile ci
```
