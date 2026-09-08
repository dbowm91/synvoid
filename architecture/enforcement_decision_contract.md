# Enforcement Decision Contract

Status: normative (Phase 17).

One canonical vocabulary for request enforcement class, source/provenance,
reason, and precedence across WAF, rate limiting, bot detection, flood
protection, honeypot/challenge, block state, HTTP dispatch, and protocol
adapters.

Detectors are **not** merged. Each detector keeps its own result type (which
carries evidence) and projects its outcome onto the canonical contract at the
composition boundary. Conflict semantics are data + tests, not call order.

## 1. Canonical types

Location: `crates/synvoid-core/src/enforcement.rs`.

`synvoid-core` was chosen because every request-path crate
(`synvoid-waf`, `synvoid-proxy`, `synvoid-http`, `synvoid-http-client`)
already depends on it, so the contract creates no dependency cycle and no new
workspace crate was needed. The module is `std` + `serde` only.

| Type | Meaning |
|------|---------|
| `EnforcementClass` | Transport-neutral action: `Allow`, `Observe`, `Challenge`, `Stall`, `Tarpit`, `Block`, `Drop`. No HTML, cookies, or protocol objects. |
| `EnforcementSource` | Typed provenance: `BlockStore`, `RateLimit`, `EndpointPolicy`, `Honeypot`, `BotPolicy`, `FloodProtection`, `AttackDetection`, `StreamingBodyScan`, `OperatorManual`, `MeshDerived`. |
| `EnforcementReason` | Bounded stable reason codes (`rate_limited`, `attack_detected`, …). Human-readable detail stays in logs; metrics/tests use these codes. |
| `EnforcementCandidate` | One claim: `{ class, source, reason }`. `Copy`, allocation-free. |
| `reduce(a, b)` / `reduce_all(set)` | Deterministic reducer (section 3). Empty set means allow; the allow path allocates nothing. |

`EnforcementSource::as_str` preserves the pre-contract
`synvoid_request_enforcement_source_total` label values (`block_store`,
`rate_limit`, `endpoint_block`, `honeypot_hit`, `bot_protection`,
`flood_protection`, `attack_detection`) so existing dashboards keep working.
New sources use the same snake_case convention. All codes are frozen.

## 2. Result inventory

Every enum/type that can affect request disposition:

| Type | Owner | Meaning | Terminal? | Carries response payload? | Role |
|------|-------|---------|-----------|---------------------------|------|
| `synvoid_core::enforcement::EnforcementClass` | `crates/synvoid-core/src/enforcement.rs` | Canonical action | varies | No | **Canonical** |
| `synvoid_core::enforcement::EnforcementCandidate` | same | One detector claim | varies | No | **Canonical** |
| `synvoid_waf::WafDecision` (`crates/synvoid-waf/src/primitives.rs`) | synvoid-waf | Rich response directive (status, HTML, cookies) | varies | **Yes** | Canonical-adjacent: exposes lossless `class()` mapping; rendering stays here |
| `synvoid_proxy::protocol::WafAction` (`crates/synvoid-proxy/src/protocol/trait_def.rs`) | synvoid-proxy | Coarse protocol-handler action | varies | No | **Transport-local adapter**: exhaustive `class()` / `from_class()` mapping, tested |
| `RateLimitResult` (`src/waf/ratelimit.rs`) | app root (WAF) | IP/site/global limiter outcome | `Limited`/`Blackholed` | No | Detector result; mapped inline in `WafCore::check_rate_limits` (`Allowed`→none, `Limited`→`Block/RateLimit/rate_limited`, `Blackholed`→`Drop/RateLimit/rate_limited`) |
| `RateLimitDecision` (`src/waf/ratelimit/core.rs`) | app root (WAF) | Limiter core outcome | `Limited`/`Blackholed` | No | Detector-internal; feeds `RateLimitResult` |
| `SlidingDecision`, `SlidingGlobalDecision` (`crates/synvoid-waf/src/ratelimit/sliding.rs`) | synvoid-waf | Sliding-window outcomes | `Limited` | No | Detector-internal; feed the limiter core |
| `FloodDecision` (`crates/synvoid-waf/src/flood/mod.rs`, re-exported by `src/waf/flood`) | synvoid-waf | SYN/connection/UDP flood outcome | `RateLimited`/`Blackholed` | No | Detector result; `synvoid_waf::enforcement::flood_candidate` |
| `BotDetectionResult` (`crates/synvoid-waf/src/bot.rs`) | synvoid-waf | Bot/scraper/fingerprint outcome | `Blocked`/`Tarpit` | No | Detector result; `synvoid_waf::enforcement::bot_candidate` |
| `EndpointCheckResult` (`crates/synvoid-waf/src/endpoints/blocker.rs`, re-exported by `src/waf/endpoints.rs`) | synvoid-waf | Static endpoint policy outcome | `Blocked` | No (optional HTML fragment) | Detector result; `synvoid_waf::enforcement::endpoint_candidate` |
| `AttackDetectionResult` (`crates/synvoid-waf/src/attack_detection/config.rs`, re-exported by `src/waf/attack_detection`) | synvoid-waf | Rule-match evidence (type, location) | Always (detection ⇒ deny) | No | Detector result; `synvoid_waf::enforcement::attack_candidate` → `Block/AttackDetection/attack_detected` |
| `synvoid_core::streaming_waf::StreamingWafDecision` (`crates/synvoid-core/src/streaming_waf.rs`) | synvoid-core | Streaming chunk scan outcome | `Block` | No | **Streaming adapter** shared by `synvoid-http-client` and `synvoid-waf` without cycles |
| `synvoid_waf::attack_detection::streaming::StreamingWafDecision` (`crates/synvoid-waf/src/attack_detection/streaming.rs`) | synvoid-waf | Internal streaming-core chunk outcome | `Block` | No | Detector-internal; adapted to the core decision at `StreamingWafCore::scan_chunk` boundary |
| `BodyPolicyError` (`crates/synvoid-http/src/body_policy.rs`) | synvoid-http | Buffered body policy failure | Always (both variants deny: 403/413) | No | **HTTP adapter**: exhaustive `candidate()` mapping, fail-closed |
| `FullWafDecisionOutcome` (`crates/synvoid-http/src/waf_decision.rs`) | synvoid-http | HTTP/1 dispatch outcome (`Pass`/`Respond`) | n/a (dispatch, not enforcement) | Yes (`Respond`) | Dispatch outcome; not an enforcement class |
| `Http3WafDecisionOutcome` (`crates/synvoid-http/src/http3_waf_dispatch.rs`) | synvoid-http | HTTP/3 dispatch outcome (`Continue`/`EarlyReturn`) | n/a (dispatch, not enforcement) | No | Dispatch outcome; not an enforcement class |
| `AsnCheckResult` (`src/waf/asn_tracker.rs`) | app root (WAF) | ASN scraping check (`Pass`/`Blocked`) | `Blocked` | No | Detector-internal; **not currently staged** in `check_request_full`. If wired in, must map to `Drop/BotPolicy/bot_blocked` (its `check_request` renders `Drop`). |
| `ChallengeResult` (`crates/synvoid-challenge/src/types.rs`) | synvoid-challenge | Challenge *verification* outcome (`Passed`/`NotSet`/`Failed`/`RateLimited`) | No | No | Verification evidence, not disposition; feeds allow/challenge decisions upstream |
| `ChallengeType`, `ChallengePriority` (`crates/synvoid-challenge/src/types.rs`) | synvoid-challenge | Challenge kind / ordering policy | No | No | Configuration, not disposition |
| `WafVerdict` (`crates/synvoid-core/src/verdict.rs`) | synvoid-core | Legacy verdict (`Pass`/`Block`/`Challenge`/`Log`/`RateLimit`) | varies | No | **Legacy adapter** (predates this contract). Canonical mapping: `Pass`→`Allow`, `Log`→`Observe`, `Challenge`→`Challenge`, `Block`→`Block`, `RateLimit`→`Block`. New code must use `EnforcementClass`. |
| `ProtocolError::WafBlocked` (`crates/synvoid-proxy/src/protocol/trait_def.rs`) | synvoid-proxy | Protocol parse error variant | Yes (error ⇒ deny) | No (message only) | Error type, not disposition; surfaces as a block at the protocol layer |

Domain detector results are intentionally retained: they carry evidence
(matched pattern, input location, bot type) that is not an enforcement
action.

## 3. Precedence and reduction

Terminal ordering (frozen, tested exhaustively pairwise in
`crates/synvoid-core/src/enforcement.rs`):

```text
Drop(6) > Block(5) > Tarpit(4) > Stall(3) > Challenge(2) > Observe(1) > Allow(0)
```

Reducer guarantees (all tested):

- higher class always wins; lower precedence can never weaken higher;
- `Allow`/`Observe` can never erase a terminal candidate;
- idempotence: `reduce(x, x) == x`;
- order independence: folding in any order yields the same winner;
- deterministic provenance: same-class ties break by `(source, reason)` code
  order (lexicographic on the frozen `as_str` codes), lowest wins — never by
  hash-map iteration or task completion order.

### Deliberate behavior deltas vs legacy call-order policy

Legacy `check_request_full` encoded policy as early-return order
(block-store → rate-limit → endpoint → honeypot → bot → flood → attack), so
an earlier weaker claim shadowed a later stronger one. The reducer fixes two
fail-closed strengthenings (both covered by pipeline tests):

- **B1 — `Drop` outranks earlier claims.** A flood-blackhole `Drop` now wins
  over an earlier rate-limit/endpoint/honeypot/bot claim. Previously the
  earlier claim shadowed the drop.
- **B2 — `Block` outranks `Stall`/`Tarpit`/`Challenge`.** A bot/flood/attack
  `Block` now wins over an earlier honeypot `Stall` or scraper `Tarpit`.
  Previously the `Stall`/`Tarpit` shadowed the block.

Preserved pairs (same outcome before and after): rate-limit `Block` over
endpoint `Block` at class level; endpoint `Block` over honeypot `Stall`;
honeypot `Stall` over bot `Challenge`; bot `Block` over flood `Block` at
class level (tie resolves to bot by code order, matching legacy order).
Same-class ties across *simultaneously evaluated* stages now resolve by
`(source, reason)` code order instead of call order; this is deterministic
and tested, but provenance for ties may differ from the legacy first-wins
behavior. No `Allow` has ever overwritten, and can never overwrite, a
terminal denial (rejection criterion, tested).

### Incidental finding: flood blackhole polarity (fail-open fixed)

While making flood outcomes explicit, the B1 pipeline test exposed that
`FloodProtector::is_in_blackhole` (`crates/synvoid-waf/src/flood/mod.rs`)
used an inverted `RunningFlag` check: `enter_blackhole()` stops the flag
(workspace convention: stopped = blackhole active, cf.
`src/waf/ratelimit/core.rs`), but `is_in_blackhole()` returned `false` when
the flag was stopped — so flood blackhole mode could never engage and the
TCP listener's `FloodDecision::Blackholed` branch was dead code. Fixed with a
regression test (`flood::tests::blackhole_engages_and_releases`); the
mirrored `FloodStats::in_blackhole` polarity was fixed in the same pass.
Fail-closed direction: blackhole now actually denies when engaged.

## 4. Staged pipeline (`WafCore::check_request_full`)

`src/waf/mod.rs`. Evidence production and action reduction are separated:
each stage yields `Option<StagedOutcome>` (`WafDecision` directive +
`EnforcementCandidate`); outcomes fold through the canonical reducer with no
allocation on the allow path.

1. **Admission state (may short-circuit).** Pre-existing block/blackhole.
   The block store itself is checked at the worker composition root, not in
   the WAF (`check_block_store` is a documented stub yielding no claim), so
   request-path code gains no mutation capability. A future admission claim
   would map to `BlockStore/blocklisted` and participate in reduction.
2. **Cheap local policy:** rate limit, endpoint policy.
3. **Challenge/bot/rate/flood candidates:** honeypot, bot protection, flood.
4. **Expensive attack inspection — conditional.** Skipped when stages 1–3
   already selected `Drop` or `Block`: attack inspection produces
   Block-class claims only, which cannot outrank the interim winner, so
   running it would only burn CPU on an already-denied request. The interim
   winner's provenance is retained. This is a documented
   resource-protection short-circuit, not an ordering artifact.
5. **Deterministic reduction** (folded across stages 1–4) + observability.
6. **Response rendering/dispatch** from the winner's directive at the HTTP
   dispatch layer (`synvoid-http`), which never re-decides policy.

No expensive detectors were parallelized: stages run sequentially in a fixed
order, but the *semantics* come from the reducer, so stage order is a
latency choice, not policy.

## 5. Transport adapters

- `WafAction` remains as an explicitly transport-local adapter (it cannot
  express silent `Drop` at the framed-protocol layer). `class()` and
  `from_class()` are exhaustive; canonical `Drop` degrades to `Block`
  (fail-closed: still denies; covered by test). Round-trip preserves every
  expressible class.
- HTTP/1 (`waf_decision.rs`) and HTTP/3 (`http3_waf_dispatch.rs`) dispatch
  match exhaustively over `WafDecision`; unknown outcomes cannot compile,
  and any future catch-all must deny (fail closed).
- Streaming/body mappings (`streaming_candidate`, `BodyPolicyError::candidate`)
  are exhaustive and terminal-only (fail closed).

## 6. Observability

- `synvoid_request_enforcement_source_total{source}` — preserved, now
  emitted once for the reduced winner with the frozen canonical source code.
- `synvoid_request_enforcement_reason_total{source,class,reason}` — new,
  bounded-cardinality reason codes from the contract.
- `synvoid.http.enforcement_class_total{class}` /
  `synvoid.http3.enforcement_class_total{class}` — unified disposition
  counters at both dispatch layers, non-allow outcomes only (allow path
  overhead unchanged).
- Existing per-action counters (`blackhole_drop`, `stalled`, `blocked`,
  `challenged`, …) are preserved.
- Metric labels never carry IPs, URLs, user agents, or rule text (tested for
  the code vocabularies; detector detail stays in tracing).

## 7. Guard

`tests/enforcement_decision_contract_guard.rs` (registered in
`tests/OWNERSHIP.toml`) scans request-path sources for new enums carrying
≥2 enforcement-action variant names (`Allow`/`Allowed`/`Pass`/`Continue`,
`Block`/`Blocked`, `Challenge`, `Drop`/`Blackholed`, `Tarpit`/`TarPit`,
`Stall`, `LogOnly`) outside the registered-adapter allowlist below. A new
disposition enum must either reuse the canonical contract or be registered
here with an exhaustive, tested mapping.

Registered adapters (guard allowlist — every entry must be mentioned in this
document):

- `crates/synvoid-core/src/enforcement.rs` — canonical contract itself.
- `crates/synvoid-core/src/verdict.rs` — legacy `WafVerdict` adapter.
- `crates/synvoid-core/src/streaming_waf.rs` — streaming adapter.
- `crates/synvoid-waf/src/primitives.rs` — rich `WafDecision` directive.
- `crates/synvoid-waf/src/bot.rs` — `BotDetectionResult` (detector result).
- `crates/synvoid-waf/src/flood/mod.rs` — `FloodDecision` (detector result).
- `crates/synvoid-waf/src/endpoints/blocker.rs` — `EndpointCheckResult` (detector result).
- `crates/synvoid-waf/src/attack_detection/streaming.rs` — internal streaming decision (detector-internal; adapted to core at the scanner boundary).
- `crates/synvoid-http/src/body_policy.rs` — `BodyPolicyError` (HTTP adapter; single-keyword spelling, registered for documentation).
- `crates/synvoid-proxy/src/protocol/trait_def.rs` — `WafAction` (transport-local adapter).
- `src/waf/asn_tracker.rs` — `AsnCheckResult` (detector-internal, unstaged).
- `src/waf/ratelimit.rs` — `RateLimitResult` (detector result).
- `src/waf/ratelimit/core.rs` — `RateLimitDecision` (detector-internal core).

## 8. Benchmarks

No hot-path detector code changed in this phase (attack detection, rate
limiter, normalization, flood counters, and bot matching are untouched);
the refactor only re-orchestrates `WafCore::check_request_full` around the
reducer. By construction the allow path gains no new allocation (fold over
`Option`s, no candidate storage), no new locking, and no new metric
emission (observability fires only for the reduced winner). A full
`bench_ratelimit` criterion run was attempted locally but exceeded the
time budget during compilation; no before/after numbers are recorded here.
Re-run the request/WAF bench suite (`bench_ratelimit`,
`bench_attack_detection`, `bench_normalization`) before/after any future
change to the staged pipeline and record material regressions for Phase 24
follow-up.
