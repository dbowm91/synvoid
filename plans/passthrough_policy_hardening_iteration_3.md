# Passthrough Policy Hardening — Iteration 3

## Goal

This pass should harden the security-policy behavior uncovered by the previous boundary cleanup. The architecture is now cleaner: HTTP/3 is extracted, `DataPlaneServicesBuilder` requires explicit services, and TLS passthrough validation is isolated. That isolation exposed a likely semantic bug: the current `rate_limited_bypass_sites` classification effectively checks whether a site still exists in the map rather than whether the site has meaningful rate limiting configured.

The priority for this pass is to fix that policy classification correctly, add focused regression tests, and clean up the small documentation/ownership gaps left by iteration 2. Do not start mesh decomposition or broad root refactoring in this pass.

## Non-Goals

Do not redesign TLS passthrough handling.

Do not change WAF enforcement behavior for passthrough sites except for correcting the rate-limit classification/reporting semantics.

Do not turn warnings into hard startup failures by default.

Do not change default feature sets.

Do not split `synvoid-mesh`.

Do not remove the DHT record-store global in this pass.

Do not perform unrelated dependency cleanup beyond the small ownership note described below.

## Phase 1 — Fix TLS Passthrough Rate-Limit Classification

### Problem

`src/worker/unified_server/passthrough_validation.rs` currently builds `rate_limited_bypass_sites` by checking whether a bypass site is missing from the same site map it was collected from. In normal operation this is always false. The tests even document that `rate_limited_bypass_sites` remains empty because the site exists in the map.

That preserves legacy behavior, but the policy intent is different: if a site uses TLS passthrough without WAF enforcement, SynVoid should at least warn when that site does not have meaningful rate limiting configured.

### Required Changes

Define a small helper that determines whether a site has meaningful rate limiting configured. Do not inline this inside the classifier.

Suggested shape:

```rust
fn site_has_rate_limit(site: &SiteConfig) -> bool {
    // inspect SiteRateLimitConfig fields and return true only when rate limiting is actually configured/enabled
}
```

Use the real `SiteRateLimitConfig` semantics. Do not assume that `SiteRateLimitConfig::default()` means rate limiting is enabled. Inspect the config struct and existing call sites to determine which fields indicate an active limiter. Likely candidates include mode, requests/window/burst values, or enabled flags if present.

Then change classification so:

```rust
rate_limited_bypass_sites
```

is renamed if needed. The current name appears backwards: the logged message says these are passthrough bypass sites that **do not** have rate limiting configured. Prefer one of:

- `bypass_sites_without_rate_limit`
- `unrate_limited_bypass_sites`

Keep old field names only if churn would be large, but correct the semantics and comments.

### Expected Classification Semantics

For each site:

- `passthrough_sites`: `tls_passthrough == Some(true)`.
- `passthrough_with_waf`: passthrough and `tls_passthrough_enforce_waf == Some(true)`.
- `bypass_sites`: passthrough without WAF enforcement.
- `bypass_sites_without_rate_limit`: bypass sites where `site_has_rate_limit(site) == false`.

Sites with WAF enforcement enabled should not be included in `bypass_sites_without_rate_limit`, even if they lack rate limiting, unless existing policy already intended to warn on all passthrough sites. Preserve the existing warning scope: bypass sites only.

### Acceptance Criteria

The classifier no longer checks whether `sites.get()` returns `None` for a site already collected from the same map.

Tests demonstrate that a passthrough bypass site with default/no rate-limit config is reported as lacking rate limiting.

Tests demonstrate that a passthrough bypass site with active rate-limit config is not reported.

Tests demonstrate that a passthrough site with WAF enforcement is not reported as an unrate-limited bypass.

The log message still preserves the existing security warning intent.

## Phase 2 — Add Optional Strict Passthrough Policy Gate

### Problem

Currently unsafe passthrough policy appears to be logged but not enforced. That is acceptable for backward compatibility, but operators should have an explicit way to make unsafe passthrough fail validation in hardened deployments.

### Required Changes

Investigate existing config structure for a suitable strict-policy field before adding anything new. Search for existing knobs around:

```bash
rg "passthrough|tls_passthrough|strict|enforce|fail" crates/synvoid-config src
```

If a suitable config knob already exists, wire the extracted validation helper to honor it.

If no suitable knob exists, add a narrowly scoped config option with a conservative default that preserves current behavior. Suggested naming:

```toml
[security]
strict_tls_passthrough_policy = false
```

or, if there is already a WAF/security config area, place it there.

When strict mode is disabled:

- preserve current behavior: log and record metrics only.

When strict mode is enabled:

- return an error if any passthrough bypass site lacks WAF enforcement and lacks active rate limiting;
- do not fail solely because passthrough exists with WAF enforcement enabled;
- keep the error message actionable and include affected site IDs.

Do not enable strict mode by default in this pass.

### Acceptance Criteria

There is a documented config option or existing config path for strict passthrough policy.

Default behavior is unchanged.

Strict mode causes validation to return an error for unsafe passthrough bypass without rate limiting.

Strict mode tests cover pass and fail cases.

## Phase 3 — Make Validation Return Structured Results

### Problem

The validation helper currently logs and records metrics directly. That is acceptable for runtime integration, but tests and future policy gates are cleaner if classification and policy evaluation are separate from side effects.

### Required Changes

Keep the pure classifier.

Add a second pure policy evaluation function, for example:

```rust
pub struct PassthroughPolicyEvaluation {
    pub classification: PassthroughClassification,
    pub violations: Vec<PassthroughPolicyViolation>,
}

pub enum PassthroughPolicyViolation {
    WafBypassed { site_id: String },
    BypassWithoutRateLimit { site_id: String },
}
```

Then let the async runtime helper:

```rust
validate_tls_passthrough_waf_policy(...)
```

perform side effects based on the evaluation.

If strict mode is added, the strict failure decision should use `PassthroughPolicyEvaluation`, not re-scan config.

### Acceptance Criteria

Policy tests can assert on structured violations without relying on logs or metrics.

The runtime helper remains the only place that emits logs and records metrics.

Current logging messages remain materially equivalent.

## Phase 4 — Complete Root Dependency Ownership Note

### Problem

Iteration 2 updated inline root dependency comments for `quinn`, `h3`, `h3-quinn`, and `webpki-roots`, but the expected ownership note was not found under `plans/root_dependency_ownership_iteration_2.md`.

### Required Changes

Create:

```text
plans/root_dependency_ownership_iteration_2.md
```

Document only the dependencies audited in iteration 2:

| Dependency | Current owner | Root direct? | Reason / next action |
|------------|---------------|--------------|----------------------|
| quinn | root + synvoid-http3/synvoid-mesh as applicable | yes | root uses for DNS-over-QUIC and TCP protocol detection; keep unless those modules move |
| h3 | synvoid-http3 | no | HTTP/3 implementation owns it |
| h3-quinn | synvoid-http3 | no | HTTP/3 implementation owns it |
| webpki-roots | root | yes | used by `src/http_client/typed_pool.rs`; later move if typed pool exits root |

Verify this table against actual code before committing. If ownership differs, document the real state.

### Acceptance Criteria

The ownership note exists.

The note matches `Cargo.toml` and actual code usage.

No functional code changes are required for this phase.

## Phase 5 — Tighten Tests Around HTTP/3 and Service Boundaries

### Required Checks

Keep the existing HTTP/3 mock-WAF boundary tests.

Add or adjust tests only if current tests are weak or misleading:

- `Http3WafBackend` remains object-safe.
- `synvoid-http3` does not import root `WafCore`.
- `DataPlaneServicesBuilder` requires explicit `ServerlessManager`.
- `DataPlaneServicesBuilder::build()` has no global plugin fallback.

Do not add brittle source-text tests unless there is already precedent. Prefer compile-time construction tests using mocks.

### Acceptance Criteria

Boundary tests still compile without requiring full root runtime initialization.

No test requires live QUIC sockets, DHT, Raft, or network listeners.

## Validation Commands

Run focused checks first:

```bash
cargo fmt --all --check
cargo test -p synvoid --lib passthrough_validation
cargo check -p synvoid-http3
cargo test -p synvoid-http3
```

Then run broader checks:

```bash
cargo check --workspace --all-targets
cargo test --workspace --all-targets
```

Feature checks:

```bash
cargo check --workspace --all-targets --no-default-features
cargo check --workspace --all-targets --features mesh
cargo check --workspace --all-targets --features dns,mesh
```

If full workspace tests are too slow or flaky, record exactly which targeted checks passed and what remains unverified.

## Completion Criteria

This iteration is complete when:

- TLS passthrough bypass sites without active rate limiting are correctly detected;
- the misleading/unreachable `sites.get().is_none()` rate-limit check is gone;
- tests cover unsafe bypass, safe bypass with rate limit, and WAF-enforced passthrough;
- strict passthrough policy exists if a config location can be added without broad churn, and defaults to current behavior;
- root dependency ownership note exists and matches the code;
- existing HTTP/3 and `DataPlaneServicesBuilder` boundary tests still pass;
- no unrelated architecture or mesh decomposition work is started.

## Follow-Up Recommendation

After this pass, reassess the root crate again. If policy validation is clean and tests are stable, the next meaningful architecture pass should either extract another root-owned runtime/protocol subsystem or begin an internal `synvoid-mesh` responsibility split by trust domain without creating new crates yet.
