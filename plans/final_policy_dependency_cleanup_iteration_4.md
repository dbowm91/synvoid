# Final Policy and Dependency Cleanup — Iteration 4

## Goal

This pass should close the small inconsistencies left after the passthrough policy hardening work. The prior pass fixed the TLS passthrough rate-limit classification semantics, added structured policy evaluation, and added `security.strict_tls_passthrough_policy`. The remaining work is cleanup: reconcile the `webpki-roots` ownership mismatch, document the strict passthrough config for operators, and run a final focused scan for stale dependency and policy comments.

This is intentionally a small stabilization pass. Do not start new architecture work here.

## Non-Goals

Do not split `synvoid-mesh`.

Do not extract another root subsystem in this pass.

Do not change the DHT/Raft model.

Do not change default feature sets.

Do not change default strict passthrough behavior; `security.strict_tls_passthrough_policy` must remain false unless explicitly enabled.

Do not alter WAF detection, challenge, tarpit, or rate-limit runtime semantics beyond documentation and consistency fixes.

## Phase 1 — Reconcile `webpki-roots` Ownership

### Problem

`plans/root_dependency_ownership_iteration_2.md` says `webpki-roots` is owned by `synvoid-http-client` and is not used by root, but root `Cargo.toml` still declares `webpki-roots` and comments it as root-owned for `src/http_client/typed_pool.rs`.

Only one of these can be true. The repo should have a single consistent source of truth.

### Required Changes

Run:

```bash
rg "webpki_roots|webpki-roots" Cargo.toml src crates
cargo tree -p synvoid -i webpki-roots
cargo tree -p synvoid-http-client -i webpki-roots
```

If root `src/` no longer imports `webpki_roots`, remove `webpki-roots` from root `[dependencies]` and update the root dependency comment block accordingly.

If root still imports `webpki_roots`, update `plans/root_dependency_ownership_iteration_2.md` to state the real root usage and keep the dependency.

Given the current audit note, the expected outcome is likely:

- remove root `webpki-roots = "0.26"`;
- leave `webpki-roots` declared in `crates/synvoid-http-client/Cargo.toml`;
- update the ownership note to say root direct: no.

### Acceptance Criteria

`Cargo.toml` and `plans/root_dependency_ownership_iteration_2.md` agree about `webpki-roots`.

`cargo check --workspace --all-targets` passes after the change.

No HTTP client TLS root behavior changes.

## Phase 2 — Document Strict TLS Passthrough Policy

### Problem

`security.strict_tls_passthrough_policy` now exists and controls whether unsafe TLS passthrough bypass without rate limiting fails validation. Operators need to know what it does, what the default is, and how it interacts with WAF enforcement and rate limiting.

### Required Changes

Search for the appropriate config documentation location:

```bash
rg "strict_tls_passthrough_policy|tls_passthrough|security" README.md docs examples crates/synvoid-config config* *.toml
```

Add documentation in the most appropriate place. Prefer a config reference doc or security hardening doc if one exists. If none exists, add a concise section to an existing security/config doc.

Document:

```toml
[security]
strict_tls_passthrough_policy = false
```

Explain behavior precisely:

- default `false` preserves compatibility: unsafe passthrough emits logs/metrics but does not fail startup;
- `true` fails worker validation when a site enables TLS passthrough without WAF enforcement and without meaningful rate limiting;
- passthrough with `tls_passthrough_enforce_waf = true` is allowed;
- passthrough bypass with configured rate limiting is allowed but still logs that L7 WAF inspection is bypassed;
- this is a safety gate for hardened deployments.

Also document the site-level remediation options:

```toml
[proxy]
tls_passthrough = true
tls_passthrough_enforce_waf = true
```

or configure meaningful site rate limiting.

### Acceptance Criteria

The new config option is documented in at least one operator-facing doc.

The documentation states the default and strict-mode failure condition.

The documentation does not imply that strict mode is enabled by default.

## Phase 3 — Add Config Serialization / Default Regression Test

### Problem

The config option was added with serde default, but there should be a lightweight regression test to ensure old configs remain compatible and the default is false.

### Required Changes

Add a targeted test in `crates/synvoid-config` or the closest existing config test module.

Test cases:

1. `MainSecurityConfig::default().strict_tls_passthrough_policy == false`.
2. Deserializing a security config without `strict_tls_passthrough_policy` yields false.
3. Deserializing `strict_tls_passthrough_policy = true` yields true.

Keep the test narrow. Do not require full config loading if a smaller struct-level TOML deserialize test is sufficient.

### Acceptance Criteria

The config default is test-covered.

Old configs that omit the field remain valid.

## Phase 4 — Final Policy Validation Test Review

### Problem

The passthrough validation tests are now good, but there are two things to verify:

- strict-mode runtime behavior is tested at the pure evaluation or validation layer;
- tests do not rely on ordering from `HashMap` in a way that could become flaky.

### Required Changes

Inspect `src/worker/unified_server/passthrough_validation.rs` tests.

If any test directly compares a vector produced from `HashMap` iteration with more than one element, sort before compare or assert with `contains`/sets.

Add a strict-mode test if missing:

- strict mode returns error or produces violations for bypass without WAF and without rate limiting;
- strict mode passes for bypass with rate limiting;
- strict mode passes for passthrough with WAF enforcement.

If the runtime async helper is difficult to test because it needs `ConfigManager`, test the pure evaluation layer and add one runtime validation test only if low-churn.

### Acceptance Criteria

No flaky vector-order assumptions remain in multi-site tests.

Strict-mode behavior is covered.

## Phase 5 — Final Stale Comment / Plan Scan

### Problem

Several cleanup passes have left comments pointing to older plans and historical root ownership notes. That is acceptable when accurate, but stale comments are now a risk.

### Required Changes

Run:

```bash
rg "moved to|owned by|root-owned|architecture_boundary_cleanup|root_dependency_ownership|KEEP_ROOT|TODO|FIXME" Cargo.toml src crates docs plans
```

Do not rewrite everything. Only fix comments that are now materially false.

Specifically check:

- root `Cargo.toml` HTTP/3/QUIC comments;
- `synvoid-http3` crate status comments;
- DHT record-store global compatibility comments;
- passthrough policy docs/comments.

### Acceptance Criteria

No known false ownership comments remain.

Comments distinguish current architecture from historical migration notes.

## Validation Commands

Run targeted checks first:

```bash
cargo fmt --all --check
cargo test -p synvoid-config strict_tls_passthrough_policy
cargo test -p synvoid --lib passthrough_validation
cargo check -p synvoid-http-client
cargo check -p synvoid-http3
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

If broad tests are too expensive or blocked by existing failures, record the exact targeted checks that passed and the reason broader checks were not completed.

## Completion Criteria

This iteration is complete when:

- `webpki-roots` ownership is consistent across root `Cargo.toml`, crate manifests, and the ownership note;
- `security.strict_tls_passthrough_policy` is documented for operators;
- config default/deserialize behavior is test-covered;
- strict passthrough policy behavior has stable tests;
- stale ownership/policy comments are corrected;
- no new architecture work has been introduced.

## Follow-Up Recommendation

After this pass, treat the current architecture cleanup thread as complete unless the validation run reveals deeper issues. The next meaningful work should be a deliberate architecture pass, either:

1. extract another root-owned runtime/protocol subsystem into an existing crate, or
2. begin an internal responsibility split inside `synvoid-mesh` by trust domain before creating new crates.
