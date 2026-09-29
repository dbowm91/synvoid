# Phase 99 — Configuration Model / Runtime Separation Closeout

Status: implemented and closed 2026-09-28.

## Ownership result

- Added internal `synvoid-config-model` with only schema-bearing DTOs and pure
  defaults. `HoneypotPortConfig` moved there, and `synvoid-config` keeps its
  existing module path as a compatibility re-export.
- `synvoid-honeypot` now consumes that model crate directly and no longer has
  a production dependency on the broad config loader.
- A machine-readable workspace dependency rule and source guard prohibit
  runtime, filesystem, and key-generation authority in the model crate.
- Main/site configuration loading, filesystem access, ConfigManager, and
  feature-aware validation remain in `synvoid-config`.
- Mesh DTOs no longer carry skipped runtime key state or expose crypto/key
  realization methods. `MainConfig::from_file` no longer performs mesh crypto
  work. The root supervisor composition adapter converts the parsed config to
  the mesh-owned runtime config and calls `synvoid-mesh` identity/key loaders
  in both supervisor and worker startup. Mesh CLI paths use that same adapter.
- Removed config-only crypto dependencies (`base64`, `base32`, `hex`, `sha2`,
  `hkdf`, `ed25519-dalek`, `x25519-dalek`, `aes-gcm`, `pbkdf2`, `subtle`, and
  `pqc`) from `synvoid-config`; it now has 16 direct dependencies including
  the model crate.

## Compatibility findings and corrections

Tracked config round trips found pre-existing compatibility gaps, corrected as
part of the characterization work:

- `TokioConfig` now accepts the documented legacy `[tokio]` table as well as
  scalar serialization.
- `DefaultsConfig`, its honeypot subsection, and rate-limit endpoints now use
  their declared defaults when omitted, matching their `Default` values and
  the tracked examples.
- Trusted proxy validation now accepts CIDR ranges already supported by the
  request sanitizer, as used in `main.toml.example`.
- The example config intentionally has a weak placeholder admin token and the
  active config names `/var/log/synvoid`; fixture validation treats the former
  as a deserialize/round-trip sample and makes the latter hermetic. Existing
  fail-closed feature-section tests still run under the full verification.

Mesh identity known-answer tests pin the previous genesis HKDF derivation,
node/router identifiers, X25519 and Ed25519 public-key derivation, and
constant-time invite-token matching in the mesh runtime owner. Loading an
existing/generated signing key now fills the router ID from the same key,
avoiding the old random fallback on repeated reads.

## Graph measurement

Recomputed with `cargo metadata --no-deps --format-version 1` on this tree:

- 53 workspace members.
- `synvoid-config-model`: 3 production dependencies (`serde`, `schemars`,
  `utoipa`); production consumers are `synvoid-config` and `synvoid-honeypot`.
- `synvoid-honeypot` has no resolved dependency on `synvoid-config`.
- `synvoid-config` has 16 direct dependencies; the duplicate runtime crypto
  stack and `pqc` edge are gone.
- The remaining broad config reverse edges belong to consumers that use
  aggregate config, feature-gated config, validation/loading, or config APIs.
  The plan’s tracked import inventory is still the guide for later selective
  migration; no consumer was migrated solely to inflate the count.

## Verification

- `cargo test -p synvoid-config-model --profile ci` — passed (1 test).
- `cargo test -p synvoid-config --profile ci` — passed (100 tests).
- `cargo test -p synvoid-config --features mesh,dns,icmp-filter --profile ci`
  — passed (98 tests across three suites, including the tracked fixture round
  trips).
- `cargo test -p synvoid-honeypot --profile ci` — passed (204 tests).
- `cargo test -p synvoid-mesh --profile ci --features mesh` — passed (1,093
  tests, including identity known-answer vectors).
- Admin router composition, route contract, and smoke flow passed (18, 24,
  and 24 tests).
- Five required feature checks passed: minimal, mesh, DNS, ICMP filter, and
  mesh+DNS.
- `cargo xtask test guards` — passed repo guards; root mesh ownership guard
  also passed (106 tests) after updating its accepted adapter shape.
- `cargo xtask verify` — passed all 10 steps on the corrected tree.
- `cargo fmt --all -- --check`, metadata recomputation, and honeypot dependency
  tree inspection passed.

The config fuzz target was not run; bounded equivalent coverage used the
existing config parser/unit suites and round-tripped tracked main/site/mesh/
tunnel fixtures through the same TOML DTO paths.

## Remaining boundary and next phase

The aggregate `MainConfig`, `SiteConfig`, DNS config tree, and feature-gated
mesh/tunnel settings remain in `synvoid-config`; their parsing/validation and
operator API contracts are still coupled to that owner. The model crate is
deliberately small because the measured model-only honeypot consumer provided
the first acyclic dependency reduction without moving those mixed contracts.

Phase 100 is unblocked. Phase 101 remains the final campaign qualification and
must recompute the graph, evaluate capability/performance evidence, and obtain
exact-SHA hosted CI and dependency-security results.
