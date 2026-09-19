# Phase 41 Plan: Fail-Closed Configuration and Process Bounds

Status: implemented and closed; retained as historical handoff detail.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

## Primary goal

Ensure that operator configuration cannot request a capability that the compiled binary silently ignores, and ensure process-count configuration cannot feed unbounded or overflowing derived capacities into runtime code.

## Evidence

`crates/synvoid-config/src/main_config.rs` conditionally removes `dns`, `mesh`, and `icmp_filter` fields from the type. Serde ignores unknown fields by default for self-describing formats unless `deny_unknown_fields` or an equivalent explicit preflight is used. The existing DNS validation branch:

```rust
#[cfg(feature = "dns")]
if self.dns.enabled && !cfg!(feature = "dns") { ... }
```

cannot observe a binary built without `dns`; the code is compiled out in exactly that build.

`MainConfig::validate()` currently validates server/http/tls/threat/fallback/logging/admin/defaults/tunnel, but not `process_manager`, `supervisor`, or `supervisor_compat`.

`src/supervisor/process.rs` currently derives:

```rust
let max_workers = config.unified_server_workers + 10;
let max_backends = 2048;
```

without checked arithmetic at that call site.

Mesh worker supervision intentionally rejects `restart_enabled = true`, but restart-related fields still exist. Current unsupported behavior should be rejected at configuration validation rather than discovered after startup composition.

## Design decision: targeted capability preflight, not immediate global strict TOML

Do not add `#[serde(deny_unknown_fields)]` indiscriminately to the entire configuration graph in this phase. That would turn every historical/forward-compatible extra field into a breaking change and can interact badly with flattened/nested compatibility structures.

Instead, add a feature-independent preflight over the raw TOML before typed deserialization. It should inspect only capability-bearing keys whose silent omission is security/operationally meaningful.

Suggested structure:

```rust
struct CompiledCapabilities {
    dns: bool,
    mesh: bool,
    icmp_filter: bool,
}

fn validate_config_capability_presence(
    raw: &toml::Value,
    compiled: CompiledCapabilities,
) -> Result<(), ConfigValidationError>;
```

The helper should reject a present/active section when the corresponding compile feature is absent. Inventory both top-level and nested ownership, especially:

- top-level `[dns]`;
- top-level mesh config if present in current schema;
- `[tunnel.mesh]` or equivalent nested mesh configuration;
- `[icmp_filter]`;
- future feature-owned sections added after this phase.

Do not reject comments or absent/default sections. Decide explicitly whether an entirely inert table with only `enabled = false` is accepted. Prefer rejection for absent capabilities so operators cannot believe the binary understood the section; if compatibility requires accepting disabled sections, document and test that exception.

The preflight should preserve `MainConfig::from_toml_str()` as the canonical parse/validation seam used by fuzzing.

## Workstream A — Capability-surface inventory

1. Enumerate every `#[cfg(feature = ...)]` field/module in `synvoid-config`.
2. Map each one to its TOML key path and root feature.
3. Classify it as capability-bearing/reject-when-absent, compile-only implementation detail, or compatibility field intentionally parsed in all builds.
4. Add the matrix to `architecture/config.md` or a focused `architecture/config_feature_contract.md`.

Do not rely on filename/module names; use actual Serde paths.

## Workstream B — Raw preflight and typed validation order

Update `MainConfig::from_toml_str()` to:

1. parse raw TOML in a bounded/self-contained way;
2. run the feature-capability preflight;
3. deserialize typed `MainConfig`;
4. run `MainConfig::validate()`.

Avoid filesystem/network side effects in this seam.

If parsing twice becomes measurable, introduce an internal deserialize-from-`toml::Value` path. Do not optimize before correctness is established.

Add typed error messages with exact config paths, for example:

```text
dns: configuration is present but this binary was built without the 'dns' feature
```

## Workstream C — Process/supervisor validation

Add explicit `validate()` methods for `ProcessManagerConfig`, `SupervisorConfig`, and `OverseerConfig` where those types can reach runtime.

Validate at minimum:

- counts are nonzero where zero has no defined meaning;
- `min_workers <= max_workers`;
- warm/pre-spawn targets do not exceed their owning capacity;
- restart backoff/cooldown relationships are sane;
- control API address parses as the required socket/address form;
- timeout values that become durations are bounded away from accidental zero/infinite behavior where the runtime assumes otherwise;
- `unified_server_workers` has an explicit hard maximum derived from supported process/IPC/resource limits.

Do not invent `unified_server_workers <= max_workers` unless code semantics prove that `max_workers` governs the same pool. First document the relationship from `ProcessManager` consumers, then encode the correct invariant.

Call these validators from `MainConfig::validate()` and from any lower-level update path that can construct/update the types independently.

## Workstream D — Checked runtime derivations

Replace unchecked derived capacity arithmetic with checked helpers and use `checked_add`, `checked_mul`, and explicit conversion checks before allocation, mmap sizing, worker IDs, or port derivations.

Config validation is the first barrier; runtime constructors must still validate because they are callable without TOML.

## Workstream E — Mesh supervision configuration truthfulness

Current production policy rejects `restart_enabled = true`; keep that behavior fail-closed.

Move the rejection into authoritative config validation so startup fails before task construction.

Audit the remaining restart fields (`restart_limit`, window/backoff values). Choose one explicit contract:

1. retain them only when a future restart capability is intentionally staged, but reject non-default tuning while restart is disabled; or
2. deprecate/remove them from operator-facing config until restart execution exists.

Do not implement `execute_mesh_restart` in this phase.

Reconcile stale documentation that still says the value is merely overridden/warned.

## Tests

Add feature-profile parser tests that compile and run under the relevant profile, not tests whose own dev dependency re-enables the feature.

Minimum behavioral cases:

- core/no-default binary rejects `[dns]`;
- core/no-default binary rejects mesh config;
- core/no-default binary rejects `[icmp_filter]`;
- DNS build accepts and validates valid DNS config;
- mesh build accepts valid mesh config and rejects `restart_enabled = true`;
- typo/unknown-key behavior outside capability-owned sections remains unchanged unless deliberately tightened;
- admin config mutation path cannot persist invalid process settings;
- `usize::MAX` and near-overflow process counts fail validation without panic;
- zero/min/max boundary tests for every process count.

Add or extend a repository guard so new feature-gated config fields must be added to the capability matrix/preflight.

## Compatibility and rollout

This deliberately converts some previously accepted-but-ignored configurations into hard errors. Treat that as a security/operational correctness fix.

Document migration messages so operators know whether to rebuild with the feature or remove the unsupported section.

Do not silently strip sections on write-back; a config editor/admin API must preserve or reject explicitly.

## Verification

```bash
cargo test -p synvoid-config --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
```

Run the config fuzz target after the preflight lands.

## Acceptance criteria

- No supported reduced-feature build silently ignores a capability-bearing config section.
- `MainConfig::validate()` invokes process/supervisor validation.
- Runtime derived capacities use checked arithmetic even when constructed outside config parsing.
- Mesh restart settings are operator-truthful and fail before runtime composition.
- Feature-profile tests prove absent-feature rejection with the actual feature absent.
- Documentation and admin mutation behavior match the parser contract.

## Closeout (Phase 48)

Implemented in `a3e5ab27f8ce`. Binding: `architecture/config_feature_contract.md`. Campaign closeout: `architecture/runtime_truthfulness_security_publication_closeout.md`.
