# Plugin Milestone 4 Phase 10: Documentation, Tests, and Observability Closure

## Goal

Close the plugin production-readiness line by making the implemented guarantees visible, testable, and operable. Milestones 1–3 hardened the core plugin boundary: manifest authority, signed-byte loading, invocation guard integration, ABI memory safety, canonical serialization, execution containment, host API sub-capabilities, unsafe native extension containment, and lifecycle/hot-reload hardening.

Phase 10 is the final consolidation pass. It should not introduce large new plugin semantics. It should ensure the repo has accurate documentation, complete verification scripts, CI guardrails, metric/status consistency, and operator-facing explanations for both sandboxed WASM plugins and unsafe native extensions.

## Non-Goals

- Do not add new host API capabilities.
- Do not add a full external native plugin RPC protocol.
- Do not redesign the WASM ABI unless docs/tests reveal a contradiction.
- Do not expand native extension authority.
- Do not add broad product-facing UI work beyond status/API surfaces already present.

## Current State

The plugin runtime now has several distinct layers:

1. **Sandboxed WASM plugin model**
   - trust tiers;
   - signed byte loading;
   - manifest-derived effective policy;
   - invocation guard;
   - allocator and ABI memory checks;
   - canonical request/response serialization;
   - fuel and epoch execution containment;
   - host-call budgets;
   - state-model semantics;
   - host API sub-capabilities;
   - generation-aware lifecycle and reload.

2. **Unsafe native extension model**
   - explicitly not sandboxed;
   - disabled by default;
   - production gate and risk acknowledgement;
   - path allowlists and hash verification;
   - retained `Arc<Library>` handle;
   - native hot-reload separately gated;
   - metrics/status/audit hooks.

3. **Lifecycle and hot-reload model**
   - generation IDs;
   - prepare-then-commit reload;
   - stable-file detection;
   - duplicate-name replacement policy;
   - lifecycle state machine;
   - operator lifecycle controls.

Phase 10 should treat these as the source of truth and align all docs/tests/metrics around them.

## Workstream 1: Documentation Truth Audit

### Purpose

Remove stale, misleading, or contradictory plugin documentation. The documentation should describe exact runtime guarantees, not aspirational behavior.

### Files to Audit

- `docs/PLUGINS.md`
- `architecture/plugin_runtime_sandbox.md`
- `architecture/unsafe_native_extensions.md`
- `AGENTS.md`
- `src/plugin/AGENTS.override.md`
- `.opencode/skills/serverless_wasm/SKILL.md`
- README sections that mention plugins, WASM, native extensions, or hot reload
- config examples and sample manifests
- inline module docs in:
  - `crates/synvoid-plugin-runtime/src/wasm_runtime.rs`
  - `crates/synvoid-plugin-runtime/src/abi_frame.rs`
  - `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`
  - `crates/synvoid-plugin-runtime/src/sandbox/types.rs`

### Required Corrections

1. **WASM sandbox claims**
   - Ensure docs state exactly what the WASM sandbox enforces.
   - Distinguish CPU containment via fuel/epoch from wall-clock behavior.
   - Describe host-call budgets and stable ABI error codes.
   - Describe `HostContextIsolated`, `FreshInstancePerRequest`, and `StatefulPooled` precisely.

2. **Native extension claims**
   - Ensure every mention of native extensions says they are unsafe and not sandboxed.
   - Avoid phrases like “native plugin sandbox” or “safe native plugin.”
   - State that native extensions bypass WASM trust tiers, capabilities, fuel, epoch, and host API sub-capabilities.
   - State production enablement requirements.

3. **Hot reload claims**
   - State that reload is prepare-then-commit.
   - State failed reload preserves old generation.
   - State stable-file detection/debounce behavior.
   - State native hot reload is separately gated.

4. **Signing and manifest claims**
   - Ensure signing docs reflect the current signing payload, including sub-capability policies.
   - Ensure docs explain verified bytes and TOCTOU closure.
   - Ensure `SignedSandboxed` requirements are explicit.

5. **Known limits**
   - Document any remaining limitations, including CI status visibility if still not visible through GitHub status APIs.
   - Document native in-process limitations and recommended out-of-process future path.

### Tests / Guardrails

Add or extend documentation guard tests:

- scan docs for forbidden phrases implying native sandboxing;
- scan docs for stale names such as `axum_loader` except migration notes;
- scan docs for `RequestIsolated` without deprecated-alias context;
- ensure `HostContextIsolated` and `FreshInstancePerRequest` are documented;
- ensure `plugin-runtime-guardrails` or equivalent verification commands are documented;
- ensure unsafe native production acknowledgement string is documented in one canonical place.

### Acceptance Criteria

- Documentation matches current code semantics.
- Native extension risk language is consistent everywhere.
- Operators can understand default-safe settings and explicit escape hatches.

## Workstream 2: Manifest and Config Reference Consolidation

### Purpose

Create a single canonical reference for plugin configuration so implementation, docs, tests, and examples do not drift.

### Target Output

A consolidated section in `docs/PLUGINS.md` or a dedicated `docs/PLUGIN_CONFIG_REFERENCE.md` covering:

- WASM global plugin config;
- per-plugin manifest config;
- trust tiers;
- capabilities and sub-capabilities;
- resource limits;
- state model;
- signing config;
- lifecycle/hot-reload config;
- unsafe native extension config;
- deprecated config aliases and migration behavior.

### Implementation Steps

1. Read config structs from:

- `crates/synvoid-config/src/plugins.rs`
- `crates/synvoid-plugin-runtime/src/sandbox/types.rs`
- `crates/synvoid-plugin-runtime/src/unsafe_native_loader.rs`
- `crates/synvoid-plugin-runtime/src/wasm_runtime.rs`

2. Build a field-by-field reference:

- field name;
- type;
- default;
- production restrictions;
- security note;
- example.

3. Add canonical TOML examples:

- minimal local sandboxed WASM plugin;
- signed sandboxed production WASM plugin;
- WASM plugin with mesh sub-capabilities;
- development hot reload config;
- unsafe native extension config with risk acknowledgement;
- deprecated native config migration example.

4. Ensure examples parse in tests where practical.

### Tests

- TOML examples parse into current structs.
- Signed sandboxed example fails if required hashes/signature fields are missing.
- Mesh sub-capability example populates expected policy fields.
- Unsafe native example validates only with explicit risk acknowledgement in production.
- Deprecated alias example migrates safely and does not override explicit new config.

### Acceptance Criteria

- There is one canonical plugin config reference.
- Examples are validated by tests, not stale prose.

## Workstream 3: Verification Script and CI Guardrail Unification

### Purpose

Make plugin verification executable through one clear local script and one clear CI job. Earlier passes added many tests, but the command surface should be consolidated so contributors know what to run.

### Target

Add or update:

- `scripts/verify_plugin_runtime.sh`; or
- a clearly named section in `scripts/verify_architecture.sh`; and
- `.github/workflows/ci.yml` plugin guard job.

### Required Verification Commands

Minimum command set:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets --all-features -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test plugin_lifecycle_guard
cargo test --test unsafe_native_sandbox_language_guard
cargo test --test plugin_failure_does_not_poison_manager
```

If root crate lifecycle/native tests exist, include:

```bash
cargo test -p synvoid -- plugin_lifecycle
cargo test -p synvoid -- plugin_native
cargo test -p synvoid -- hot_reload
```

### Implementation Steps

1. Create `scripts/verify_plugin_runtime.sh` with strict mode:

```bash
#!/usr/bin/env bash
set -euo pipefail
```

2. Add grouped output sections:

- formatting;
- clippy;
- runtime unit tests;
- ABI/manifest/signature guards;
- capability/sub-capability guards;
- lifecycle/hot-reload guards;
- unsafe-native language/loader guards;
- docs/config reference tests.

3. Make `scripts/verify_architecture.sh` call the plugin verifier or mention it clearly.
4. Update CI to call the same script if feasible.
5. Add `workflow_dispatch` if manual CI status remains hard to observe.
6. Update `AGENTS.md` with the exact command.

### Tests

- Script exists and is executable.
- CI references the same script or the same command list.
- Guardrail test checks the script contains critical plugin guard files.

### Acceptance Criteria

- There is one canonical local verification command for plugin runtime work.
- CI and local verification cannot silently diverge.

## Workstream 4: Observability Surface Audit

### Purpose

Ensure all plugin decisions, failures, reloads, lifecycle transitions, and unsafe native extension events are visible through bounded metrics and status APIs.

### Metrics to Audit

WASM runtime metrics:

- invocation attempts/success/failure;
- guard denials;
- capability violations;
- serialization rejections;
- host-call failures;
- fuel exhaustion;
- epoch timeout;
- pool hit/miss/drop;
- fresh instance count;
- concurrency limit exceeded;
- lifecycle transitions;
- reload success/failure.

Unsafe native metrics:

- load success;
- load failure;
- reload success/failure;
- request count;
- policy rejection;
- last failure class.

### Label Rules

- Labels must be bounded.
- Do not use raw paths as metric labels.
- Do not use request URI, header values, body content, DHT keys, or event payloads as labels.
- Prefer plugin name, trust tier, hook type, failure class, lifecycle state, and coarse source kind.
- Hashes and generations may be logged/audited but should be used carefully as metric labels.

### Status/API Surface

Verify status includes:

- plugin name;
- generation ID;
- lifecycle state;
- trust tier;
- source identity kind;
- binary hash;
- manifest hash;
- loaded_at;
- previous generation;
- last reload error;
- failure policy summary;
- failure count;
- timeout count;
- last failure class;
- state model;
- pool stats;
- unsafe native loaded count/status;
- unsafe native path/hash/ABI/generation/last load error.

### Implementation Steps

1. Audit `WasmPluginMetrics` and status structs.
2. Add missing counters or fields only if they correspond to existing events.
3. Add helper functions to record lifecycle/reload/native decisions consistently.
4. Add tests ensuring metric labels are bounded and do not contain raw payloads/paths.
5. Add docs explaining important metrics and status fields.

### Tests

- serialization rejection metrics never include raw header/body data;
- native load failure metrics do not include full path labels;
- lifecycle transition metric labels are bounded;
- status includes generation/hash/lifecycle/last error;
- unsafe native status is separate from WASM sandbox status;
- operator can query last native load error and last WASM reload error.

### Acceptance Criteria

- Operators can debug plugin behavior without inspecting logs only.
- Metrics are safe for production cardinality.
- Status output cleanly separates WASM sandbox plugins from unsafe native extensions.

## Workstream 5: Malicious and Regression Fixture Suite

### Purpose

Codify the adversarial cases that motivated the hardening work. Regression tests should catch the specific classes of bugs fixed in Milestones 1–3.

### Fixture Categories

1. **ABI memory fixtures**
   - overlapping allocator returns;
   - allocator trap;
   - free trap;
   - invalid guest pointer;
   - oversized input/output;
   - missing `guest_alloc`/`guest_free` in production.

2. **Serialization fixtures**
   - excessive headers;
   - oversized header name/value;
   - non-UTF8 values;
   - repeated headers;
   - invalid response status;
   - forbidden response header mutation.

3. **Execution fixtures**
   - infinite loop fuel exhaustion;
   - epoch timeout;
   - host-call timeout;
   - body chunk over limit;
   - capability violation.

4. **Policy/signing fixtures**
   - tampered manifest;
   - tampered WASM bytes;
   - signed sandboxed missing hash;
   - sub-capability tamper;
   - mesh prefix wildcard in strict mode.

5. **Lifecycle fixtures**
   - partial file write;
   - failed reload preserving old generation;
   - duplicate name from different source;
   - namespace collision between native and WASM;
   - quarantine/reset/remove transitions.

6. **Unsafe native fixtures**
   - disabled default load;
   - production missing acknowledgement;
   - path outside allowlist;
   - symlink;
   - world-writable file/parent;
   - hash mismatch;
   - factory panic/null pointer where testable.

### Implementation Steps

1. Inventory existing fixtures in `test_fixtures.rs` and integration tests.
2. Create a table mapping each fixed bug class to a test name.
3. Add missing tests or document deferrals.
4. Ensure fixture names describe the invariant, not only the implementation detail.
5. Add the fixture suite to the plugin verification script.

### Acceptance Criteria

- Every major bug class fixed in Milestones 1–3 has a regression test.
- Test names are searchable by invariant.
- Deferred cases are documented with rationale.

## Workstream 6: Operator Runbook

### Purpose

Give operators a practical guide for configuring, inspecting, and recovering plugin runtime behavior in production.

### Target Document

Create or update `docs/PLUGIN_OPERATOR_RUNBOOK.md`.

### Required Sections

1. **Default posture**
   - WASM enabled/disabled defaults;
   - unsafe native disabled by default;
   - production signing expectations.

2. **Deploying a signed WASM plugin**
   - manifest fields;
   - signing/hash steps;
   - config example;
   - validation command;
   - expected status output.

3. **Configuring sub-capabilities**
   - mesh read prefix example;
   - event topic example;
   - metrics policy example.

4. **Hot reload**
   - development mode;
   - production mode;
   - stable-file behavior;
   - failed reload recovery.

5. **Lifecycle operations**
   - disable;
   - reset;
   - quarantine;
   - remove;
   - inspect generation.

6. **Unsafe native extensions**
   - warnings;
   - production acknowledgement;
   - path/hash allowlist;
   - why out-of-process is recommended.

7. **Troubleshooting**
   - signature failure;
   - capability denied;
   - ABI validation failure;
   - fuel exhausted;
   - epoch timeout;
   - host-call timeout;
   - serialization rejection;
   - native load rejected;
   - reload failed but old generation preserved.

8. **Metrics and status fields**
   - key metrics;
   - status fields;
   - common dashboards/alerts.

### Tests / Guardrails

- docs path reference guard includes runbook links;
- runbook includes unsafe native warning;
- runbook includes canonical verification command;
- runbook does not include stale config keys except migration notes.

### Acceptance Criteria

- An operator can deploy and troubleshoot plugins from the runbook.
- The runbook accurately reflects runtime behavior.

## Workstream 7: Developer Guide and Contributor Rules

### Purpose

Prevent future regressions by giving contributors clear extension rules.

### Target Content

Update `AGENTS.md`, `src/plugin/AGENTS.override.md`, and `.opencode/skills/serverless_wasm/SKILL.md` with concise rules:

- New WASM host functions must have sub-capabilities.
- New host functions must use checked guest pointer/range validation.
- New serialization paths must go through `abi_frame`.
- New load paths must use prepared/verified bytes.
- New reload paths must be prepare-then-commit.
- Native extension code must be labelled unsafe and cannot claim sandboxing.
- Native load paths must enforce production gate before opening libraries.
- Metrics labels must be bounded.
- Any new plugin authority must be signed/manifest-covered.

### Guardrails

Add source-scanning tests where appropriate:

- no direct ad-hoc request serialization outside `abi_frame`;
- no `Library::new` outside `unsafe_native_loader`;
- no native docs claiming sandboxing;
- no plugin load path bypassing `PreparedPluginLoad`/effective policy;
- no reload commit before candidate validation.

### Acceptance Criteria

- Future contributors get explicit plugin rules.
- Guardrails catch the most dangerous regressions.

## Workstream 8: Phase Closure Report

### Purpose

Create a final report that summarizes what the plugin production-readiness line now guarantees and what remains intentionally deferred.

### Target Document

Create `plans/plugin_production_readiness_closure_report.md` or update the original roadmap with a closure section.

### Required Content

- Completed phases 1–10.
- Key invariants now enforced.
- Test/guardrail inventory.
- Runtime status/metrics inventory.
- Known limitations.
- Deferred future work:
  - out-of-process native plugin service;
  - broader admin/TUI plugin controls if not present;
  - distributed plugin registry if needed;
  - external signing/key management workflow;
  - GitHub Actions status visibility if still unresolved.

### Acceptance Criteria

- The roadmap has a clear endpoint.
- Future work is separated from current closure requirements.

## Recommended Execution Order

1. Documentation truth audit.
2. Config reference consolidation with parse-tested examples.
3. Verification script and CI unification.
4. Observability/status/metrics audit.
5. Malicious/regression fixture inventory and missing tests.
6. Operator runbook.
7. Developer guide/guardrail updates.
8. Closure report.

## Validation Commands

Run at minimum:

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets --all-features -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test abi_memory_boundary_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test plugin_lifecycle_guard
cargo test --test unsafe_native_sandbox_language_guard
cargo test --test plugin_failure_does_not_poison_manager
cargo test --test docs_path_reference_guard
```

If a dedicated script is added:

```bash
./scripts/verify_plugin_runtime.sh
```

## Completion Definition

Phase 10 is complete when:

- Plugin docs accurately match code guarantees.
- Config and manifest examples are parse-tested.
- One canonical plugin verification script exists and is documented.
- CI runs the same plugin guardrail suite or explicitly invokes the verification script.
- Metrics/status surfaces cover WASM sandboxed plugins, lifecycle transitions, reload outcomes, and unsafe native extensions with bounded labels.
- Regression fixtures cover the main bug classes fixed in Milestones 1–3.
- Operator runbook exists and explains deployment, hot reload, lifecycle recovery, and troubleshooting.
- Developer rules and guardrails prevent future bypasses.
- A closure report summarizes completed guarantees and deferred work.
