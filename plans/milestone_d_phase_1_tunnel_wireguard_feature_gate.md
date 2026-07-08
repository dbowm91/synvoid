# Milestone D Phase 1: Tunnel and WireGuard Feature Gate Closure

## Purpose

Close the `synvoid-tunnel` workspace debt identified during workspace-wide validation. The tunnel crate currently blocks full workspace release-clean classification through clippy debt and a WireGuard feature-gate issue involving an undeclared `wireguard_control` dependency.

This phase should make tunnel compile and lint behavior explicit across default, all-targets, and supported feature profiles.

## Current issues

From workspace validation:

- `synvoid-tunnel` clippy failures:
  - `unnecessary_cast`
  - `too_many_arguments`
- WireGuard feature profile failure:
  - missing/undeclared `wireguard_control` dependency under `--features wireguard`
- The crate checks clean with no features, but full workspace all-features validation is blocked by tunnel feature debt.

## Non-goals

- Do not implement new tunnel protocols.
- Do not redesign tunnel architecture.
- Do not introduce platform-specific WireGuard runtime assumptions without feature gates.
- Do not paper over compile failures with broad `#[allow]` attributes.

## Workstream 1: Reproduce and isolate tunnel failures

Run and capture:

```bash
cargo check -p synvoid-tunnel
cargo check -p synvoid-tunnel --all-targets
cargo clippy -p synvoid-tunnel --all-targets -- -D warnings
cargo check -p synvoid-tunnel --all-features
cargo check -p synvoid-tunnel --all-targets --all-features
cargo clippy -p synvoid-tunnel --all-targets --all-features -- -D warnings
```

If WireGuard has a named feature:

```bash
cargo check -p synvoid-tunnel --features wireguard
cargo check -p synvoid-tunnel --all-targets --features wireguard
cargo clippy -p synvoid-tunnel --all-targets --features wireguard -- -D warnings
```

Record exact error codes, files, and line numbers in the implementation commit or validation note.

## Workstream 2: Fix clippy debt correctly

### `unnecessary_cast`

Prefer removing redundant casts. Confirm integer types at the call site so removal does not alter platform-dependent behavior.

Acceptance:

- no `unnecessary_cast` warning remains
- tests still compile/run
- no semantic change from cast removal

### `too_many_arguments`

First determine whether the function is:

- public API
- internal constructor/helper
- test helper
- protocol operation boundary

Preferred fix:

- introduce a narrow parameter struct for cohesive fields
- use existing config structs if available
- keep call sites readable

Acceptable exception:

- a narrow `#[allow(clippy::too_many_arguments)]` with a comment only if the function is a stable protocol/API boundary where grouping would obscure semantics or create churn.

Rejected fix:

- crate-level allow
- module-wide allow without justification
- splitting parameters into unrelated globals

## Workstream 3: Resolve WireGuard dependency gate

Decide which model is correct:

### Option A: WireGuard feature is supported now

If supported:

1. Add the correct optional dependency to `crates/synvoid-tunnel/Cargo.toml`.
2. Wire the feature to the dependency:

```toml
[features]
wireguard = ["dep:wireguard-control"]
```

Use the actual crate name and module path supported by the code.

3. Ensure platform-specific APIs are gated:

- Linux-only code under `cfg(target_os = "linux")`, if needed.
- Unsupported platforms return explicit `UnsupportedPlatform` error.
- Tests are cfg-gated or use mockable interfaces.

4. Add compile tests for `--features wireguard`.

### Option B: WireGuard feature is deferred

If not ready:

1. Remove the broken feature from all-features default surface, or make it compile as an explicit stub.
2. Add a clear error variant such as `TunnelError::WireGuardUnsupported`.
3. Document WireGuard as deferred/experimental.
4. Ensure `cargo check -p synvoid-tunnel --all-features` passes.

### Option C: Rename/fix stale module path

If the code references `wireguard_control` but the dependency is named or imported differently, fix the import/dependency mapping without broad refactor.

## Workstream 4: Tests

Add or update tests for:

- default tunnel config compiles and validates
- WireGuard feature either works through mocked path or returns unsupported error
- unsupported platform behavior is explicit
- parameter struct construction if `too_many_arguments` is refactored
- no feature combination pulls WireGuard unintentionally into default builds

## Workstream 5: Documentation

Update relevant docs:

- `docs/TUNNELS.md`
- `docs/CONFIGURATION.md` if tunnel config changes
- `AGENTS.md` validation commands if needed
- `plans/workspace_wide_validation_results.md` only if this phase updates closure status

Document:

- supported tunnel feature profiles
- WireGuard support status
- platform requirements
- local validation commands

## Local validation commands

```bash
cargo fmt --all -- --check
cargo check -p synvoid-tunnel
cargo check -p synvoid-tunnel --all-targets
cargo clippy -p synvoid-tunnel --all-targets -- -D warnings
cargo test -p synvoid-tunnel --all-targets
cargo check -p synvoid-tunnel --all-features
cargo clippy -p synvoid-tunnel --all-targets --all-features -- -D warnings
```

If WireGuard remains as a feature:

```bash
cargo check -p synvoid-tunnel --features wireguard
cargo clippy -p synvoid-tunnel --all-targets --features wireguard -- -D warnings
```

## Success criteria

- `synvoid-tunnel` default check/clippy/test passes.
- `synvoid-tunnel --all-features` check/clippy passes or unsupported features are removed from all-features exposure.
- WireGuard behavior is explicit: supported, stubbed, or deferred.
- No broad lint suppression is introduced.
- Documentation matches the actual feature behavior.

## Handoff notes

This phase is a release-readiness cleanup. If WireGuard support needs real design work, prefer a safe stub/defer path over partial implementation that keeps `--all-features` broken.
