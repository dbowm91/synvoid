# SynVoid Workspace-Green and HTTP/3 Readiness Plan

> Status: proposed next-iteration handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: make the workspace validation surface green after the stability/dead-code cleanup pass, then perform the smallest HTTP/3 readiness work needed to decide whether `src/http3/server.rs` can move later.

## 0. Current state

The modularization and cleanup effort has reached a stable phase:

```text
- Root proxy is a compatibility shim over `synvoid-proxy`.
- Canonical upload/YARA runtime lives in `synvoid-upload` and `synvoid-mesh`.
- Dead duplicate root upload files were deleted.
- Root direct `yara-x` was removed.
- Mesh feature profile compiles again.
- Image rights terminology is canonical; old poisoning names remain only as compatibility/wire debt.
- All standard root feature profile checks pass.
```

The remaining validation problem is broad workspace validation:

```text
cargo check --workspace --all-targets
```

The latest recommendation note reports this command still fails in four known areas:

```text
1. `myapp-dynamic` example: E0507 move error.
2. `synvoid-ipc` test: missing `sha2` dependency.
3. `admin-ui`: several compile errors.
4. `synvoid-mesh` tests: test compile errors.
```

This plan prioritizes making `cargo check --workspace --all-targets` green before further architecture moves.

## 1. Strategic position

Do not resume broad crate-splitting yet. The repo is already modular enough that further architecture work should happen only after validation is reliable.

The next two technical priorities are:

```text
Priority 1: Make workspace-all-targets clean or document irreducible external/test-only failures precisely.
Priority 2: Investigate HTTP/3 `Http3RequestWaf` object-safety/readiness without moving the server prematurely.
```

The order matters. Fixing workspace validation first makes later HTTP/3 work much safer.

## 2. Non-goals

Do not do these in this pass:

```text
Do not create new crates.
Do not move `src/http/server.rs`.
Do not move `src/http3/server.rs` unless a final readiness task explicitly proves it is trivial.
Do not move WafCore.
Do not move worker or supervisor.
Do not split Raft from mesh.
Do not change IPC wire names such as `PoisonImage`.
Do not remove image_poisoning compatibility shims.
Do not redesign admin-ui.
Do not rewrite mesh tests broadly.
```

## 3. Hard constraints

1. Preserve runtime behavior.
2. Keep fixes narrow and tied to compiler errors.
3. Prefer adding missing dev/test dependencies over moving production code.
4. Do not silence errors by excluding crates from the workspace unless explicitly approved.
5. Do not weaken validation by deleting tests/examples merely because they fail.
6. If a test/example is obsolete, document why before disabling or deleting.
7. Do not add dependencies from extracted crates back to root `synvoid`.
8. Every task must record exact commands run and whether they passed.

## 4. Validation matrix

For each task, run the task-specific checks.

At the end of each wave, run:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

If `cargo test --workspace --no-run` fails after `cargo check --workspace --all-targets` passes, document whether the failure is test-only or production-relevant.

## 5. Wave A: refresh workspace failure inventory

Purpose: capture the current exact failure set before patching.

### Task WGH-A01: reproduce workspace-all-targets failures

Run:

```bash
cargo check --workspace --all-targets
```

Create or update:

```text
plans/workspace_all_targets_failure_inventory.md
```

Record each failure:

```text
Crate/target | Error code | File | Root cause | Proposed task | Notes
```

Expected current buckets:

```text
myapp-dynamic example E0507
synvoid-ipc test missing sha2
admin-ui errors
synvoid-mesh test errors
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

Do not modify source code in this task except the inventory file.

## 6. Wave B: fix myapp-dynamic example

Purpose: remove example-only compiler failure without changing runtime library behavior.

### Task WGH-B01: inspect myapp-dynamic ownership and failure

Likely location:

```text
examples/dynamic-plugin-example
```

Run targeted check:

```bash
cargo check -p myapp-dynamic
```

or, if the package name differs:

```bash
cargo check --manifest-path examples/dynamic-plugin-example/Cargo.toml
```

Inspect the E0507 move error.

Update:

```text
plans/workspace_all_targets_failure_inventory.md
```

Record:

```text
Moved value | Source line | Correct ownership model | Proposed patch
```

Acceptance:

```bash
cargo check --manifest-path examples/dynamic-plugin-example/Cargo.toml
```

### Task WGH-B02: fix E0507 in myapp-dynamic narrowly

Apply the smallest Rust ownership fix.

Preferred fixes, in order:

```text
1. Borrow instead of move.
2. Clone only if the type is cheap/expected to be cloned.
3. Use `as_ref()` / `as_deref()` for Option/String-like values.
4. Restructure match to avoid moving out of borrowed content.
```

Do not redesign the example.

Acceptance:

```bash
cargo check --manifest-path examples/dynamic-plugin-example/Cargo.toml
cargo check --workspace --all-targets
```

If workspace still fails elsewhere, only the myapp-dynamic failure should be gone.

## 7. Wave C: fix synvoid-ipc test dependency

Purpose: fix a test-only missing dependency cleanly.

### Task WGH-C01: confirm synvoid-ipc sha2 usage scope

Inspect:

```text
crates/synvoid-ipc/Cargo.toml
crates/synvoid-ipc/src/**
crates/synvoid-ipc/tests/**
```

Run:

```bash
cargo check -p synvoid-ipc --all-targets
```

If `sha2` is only used in tests, add it under `[dev-dependencies]`.
If `sha2` is used in production source, add it under `[dependencies]`.

Acceptance:

```bash
cargo check -p synvoid-ipc --all-targets
```

### Task WGH-C02: add missing sha2 dependency to synvoid-ipc

Target file:

```text
crates/synvoid-ipc/Cargo.toml
```

Likely patch:

```toml
[dev-dependencies]
sha2 = "0.10"
```

Only add production dependency if confirmed required outside tests.

Acceptance:

```bash
cargo check -p synvoid-ipc --all-targets
cargo test -p synvoid-ipc --no-run
```

## 8. Wave D: fix admin-ui compile blockers narrowly

Purpose: make admin-ui compile as part of workspace checks without redesigning the UI.

### Task WGH-D01: inventory admin-ui errors

Run:

```bash
cargo check -p admin-ui --all-targets
```

Update:

```text
plans/admin_ui_workspace_fix.md
```

Record:

```text
Error code | File | Line | Cause | Minimal fix | Notes
```

Expected prior classes:

```text
E0277
E0282
E0609
missing `tempfile`
missing `sha2`
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

No source changes except the inventory note.

### Task WGH-D02: add missing admin-ui dev/test dependencies

Target file:

```text
admin-ui/Cargo.toml
```

Only add dependencies confirmed by WGH-D01.

Likely additions:

```toml
[dev-dependencies]
tempfile = "3"
sha2 = "0.10"
```

If the imports are in production source rather than tests, use `[dependencies]` instead and document why.

Acceptance:

```bash
cargo check -p admin-ui --all-targets
```

### Task WGH-D03: fix admin-ui type/field errors narrowly

Target files:

```text
admin-ui/src/**
```

Patch only the reported type errors.

Common fixes:

```text
- Add explicit type annotation where inference fails.
- Update renamed API field names after backend/schema refactors.
- Borrow/clone where Yew properties require owned values.
- Fix component prop mismatch.
```

Do not redesign components.

Acceptance:

```bash
cargo check -p admin-ui --all-targets
cargo check --workspace --all-targets
```

If workspace still fails elsewhere, admin-ui should no longer be in the failure set.

## 9. Wave E: fix synvoid-mesh test compile errors

Purpose: make mesh tests compile without changing mesh architecture.

### Task WGH-E01: inventory synvoid-mesh test failures

Run:

```bash
cargo check -p synvoid-mesh --all-targets --features mesh
```

or, if features differ:

```bash
cargo test -p synvoid-mesh --no-run --features mesh
```

Update:

```text
plans/mesh_test_compile_fix.md
```

Record:

```text
Error code | Test/file | Cause | Minimal fix | Notes
```

Acceptance:

```bash
cargo check -p synvoid-mesh --features mesh
```

No source changes except the inventory note.

### Task WGH-E02: patch mesh tests narrowly

Patch only test/build-target failures.

Likely categories:

```text
- stale imports after crate extraction
- renamed config/type paths
- missing feature gate in test module
- async test helper signature mismatch
- moved YARA/upload/proxy/http type paths
```

Do not refactor mesh transport or Raft.

Acceptance:

```bash
cargo check -p synvoid-mesh --all-targets --features mesh
cargo test -p synvoid-mesh --no-run --features mesh
```

## 10. Wave F: root upload import directness cleanup

Purpose: reduce remaining compatibility-shim import debt after dead upload files were removed.

This is not required for correctness but improves ownership clarity.

### Task WGH-F01: inventory `crate::upload::submodule` imports

Run:

```bash
rg -n "crate::upload::(yara_scanner|malware_scanner|rate_limit|sandbox|config|metrics|signature|yara_rule_feed)" src crates
```

Update:

```text
plans/security_scanner_ownership.md
```

Record:

```text
File | Current import | Replacement import | Safe to change? | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task WGH-F02: replace submodule imports with synvoid_upload imports

Patch internal live code only.

Examples:

```rust
use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};
```

becomes:

```rust
use synvoid_upload::yara_scanner::{YaraRulesSource, YaraScanner};
```

Also replace:

```text
crate::upload::malware_scanner::MalwareScanner
crate::upload::rate_limit::*
crate::upload::YaraError
```

with direct `synvoid_upload` imports where possible.

Keep broad public compatibility through `crate::upload::*` if used by root orchestration.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-upload
```

## 11. Wave G: workspace green validation

Purpose: prove the previous fixes achieved the pass objective.

### Task WGH-G01: rerun full validation

Run:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check --workspace --all-targets
cargo test --workspace --no-run
```

Update:

```text
plans/next_modularization_recommendation.md
plans/workspace_all_targets_failure_inventory.md
```

Record:

```text
Command | Pass/fail | Remaining failures | Introduced by this pass? | Notes
```

Acceptance:

```text
All check commands pass, or remaining failures are documented and explicitly out of scope.
```

## 12. Wave H: HTTP/3 object-safety/readiness investigation

Only start this wave after `cargo check --workspace --all-targets` is green or remaining failures are explicitly accepted as out of scope.

Purpose: decide whether `src/http3/server.rs` can be decoupled further without a broad rewrite.

### Task WGH-H01: inspect `Http3RequestWaf` trait object-safety

Find the trait definition, likely in:

```text
crates/synvoid-http/src/http3_request_dispatch.rs
```

Inspect whether it has:

```text
- generic methods
- `async fn` without async-trait/object-safe wrapper
- methods returning `Self`
- associated types that prevent `dyn` usage
- `Sized` bounds
```

Create:

```text
plans/http3_request_waf_object_safety.md
```

Record:

```text
Trait method | Object-safe? | Reason | Possible fix | Notes
```

Acceptance:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

Do not change source in this task except the inventory.

### Task WGH-H02: choose HTTP3 decoupling strategy

Update:

```text
plans/http3_request_waf_object_safety.md
plans/http3_server_dependency_inventory.md
```

Choose one:

```text
A. Use `Arc<dyn Http3RequestWaf>` if object-safe.
B. Make `Http3Server<W>` generic over Waf type if object safety is poor but generic propagation is small.
C. Create a thin object-safe adapter trait if `Http3RequestWaf` itself should remain generic.
D. Defer — not worth moving HTTP3 server yet.
```

Default bias:

```text
Prefer C over B if generic propagation reaches many root/server/worker call sites.
Prefer D if HTTP3 is not a frequent edit path and compile-time data says it is cheap.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task WGH-H03: implement only if strategy A is trivial

If WGH-H02 chooses strategy A and the change is small, update `src/http3/server.rs` to store/use:

```rust
Arc<dyn Http3RequestWaf<...> + Send + Sync>
```

or an equivalent object-safe type.

If associated types make that ugly, do not implement. Document strategy C instead.

Acceptance if implemented:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
cargo check --workspace --all-targets
```

Stop condition:

If this starts touching root worker/server construction broadly, revert and document deferral.

## 13. Recommended task order

Use this order:

```text
WGH-A01  reproduce workspace-all-targets failures
WGH-B01  inspect myapp-dynamic ownership and failure
WGH-B02  fix E0507 in myapp-dynamic narrowly
WGH-C01  confirm synvoid-ipc sha2 usage scope
WGH-C02  add missing sha2 dependency to synvoid-ipc
WGH-D01  inventory admin-ui errors
WGH-D02  add missing admin-ui dependencies if confirmed
WGH-D03  fix admin-ui type/field errors narrowly
WGH-E01  inventory synvoid-mesh test failures
WGH-E02  patch mesh tests narrowly
WGH-F01  inventory crate::upload::submodule imports
WGH-F02  replace submodule imports with synvoid_upload imports
WGH-G01  rerun full validation
WGH-H01  inspect Http3RequestWaf object-safety
WGH-H02  choose HTTP3 decoupling strategy
WGH-H03  implement only if strategy A is trivial
```

## 14. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid workspace-green / HTTP3 readiness task WGH-XX from plans/workspace_green_and_http3_readiness.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code unless this task explicitly allows it. Prefer compiler-error-driven fixes and direct imports from extracted crates. Do not change IPC wire names or compatibility shims. Run the task acceptance commands and report exact failures.
```

## 15. Success criteria

This pass is successful when:

```text
1. `cargo check --workspace --all-targets` passes, or remaining failures are explicitly documented as out of scope.
2. `myapp-dynamic` example compile failure is fixed or classified obsolete.
3. `synvoid-ipc` test dependency issue is fixed.
4. `admin-ui` compile blockers are fixed or tightly documented.
5. `synvoid-mesh` test compile blockers are fixed or tightly documented.
6. Internal upload submodule imports are direct to `synvoid_upload` where practical.
7. HTTP3 `Http3RequestWaf` object-safety/readiness is understood and documented.
8. No broad architecture movement occurs before validation is green.
```
