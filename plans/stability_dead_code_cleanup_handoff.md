# SynVoid Stability and Dead-Code Cleanup Handoff Plan

> Status: proposed next-pass handoff after measurement-driven modularization.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: fix the concrete validation blockers and remove dead duplicate code identified by the measurement/audit pass before attempting further modularization.

## 0. Why this pass exists

The recent modularization work succeeded: SynVoid is now a real multi-crate workspace with subsystem crates for WAF, proxy, HTTP helpers, static files, upload, IPC, DNS, mesh, TLS, admin, config, core, and related support crates.

The measurement pass changed the next priority. The main finding is not “create more crates.” The main findings are:

```text
1. `cargo check --no-default-features --features mesh` currently fails.
2. `cargo check --workspace --all-targets` currently fails in admin-ui.
3. Root upload contains dead duplicate files behind a one-line re-export shim.
4. Root still directly depends on yara-x, apparently only because of dead root upload files.
5. Some live call sites import upload internals through `crate::upload::...`, which is a latent hazard because root `src/upload/mod.rs` is currently just `pub use synvoid_upload::*;`.
```

This pass should improve repo health and validation reliability. Do not broaden it into another architectural refactor.

## 1. Source-of-truth prior artifacts

Use these files as context:

```text
plans/compile_time_measurements.md
plans/root_dependency_ownership.md
plans/security_scanner_ownership.md
plans/persistence_ownership.md
plans/http_server_dependency_inventory.md
plans/http3_server_dependency_inventory.md
plans/measurement_driven_modularization_cleanup.md
```

Important measurement findings:

```text
- `cargo check --lib --no-default-features` is about 19s warm.
- `cargo check --no-default-features --features mesh` fails with E0425 in `src/worker/unified_server/init_mesh.rs`.
- `cargo check --workspace --all-targets` fails in `admin-ui`.
- Dead root upload files duplicate `crates/synvoid-upload` and are not compiled because `src/upload/mod.rs` is a one-line re-export.
- Root `yara-x` direct dependency appears removable after dead upload cleanup and import correction.
```

## 2. Non-goals

Do not do these in this pass:

```text
Do not create new crates.
Do not move HTTP server.
Do not move HTTP/3 server.
Do not move WafCore.
Do not move worker or supervisor.
Do not split Raft from mesh.
Do not change IPC wire names such as PoisonImage.
Do not remove image_poisoning compatibility shims.
Do not redesign upload scanning behavior.
Do not rewrite admin-ui; fix only the compile blockers.
```

## 3. Hard constraints

1. Preserve runtime behavior.
2. Keep `src/upload/mod.rs` as a compatibility shim unless a task explicitly says otherwise.
3. Prefer direct imports from `synvoid_upload` for live code instead of `crate::upload::...` internals when referring to upload submodules.
4. Do not silently change IPC protocols, DHT keys, admin JSON fields, or config keys.
5. Remove dead files only after verifying they are not declared by a `mod` statement.
6. Remove root dependencies only after compiler validation.
7. Keep diffs narrow and task-scoped.

## 4. Validation matrix

Run task-specific checks after each task.

At the end of each wave, run:

```bash
cargo fmt
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-upload
cargo check -p synvoid-mesh --features mesh
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
```

If `admin-ui` remains intentionally broken after its task, record the exact remaining errors in the plan note. Do not claim the workspace is clean unless the command actually passes.

## 5. Wave A: fix mesh feature compile failure

Purpose: restore `cargo check --no-default-features --features mesh` so mesh/Raft and mesh-influenced hot spots can be measured again.

### Task SDC-A01: reproduce and document mesh feature failure

Do not change source code except for notes if needed.

Run:

```bash
cargo check --no-default-features --features mesh
```

Expected current failure from measurements:

```text
error[E0425]: cannot find value `backend_pool` in this scope
  src/worker/unified_server/init_mesh.rs:311

error[E0425]: cannot find value `signer_for_mesh` in this scope
  src/worker/unified_server/init_mesh.rs:313
```

Inspect:

```text
src/worker/unified_server/init_mesh.rs
```

Confirm whether the variables are bound as:

```text
_backend_pool
_signer_for_mesh
```

and later used as:

```text
backend_pool
signer_for_mesh
```

Update or create:

```text
plans/mesh_feature_compile_fix.md
```

with the exact failure and intended fix.

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task SDC-A02: fix variable binding mismatch in init_mesh

Target file:

```text
src/worker/unified_server/init_mesh.rs
```

Apply the smallest behavior-preserving fix.

Likely fix:

```text
Rename `_backend_pool` -> `backend_pool` if it is intentionally used later.
Rename `_signer_for_mesh` -> `signer_for_mesh` if it is intentionally used later.
```

Alternative:

```text
If the later code should not use them, change the later code to use the existing optional values correctly.
```

Do not restructure mesh initialization.

Acceptance:

```bash
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check --lib --no-default-features
```

### Task SDC-A03: update compile-time measurement notes after mesh fix

Update:

```text
plans/compile_time_measurements.md
```

Add a note under pre-existing failures:

```text
Mesh feature compile failure fixed in SDC-A02.
```

If possible, rerun:

```bash
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
```

and record wall times.

Acceptance:

```bash
cargo check --no-default-features --features mesh
```

## 6. Wave B: fix admin-ui workspace validation blockers

Purpose: make `cargo check --workspace --all-targets` meaningful again, or at least reduce known failures to a documented minimal set.

### Task SDC-B01: reproduce admin-ui workspace failures

Run:

```bash
cargo check --workspace --all-targets
```

Expected current failures from measurement notes:

```text
admin-ui lib + lib-test fail with 5 errors in Yew/leptos pages:
- E0277
- E0282
- E0609
- unresolved import `sha2`
- cannot find module/crate `tempfile`
```

Create:

```text
plans/admin_ui_workspace_fix.md
```

Record:

```text
Error | File | Cause | Proposed fix | Notes
```

Acceptance:

```bash
cargo check -p admin-ui
```

or, if it fails, the errors are captured in the note.

### Task SDC-B02: add missing admin-ui dependencies if confirmed

Target file:

```text
admin-ui/Cargo.toml
```

If errors confirm missing direct dependencies, add them narrowly:

```toml
tempfile = "3"
sha2 = "0.10"
```

Only add dependencies that are actually used by admin-ui source/tests.

Acceptance:

```bash
cargo check -p admin-ui
```

### Task SDC-B03: fix admin-ui type errors narrowly

Target files:

```text
admin-ui/src/**
```

Fix only the reported Yew/leptos compile errors. Do not redesign the admin UI.

Common patterns to check:

```text
- Missing type annotation for closure/state handle.
- Incorrect field name after API/schema refactor.
- Component prop type mismatch.
- Leptos/Yew signal/value mismatch.
```

Acceptance:

```bash
cargo check -p admin-ui
cargo check --workspace --all-targets
```

Stop condition:

If admin-ui errors cascade into broad UI redesign, stop after documenting exact failures in `plans/admin_ui_workspace_fix.md`.

## 7. Wave C: remove dead root upload duplicates safely

Purpose: eliminate dead duplicate upload modules and prevent future accidental import resolution to stale root files.

### Task SDC-C01: verify root upload shim status

Inspect:

```text
src/upload/mod.rs
```

Expected:

```rust
pub use synvoid_upload::*;
```

Search for root declarations:

```bash
rg -n "pub mod|mod " src/upload src/lib.rs src/main.rs
```

Confirm that root `src/upload/*.rs` files are not declared as modules.

Create/update:

```text
plans/security_scanner_ownership.md
```

Add a section:

```text
## Dead root upload duplicate deletion readiness
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check -p synvoid-upload
```

### Task SDC-C02: replace accidental `crate::upload::submodule` imports

Target files identified in `plans/security_scanner_ownership.md`:

```text
src/worker/cpu_task/yara.rs
src/worker/cpu_task/state.rs
src/static_files/file_manager.rs
possibly other `crate::upload::{malware_scanner,yara_scanner,rate_limit,...}` imports
```

Replace imports that reach through root upload submodules with direct extracted-crate imports.

Examples:

```rust
// before
use crate::upload::yara_scanner::{YaraRulesSource, YaraScanner};

// after
use synvoid_upload::yara_scanner::{YaraRulesSource, YaraScanner};
```

Also replace:

```rust
crate::upload::malware_scanner::MalwareScanner -> synvoid_upload::malware_scanner::MalwareScanner
crate::upload::rate_limit::* -> synvoid_upload::rate_limit::*
crate::upload::YaraError -> synvoid_upload::YaraError
```

Keep public `crate::upload::*` compatibility for broad callers if needed, but avoid submodule paths in internal code.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check -p synvoid-upload
cargo check --no-default-features --features mesh,dns
```

### Task SDC-C03: delete dead duplicate root upload files

Only after SDC-C01 and SDC-C02 pass.

Delete dead files if they are not declared by `src/upload/mod.rs`:

```text
src/upload/yara_scanner.rs
src/upload/malware_scanner.rs
src/upload/sandbox.rs
src/upload/yara_rule_feed.rs
src/upload/config.rs
src/upload/metrics.rs
src/upload/rate_limit.rs
src/upload/signature.rs
```

Keep:

```text
src/upload/mod.rs
```

with the compatibility re-export.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check -p synvoid-upload
cargo check --no-default-features --features mesh,dns
rg -n "src/upload/(yara_scanner|malware_scanner|sandbox|yara_rule_feed|config|metrics|rate_limit|signature)" plans src crates || true
```

Remaining references should only be historical plan notes or deleted-file inventory.

### Task SDC-C04: update dead-code audit notes

Update:

```text
plans/security_scanner_ownership.md
plans/root_dependency_ownership.md
```

Mark root upload duplicate files deleted and note that live upload code is owned by `synvoid-upload`.

Acceptance:

```bash
cargo check --workspace --all-targets
```

If workspace still fails due to admin-ui or other known issues, record that in the note instead of claiming full success.

## 8. Wave D: prune root yara-x dependency if safe

Purpose: remove a heavy root dependency that appears to be dead after root upload duplicate cleanup.

### Task SDC-D01: verify root yara-x usage after dead file deletion

Run:

```bash
rg -n "yara_x|yara-x|YaraScanner|YaraRulesSource" src Cargo.toml crates
cargo tree -p synvoid -i yara-x
```

Expected state:

```text
- No `use yara_x::...` in root `src/`.
- `yara-x` still appears through `synvoid-upload` and `synvoid-mesh`.
- Root direct dependency is no longer needed.
```

Update:

```text
plans/security_scanner_ownership.md
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task SDC-D02: remove root yara-x dependency

Target file:

```text
Cargo.toml
```

Remove from root `[dependencies]`:

```toml
yara-x = { version = "1.15", default-features = false, features = ["default-modules", "linkme"] }
```

Do not change the `wasmtime` patch in `[patch.crates-io]`; `yara-x` still exists transitively via extracted crates.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check -p synvoid-upload
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

### Task SDC-D03: update ownership matrix after yara-x removal

Update:

```text
plans/root_dependency_ownership.md
```

Change root `yara-x` from `KEEP_ROOT_FOR_NOW` to `KEEP_REMOVED`, with owners:

```text
synvoid-upload
synvoid-mesh
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

If workspace still fails due to unrelated admin-ui problems, note exact remaining failures.

## 9. Wave E: final validation and measurement refresh

Purpose: prove the cleanup improved validation and did not regress modularization.

### Task SDC-E01: rerun core validation matrix

Run:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-upload
cargo check -p synvoid-mesh --features mesh
cargo check --workspace --all-targets
```

Update:

```text
plans/compile_time_measurements.md
```

with a section:

```text
## Stability cleanup follow-up
```

Record pass/fail status and wall times if available.

Acceptance:

All commands pass, or remaining failures are explicitly documented and not introduced by this pass.

### Task SDC-E02: update next-action recommendation

Create or update:

```text
plans/next_modularization_recommendation.md
```

Recommended content:

```text
- Validation status after SDC pass.
- Whether root yara-x was removed.
- Whether mesh feature now compiles.
- Whether workspace all-targets now compiles.
- Next recommended technical pass:
  1. HTTP3 Http3RequestWaf object-safety check, or
  2. server-runtime context design, or
  3. admin/schema ownership cleanup, depending on latest validation and measurements.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 10. Recommended task order

Use this exact order:

```text
SDC-A01  reproduce and document mesh feature failure
SDC-A02  fix variable binding mismatch in init_mesh
SDC-A03  update compile-time measurement notes after mesh fix
SDC-B01  reproduce admin-ui workspace failures
SDC-B02  add missing admin-ui dependencies if confirmed
SDC-B03  fix admin-ui type errors narrowly
SDC-C01  verify root upload shim status
SDC-C02  replace accidental crate::upload::submodule imports
SDC-C03  delete dead duplicate root upload files
SDC-C04  update dead-code audit notes
SDC-D01  verify root yara-x usage after dead file deletion
SDC-D02  remove root yara-x dependency
SDC-D03  update ownership matrix after yara-x removal
SDC-E01  rerun core validation matrix
SDC-E02  update next-action recommendation
```

## 11. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid stability/dead-code cleanup task SDC-XX from plans/stability_dead_code_cleanup_handoff.md.
Scope is limited to this task. Preserve behavior. Do not create new crates. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, mesh, or proxy code. Prefer direct imports from extracted crates where ownership has moved. Do not change IPC wire names or config compatibility aliases. Run the task acceptance commands and report exact failures.
```

## 12. Success criteria

This pass is successful when:

```text
1. `cargo check --no-default-features --features mesh` passes.
2. `cargo check --workspace --all-targets` either passes or has only documented unrelated failures.
3. Dead duplicate root upload files are deleted.
4. Internal live code no longer imports upload internals through fragile `crate::upload::submodule` paths.
5. Root direct `yara-x` dependency is removed if validation proves it is unused.
6. `plans/security_scanner_ownership.md` and `plans/root_dependency_ownership.md` reflect the new state.
7. Next recommended modularization target is evidence-based.
```
