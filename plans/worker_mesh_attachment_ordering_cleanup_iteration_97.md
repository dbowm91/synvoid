# Worker Mesh Attachment Ordering Cleanup — Iteration 97

## Purpose

Iteration 96 successfully polished `mesh_attachment.rs` into helper phases. The module now has the right local shape:

- `attach_mesh()` is a thin orchestration wrapper;
- `create_mesh_pipeline()` owns pipeline creation and critical task registration;
- `send_ready_if_deferred()` deduplicates required-mesh ready signaling;
- `start_required_mesh()` owns required startup;
- `spawn_optional_support_registration()` owns optional support-registration one-shot spawning;
- `spawn_optional_mesh_startup()` owns optional mesh startup one-shot spawning;
- `await_optional_mesh_startup()` owns the optional startup/degradation race loop.

However, review of the Iteration 96 commit found two small cleanup items:

1. The optional mesh path now transitions mesh status to `starting` after spawning the optional one-shot tasks. Pre-polish behavior transitioned to `starting` before spawning those tasks. Restore the original ordering.
2. `RequiredMeshStartInput` carries a `mesh_status` field, but `start_required_mesh()` ignores it and re-clones `input.state.mesh_status`. Remove the redundant field or use it consistently.

This is a narrow corrective cleanup pass. Do not expand scope.

## Non-Goals

Do not move ownership out of `mesh_attachment.rs`.

Do not rename `attach_mesh()`.

Do not alter required/optional mesh semantics.

Do not change support task registration timing relative to mesh startup success.

Do not change readiness behavior except restoring pre-polish optional status-transition ordering.

Do not change shutdown executor behavior.

Do not change mesh transport internals.

Do not add dependencies.

## Current Ordering Concern

The current optional branch in `attach_mesh()` is shaped approximately like this:

```rust
let mut registry = input.state.task_registry.lock().await;
let support_rx = spawn_optional_support_registration(input.state, input.support_tasks, &mut registry);

let (startup_complete_tx, startup_complete_rx) = tokio::sync::oneshot::channel();
spawn_optional_mesh_startup(
    &mut registry,
    mesh_transport,
    event_tx,
    support_rx,
    startup_complete_tx,
);
drop(registry);

{
    let mut s = mesh_status.write().await;
    s.transition_starting();
}

let (output, decision_rx) = await_optional_mesh_startup(...).await;
```

Pre-polish behavior transitioned status to starting before spawning the optional one-shot tasks. The post-polish code should restore that sequence.

## Desired Ordering

The optional branch should become:

```rust
{
    let mut s = mesh_status.write().await;
    s.transition_starting();
}

let mut registry = input.state.task_registry.lock().await;
let support_rx = spawn_optional_support_registration(input.state, input.support_tasks, &mut registry);

let (startup_complete_tx, startup_complete_rx) = tokio::sync::oneshot::channel();
spawn_optional_mesh_startup(
    &mut registry,
    mesh_transport,
    event_tx,
    support_rx,
    startup_complete_tx,
);
drop(registry);

let (output, decision_rx) = await_optional_mesh_startup(...).await;
```

This keeps the helper decomposition while restoring the pre-polish status sequencing.

## Phase 1 — Restore Optional `transition_starting()` Ordering

Edit:

```text
src/worker/unified_server/mesh_attachment.rs
```

Inside the optional branch of `attach_mesh()`:

- move the `mesh_status.write().await.transition_starting()` block before acquiring the task registry and before calling `spawn_optional_support_registration()`;
- keep `drop(registry)` before awaiting `await_optional_mesh_startup()`;
- do not move required-mesh status behavior.

### Required Result

The optional path must satisfy this order:

1. `s.transition_starting()`;
2. `spawn_optional_support_registration(...)`;
3. `spawn_optional_mesh_startup(...)`;
4. `drop(registry)`;
5. `await_optional_mesh_startup(...)`.

## Phase 2 — Clean Up `RequiredMeshStartInput::mesh_status`

Currently `RequiredMeshStartInput` includes:

```rust
mesh_status: Arc<tokio::sync::RwLock<crate::worker::mesh_supervision::WorkerMeshStatus>>,
```

but `start_required_mesh()` does:

```rust
let mesh_status = input.state.mesh_status.clone();
```

Choose one of two options.

### Preferred Option: Use The Field

Update `start_required_mesh()` to use:

```rust
let mesh_status = input.mesh_status.clone();
```

This keeps the input struct explicit and consistent with `OptionalMeshStartInput`.

### Acceptable Option: Remove The Field

Remove `mesh_status` from `RequiredMeshStartInput` and from the `attach_mesh()` construction if the helper should simply derive it from `state`.

Do not leave an unused field.

## Phase 3 — Add/Update Guard For Optional Ordering

Update:

```text
tests/unified_worker_composition_root_guard.rs
```

Add a guard that checks the optional branch ordering in `attach_mesh()`.

Because source guards are intentionally simple, use a substring index check over `mesh_attachment.rs`:

```rust
#[test]
fn optional_mesh_marks_starting_before_spawning_one_shots() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
    ).unwrap();

    let optional_branch = source
        .split("let mut registry = input.state.task_registry.lock().await;")
        .next()
        .expect("optional branch region exists");

    let starting_idx = source
        .find("s.transition_starting();")
        .expect("transition_starting exists");
    let support_idx = source
        .find("spawn_optional_support_registration")
        .expect("optional support registration helper is called");
    let startup_idx = source
        .find("spawn_optional_mesh_startup")
        .expect("optional mesh startup helper is called");

    assert!(
        starting_idx < support_idx,
        "optional mesh must transition to starting before spawning support registration"
    );
    assert!(
        starting_idx < startup_idx,
        "optional mesh must transition to starting before spawning mesh startup"
    );
}
```

Improve the region extraction if necessary to avoid matching required-mesh `transition_starting()`. A better version can locate the optional branch by finding this anchor first:

```rust
let optional_anchor = "} else {";
```

or by locating the call sequence around `spawn_optional_support_registration` and scanning a bounded prefix.

### Safer Source Guard Shape

Recommended robust-enough implementation:

```rust
#[test]
fn optional_mesh_marks_starting_before_spawning_one_shots() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
    ).unwrap();

    let support_idx = source
        .find("let support_rx = spawn_optional_support_registration")
        .expect("optional support registration call exists");
    let startup_idx = source
        .find("spawn_optional_mesh_startup(")
        .expect("optional mesh startup call exists");

    let prefix = &source[..support_idx];
    let starting_idx = prefix
        .rfind("s.transition_starting();")
        .expect("optional branch transitions to starting before support registration");

    assert!(starting_idx < support_idx);
    assert!(starting_idx < startup_idx);
}
```

This checks that the nearest prior `transition_starting()` appears before support registration. If the required branch also contains a prior `transition_starting()`, keep the bounded region tight enough to avoid a false pass.

## Phase 4 — Add/Update Guard For Required Input Shape

Add a small guard preventing the redundant field from recurring.

If using the field:

```rust
#[test]
fn required_mesh_start_uses_explicit_mesh_status_field() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
    ).unwrap();
    let helper = extract_function_body(&source, "start_required_mesh");
    assert!(helper.contains("input.mesh_status.clone()"));
    assert!(!helper.contains("input.state.mesh_status.clone()"));
}
```

If removing the field:

```rust
#[test]
fn required_mesh_start_input_does_not_carry_unused_mesh_status() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(
        repo.join("src/worker/unified_server/mesh_attachment.rs")
    ).unwrap();
    let required_input_region = extract_struct_body(&source, "RequiredMeshStartInput");
    assert!(!required_input_region.contains("mesh_status"));
}
```

Do not add a brittle guard if the helper body extraction is unreliable. The source-level cleanup is small enough that `cargo clippy` would also catch the unused field if warnings are elevated later.

## Phase 5 — Verify No Semantics Drift

Inspect `mesh_attachment.rs` after the edit and confirm:

- required mesh still transitions to starting before `start_mesh_generation()`;
- required mesh still sends ready only after startup and support registration success;
- optional mesh now transitions to starting before spawning optional one-shots;
- support registration still occurs in the same one-shot helper;
- optional startup/degradation race loop remains in `await_optional_mesh_startup()`;
- `SupportStopContext::OptionalMeshDegraded` remains only in mesh attachment;
- `SupportStopContext::WorkerShutdown` remains only in shutdown executor.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test --test unified_worker_composition_root_guard
```

Recommended additional checks:

```bash
cargo test --test worker_mesh_supervision_boundary_guard --features mesh,dns
cargo test --test worker_supervision_control_flow --features mesh,dns
cargo test --test composition_root_behavioral --features mesh,dns
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
```

Feature/package checks:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh,dns
```

If a known unrelated feature-check failure still exists, document the exact error and verify the targeted tests pass.

## Acceptance Criteria

This cleanup is complete when:

- optional mesh status transitions to starting before optional support/startup one-shot tasks are spawned;
- `RequiredMeshStartInput` no longer contains an ignored field;
- `attach_mesh()` remains under the guard threshold and still delegates to helpers;
- guard tests cover the restored optional ordering;
- no shutdown executor changes are needed;
- all targeted checks pass or unrelated existing failures are documented.

## Expected Files To Touch

Likely:

```text
src/worker/unified_server/mesh_attachment.rs
tests/unified_worker_composition_root_guard.rs
```

Possibly:

```text
tests/worker_mesh_supervision_boundary_guard.rs
```

Avoid touching:

```text
src/worker/unified_server/startup_plan.rs
src/worker/unified_server/shutdown_executor.rs
src/worker/unified_server/supervision_loop.rs
crates/synvoid-mesh/**
```

## Handoff Summary

Iteration 96 delivered the right helper decomposition. Iteration 97 should make a narrow corrective pass: restore pre-polish optional mesh status ordering and remove redundant helper input shape. Keep the mesh attachment boundary intact and behavior otherwise unchanged.
