# CLI Command Dispatch Corrective Pass — Iteration 102

## Purpose

Iteration 101 successfully extracted broad command-dispatch logic out of `src/main.rs` into `src/commands/{plan,execute}.rs`. The shape is now correct:

- `src/main.rs` is a thin process entrypoint.
- `plan_command(&Args)` classifies CLI arguments into typed command plans.
- `execute_command(CommandPlan)` delegates to one-shot, supervisor-control, or runtime execution.
- Planner tests cover the major command classes.
- `tests/cli_command_dispatch_guard.rs` prevents `main.rs` from regrowing command implementation logic.

Review found two narrow correctness issues that should be fixed before treating Iteration 101 as fully closed:

1. `--restart` planning/execution has drifted. `SupervisorControlCommand::Restart` exists, but `plan_command()` does not classify `args.restart` into that variant. The separate `CommandPlan.restart` bool causes `execute_command()` to call `handle_stop(ca, false)` with a usually missing control address and TLS forced to `false`.
2. Missing `--hash-token` value reuses `CommandPlanError::TestModeRequiresForce`, producing misleading planner error semantics.

This corrective pass should fix those without broadening command-dispatch scope.

## Non-Goals

Do not change command names.

Do not change CLI flag names.

Do not change supervisor IPC semantics.

Do not change worker/supervisor runtime startup behavior.

Do not move runtime logic back into `src/main.rs`.

Do not add new command categories unless required by current behavior.

Do not perform the next supervisor-control API boundary phase here.

Do not change HTTP, mesh, data-plane, or request-path code.

## Current Restart Problem

Current planning shape is approximately:

```rust
pub enum SupervisorControlCommand {
    Restart { control_addr: Option<String>, use_tls: bool },
    // ...
}

pub struct CommandPlan {
    pub plan: SynvoidCommandPlan,
    pub restart: bool,
    // ...
}
```

`SynvoidCommandPlan::control_addr_for_restart()` only returns a control address when the inner plan is `SupervisorControlCommand::Restart`.

But `plan_command()` stores:

```rust
restart: args.restart,
```

and does not map `args.restart` to `SupervisorControlCommand::Restart`.

Then `execute_command()` does:

```rust
if plan.restart {
    let ca = plan.plan.control_addr_for_restart().map(|s| s.to_string());
    let _ = handle_stop(ca, false);
    std::thread::sleep(std::time::Duration::from_secs(1));
}
```

This loses both:

- `args.control_addr`; and
- `args.control_api_tls`.

It also makes the `Restart` enum variant effectively dead in normal planning.

## Desired Restart Semantics

The corrective implementation should preserve the intended historical behavior. Determine exact prior behavior from the pre-Iteration-101 `main.rs` if needed.

The likely intended behavior is:

- `synvoid --restart` is a pre-action before normal supervisor runtime launch: send stop to the existing supervisor, wait briefly, then launch supervisor runtime.
- `--restart --control-addr ... --control-api-tls` must pass both control address and TLS setting to the stop command.
- `--restart` should remain compatible with existing usage.

Do not convert restart into a pure one-shot control command unless that was the previous behavior. The code comment says restart triggers stop + sleep before runtime launch, so preserve that model unless inspection proves otherwise.

## Phase 1 — Make Restart Pre-Action Typed

Replace the loose `restart: bool` with a typed pre-action or typed restart metadata.

Preferred shape:

```rust
#[derive(Debug, Clone)]
pub enum CommandPreAction {
    RestartSupervisor {
        control_addr: Option<String>,
        use_tls: bool,
    },
}

pub struct CommandPlan {
    pub plan: SynvoidCommandPlan,
    pub pre_action: Option<CommandPreAction>,
    // ...
}
```

Then in `plan_command()`:

```rust
let pre_action = if args.restart {
    Some(CommandPreAction::RestartSupervisor {
        control_addr: args.control_addr.clone(),
        use_tls: args.control_api_tls,
    })
} else {
    None
};
```

And in `execute_command()`:

```rust
if let Some(CommandPreAction::RestartSupervisor { control_addr, use_tls }) = plan.pre_action.clone() {
    if let Err(e) = handle_stop(control_addr, use_tls) {
        eprintln!("Restart pre-stop failed: {}", e);
        return 1;
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
}
```

This removes the need for `control_addr_for_restart()`.

## Phase 2 — Decide Whether To Keep `SupervisorControlCommand::Restart`

Choose one of two clean outcomes.

### Preferred Outcome: Remove The Dead Variant

If `--restart` is a pre-action and not a standalone supervisor-control command, remove:

```rust
SupervisorControlCommand::Restart { ... }
SynvoidCommandPlan::control_addr_for_restart()
```

Also remove the unreachable `execute_supervisor_control(Restart { .. })` branch.

This is preferable if current CLI has only `--restart` and the semantics are stop-then-launch.

### Acceptable Outcome: Make The Variant Live

If the intended CLI semantics are that `--restart` should be classified as `SupervisorControlCommand::Restart`, then make `plan_command()` produce that variant and implement it as a one-shot supervisor-control command.

Do not leave both a dead variant and a separate restart bool/pre-action.

## Phase 3 — Add A Distinct Hash-Token Error

Add a dedicated planner error variant:

```rust
pub enum CommandPlanError {
    MultipleWorkerModes,
    MeshFeatureRequired,
    TestModeRequiresForce,
    MissingHashToken,
}
```

Display text should be explicit:

```rust
CommandPlanError::MissingHashToken => {
    write!(f, "--hash-token requires a token value")
}
```

Then replace the current reused error:

```rust
return Err(CommandPlanError::MissingHashToken);
```

If `hash_token` is a nested `Option<Option<String>>` because clap accepts optional values, preserve current parser semantics; only fix the error classification.

## Phase 4 — Add Planner Tests For Restart

Add tests in `src/commands/plan.rs` or an integration test if preferred.

Required cases:

```rust
#[test]
fn restart_preserves_control_addr_and_tls() {
    let mut args = default_args();
    args.restart = true;
    args.control_addr = Some("127.0.0.1:9443".to_string());
    args.control_api_tls = true;

    let plan = plan_command(&args).unwrap();

    assert!(matches!(
        plan.pre_action,
        Some(CommandPreAction::RestartSupervisor { ref control_addr, use_tls: true })
            if control_addr.as_deref() == Some("127.0.0.1:9443")
    ));
}
```

Also test default runtime still launches supervisor after restart pre-action:

```rust
#[test]
fn restart_defaults_to_supervisor_runtime_after_pre_stop() {
    let mut args = default_args();
    args.restart = true;

    let plan = plan_command(&args).unwrap();
    assert!(matches!(plan.plan, SynvoidCommandPlan::Runtime(RuntimeCommand::Supervisor)));
    assert!(matches!(plan.pre_action, Some(CommandPreAction::RestartSupervisor { .. })));
}
```

If the implementation chooses live `SupervisorControlCommand::Restart`, adapt the tests accordingly.

## Phase 5 — Add Planner Test For Missing Hash Token

Add:

```rust
#[test]
fn hash_token_without_value_reports_missing_hash_token() {
    let mut args = default_args();
    args.hash_token = Some(None);

    let result = plan_command(&args);
    assert!(matches!(result.unwrap_err(), CommandPlanError::MissingHashToken));
}
```

Keep the existing valid hash-token behavior covered if present.

## Phase 6 — Update CLI Dispatch Guard If Needed

Update:

```text
tests/cli_command_dispatch_guard.rs
```

If `restart` control logic moves into a new `CommandPreAction`, add a source guard that keeps restart handling out of `main.rs` and prevents the old broken pattern from recurring in `execute.rs`.

Suggested guard:

```rust
#[test]
fn command_dispatch_does_not_drop_restart_control_tls() {
    let root = workspace_root();
    let source = std::fs::read_to_string(root.join("src/commands/execute.rs")).unwrap();
    let non_comment = strip_comments(&source);

    assert!(
        !non_comment.contains("handle_stop(ca, false)"),
        "restart pre-stop must not force TLS=false or drop control address"
    );
}
```

If a stronger typed-source guard is easy, assert the source contains `CommandPreAction::RestartSupervisor`.

## Phase 7 — Docs Update

Update concise docs if they mention Iteration 101 command dispatch:

```text
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
architecture/root_module_ledger.md
```

Required doc note:

- restart is a typed pre-action, not a loose bool;
- control address and TLS are preserved during restart pre-stop;
- hash-token missing value has a distinct planner error.

Do not duplicate implementation details across multiple docs.

## Verification Commands

Minimum:

```bash
cargo fmt
cargo check -p synvoid
cargo test -p synvoid commands::plan
cargo test --test cli_command_dispatch_guard
```

Recommended broader guard checks:

```bash
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test unified_worker_composition_root_guard
cargo test --test data_plane_composition_boundary_guard
cargo test --test http_request_pipeline_boundary_guard
```

Feature checks:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-mesh --features mesh
```

If unrelated failures exist, document exact error text and confirm the targeted planner/guard tests pass.

## Acceptance Criteria

This pass is complete when:

- restart planning no longer uses a loose bool that drops control address or TLS;
- restart pre-stop passes both `control_addr` and `control_api_tls` into `handle_stop()`;
- `SupervisorControlCommand::Restart` is either removed as dead shape or made live by planning;
- missing hash token reports a dedicated planner error;
- planner tests cover restart address/TLS preservation and missing hash token;
- guard tests prevent the old `handle_stop(ca, false)` pattern from recurring;
- `src/main.rs` remains thin;
- command behavior is otherwise unchanged.

## Expected Files To Touch

Likely:

```text
src/commands/plan.rs
src/commands/execute.rs
tests/cli_command_dispatch_guard.rs
architecture/cli_supervisor_command_dispatch.md
AGENTS.md
```

Possibly:

```text
architecture/root_module_ledger.md
src/commands/mod.rs
```

Avoid touching:

```text
src/main.rs
crates/synvoid-http/**
crates/synvoid-http3/**
src/worker/unified_server/**
crates/synvoid-mesh/**
```

`src/main.rs` should already be thin; only touch it if a compile fix is unavoidable.

## Handoff Summary

Iteration 101 achieved the architectural extraction, but restart and hash-token planner details need correction. Iteration 102 should keep scope narrow: replace loose restart bool handling with a typed pre-action or live restart command, preserve control address/TLS during restart pre-stop, add a dedicated missing-hash-token error, and guard against the old broken pattern.
