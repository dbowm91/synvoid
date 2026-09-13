# Phase 29 Plan: Jail Runtime Package and Process Split

Status: complete (2026-09-12). Landing commit: `fd10114507767b41eb40891d0b917e95dd206419`. Closure evidence: `architecture/track4_dependency_security_closeout.md`.

The body below is the executed handoff specification, preserved as historical implementation guidance.

Roadmap position: Track 4, Phase 29.

Primary goal: make WASM/YARA child execution an explicit package/process dependency boundary rather than implementation living in the root application crate, while preserving the Phase 22 IPC protocol and fail-closed supervision semantics.

## Current state

Phase 22 successfully operationalized jail execution. The wire protocol/supervision belongs primarily to `synvoid-ipc`; root `src/sandbox/` owns child-side `wasm_service.rs`, `yara_service.rs`, policy adaptation, and jail-mode entry points. This works behaviorally, but it means the root application package must compile/link child execution implementation and its heavy engines even though normal supervisor/worker processes should interact with them only through IPC.

Phase 26 removes upload-domain coupling from YARA execution first. This phase then makes the process boundary visible in Cargo/package composition.

## Target architecture

Create an explicit runtime package, tentatively `crates/synvoid-jail-runtime/`, and one or more dedicated binaries.

Preferred structure:

- `synvoid-ipc`: versioned jail protocol, framing, DTOs, parent supervision/client, limits shared across sides;
- `synvoid-jail-runtime`: child-side handler dispatch, WASM/YARA service implementations, sandbox-entry sequencing, child-only observability;
- `synvoid-yara`: YARA engine implementation from Phase 26;
- `synvoid-plugin-runtime`: WASM engine/ABI implementation consumed by the jail runtime as appropriate;
- root `synvoid`: parent policy/composition and process spawning only.

Binary options:

1. one `synvoid-jail` binary with an explicit fixed kind (`--kind wasm|yara`) accepted only as local supervisor input; or
2. separate `synvoid-wasm-jail` and `synvoid-yara-jail` binaries for the strongest dependency separation.

Prefer separate binaries if doing so materially removes YARA dependencies from the WASM jail and vice versa without duplicating supervision logic.

## Part A — Freeze the existing protocol

Before moving code, capture Phase 22 protocol behavior with golden tests:

- frame version;
- maximum frame/input/match/ruleset sizes;
- operation enums and wrong-kind rejection;
- digest verification;
- stdout framing vs stderr logs;
- parent EOF/shutdown semantics;
- timeout/crash/restart bounds;
- `IsolationPolicy::Required` fallback prohibition.

Do not alter wire semantics during the initial package move unless a protocol version bump is explicitly required.

## Part B — Extract child handlers

Move child-side implementations from root `src/sandbox/` into the jail runtime crate:

- `YaraJailService` after Phase 26 points it at `synvoid-yara`;
- WASM jail service and child-only runtime setup;
- handler dispatch loop;
- child-side policy setup that does not require root composition.

Keep root-side policy selection/adaptation in root if it depends on application config/supervisor state. Keep generic protocol DTOs/limits in `synvoid-ipc`.

The jail runtime crate must not import root `synvoid::` paths.

## Part C — Dedicated binary launch and packaging

Refactor supervisor/process launch to resolve the dedicated jail binary rather than recursively launching the main `synvoid` executable with hidden jail flags.

Requirements:

- deterministic binary path resolution for packaged installs;
- no search of current working directory or writable plugin directories;
- verify expected binary identity/version where practical;
- parent creates IPC pipes before sandbox entry;
- child receives only explicit minimal environment/argv;
- no payload/secrets in argv or environment;
- child cannot bind/connect after sandbox if current policy forbids it;
- stderr remains diagnostic only; stdout remains protocol frames;
- package/install/release scripts include the jail binary atomically with the main binary.

If compatibility requires existing `--wasm-jail` / `--yara-jail` flags temporarily, retain them only as internal forwarding shims with a removal plan and no alternate unisolated execution path.

## Part D — Dependency isolation

After split, prove the package graph matches process authority.

Desired properties:

- root/main binary no longer directly depends on YARA compiler implementation solely because it contains the child service;
- WASM jail does not link YARA when separate binaries are used;
- YARA jail does not link unrelated HTTP/mesh/admin stacks;
- jail runtime depends on `synvoid-ipc` and narrow engine crates, never supervisor/admin/mesh implementations;
- root remains the only process lifecycle authority.

Use `cargo tree` plus artifact inspection (`cargo bloat`/`nm` optional) as evidence, not as hard acceptance tools.

## Part E — Sandbox sequencing

Preserve platform sandbox entry order exactly or strengthen it.

Document and test:

1. parent opens pipes and spawns child;
2. child initializes only resources that must exist before sandbox;
3. child applies OS isolation;
4. child enters framed request loop;
5. engine operations execute only after isolation when `Required`;
6. any isolation setup failure terminates/fails closed before workload handling.

Linux should remain the primary verified target. macOS/Windows behavior must be explicitly classified as enforced, degraded, or unsupported; never silently report equivalent isolation.

## Part F — Parent supervision compatibility

Existing `JailClient`/supervision semantics must remain:

- bounded queue/request deadline;
- crash detection;
- quarantine/restart budget;
- typed protocol errors;
- no fallback to in-process execution under `Required`;
- graceful shutdown/drain ownership.

Add integration tests that launch the packaged child binary, not only in-process handler tests.

## Part G — Release/install behavior

Update release qualification and installers so the main SynVoid artifact cannot be installed with jail-required configuration while silently missing its jail binary.

Options:

- ship binaries together in one archive/package;
- startup preflight checks required helper availability/version;
- `synvoid version`/diagnostics may report jail runtime version/capability.

Release verification should inspect package/archive contents for the child binaries and prohibit accidental omission.

## Part H — Documentation/guards

Update:

- `architecture/sandbox_jail_protocol.md`;
- process/supervisor architecture docs;
- release/install docs;
- `AGENTS.md` path map;
- root module ledger (`sandbox` should shrink to parent composition/policy or a facade);
- root dependency ownership;
- crate granularity audit.

Add guards preventing child runtime from importing root/supervisor/admin/mesh implementation and preventing root reintroduction of engine implementation files.

## Acceptance criteria

Phase 29 is complete when:

- child-side WASM/YARA execution lives in an explicit non-root runtime package;
- real integration tests spawn the packaged child binary and complete load/invoke/scan/unload round trips;
- Phase 22 protocol and required-isolation fail-closed semantics are unchanged or explicitly versioned;
- root owns policy/supervision, not child engine implementation;
- release/install artifacts include and validate required helper binaries;
- dependency trees show reduced engine authority in the main application package;
- platform isolation support is documented truthfully.

## Rejection criteria

Reject an implementation that:

- copies child code into a crate but still executes it in-process in normal production paths;
- launches helpers by searching writable directories/PATH without validation;
- weakens `IsolationPolicy::Required` to preserve compatibility;
- adds generic arbitrary-exec operations to the jail protocol;
- splits binaries but leaves release/install tooling able to omit them silently;
- changes YARA/WASM semantics and process packaging simultaneously without characterization tests.

## Verification

```bash
cargo test -p synvoid-ipc --all-targets
cargo test -p synvoid-jail-runtime --all-targets
cargo test --test security_regression --profile ci -- --test-threads=1
cargo test --test failure_injection --profile ci
cargo xtask verify
cargo xtask verify-release --allow-dirty
cargo tree -p synvoid-jail-runtime
cargo tree -p synvoid
```