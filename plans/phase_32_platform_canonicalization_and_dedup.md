# Phase 32 Plan: Platform Canonicalization and Duplicate-Source Removal

Status: complete (2026-09-16).

Roadmap: `plans/crate_boundary_reuse_followup_roadmap.md`.

Primary goal: make `crates/synvoid-platform` the single compiled owner of reusable OS/platform primitives and remove the current duplicate implementation copies under `src/platform` without pulling SynVoid application policy into the library crate.

## Current problem

The architecture ledger describes `synvoid-platform` as the canonical owner of platform primitives, but the source tree still contains parallel implementations in both locations. Examples include `process.rs` and `ipc.rs`, which are materially the same code with only root-vs-crate import differences. The crate also contains `service/`, `socket.rs`, `unix.rs`, and Windows implementations that are not currently declared from `synvoid-platform/src/lib.rs`, while the root package compiles its own counterparts.

This creates three risks:

1. fixes can land in one copy and not the other;
2. the documented crate boundary does not match compiled ownership;
3. downstream crates cannot reliably consume the supposedly canonical platform surface.

This phase corrects ownership before adding any new platform functionality.

## Part A — Build an exact duplicate/disposition matrix

Compare every file under:

```text
src/platform/
crates/synvoid-platform/src/
```

Classify each pair as one of:

- byte/semantic duplicate -> crate canonical, root becomes re-export;
- generic implementation with small root-specific dependency -> parameterize/inject dependency and move canonical implementation to crate;
- genuine SynVoid application composition -> keep root-owned and document why;
- stale/dead -> remove after consumer verification.

At minimum cover:

- `ipc.rs`;
- `process.rs`;
- `socket.rs`;
- `service/`;
- `unix.rs`;
- `windows.rs` / `windows_impl.rs` / Windows submodules;
- sandbox facade/backend ownership;
- filesystem/path helpers.

Record the resulting ownership table in `architecture/platform.md` or a dedicated current architecture note, and reconcile `architecture/root_module_ledger.md`.

## Part B — Activate canonical crate modules

Wire the generic modules from `crates/synvoid-platform/src/lib.rs` rather than leaving source files dormant.

Target shape should be approximately:

```rust
pub mod fs;
pub mod ipc;
pub mod process;
pub mod sandbox;
pub mod service;
pub mod socket;
pub mod socket_bind;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows_impl;
```

Exact visibility may differ where implementation modules should remain private, but public traits/types should be reachable from `synvoid_platform` through stable module or top-level re-export paths.

Do not expose raw OS implementation details merely because the source files become canonical.

## Part C — Resolve crate dependency requirements without recreating application coupling

For every generic implementation currently justified as root-owned because it uses `nix`, Tokio, metrics, or another package, determine whether that dependency is actually intrinsic.

Rules:

- OS syscall wrappers may add target-scoped dependencies to `synvoid-platform` when that is the natural owner.
- Async/application orchestration does not move merely to eliminate root code.
- Metrics emission should normally be injected or kept at the caller rather than forcing `synvoid-metrics` into low-level platform primitives.
- SynVoid configuration types must not become dependencies of `synvoid-platform`.
- `synvoid-ipc` must remain above `synvoid-platform`; do not create a `platform -> ipc -> platform` cycle. If the current manifest/doc graph implies such a cycle, correct the ownership/documentation rather than adding one.

Use feature gates only when they create meaningful dependency/build isolation. Avoid a feature per file if the dependency cost is negligible.

## Part D — Generalize path construction

`PlatformPaths::new()` currently embeds SynVoid names and locations such as `/var/lib/synvoid`, `/etc/synvoid`, `synvoid.pid`, and `synvoid-supervisor.sock`. That prevents the otherwise reusable platform crate from being application-neutral.

Introduce an application-aware API while preserving SynVoid compatibility. Preferred direction:

```rust
PlatformPaths::for_app("synvoid")
PlatformPaths::with_base(...)
```

or a small validated application/path policy type.

Requirements:

- reject or sanitize path separators and traversal in application identifiers;
- preserve existing SynVoid paths exactly for current callers;
- keep `with_base` deterministic for tests;
- distinguish generic path primitives from SynVoid-specific helper names such as supervisor/worker socket names;
- SynVoid-specific filenames may remain in a root/application wrapper if making them generic would create awkward APIs.

Do not silently change deployment paths.

## Part E — Collapse root platform implementation to facade/application adapters

After internal call sites use the canonical crate, replace duplicated root files with thin re-exports or delete them where the facade policy allows it.

The root may retain code only when it performs SynVoid-specific composition, such as:

- supervisor/worker policy;
- application-specific service definitions;
- application metrics around platform calls;
- root-only runtime wiring.

The root platform module must not retain a second implementation of `Signal`, `ProcessControl`, `IpcTransport`, socket ownership wrappers, service-control traits, or OS backends.

Add a repo guard that fails if known canonical platform types/traits are redefined under `src/platform`.

## Part F — Consumer migration

Migrate domain crates to direct `synvoid_platform` imports where they currently rely on root facades or private duplicate behavior.

Preserve root compatibility exports where required by `architecture/facade_disposition_matrix.md`, but new domain code must use the crate path.

Pay particular attention to:

- `synvoid-ipc`;
- `synvoid-jail-runtime`;
- `synvoid-tunnel` / VPN code;
- HTTP/socket bind paths;
- sandbox callers;
- service/install code.

## Part G — Tests

Move duplicate unit tests to the canonical crate and add parity tests for behavior that previously existed in both copies.

Required coverage:

- platform detection;
- process-liveness and graceful termination behavior where testable;
- Unix IPC bind/connect and peer behavior;
- socket reuse/bind semantics;
- secure directory permissions on Unix;
- path construction for Linux/macOS/BSD/Windows via injectable platform/path-policy helpers where practical;
- sandbox capability reporting and fail-closed behavior;
- unsupported-platform stub behavior;
- no path traversal via application identifier.

Windows/BSD-specific behavior may remain target CI/specialist coverage where host execution is unavailable, but compilation must stay gated in CI.

## Acceptance criteria

Phase 32 is complete only when:

- generic platform traits/types/backends have one source owner under `crates/synvoid-platform`;
- dormant duplicate crate modules are either compiled/canonical or deleted with rationale;
- root `src/platform` contains no duplicate generic implementations;
- no dependency cycle is introduced;
- existing SynVoid filesystem/socket paths remain compatible;
- application-neutral path construction exists for external reuse;
- `architecture/platform.md`, `root_module_ledger.md`, `root_dependency_ownership.md`, and `crate_granularity_audit.md` describe the compiled state accurately;
- platform tests run from the crate rather than relying on root duplicates;
- default and minimal SynVoid builds pass.

## Rejection criteria

Reject an implementation that:

- simply deletes crate copies and leaves root as canonical;
- moves supervisor/application policy into `synvoid-platform`;
- introduces `synvoid-config`, root `synvoid`, or broad metrics dependencies into the platform crate;
- changes operator-visible default paths;
- creates cyclic `synvoid-platform`/`synvoid-ipc` ownership;
- retains two versions of the same OS abstraction behind different public paths.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo check -p synvoid-platform --all-targets
cargo test -p synvoid-platform
cargo check -p synvoid-ipc --all-targets
cargo xtask verify
cargo xtask verify-full
cargo check --no-default-features
cargo check --no-default-features --features mesh,dns
```

Also run the repository architecture/facade guards and target compilation used by CI for Windows/macOS/BSD support where available.

## Completion record (2026-09-16)

All acceptance criteria met; all rejection criteria avoided:

- Single owner: `ipc`, `process`, `socket`, `service`, `unix`, `windows_impl`,
  and `windows/` (+ submodules) compile exactly once under
  `crates/synvoid-platform` (wired from `lib.rs`; previously dormant). Root
  `src/platform/` holds only `mod.rs` (module aliases + top-level re-exports).
- Newest fixes from either copy ported into the crate (rc.conf warn logging,
  saturating Windows timeout clamp, `mem::take` handler drain).
- `socket.rs` `bind_tcp_reuse`/`bind_udp_reuse` copies collapsed onto
  `socket_bind` (broader reuse-port cfg wins; noted in `architecture/platform.md` §12).
- Deps: target-gated `nix`/`daemonize2` (unix), `tokio` rt+signal
  (unix/Windows), `windows-sys`/`libloading`/`zip` (Windows), plus acyclic
  `synvoid-utils`. No metrics/config/root/ipc edges; `synvoid-ipc` dev-dep
  removed (handoff test rewritten against the crate surface).
- Paths: `PlatformPaths::for_app(id)` + `validate_app_id` +
  `PlatformError::InvalidAppId`; `new()` output byte-identical (tested).
- Consumers migrated: root `tls`/`http`/`worker`/`startup`/`supervisor` import
  `synvoid_platform` directly. Orphaned root manifest edges (`zip`,
  `libloading`, `windows-sys`) removed; `root_dependency_ownership.md`
  re-entitled (guard-verified).
- Tests: 32 crate tests (`socket_handoff_test`, `platform_paths_test`,
  `platform_core_test`); new `tests/platform_canonicalization_guard.rs`
  (+ `OWNERSHIP.toml` entry).
- Docs: `architecture/platform.md` (§1.1 disposition matrix, §12 notes),
  `root_module_ledger.md`, `root_dependency_ownership.md`,
  `crate_granularity_audit.md`, `AGENTS.md`, `src/platform/AGENTS.override.md`,
  `windows_service` skill, plan status.
