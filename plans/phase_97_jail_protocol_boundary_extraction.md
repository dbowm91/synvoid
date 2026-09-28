# Phase 97 Plan: Jail Protocol Boundary Extraction

Status: planned/open.

Registered in: plans/roadmap.md and plans/architecture_maintenance_auditability_roadmap.md.

Baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2; execute after Phase 96 lands.

Depends on: Phase 96 dependency-direction guard baseline.

## Goal

Extract the versioned sandbox-jail wire contract into a low-capability leaf crate so the child runtime no longer depends on the full supervisor/process IPC implementation.

This phase must preserve the SVJL v1 wire format, sandbox ordering, restart/fail-closed semantics, dedicated binary behavior, and packaging capability exactly.

## Current-head boundary

Today synvoid-ipc owns:

- generic supervisor/worker IPC and signing;
- process manager/worker types and socket paths;
- jail executable resolution;
- jail process supervision/restart handling;
- jail wire DTOs, bounds, validation, framing, typed errors, digest helpers, isolation policy, and jail observability counters.

synvoid-jail-runtime depends on synvoid-ipc despite requiring only the child-facing protocol/service contract plus the framed serve loop surface.

The existing golden-vector tests explicitly require a JAIL_PROTOCOL_VERSION bump for wire-semantic changes. This extraction should require no bump.

## Workstream A — create synvoid-jail-protocol

Add crates/synvoid-jail-protocol as an internal workspace crate.

It should own only protocol-level concerns:

- JAIL_MAGIC and JAIL_PROTOCOL_VERSION;
- protocol size/count/time/resource bounds that are validated on both sides;
- JailKind and hook-capability vocabulary;
- JailOperation, JailOutput, request/response/result/error DTOs;
- typed protocol error codes/errors used at the boundary;
- request/response validation;
- frame encode/decode and bounded read/write framing;
- SHA-256 digest helpers required to bind transferred artifacts;
- IsolationPolicy and other wire/policy vocabulary that is not process-manager state.

Keep the dependency set deliberately small. Expected dependencies are serde/serde_bytes, postcard, sha2/hex if required by existing helpers, thiserror, and std. Do not add Tokio, synvoid-config, synvoid-platform, synvoid-metrics, TLS, process management, plugin runtime, YARA engine, or root SynVoid.

## Workstream B — keep parent supervision in synvoid-ipc

Do not move these merely because they mention jails:

- JailHandle and restart/quarantine logic;
- JailSpawnSpec/JailHandleConfig if they are parent process state rather than wire vocabulary;
- dedicated binary lookup and verification;
- child process spawning/reaping;
- parent observability integration;
- supervisor/process-manager wiring.

Refactor synvoid-ipc to depend on synvoid-jail-protocol and re-export the existing jail protocol names from synvoid_ipc where this is acyclic and preserves current internal call sites.

If a type currently mixes wire data and parent runtime state, split it before moving rather than pulling process-management dependencies into the protocol crate.

## Workstream C — move child runtime to the protocol leaf

Change synvoid-jail-runtime to consume synvoid-jail-protocol directly for:

- request/response DTOs;
- framing;
- validation;
- constants/version;
- typed protocol errors.

The child runtime must no longer depend on synvoid-ipc after the move unless an independently justified non-protocol requirement is found. Such a residual blocks Phase 97 closeout until it is documented and narrowed.

Dedicated binaries continue to print the same jail runtime version and protocol v1.

## Workstream D — separate protocol counters from protocol semantics

The current jail protocol module also owns process counters via std atomics.

Do not make observability state part of the new wire crate unless it is purely protocol-local and both sides genuinely need it.

Preferred direction:

- protocol crate: no global runtime counters;
- synvoid-ipc parent supervision: parent lifecycle/restart/failure counters;
- synvoid-jail-runtime: child-only stderr/logging or narrow child counters if needed;
- existing metric names/operator-visible semantics preserved by adapters.

## Workstream E — wire compatibility proof

Move or duplicate only test ownership, never implementation semantics.

Required proof:

1. v1 golden request vectors are byte-identical before/after;
2. v1 golden response vectors are byte-identical;
3. unknown magic/version rejection is unchanged;
4. every length/count/resource bound is unchanged;
5. malformed/truncated/oversized frame behavior is unchanged;
6. digest mismatch behavior is unchanged;
7. WASM load/invoke/unload round trip remains identical;
8. YARA load/scan/unload round trip remains identical;
9. timeout/quarantine/restart-budget behavior in synvoid-ipc is unchanged;
10. required-isolation failure remains fail closed before workload service.

JAIL_PROTOCOL_VERSION stays 1. A required version bump means this phase has changed scope and must stop for a separate protocol-change plan.

## Workstream F — package/release and guard updates

Update:

- workspace membership and release-order documentation;
- architecture/sandbox_jail_protocol.md;
- crate granularity audit/current authority;
- jail runtime docs/comments that currently say protocol lives in synvoid-ipc;
- repo guards so synvoid-jail-protocol cannot gain root/config/platform/runtime-engine dependencies;
- package verification so both dedicated jail binaries remain shipped exactly as before.

The new crate remains internal; no crates.io/public support promise is created.

## Verification

At minimum:

    cargo test -p synvoid-jail-protocol --profile ci
    cargo test -p synvoid-ipc --profile ci
    cargo test -p synvoid-jail-runtime --profile ci
    cargo test --test jail_isolation_guard --profile ci
    cargo xtask test guards
    cargo check --no-default-features --profile ci
    cargo xtask verify
    cargo xtask verify-release

Run the existing real WASM/YARA jail round-trip tests that cross the process boundary.

## Acceptance criteria

- synvoid-jail-protocol is a low-capability leaf with a strict dependency budget.
- synvoid-jail-runtime no longer imports the broad synvoid-ipc crate for wire semantics.
- synvoid-ipc remains the parent supervision/process owner and provides compatibility re-exports where useful.
- SVJL v1 wire bytes and all bounds are unchanged.
- Dedicated binary names, lookup, packaging, sandbox entry, and failure semantics are unchanged.
- No feature capability or runtime fallback is removed.
- Release verification remains green.

## Rejection criteria

Reject the phase if it:

- moves process spawning/restart management into the protocol crate;
- adds Tokio/platform/config/TLS/engine dependencies to the protocol leaf;
- changes serialized bytes while retaining protocol v1;
- weakens any size/resource bound;
- changes required isolation to fail open;
- removes dedicated binaries or legacy compatibility shims as a shortcut;
- promotes the new crate publicly.
