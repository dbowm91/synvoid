# Phase 120 Closeout — Sandbox Guarantee Boundary Split

Plan: `plans/phase_120_sandbox_guarantee_boundary_crate_split.md`.
Date: 2026-10-02.
Disposition: **CLOSED RETAIN**. No module or runtime contract moved.

## Feasibility evidence

The public guarantee vocabulary, planning, backend contract and platform
implementations are co-located in `crates/synvoid-platform/src/sandbox.rs`.
The platform dispatcher selects private `crate::sandbox::{linux,capsicum,
pledge,windows,darwin}` backends. The production jail consumer calls
`synvoid_platform::{jail_guarantee_request, prepare_sandbox, EnteredSandbox}`
in `crates/synvoid-jail-runtime/src/sandbox_entry.rs`.

`landlock` and `seccompiler` are Linux-only platform dependencies; Windows
Job Object support is likewise target-scoped. The platform crate also owns
unrelated process, socket, IPC, service, and Wintun operations. A split could
move sandbox-only target dependencies but would relocate a large multi-platform
surface and require new native enforcement lanes. No dependency-tree or consumer
evidence in this phase demonstrated that the new crate would reduce unrelated
platform reachability enough to justify that extra owner.

## Verification and status

Executed on Linux:

- `cargo test -p synvoid-platform --profile ci` — passed, including sandbox
  guarantee conformance, no-downgrade and Linux enforcement tests.
- `cargo test -p synvoid-jail-runtime --profile ci` — passed, including the
  packaged YARA jail load/scan/unload round trip and jail-kind rejection cases.
- `cargo test -p synvoid-jail-protocol --profile ci` — passed (20 unit tests).

Linux native tests are not evidence for macOS/Windows native enforcement. No
support tier was changed; external sandbox extraction remains DEFER. Phase 121
and Phase 122 remain eligible, and Phase 123 must include this RETAIN decision.
