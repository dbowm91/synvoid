# Phase 84 Plan: Process Sandbox Requalification and Extraction-Readiness Closeout

Status: planned (2026-09-26).

Roadmap: `plans/process_sandbox_corrective_extraction_readiness_roadmap.md`.

Depends on: Phases 81-83.

Primary goal: prove the corrected sandbox boundary end to end, reconcile every current security claim, and decide whether the application-neutral policy/self-confinement layer is mature enough to extract from SynVoid.

This phase does not publish a crate or create another repository.

## Workstream A — Recompute the backend guarantee matrix

Build the matrix from native evidence, not intended behavior.

For each supported OS/backend record:

- mechanism(s);
- minimum/runtime requirement;
- filesystem guarantees;
- network guarantees;
- child creation versus descendant confinement;
- exec guarantee;
- process/thread scope;
- resource limits;
- inherited-resource semantics;
- support tier;
- native test host/OS/kernel version;
- exact unsupported/degraded cases.

The matrix must be generated/reviewed against `EnforcementReport` vocabulary so docs and code cannot use different meanings.

## Workstream B — Jail end-to-end qualification

For WASM and YARA jail binaries verify:

- inherited stdio handshake after sandbox entry;
- allowed workload round trip;
- no unlisted filesystem access;
- no new external network access when required;
- child/exec denial where required;
- timeout/quarantine/restart path;
- parent EOF causes child exit;
- shutdown reaps the child;
- missing required guarantee aborts before handshake;
- test-only no-sandbox hatch remains unreachable from production spawn construction.

Keep protocol framing/version behavior unchanged unless a real protocol defect is found; this campaign is sandbox enforcement, not jail RPC redesign.

## Workstream C — No-silent-downgrade adversarial tests

Add deterministic fake-backend tests for:

- capability probe says present but installation fails;
- prepare succeeds but entry fails;
- partial enforcement of one required guarantee;
- optional guarantee unsupported;
- thread-scope mismatch;
- backend resource guard dropped unexpectedly;
- nested/repeated sandbox entry;
- conflicting allow/deny policy;
- unsupported explicit deny under an allowed Landlock ancestor;
- Windows outer-job conflict;
- disabled/old Landlock ABI;
- seccomp install failure.

Every required-path case must fail closed.

## Workstream D — Dependency and footprint audit

Record before/after for at least:

- `synvoid-platform` dependency graph;
- Linux target dependencies;
- default/minimal release binary size;
- jail binary sizes individually;
- cold/check build impact where meaningful;
- target packaging requirements.

Specific decisions to record:

- safe `landlock` crate adopted or rejected and why;
- `seccompiler` adopted or rejected and why;
- `capsicum` crate adopted or rejected and why;
- any Windows binding version change;
- no unexpected system-library requirement.

Do not reject a security-correct abstraction solely for a small measured size increase; do reject unexplained/broad dependency growth when a narrower mechanism exists.

## Workstream E — Unsafe/FFI audit

Review all sandbox unsafe blocks.

Require:

- generated/safe bindings where practical;
- local SAFETY comments for remaining FFI/syscalls;
- explicit pointer/handle/fd ownership;
- no raw handle/fd leak used as lifetime management;
- no lossy path conversion at an OS security boundary;
- no host-global side effect hidden behind process-sandbox terminology.

## Workstream F — Documentation reconciliation

Update current binding/current-state docs:

- `docs/SANDBOXING.md`;
- `architecture/platform.md`;
- `architecture/platform_deep_dive.md`;
- `architecture/sandbox_jail_protocol.md`;
- `architecture/overview.md` documentation map if a new binding doc is added;
- `.opencode/skills/sandboxing/SKILL.md`;
- `AGENTS.md` sandbox facts where needed;
- public/reuse classification docs.

Create `architecture/process_sandbox_corrective_closeout.md` with:

- baseline and implementation SHAs;
- defect/root-cause table;
- before/after guarantee matrix;
- native evidence;
- dependency/footprint delta;
- residual risks;
- final extraction decision.

Historical Phase 46/48 evidence remains preserved but current docs must state that this campaign supersedes their backend-correctness conclusion where applicable.

## Workstream G — Extraction boundary audit

Evaluate whether the corrected code now has a clean standalone seam.

The candidate standalone scope is intentionally narrow:

- portable guarantee/policy types;
- policy validation/intersection if present;
- backend capability probing/lowering;
- prepare/enter self-confinement lifecycle;
- enforcement reporting;
- inherited/preopened resource description;
- native backends.

Explicitly exclude from a candidate extraction:

- SynVoid config types;
- jail IPC protocol;
- supervisor/restart policy;
- WASM/YARA services;
- metrics registry;
- mesh/admin/WAF policy;
- binary resolution.

Check dependency direction: the candidate boundary must not depend on root `synvoid`, `synvoid-config`, `synvoid-ipc`, `synvoid-jail-runtime`, or application domain crates.

## Workstream H — Extraction decision

Record one disposition:

### GO_EXTRACT

Use only if:

- backend/API semantics are application-neutral;
- Linux native evidence is strong;
- unsupported platforms fail/report truthfully;
- at least two independent SynVoid call sites consume the generic boundary without SynVoid-specific branches;
- dependency footprint is acceptable;
- no unstable application policy remains embedded;
- support/MSRV/licensing/repository metadata requirements are understood.

If GO_EXTRACT, register a new later plan for extraction/migration. Do not perform it in Phase 84.

### DEFER

Use if:

- only the jail meaningfully consumes the new contract;
- Windows launch semantics still dominate the API design;
- BSD/native evidence is unavailable;
- the guarantee vocabulary is still changing materially;
- extraction would merely move files without reducing maintenance authority.

Record concrete re-evaluation triggers.

### RETAIN_INTERNAL

Use only if research shows the boundary is intrinsically SynVoid-specific or another maintained crate now provides the same self-confinement/BSD/guarantee-report capability sufficiently.

## Workstream I — Plan/status reconciliation

At closeout:

- mark Phases 81-84 with implementation/evidence SHAs;
- update `plans/roadmap.md`;
- ensure no plan claims backend support stronger than current docs;
- add any residual future plan only when it has an owner/trigger;
- leave no ambiguous "planned" status for completed work.

## Verification

At minimum:

    cargo fmt --all -- --check
    cargo xtask test guards
    cargo xtask verify
    cargo xtask verify-full
    cargo xtask verify-release
    cargo deny check
    cargo audit
    cargo check --no-default-features
    cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz
    cargo test --workspace --doc --profile ci

Plus all platform-native sandbox suites and the jail end-to-end enforcement matrix.

## Acceptance criteria

- current documentation and `EnforcementReport` agree exactly;
- no old "Strict == read allowlist" claim remains as the authoritative security model;
- native evidence exists for every platform marked supported;
- unsupported/partial required enforcement always fails closed;
- jail round trips pass under the actual native confinement mechanisms;
- dependency/footprint and unsafe-boundary deltas are recorded;
- no host-global ACL mutation remains in process-sandbox code;
- historical evidence is preserved but superseded clearly where necessary;
- `architecture/process_sandbox_corrective_closeout.md` records GO_EXTRACT, DEFER, or RETAIN_INTERNAL with evidence;
- no crate/repository is published or created implicitly by this phase.
