# Phase 121 Plan: Honeypot Standalone-Package Hardening

Status: **CLOSED DEFER — native macOS qualification unavailable** (2026-10-02).

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

Predecessor: Phase 107 CLOSED DEFER after successful packaged/outside-workspace
consumer proof and zero normal SynVoid dependencies.

## Goal

Close the concrete package-security and consumer-contract gaps identified by
Phase 107 so `synvoid-honeypot` can qualify as a standalone-capable class-2
package in the monorepo.

This phase does not create a repository or class-3 support promise.

## Workstream A — hard resource ceilings

Introduce crate-level absolute maxima for hostile-input/resource dimensions that
currently accept arbitrarily high public configuration values, including as
applicable:

- per-connection payload retention/read cap;
- writer queue capacity;
- batch size;
- concurrent connections;
- per-IP connections;
- AI prompt/response/turn/concurrency budgets;
- protocol detector input window;
- port/listener count.

Configuration above hard maxima must reject deterministically rather than clamp
silently unless an existing compatibility requirement mandates a documented
clamp.

Test integer-boundary and allocation behavior.

## Workstream B — persistence contract

Classify `HoneypotRecord` and SQLite schema:

- internal storage format versus supported consumer API;
- schema/version metadata;
- migration strategy for any persisted format intended to survive upgrades;
- corruption/failure behavior;
- busy/locking behavior;
- parent directory creation and file permission policy;
- backup/export expectations;
- encryption-at-rest non-goal unless deliberately added.

On Unix, explicitly enforce/verify intended directory/file permissions rather than
relying only on ambient umask if feasible without breaking existing deployments.
On Windows, document the actual boundary rather than claiming POSIX semantics.

Do not make a broad stable database schema promise solely to qualify packaging.

## Workstream C — hostile-input testing

Add parser/protocol property/fuzz coverage for attacker-controlled data:

- protocol detection;
- line/header parsing;
- responder input normalization;
- retained payload truncation/digest behavior;
- malformed encodings and boundary lengths.

Seed with representative HTTP/SSH/MySQL/Redis-like and random binary inputs.
No fuzz target may require network access.

Add deterministic regression fixtures for any issue found.

## Workstream D — provider/AI containment contract

Document and test the embedding responsibilities of
`AiProviderTransport`:

- TLS identity validation belongs to the transport;
- destination allowlist/egress policy;
- request deadline;
- streaming response byte cap;
- secret-safe errors/logging;
- cancellation;
- provider retry/cost boundaries.

Keep AI disabled by default. Do not add provider SDK dependencies simply to make
the package self-contained.

Threat-intelligence publication remains advisory; no implicit block/ban action
may be introduced.

## Workstream E — package docs and compatibility classification

Add/refresh consumer-oriented README/rustdoc/examples covering:

- basic static honeypot;
- injected threat publisher;
- storage modes;
- optional AI transport;
- shutdown/drain;
- security threat model and non-goals.

Define MSRV evidence for standalone-capable class 2 without describing it as a
class-3 support guarantee. Add a changelog only if the repository policy calls for
one at this state.

Explicitly classify runtime config and extension traits as experimental or stable
for package consumers.

## Workstream F — target qualification

Run package/unit/integration proof on the repository's supported practical
targets. At minimum include Linux and macOS; compile/test Windows where the crate
supports it. The current TCP-only listener limitation remains explicit.

Do not claim native features that were only cross-compiled.

## Verification

```bash
cargo test -p synvoid-honeypot --profile ci
cargo test -p synvoid-honeypot --doc --profile ci
RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-honeypot --no-deps
cargo package -p synvoid-honeypot --allow-dirty
cargo publish -p synvoid-honeypot --dry-run
cargo xtask <standalone-consumer-command> synvoid-honeypot
cargo xtask verify-full
cargo deny check
cargo audit
```

No actual publish.

## Acceptance criteria

- hard hostile-input/resource ceilings exist;
- persistence behavior and compatibility are explicit;
- fuzz/property coverage exists for exposed parsers;
- consumer docs/threat model are usable without SynVoid knowledge;
- packaged outside-workspace consumer still passes;
- package may be marked standalone-capable class 2;
- external repository/class-3 decision remains for Phase 123 or later.

## Rejection criteria

Reject implementation that:

- stabilizes the SQLite schema accidentally;
- stores full hostile payloads by default to improve examples;
- gives AI responders production tools/secrets;
- turns advisory indicators into enforcement;
- claims cross-platform support without native evidence;
- publishes the package.

## Formal closeout

The security, persistence, resource-limit, property-test, documentation, and
packaged-consumer workstreams are implemented. Linux package/test/doc checks
and an outside-workspace Rust 1.85.0 consumer passed. The package is recorded as
a class-2 candidate with `external_support = false`; this is packaged Linux
evidence, not a class-3 support commitment. The required native macOS run was
unavailable because only `x86_64-unknown-linux-gnu` is installed in this
worktree environment. Cross-compilation would not meet the plan's native target
criterion, so target qualification is **DEFERRED**. No Windows target claim is
made. Detailed evidence is in
`architecture/standalone_crate_phase121_closeout.md`.

Phase 122 remains eligible and independent. Phase 123 must retain this target
qualification residual; it must not describe the crate as fully qualified
across platforms or publish it.
