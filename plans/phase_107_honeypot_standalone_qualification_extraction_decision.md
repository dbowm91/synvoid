# Phase 107 Plan: Honeypot Standalone Qualification and Extraction Decision

Status: **CLOSED DEFER** (2026-10-01; qualified package, extraction deferred).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline for registration: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).
Implementation must rebase the evidence on the Phase 106 closeout SHA.

Owner: honeypot/deception / release / security.

## Goal

Decide from the post-Phase-106 boundary whether the honeypot subsystem should
move to an independent repository, remain a workspace crate, or require one
additional corrective pass. If GO, produce the exact extraction contract and
handoff without weakening SynVoid capability.

This phase does not automatically publish crates. Repository location and public
API stability are separate decisions.

## Preconditions

Phase 106 must have:

- application-neutral runtime configuration ownership;
- no broad SynVoid config/mesh/root dependency;
- an embedding-neutral HTTP/provider boundary;
- standalone package build/test evidence;
- explicit storage/privacy semantics.

If those conditions are not met, close Phase 107 as DEFER/RETAIN with exact
blockers rather than compensating with cross-repository path/git dependencies.

## Workstream A — standalone consumer proof

Create a temporary or checked example consumer outside the SynVoid workspace
that exercises:

- constructing runtime config;
- starting bounded listeners;
- registering deterministic responders;
- recording an interaction;
- reading/storing an indicator;
- injecting a fake threat publisher;
- injecting or configuring an AI transport without SynVoid types;
- orderly shutdown.

The proof must use only the candidate package surface and registry/path package
semantics that an independent repository could provide.

## Workstream B — API/support classification

Classify the candidate API into:

- stable consumer contract;
- experimental extension point;
- implementation detail.

At minimum classify:

- config DTOs;
- listener/runner/controller lifecycle;
- responder traits;
- AI transport/provider interfaces;
- storage interfaces and record schema;
- threat-intel indicators/scoring;
- publisher interface;
- metrics/event hooks if exposed.

Write semver rules for changes to persisted records/config where externally
observable.

## Workstream C — security and threat model

Create a consumer-facing threat model covering:

- the honeypot is deliberately exposed to hostile peers;
- no real service credentials/production secrets are presented to attackers;
- bounded payload capture and retention;
- protocol-parser hostile-input limits;
- concurrency/file-descriptor exhaustion;
- AI prompt-injection and cost-amplification containment;
- provider API-key custody/redaction;
- storage saturation/failure behavior;
- outbound network behavior of local/external AI modes;
- threat-intel publication is advisory until the embedding application chooses
  enforcement.

Fuzz or property-test the parsers/boundaries most exposed to attacker-controlled
input if coverage is absent.

## Workstream D — package/release hygiene

A GO extraction requires:

- explicit `rust-version` with MSRV test evidence;
- README quickstart;
- crate-level rustdoc;
- runnable examples;
- CHANGELOG;
- license/repository/documentation metadata;
- `cargo package` and `cargo publish --dry-run`;
- packaged tarball build/test outside SynVoid;
- `cargo deny`/`cargo audit`;
- supported-target build matrix proportionate to the actual runtime.

Do not claim Windows/BSD support simply because Tokio compiles there if native
listener/storage behavior has not been exercised.

## Workstream E — extraction topology

If GO, prefer one repository with one primary library initially.

Only split optional provider/storage crates when there is a measurable
dependency or support advantage. Avoid creating a workspace of microcrates
solely to mirror the current module layout.

The independent repository must not depend on SynVoid application crates.

SynVoid should retain only:

- persisted-config translation;
- lifecycle composition;
- admin/control-plane adapter;
- threat-intel/mesh publisher implementation;
- SynVoid-specific metrics/labels if needed.

## Workstream F — history and migration strategy

Choose and document one extraction mechanism:

- git history filter/subtree preserving useful history; or
- clean initial import with provenance reference if history filtering creates
  more maintenance risk.

Define the temporary SynVoid migration strategy:

1. independent repo/crate established;
2. version/tag pinned;
3. SynVoid switches from workspace path to released/versioned dependency or an
   explicitly temporary repository reference;
4. parity qualification;
5. in-tree implementation removed;
6. compatibility facade retained only if warranted.

No long-lived git dependency is the desired final state.

## Workstream G — decision

Allowed terminal dispositions:

- **GO EXTRACT** — all criteria satisfied; register/create the independent repo
  in a separate explicitly approved execution step and record the exact API
  contract;
- **DEFER** — boundary is good but external evidence/support prerequisites remain;
- **RETAIN** — independent ownership does not reduce maintenance enough to justify
  a second release/support surface.

Do not use a numeric score. Record concrete evidence and blockers.

## Verification

Phase 107 itself is primarily a qualification/decision phase. At minimum:

```bash
cargo test -p synvoid-honeypot --profile ci
cargo package -p synvoid-honeypot
cargo publish -p synvoid-honeypot --dry-run
cargo xtask verify
cargo xtask verify-release
cargo deny check
cargo audit
```

Run the packaged artifact outside the workspace and record the exact head.

## Acceptance criteria

- the decision is based on a standalone consumer and package, not source
  inspection alone;
- threat/privacy/resource semantics are explicit;
- an extraction topology is documented if GO;
- SynVoid adapter ownership is explicit;
- no capability or config compatibility is lost;
- planning/current architecture docs record GO/DEFER/RETAIN consistently.

## Rejection criteria

Reject a GO verdict that:

- still requires a SynVoid application crate;
- lacks package/MSRV/security proof;
- leaves ambiguous config ownership;
- turns advisory honeypot intel into implicit enforcement;
- requires synchronized unreleased commits in two repositories;
- equates repository extraction with a stable 1.0/public support promise.

## Closeout

Terminal disposition: **DEFER**. The package and independent consumer are
qualified, but this is not a GO EXTRACT support decision. See
`architecture/honeypot_standalone_qualification_phase107.md` for the tested
package evidence, threat model, API classification, and exact blockers.

Verification:

- `cargo test -p synvoid-honeypot --profile ci` — 207 passed;
- `cargo package -p synvoid-honeypot` — passed;
- `cargo publish -p synvoid-honeypot --dry-run` — passed; upload explicitly
  aborted by dry-run;
- external consumer using extracted `synvoid-honeypot-0.1.0.crate` — passed,
  including loopback listener, persistence readback, fake publisher, responder,
  and orderly shutdown;
- `cargo xtask verify` — passed 10/10 on Phase 106 implementation SHA;
- `cargo xtask verify-full` — passed 10/10 (7,896 tests and doctests);
- `cargo xtask verify-release` — passed 14/14, including package inspection;
  package classification: `synvoid-honeypot` PackagedSourceVerified;
- `cargo deny check` — passed;
- `cargo audit` — no vulnerable advisory, six repository-allowed unmaintained
  dependency warnings.

The qualification head was Phase 106 implementation commit `a87d0b0c` with
closeout commit `340c13fb`; the external tarball consumer ran after packaging
that same crate source. No publication or repository creation occurred. Phase
108 remains ready from Phase 105. Phase 109 remains blocked on Phase 108.
