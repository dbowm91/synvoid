# Phase 47 Plan: Public Crate Release Readiness

Status: implemented and closed; retained as historical handoff detail.

Roadmap: `plans/runtime_truthfulness_security_publication_roadmap.md`.

Baseline: `03cec2235fb250e64c33f29b66258eeb0607cdbc`.

Depends on: Phases 41-46 as applicable to each candidate.

## Primary goal

Convert the Phase 35 "reusable workspace library, no external support promise" classification into an evidence-backed public-support decision for a small subset of crates. Publication is optional; the deliverable is a supportable release boundary, not registry churn.

## Candidate waves

### Wave 1 — `synvoid-rate-limit`

Strongest candidate:

- std-only leaf;
- no SynVoid internal dependencies;
- two real production consumer domains (root WAF + mesh);
- deterministic tests;
- existing benchmark evidence;
- policy-free API.

Required before promotion:

- crate README/rustdoc quickstart;
- explicit overflow/time-base semantics;
- stable-vs-implementation-detail decision for slot hashing;
- per-crate MSRV;
- semver/support statement;
- property/fuzz tests around rotation/large jumps/N/N+1;
- package/publish dry-run.

### Wave 1/2 — `synvoid-mesh-protocol`

Good external seam for SynVoid-compatible tooling, not a generic mesh library.

Required:

- independent wire/protocol versioning policy;
- golden vectors treated as compatibility fixtures;
- explicit replay-window/time assumptions;
- `#[non_exhaustive]` or equivalent evolution strategy where appropriate;
- canonical serialization/verification examples;
- semver rules separating Rust API compatibility from wire compatibility.

Do not publish the full `synvoid-mesh` implementation as the public seam.

### Wave 2 — `synvoid-proxy-cache`

Generic value exists, but "HTTP response cache" creates standards expectations.

Before publication, explicitly define supported RFC 9111 subset:

- cache key derivation;
- `Vary`;
- validators/ETag/Last-Modified;
- 304 merge behavior;
- Authorization/private/no-store semantics;
- stale handling;
- request/response header normalization;
- disk persistence semantics if exposed.

If the crate intentionally implements only a reverse-proxy object cache rather than a conforming HTTP cache, rename/document accordingly instead of implying broader RFC coverage.

### Wave 3 — `synvoid-dnssec-keystore`

Security-sensitive but well isolated.

Prerequisites:

- explicit threat model;
- public security/contact policy;
- MSRV and feature support matrix;
- zeroization/secret-lifetime review;
- crash-consistency tests;
- Unix/Windows permission behavior documented;
- PKCS#11/HSM CI or release validation;
- known-answer tests and key-rotation coverage;
- review of RSA advisory exposure and supported algorithms.

Do not make an external support promise merely because the crate is a leaf.

## Deferred candidates

### `synvoid-platform`

Defer until Phase 46 closes and native platform enforcement evidence exists.

### `synvoid-yara`

Defer while SynVoid carries a temporary YARA-X compatibility fork or other downstream dependency exception that would become an external support burden.

### `synvoid-http-client`

Do not publish as a separately supported generic HTTP client until the eggfetch decision is refreshed against the current line (0.1.5 or newer).

Re-run the Phase 34 capability matrix against current eggfetch:

- aws-lc-rs / PQ TLS behavior;
- open/generic request body required by streaming WAF callers;
- direct UDS egress;
- hostname-only verification bypass with chain validation retained;
- pool/timeout/size/error semantics;
- H1/H2 behavior;
- dependency/feature footprint;
- public API maturity.

If eggfetch now covers the requirements, prefer making it the external reusable owner and keep a thin SynVoid adapter internally. Avoid two public clients owned by the same maintainer with overlapping maintenance burden.

If material gaps remain, record exact gaps and an exit condition before considering `synvoid-http-client` public.

### `synvoid-utils` and `synvoid-core`

Remain internal. Their value is workspace contract/implementation ownership, and publication would freeze incidental helpers/domain semantics.

## Workstream A — Establish package support metadata

For each candidate chosen for promotion, add:

- `rust-version`;
- README;
- documentation URL if useful;
- keywords/categories;
- concise description;
- feature table;
- support/security statement;
- changelog/release notes.

Important: the repository's pinned Rust 1.98.1 toolchain is not automatically the public crate MSRV. Determine the lowest toolchain the crate actually intends to support, then test that version. Do not lower MSRV merely for marketing.

A public crate's `rust-version` must match CI evidence.

## Workstream B — Semver/API policy

Add a short policy, either shared or crate-local, covering pre-1.0 expectations.

Classify:

- public stable APIs;
- experimental feature-gated APIs;
- wire-format compatibility;
- serialized data compatibility;
- behavior/performance that is not semver-guaranteed.

Use `cargo-semver-checks` if it fits the release workflow, but do not make release correctness depend on a tool the project will not maintain.

## Workstream C — Remove hidden workspace assumptions

For each candidate:

```bash
cargo tree -p <crate>
cargo package -p <crate> --allow-dirty
```

Inspect the packaged file list and build from the produced crate package outside the workspace.

Verify:

- no root-relative config paths;
- no undocumented environment variables;
- no `path =` dependency that is unavailable on crates.io;
- examples/tests do not depend on root fixtures;
- feature defaults are sensible for external users.

Add `publish = false` to crates intentionally internal if accidental publication becomes a realistic risk; otherwise retain the Phase 35 documented policy.

## Workstream D — Documentation quality gate

Every public candidate needs:

- crate-level rustdoc explaining purpose/non-goals;
- minimal runnable example;
- error/overflow/security semantics;
- feature examples;
- no references to "Phase 27/30/33" as the primary user-facing description.

Historical extraction notes can stay in architecture docs, not package marketing.

## Workstream E — CI/release gate

For each promoted crate, add a focused release command rather than a huge workspace matrix:

1. test on pinned workspace toolchain;
2. check/test on declared MSRV;
3. docs with warnings denied;
4. package dry-run;
5. semver check against last published tag once a previous release exists.

Keep routine CI proportional; publication qualification can live in `verify-release`.

## Workstream F — Name/ownership verification

Before first registry publication:

- verify crate name availability on crates.io;
- verify repository metadata;
- ensure maintainers/owners are intentional;
- decide whether all crates use the `synvoid-` namespace or whether a generic crate deserves a neutral independent project name.

Do not rename after publishing without a compatibility/deprecation plan.

## Workstream G — Release ordering

Because the preferred first candidates have no internal workspace dependencies, publish them independently.

If a later public crate depends on another SynVoid crate, require a released registry version and replace path-only dependency assumptions with `version + path` during workspace development.

Update `docs/releasing.md` with a separate "externally supported library" order, not merely the current technical package order.

## Verification per candidate

```bash
cargo test -p <crate> --profile ci
cargo test -p <crate> --doc --profile ci
cargo doc -p <crate> --no-deps
cargo package -p <crate> --allow-dirty
cargo publish -p <crate> --dry-run
```

Run the declared MSRV check with the exact toolchain.

For security-sensitive crates also run:

```bash
cargo deny check
cargo audit
```

## Acceptance criteria

A crate may be promoted from Phase 35 class 2 to class 3 only when:

- API purpose is independently useful and not just a SynVoid implementation seam;
- no hidden root/runtime dependency exists;
- MSRV is declared and tested;
- semver/wire compatibility policy is written;
- docs/examples are consumer-oriented;
- package builds outside the workspace;
- security/performance invariants relevant to the crate are tested;
- registry/public maintenance burden is justified.

It is valid for this phase to conclude that only `synvoid-rate-limit` is ready, or that no crate should be published yet.

## Closeout (Phase 48)

Implemented in `91732e228864`. Binding: `architecture/public_crate_release_policy.md` + `architecture/public_crate_release_readiness_phase47.md`. Campaign closeout: `architecture/runtime_truthfulness_security_publication_closeout.md`.
