# Release Packaging and Operator Readiness Plan

## Purpose

Milestones A-D brought the upload, honeypot, tarpit, deception, workspace validation, and supported-profile release posture to a strong State B: release-ready for supported profiles with Beta features explicitly classified. This plan turns that technical closure into a practical operator/release handoff.

The goal is to make the repository consumable by operators and maintainers: clear version/tag policy, release notes, install/deploy paths, supported profile declaration, CI/status evidence expectations, and Beta-feature documentation.

## Current baseline

Known state after post-Milestone-D corrective closure:

- Milestone A: upload/YARA hardening closed.
- Milestone B: native detector, archive inspection, honeypot listener/protocol, confidence capping, and dependency cleanup closed.
- Milestone C: honeypot storage, actionability, AI containment, tarpit safety, and operator docs closed.
- Milestone D: tunnel/WireGuard, workspace clippy, ignored tests, CI parity, and workspace validation closed for supported profiles.
- Post-Milestone-D corrective closure: `synvoid-icmp-filter` eBPF compiles and is classified as Beta; release profile matrix exists.
- Current classification: State B — release-ready for supported profiles, with constrained/Beta features documented separately.

## Non-goals

- Do not add broad new product functionality.
- Do not promote Beta features to Supported without runtime validation.
- Do not change release classification without validation evidence.
- Do not rely solely on GitHub CI status if status visibility remains unavailable.

## Workstream 1: Versioning and tag policy

### Tasks

1. Define the initial release candidate version.

Options:

- `v0.1.0-rc.1` if this is the first externally consumable release candidate.
- `v0.1.0` only if the repo owner is ready to treat supported profiles as generally consumable.
- `v0.2.0-rc.1` if prior public tags/releases already used `0.1.x` semantics.

2. Create or update a release policy doc:

- `architecture/release_profile_matrix.md`, or
- new `docs/RELEASE.md` if operator-facing release policy deserves a separate document.

3. Define tag naming:

```text
vMAJOR.MINOR.PATCH
vMAJOR.MINOR.PATCH-rc.N
```

4. Define supported-profile release gate.

A tag may be cut only if these pass locally or in visible CI:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo audit
```

If `cargo audit` is unavailable locally, CI artifact/status must be cited in release notes.

5. Define Beta-feature release gate separately:

- Beta features must compile and have explicit runtime constraints.
- Beta features do not block supported-profile release unless they are part of default/supported profile matrix.
- Beta features must be listed in release notes.

### Success criteria

- Release/tag policy is explicit.
- Supported profile gate is documented.
- Beta feature gate is documented.
- Version chosen for first release candidate is justified.

## Workstream 2: Release notes and changelog structure

### Tasks

1. Create `CHANGELOG.md` if absent.

Use a format compatible with Keep a Changelog-style sections without overclaiming semantic stability.

2. Add an entry for the upcoming release candidate.

Include sections:

- Security hardening
- Upload/YARA/archive
- Honeypot/deception
- Tarpit
- Threat intelligence/mesh actionability
- Tunnel/WireGuard
- Workspace validation/release posture
- Dependency/security policy
- Known limitations
- Beta features

3. Include validation summary:

- test counts from Milestone D/post-D closure
- cargo-deny status
- ignored tests status
- supported-profile status
- CI-status caveat if remote statuses are unavailable

4. Include migration/upgrade notes:

- new honeypot storage columns: `payload_hash`, `payload_length`
- payload retention defaults
- threat-intel action class behavior
- AI responder default disabled
- tarpit admission/budget defaults
- archive inspection ZIP-only and non-recursive behavior
- WireGuard feature-gated/stubbed behavior if applicable
- eBPF Beta behavior

5. Add release-notes checklist to `docs/RELEASE.md` or `AGENTS.md`.

### Success criteria

- `CHANGELOG.md` exists and accurately summarizes A-D plus corrective closure.
- Known limitations are visible.
- Beta features are not presented as production-supported.
- Migration notes are clear enough for operators.

## Workstream 3: Install and deploy documentation

### Tasks

1. Review existing install/deploy docs.

Likely targets:

- `README.md`
- `docs/DEPLOYMENT.md` if present
- `docs/CONFIGURATION.md`
- `docs/HONEYPOT.md`
- `docs/TARPIT.md`
- `docs/TUNNELS.md`
- `SECURITY.md`

2. Add or update a concise install section:

```bash
git clone <repo>
cd synvoid
cargo build --release
cargo test --workspace --all-targets
```

3. Add profile-specific build examples:

```bash
cargo build --release
cargo build --release --no-default-features
cargo build --release --no-default-features --features mesh
cargo build --release --no-default-features --features dns
cargo build --release --no-default-features --features mesh,dns
```

4. Add explicit Beta-feature examples with warnings:

```bash
cargo build --release -p synvoid-icmp-filter --features icmp-ebpf
```

Document required runtime conditions:

- Linux only
- BTF-capable kernel
- root/CAP_NET_ADMIN
- precompiled eBPF object if required
- fallback behavior when unavailable

5. Add deployment profile recommendations:

- minimal/core deployment
- DNS-enabled deployment
- mesh-enabled deployment
- honeypot/tarpit enabled deployment
- upload/YARA enabled deployment

6. Add production-default reminders:

- AI responder disabled by default
- honeypot disabled by default unless configured
- mesh propagation disabled unless configured
- raw payload retention minimized by default
- tarpit admission/budgets enabled
- archive inspection ZIP-only/non-recursive

### Success criteria

- README gives a practical first build path.
- Docs explain supported feature profiles.
- Beta features have warnings and runtime constraints.
- Operator defaults are visible.

## Workstream 4: Supported-profile declaration and Beta feature registry

### Tasks

1. Expand `architecture/release_profile_matrix.md` or create `docs/FEATURE_STATUS.md` with:

- Supported features
- Beta features
- Experimental/deferred features
- Unsupported/removed features

2. For every Beta feature, include:

- compile status
- CI/local validation status
- runtime constraints
- fallback behavior
- known gaps
- promotion criteria

Current Beta candidates:

- `icmp-ebpf`
- `post-quantum`
- `verify-pq`
- any other feature already classified Beta in release matrix

3. Promotion criteria for `icmp-ebpf` should include:

- integration test on Linux with BTF/root-capable environment
- verified XDP/TC attach/detach lifecycle
- verified fallback path
- metrics and error reporting validated under real kernel constraints
- documented operational runbook

4. Supported profiles should be listed in README and docs:

- Default
- Core
- Mesh
- DNS
- Full mesh+DNS supported profile

### Success criteria

- Operators can tell what is supported versus Beta.
- Beta features have promotion criteria.
- Supported profiles are consistent across README, release matrix, and changelog.

## Workstream 5: CI/status evidence and release artifacts

### Tasks

1. Attempt to retrieve or document GitHub CI status for the final candidate commit.

If status is not visible through current tooling, state that clearly in the release note.

2. Ensure CI summary includes release-critical jobs:

- build
- fmt
- clippy
- tests
- upload
- honeypot
- tarpit
- mesh
- DNS
- security audit
- dependency audit
- profile matrix
- guard suite
- fuzz smoke
- platform compatibility

3. Add a local release validation artifact:

- `plans/release_candidate_validation_results.md`

This should include:

- commit SHA
- version/tag candidate
- exact commands run
- pass/fail table
- CI visibility status
- remaining exceptions
- final release classification

4. Optional but preferred: add a release checklist template:

- `.github/ISSUE_TEMPLATE/release_checklist.md`, or
- `docs/RELEASE_CHECKLIST.md`

### Success criteria

- Release validation results are committed.
- CI visibility caveat is explicit if still unavailable.
- Release checklist exists for future runs.

## Workstream 6: Operator security posture review

### Tasks

1. Update `SECURITY.md` with release posture:

- supported profiles
- Beta features
- known advisories and mitigations
- responsible disclosure/contact if applicable
- YARA/wasmtime advisory stance
- operational security defaults

2. Ensure docs do not overclaim:

- not a blanket production guarantee for every optional feature
- eBPF Beta is not Supported
- AI responder external providers require explicit opt-in
- mesh propagation requires thresholds/config
- archive inspection does not recursively inspect nested archives

3. Review examples/configs for dangerous defaults:

- external AI enabled accidentally
- mesh propagation enabled by default
- raw payload full retention enabled by default
- eBPF enabled by default
- tarpit unbounded stream config

4. If example configs enable risky features for demonstration, label them explicitly as examples and not production defaults.

### Success criteria

- Security posture is accurate and conservative.
- Example configs do not undermine safe defaults.
- Known advisory exceptions are transparent.

## Workstream 7: Final release handoff note

### Tasks

Create:

- `plans/release_packaging_operator_readiness_results.md`

Include:

- version/tag recommendation
- docs changed
- release notes/changelog status
- supported profiles
- Beta features
- validation commands
- CI status visibility
- remaining known limitations
- final go/no-go classification

Suggested classification:

### Release Candidate Ready

Use if supported profiles pass locally, docs are updated, changelog exists, and only Beta features remain constrained.

### Not Release Candidate Ready

Use if supported profiles fail, release docs are missing, or security/advisory status is ambiguous.

## Final acceptance checklist

- [ ] Version/tag policy documented.
- [ ] `CHANGELOG.md` exists or is updated.
- [ ] Install/build docs updated.
- [ ] Supported profiles listed in README/docs.
- [ ] Beta features listed with constraints and promotion criteria.
- [ ] `SECURITY.md` reflects release posture.
- [ ] CI/status evidence is recorded or caveat is explicit.
- [ ] `plans/release_candidate_validation_results.md` exists.
- [ ] `plans/release_packaging_operator_readiness_results.md` exists.
- [ ] Final go/no-go classification is explicit.

## Handoff guidance

This pass should be documentation, release hygiene, and validation evidence. Avoid large implementation changes. If a supported-profile validation command fails, stop and create a corrective plan rather than continuing to polish docs around a failing release gate.
