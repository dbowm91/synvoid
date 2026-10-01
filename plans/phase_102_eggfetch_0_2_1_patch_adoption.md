# Phase 102 Plan: Eggfetch 0.2.1 Patch Adoption

Status: ACTIVE / READY FOR IMPLEMENTATION.

Registered in: plans/roadmap.md.

Planning baseline: main at 0dc1f7fb21a5df60e72fc7f2cd60b7cb73bc9f35 (2026-09-29).

Upstream target: eggstack/eggfetch v0.2.1, published 2026-09-26.

Depends on: the closed Eggfetch 0.2 transport consolidation campaign through Phase 64. Production remains on the eggfetch-backed transport introduced by Phases 58-62; Phase 63 remains the performance authority and Phase 64 remains the documentation/evidence-truth correction.

## Goal

Move SynVoid's production eggfetch dependency from the exact eggfetch-core 0.2.0 artifact to the exact 0.2.1 artifact, preserving all existing transport, TLS, pooling, timeout, streaming, trailer, UDS, resolved-target, API-compatibility, and security semantics.

This is a patch-adoption and qualification phase, not a transport redesign. The upstream release contains no production eggfetch-core source changes relative to v0.2.0 and explicitly states that public APIs, feature graph/defaults, MSRV, dependency policy, and runtime/user-visible behavior are unchanged.

## Research finding and scope decision

The v0.2.0...v0.2.1 upstream comparison contains 49 commits, but the production eggfetch-core crate changes are limited to release identity in its manifest:

- package version: 0.2.0 -> 0.2.1;
- optional eggfetch-http-connect dependency version: 0.2.0 -> 0.2.1.

There are no changes under crates/eggfetch-core/src/** between the two tags.

The remaining upstream changes are qualification/test hardening, benchmark harness work, documentation/planning changes, and coordinated package-version updates. In particular, 0.2.1 adds a hermetic Windows TLS response-completeness test matrix, but it does not change production transport code.

SynVoid currently enables exactly:

- native-http1;
- native-http2;
- tls-rustls;
- tls-native-roots.

SynVoid does not enable eggfetch's proxy feature, and the current Cargo.lock contains eggfetch-core 0.2.0 but no eggfetch-http-connect package. Therefore the upstream optional connector version bump should not enter SynVoid's resolved graph.

Conclusion: no SynVoid adapter or policy code change is warranted solely by the 0.2.1 release. Any production Rust change beyond the version/lock update must be justified by a concrete compile/test failure and reviewed as a newly discovered compatibility defect, not bundled opportunistically into this phase.

## Workstream A — exact dependency and lockfile update

In crates/synvoid-http-client/Cargo.toml:

1. Change the exact eggfetch-core pin from =0.2.0 to =0.2.1.
2. Retain default-features = false.
3. Retain the exact feature set:
   - native-http1
   - native-http2
   - tls-rustls
   - tls-native-roots
4. Keep an exact pre-1.0 pin. Do not broaden this to "0.2", "^0.2.1", a git dependency, or a workspace-wide loose range.
5. Update the nearby qualification comment so it no longer describes 0.2.0 as the current dependency artifact. Preserve the historical Phase 58 provenance rather than rewriting that phase as if it originally qualified 0.2.1.

Regenerate Cargo.lock with a targeted dependency update, preferably:

    cargo update -p eggfetch-core --precise 0.2.1

Expected lock delta:

- eggfetch-core version 0.2.0 -> 0.2.1;
- eggfetch-core checksum changes to the crates.io 0.2.1 checksum;
- no new package nodes;
- no eggfetch-http-connect package;
- no changed versions in Hyper, Rustls, Tokio, H2, HTTP/body, or other transport dependencies caused by this patch.

If the lock delta is broader than that expectation, stop and explain the resolver change before accepting it. Do not normalize unrelated dependency drift into this patch-adoption commit.

## Workstream B — preserve the qualified feature and policy boundary

Do not adopt additional eggfetch features or move SynVoid policy into eggfetch as part of this bump.

The following boundaries remain binding:

- SynVoid owns upstream selection, retry policy, WAF/cache/auth policy, compression policy, redirect policy, and outbound H3 decisions.
- crates/synvoid-http-client/src/eggfetch_policy.rs remains the canonical translator from UpstreamTlsConfig to eggfetch_core::TlsConfig.
- The explicit aws-lc-rs CryptoProvider remains mandatory; do not fall back to process-global provider selection.
- Custom CA behavior remains additive.
- Hostname-skip remains chain-validating and narrowly scoped.
- SNI override remains request-scoped and must not leak across pooled origins.
- Plaintext allowance remains a SynVoid routing gate rather than a hidden TLS switch.
- The eggfetch lane remains the sole production generic egress transport while legacy Hyper helpers remain compatibility/test-only.
- Existing timeout semantics, including the SynVoid outer time-to-headers behavior and connect-only client timeout translation, remain unchanged.
- Generic request bodies and response frames/trailers remain streaming; do not add a buffering adapter.

No source changes are expected in eggfetch_transport.rs or eggfetch_policy.rs. If compilation requires one, document the exact changed upstream symbol/behavior first; that would contradict the published patch-release contract and must be treated as a finding.

## Workstream C — targeted regression qualification

Re-run the existing SynVoid evidence against the resolved 0.2.1 artifact rather than inventing a duplicate downstream test matrix.

Required focused verification:

    cargo test -p synvoid-http-client --profile ci
    cargo test -p synvoid-http-client --test eggfetch_qualification --profile ci
    cargo test -p synvoid-http-client --test egress_parity --profile ci

The package-wide run is required because the differential eggfetch harness is crate-internal rather than a standalone integration-test target.

The qualification evidence must continue to cover, through the existing suites:

- ordinary TLS verification;
- custom CA;
- invalid/untrusted certificate failure;
- hostname-skip with chain validation;
- explicit aws-lc-rs provider;
- SNI override and pool isolation;
- H1 keepalive;
- H2 negotiation/multiplexing;
- request and response trailers/frame preservation;
- generic/WAF-shaped/H3-shaped streaming request bodies;
- connect/read/total timeout behavior;
- cancellation and closed-upstream errors;
- resolved-target pinning and origin isolation;
- UDS on Unix;
- bounded pooling/saturation behavior;
- response-size/error mapping;
- compatibility helper behavior.

The upstream Windows TLS response-completeness matrix is evidence for the release, not a new SynVoid API contract. Do not copy its full matrix into SynVoid merely because it was added upstream. Add a downstream regression only if SynVoid's adapter changes or a SynVoid-specific failure is observed.

## Workstream D — feature/profile and dependency-security verification

Verify that the patch does not change feature resolution or security posture.

At minimum run:

    cargo tree -p synvoid-http-client -e features
    cargo tree -i eggfetch-core
    cargo check --no-default-features --features post-quantum
    cargo deny check
    cargo audit
    cargo xtask verify

Record:

- eggfetch-core resolves exactly once at 0.2.1;
- eggfetch-http-connect is absent;
- no proxy/http3/json/compression/cookies/logical-retry/redirect feature becomes enabled;
- the post-quantum profile still compiles with SynVoid's explicit provider policy;
- no new advisory or denied dependency is introduced by the lock update.

If repository verification has changed since this plan was written, use the current repository-defined equivalent in addition to the commands above rather than weakening the gate.

## Workstream E — documentation and historical-evidence reconciliation

Keep the closed 0.2.0 campaign truthful.

Do not bulk-replace "0.2.0" in:

- architecture/eggfetch_0_2_compatibility_matrix.md;
- architecture/eggfetch_0_2_transport_closeout.md;
- architecture/eggfetch_0_2_transport_corrective_closeout.md;
- architecture/eggfetch_0_2_transport_performance_requalification.md;
- Phases 58-64 planning/closeout records.

Those documents describe evidence actually produced against 0.2.0 and should remain historical records.

Update only current-authority text that asserts the presently resolved dependency version. In particular:

- crates/synvoid-http-client/Cargo.toml current-version comment;
- the heading/preamble in crates/synvoid-http-client/tests/eggfetch_qualification.rs if it would otherwise falsely claim the executing suite is still bound to the 0.2.0 artifact;
- plans/roadmap.md Phase 102 status;
- any current operator/developer guidance found by a repository-wide exact-version search that describes 0.2.0 as the current pin rather than historical evidence.

Recommended qualification-suite wording: the suite was established for Phase 58 against 0.2.0 and is retained as the regression contract for the current qualified 0.2.x exact pin.

## Workstream F — closeout record

After implementation and verification, write:

    architecture/eggfetch_0_2_1_patch_adoption_closeout.md

The closeout must record:

- implementation/proof-bearing SHA;
- upstream tag/release and the v0.2.0...v0.2.1 production-source finding;
- exact manifest change;
- actual Cargo.lock delta;
- resolved feature graph;
- focused test results;
- post-quantum compile result;
- cargo deny/audit result;
- cargo xtask verify result;
- any hosted CI/dependency-security run used as exact-SHA proof;
- explicit statement that no SynVoid production adapter/policy behavior changed, if that remains true;
- any deviation from the expected narrow lock delta.

Then update this plan and plans/roadmap.md from ACTIVE to CLOSED QUALIFIED.

## Performance disposition

Do not rerun the Phase 63 transport benchmark campaign solely for this version bump.

Reason: v0.2.1 contains no production eggfetch-core source change relative to v0.2.0, and SynVoid is not changing adapter code, features, policy translation, pooling, or request-path structure. Re-running the full immutable before/after performance campaign would not measure a changed runtime implementation.

Performance qualification must be reopened only if:

- the resolved runtime dependency graph changes materially;
- SynVoid adapter/policy code changes;
- focused regression tests expose changed runtime behavior; or
- a reproducible post-bump regression is observed.

The accepted Phase 63 concurrent-streaming tail residual remains a separate historical/current performance consideration and is not re-adjudicated by this patch bump.

## Acceptance criteria

Phase 102 may close only when all of the following are true:

1. crates/synvoid-http-client/Cargo.toml pins eggfetch-core exactly to =0.2.1.
2. Cargo.lock resolves eggfetch-core 0.2.1 and no unexpected dependency/feature drift is accepted.
3. eggfetch-http-connect remains absent from the SynVoid lock graph under the production feature set.
4. No production adapter/policy source change was needed, or any required change is separately explained and qualified.
5. The existing eggfetch qualification, parity, package, feature/profile, and repository verification gates pass.
6. Explicit aws-lc/PQ/TLS fail-closed behavior remains intact.
7. Streaming bodies, response frames/trailers, UDS, resolved-target routing, pooling, and timeout semantics remain intact.
8. Historical 0.2.0 evidence remains historically accurate.
9. A Phase 102 closeout records exact-SHA evidence and the actual lock/feature delta.

## Rejection / corrective triggers

Do not close Phase 102 as a routine patch adoption if any of these occur:

- eggfetch-core 0.2.1 requires a SynVoid API adaptation despite the upstream no-runtime-change claim;
- the lock update introduces eggfetch-http-connect or another unexpected runtime package;
- the production feature closure changes;
- TLS/provider/SNI/custom-CA/hostname-skip behavior changes;
- existing trailer/streaming/timeout/UDS/resolved-target tests regress;
- dependency-security verification introduces a new unadjudicated finding;
- repository verification fails on a touched boundary.

If one occurs, leave Phase 102 open and write a narrow corrective plan describing the observed defect. Do not mask it by broadening features, weakening tests, or reverting to an unqualified semver range.

## Non-goals

- No Eggress adoption.
- No EggServe change.
- No migration to eggfetch proxy support.
- No outbound HTTP/3 expansion.
- No retry/redirect/compression/cookie policy migration into eggfetch.
- No legacy Hyper compatibility-surface removal.
- No public synvoid-http-client publication decision.
- No broad dependency refresh.
- No full performance requalification absent a runtime-path change.
