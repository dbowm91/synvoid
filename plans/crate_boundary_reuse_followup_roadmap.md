# Post-Phase-31 Crate Boundary and Reuse Roadmap

Status: planned (2026-09-16).

This roadmap follows the Phase 31 dependency-surface closeout. It is intentionally narrower than the earlier crate-decomposition tracks: the workspace already has strong domain boundaries, and success is not measured by crate count. Work proceeds only where it removes duplicate implementation, establishes a reusable mechanism already demanded by multiple consumers, or reduces application-specific coupling from an otherwise reusable library.

## Goals

1. Finish the `synvoid-platform` boundary so root and crate implementations cannot drift.
2. Extract the genuinely shared rate-limit mechanisms currently duplicated or stubbed across WAF, mesh, IPC, admin, upload, and related paths.
3. Tighten reusable-library boundaries around DNSSEC key custody and egress HTTP without creating another generic HTTP stack when `eggfetch-core` can satisfy the requirement.
4. Re-run the crate-granularity and dependency-ownership audits after the changes and retain only boundaries that produce measurable dependency, authority, or reuse value.

## Binding principles

- Do not create crates solely to reduce LOC or root-module count.
- Application composition remains in the root crate when it wires SynVoid-specific policy, supervisor state, workers, metrics, or feature orchestration.
- Generic mechanism moves downward; SynVoid policy remains in domain/application crates.
- A reusable crate must not gain a dependency on the root `synvoid` package.
- Preserve public compatibility paths where the existing facade policy requires them; migrate internal callers to canonical paths before removing aliases.
- Prefer dependency injection and narrow conversion adapters over importing `synvoid-config` into low-level mechanism crates.
- Any cross-repository adoption of eggfetch is gated on demonstrated parity and regression tests; do not replace a proven transport merely to standardize names.

## Sequence

### Phase 32 — Platform canonicalization and duplicate-source removal

Plan: `plans/phase_32_platform_canonicalization_and_dedup.md`.

Make `crates/synvoid-platform` the single compiled owner of generic process, IPC, socket, service, Unix/Windows, filesystem, and sandbox primitives. The root `src/platform` path becomes compatibility/application composition only. Generalize application path construction so the library does not hard-code SynVoid naming in its generic layer.

This phase is first because later crates already depend on `synvoid-platform`; leaving duplicate implementations undermines every subsequent ownership claim.

### Phase 33 — Shared rate-limit primitive extraction

Plan: `plans/phase_33_rate_limit_primitive_extraction.md`.

Create one small mechanism crate only if the implementation audit confirms multiple real consumers. Move sliding-window counters, keyed/IP admission contracts, deterministic time-aware primitives, and optional shared-memory counter machinery into it. Keep WAF blackhole behavior, auth lockout semantics, upload policy, IPC rejection policy, and mesh peer policy in their domain crates.

### Phase 34 — Reusable library boundary cleanup and egress decision gate

Plan: `plans/phase_34_reusable_library_boundary_cleanup.md`.

Remove avoidable SynVoid-only coupling from `synvoid-dnssec-keystore`; separate WAF/config adapters from `synvoid-http-client`; compare the remaining generic HTTP transport requirements against `eggfetch-core`; and either adopt eggfetch behind a narrow SynVoid adapter or document why `synvoid-http-client` remains necessary. No new generic HTTP crate is permitted by this phase without explicit gap evidence.

### Phase 35 — Closeout, audit reconciliation, and publication/reuse policy

Plan: `plans/phase_35_crate_boundary_reuse_closeout.md`.

Recompute dependency graphs, source ownership, feature matrices, public surfaces, package/release behavior, and tests. Update the architectural ledgers so there is no discrepancy between documented ownership and compiled ownership. Decide which crates are internal-only versus reasonable reusable/public libraries.

## Explicit non-goals

The following are not part of this roadmap unless new evidence appears during implementation:

- splitting `synvoid-core` into several protocol/type crates;
- extracting `synvoid-admin-server` or `synvoid-waf-runtime`;
- splitting supervisor, worker, TCP, UDP, root HTTP, or root TLS integration solely to shrink the application crate;
- merging `synvoid-filter` for crate-count reduction;
- splitting `synvoid-ipc` into an IPC-core crate before a real second consumer exists;
- publishing `synvoid-utils` as a promised general-purpose utility API;
- creating a second generic HTTP client library alongside eggfetch without an identified capability gap.

## Cross-project reuse targets

Likely reusable surfaces after this roadmap:

- `synvoid-platform`: cross-platform process, IPC/socket, service, secure filesystem and sandbox primitives, with application naming injected by callers;
- rate-limit mechanism crate: atomic sliding windows, keyed/IP admission primitives, optional shared-memory counters;
- `synvoid-dnssec-keystore`: sealed DNSSEC key custody/signing/HSM boundary with no unnecessary SynVoid application dependency;
- selected existing leaf crates such as `synvoid-filter`, `synvoid-yara`, and `synvoid-mesh-protocol` where their APIs are already intentionally narrow.

Reuse value is not sufficient by itself to force publication. Phase 35 records a publication/support policy separately from architectural ownership.

## Roadmap acceptance criteria

The roadmap is complete when:

- generic platform implementation has exactly one canonical source owner;
- root platform modules contain only documented compatibility/application adapters;
- shared rate-limit mechanisms no longer require mesh stubs or root-WAF imports;
- domain-specific limiting policy remains outside the generic primitive layer;
- DNSSEC custody can be consumed without dragging unrelated SynVoid application contracts when technically feasible;
- the egress HTTP decision is supported by parity tests and dependency evidence;
- no unnecessary generic HTTP crate was introduced;
- architecture ledgers, Cargo manifests, feature documentation, and compiled ownership agree;
- default and minimal feature profiles continue to pass the existing verification contract.
