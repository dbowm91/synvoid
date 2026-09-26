# Phase 88 Plan: ICMP Extraction Readiness and Platform Qualification

Status: closed 2026-09-26 with disposition **RETAIN** (no extraction,
no promotion, no publication). Implementation SHA:
`f85b7871dcd0323bc45bc1009852d501904bd2c6`. Decision record:
`architecture/icmp_policy_enforcement_extraction_readiness.md`. Closeout:
`architecture/icmp_phase88_extraction_readiness_closeout.md`.

Registered in: `plans/roadmap.md` and
`plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

Depends on: Phases 85–87.

## Goal

Requalify the cleaned ICMP policy/enforcement boundary against current Rust
ecosystem alternatives and native platforms, then produce a truthful go/no-go
record for a separate extraction/publication campaign.

This phase does not publish a crate and does not create the external repository.

## Workstream A — repeat the ecosystem comparison on the final API

Compare the cleaned boundary against current maintained alternatives.

At minimum examine:

- generic cross-platform firewall APIs such as Net Lattice;
- Linux nftables abstractions (`nftnl`, `rustables`, `nftables`);
- macOS direct PF libraries such as `pfctl`;
- Windows WFP libraries;
- ICMP packet/probe crates only to confirm they solve a different layer.

The go/no-go case must be based on remaining differentiated functionality, not
on "SynVoid already has this code."

Expected differentiators to test:

- family-aware ICMP type/code policy;
- RFC-aware ICMPv6 safety validation;
- explicit rate-limit semantics;
- requested-policy/backend capability compilation;
- operation-specific privilege diagnostics;
- exact/unsupported semantic reporting;
- transactional/scoped enforcement;
- live owned-state verification/drift reporting.

If a current ecosystem crate now provides the same boundary cleanly, record
that and prefer adoption/contribution over extraction.

## Workstream B — adjudicate subprocess vs native backend mechanisms

Current implementations invoke external tools in several paths
(`nft`, `pfctl`, `tc`).

For each platform, record:

- current subprocess behavior and injection/input surface;
- atomicity;
- live readback;
- dependency/footprint cost;
- privilege behavior;
- API maturity/maintenance;
- license/MSRV implications;
- portability.

Then choose one of:

1. retain subprocess deliberately for now;
2. migrate to a native API before extraction;
3. keep subprocess as a feature/backend fallback behind the same enforcement
   contract.

Do not require removal of every subprocess merely to call the library
"native." Conversely, do not retain a subprocess if it prevents the Phase 87
atomicity/readback contract from being truthful.

Linux candidates:
- https://docs.rs/nftnl/latest/nftnl/
- https://docs.rs/rustables/latest/rustables/
- https://docs.rs/nftables/latest/nftables/

macOS candidate:
- https://docs.rs/pfctl/latest/pfctl/

The optional eBPF lane may retain `tc` temporarily if it remains clearly
experimental/optional and does not contaminate the baseline API.

## Workstream C — native platform qualification matrix

Record compile evidence separately from native enforcement evidence.

### Linux nftables — required baseline

Require native privileged smoke proof for:

- install;
- type/code policy;
- exemption;
- rate-limit behavior supported by the policy;
- update/replacement;
- readback verification;
- external drift detection;
- disable/cleanup;
- failure/rollback path.

### Linux eBPF — optional

Qualify only if the feature remains worth retaining. Failure does not block the
baseline extraction decision if nftables is complete and eBPF is clearly
experimental/optional.

### macOS PF

Require native proof before labeling supported. Otherwise retain a lower
experimental/best-effort tier with compile evidence only.

### Windows WFP / Windows Firewall

Require native Windows proof before labeling supported. Cross-compilation alone
must be recorded as compile-only.

If two Windows backends remain, qualify both independently.

### FreeBSD/OpenBSD PF

Qualify each target separately. Do not infer OpenBSD behavior from FreeBSD or
vice versa.

### NetBSD

Expected disposition for this campaign is explicit unsupported ICMP
enforcement with NPF identified as a future backend. Do not treat absence of
NPF as a blocker to extracting a library that truthfully excludes NetBSD.

## Workstream D — extraction/publication hygiene audit

Evaluate the cleaned crate against
`architecture/public_crate_release_policy.md` without promoting it yet.

Audit:

- SynVoid-specific names in public API;
- hidden environment/config assumptions;
- root-relative paths;
- target-gated dependencies;
- default feature footprint;
- optional `metrics` / `tracing` integration;
- examples/rustdoc;
- deterministic tests;
- package contents;
- dependency licenses/advisories;
- MSRV feasibility;
- semver-support surface;
- maintenance burden.

Use an out-of-workspace packaged-tarball build/test as readiness evidence where
practical.

Do not run `cargo publish`; a dry-run/package check is sufficient if the
phase reaches that bar.

## Workstream E — decide extraction shape

Produce
`architecture/icmp_policy_enforcement_extraction_readiness.md`.

It must record one of:

### GO — split policy + enforcement

A likely shape if dependency boundaries justify it:

```text
ICMP policy/core
    typed protocol vocabulary
    validation
    capability requirements
    compile-neutral IR

ICMP enforcement
    backend discovery
    nft/PF/WFP/eBPF adapters
    apply/readback/reconcile
```

### GO — one crate with target-gated backends

Choose this if the two-crate split creates more API/versioning burden than
dependency isolation value.

### RETAIN

Keep the functionality internal if the ecosystem now provides an equivalent
boundary or the maintenance/platform burden exceeds reuse value.

The readiness record must explain dependency flow and support tiers, not just
LOC.

## Workstream F — reconcile repository truth

Update the relevant current-authority docs:

- `architecture/icmp_filter.md`
- `architecture/crate_granularity_audit.md`
- `architecture/final_surface_audit.md` if classification changes
- `docs/FEATURE_STATUS.md`
- `docs/PLATFORM_SUPPORT.md`
- `docs/releasing.md` only if technical package/readiness facts change
- ICMP skill guidance
- this roadmap and `plans/roadmap.md`

Do not mark a class-3/public support promise in this phase. A GO means "ready
for a separately approved extraction/promotion campaign."

## Verification envelope

Run the repository's current required verification, plus the package/platform
evidence that is actually available.

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-icmp-filter --profile ci
cargo test -p synvoid-icmp-filter --doc --profile ci
RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-icmp-filter --no-deps
cargo check --no-default-features --features icmp-filter --profile ci
cargo xtask test guards
cargo xtask verify
cargo deny check
cargo audit
```

Where readiness justifies it:

```bash
cargo package -p synvoid-icmp-filter --allow-dirty
```

Run native privileged platform scripts/tests separately and record exact host
OS, backend, command, and cleanup outcome. Absence of a host must result in an
honest lower support tier, not fabricated qualification.

## Acceptance criteria

- Current ecosystem comparison still demonstrates a meaningful reusable gap or
  records RETAIN.
- Subprocess/native choices are explicit per backend.
- Linux nftables has native apply/update/readback/drift/cleanup proof.
- Every other advertised supported platform has native proof; otherwise its
  support tier is lowered.
- NetBSD is explicitly unsupported unless a separately justified NPF backend
  exists.
- Package/dependency/public-API hygiene is evaluated against the binding Phase
  47 policy.
- Final architecture record gives one unambiguous GO/RETAIN disposition and
  names residual blockers/future work.
- No crate is published and no external repository is created.

## Rejection criteria

Reject the phase if it:

- declares extraction worthwhile merely because code already exists;
- treats generic firewall capability as equivalent to ICMP semantic policy
  without comparing the actual APIs;
- upgrades support tiers from cross-compilation;
- hides missing privileged/native proof;
- requires eBPF success for the baseline library;
- keeps a subprocess that prevents truthful transaction/readback semantics
  without documenting the limitation;
- publishes/promotes before a separately approved release/extraction plan.
