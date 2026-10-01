# Phase 105 Plan: DNS Hickory Patch Adoption and Security Requalification

Status: **IMPLEMENTATION COMPLETE — PENDING EXACT-SHA HOSTED PROOF**.

Interim evidence: `architecture/dns_hickory_patch_requalification.md`.
The terminal CLOSED QUALIFIED status remains gated on hosted CI and
dependency-security for the exact proof-bearing SHA.

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline: `main` at `19c0636535f3728e80b7c6777ec6a552c38c61a0` (2026-10-01).

Owner: DNS / security / dependency maintenance.

## Goal

Move the DNS dependency graph from the currently resolved Hickory 0.26.1 line
to the qualified current 0.26.3 patch line, prove DNSSEC/resolver/transport
compatibility, and establish a trustworthy baseline for the subsequent DNS
ownership/delegation audit.

This phase is intentionally narrow. It is not the DNS extraction phase and must
not mix a dependency patch update with broad DNS rewrites.

## Current state

`crates/synvoid-dns/Cargo.toml` declares:

- `hickory-proto = "0.26"` with `dnssec-ring`;
- `hickory-resolver = "0.26"` with
  `system-config`, `recursor`, and `dnssec-ring`.

The current committed lock resolves `hickory-resolver 0.26.1`.

The 0.26.2/0.26.3 release train contains material DNS security/correctness work,
including DNSSEC validation hardening and follow-on fixes for regressions and
delegation/transport behavior. Phase 108 must compare SynVoid against the
post-fix Hickory behavior, not the older 0.26.1 baseline.

Upstream references to verify immediately before implementation:

- https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.2
- https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3

## Workstream A — establish exact pre-change graph

Record from the implementation baseline:

```bash
cargo tree -p synvoid-dns
cargo tree -p synvoid-dns | grep hickory
cargo tree -i hickory-proto
cargo tree -i hickory-resolver
```

Identify every resolved Hickory-family package/version, not only the two direct
manifest entries. Record whether another workspace dependency constrains the
family below 0.26.3.

Do not edit the manifest solely to force a patch if the existing `0.26`
requirements already admit the qualified line.

## Workstream B — targeted patch adoption

Prefer targeted lockfile updates over a whole-workspace re-resolution.

Expected shape:

```bash
cargo update -p hickory-proto --precise 0.26.3
cargo update -p hickory-resolver --precise 0.26.3
```

Adjust exact package selectors if Cargo reports multiple Hickory versions.

If 0.26.3 causes an unexpected transitive major/minor movement, stop and record
the graph delta before accepting it. Do not hide unrelated dependency churn in
this phase.

No git dependency or vendored Hickory fork is authorized.

## Workstream C — DNSSEC and recursive-resolution qualification

Run all existing focused tests covering:

- DNSKEY/DS chain construction and validation;
- signature verification algorithms used by SynVoid;
- negative answers and authenticated denial where covered;
- trust-anchor/RFC5011 behavior;
- recursive resolver success/failure paths;
- cache insertion/expiry/negative-cache behavior;
- malformed/hostile response handling;
- CNAME/delegation/referral handling;
- DNS64 interaction with recursive answers;
- resolver timeout/retry/error mapping.

Add regression fixtures only where 0.26.2/0.26.3 changed behavior that SynVoid
must pin. Prefer protocol vectors and deterministic synthetic zones over
internet-dependent tests.

The phase may update expected error classification if upstream correctly rejects
previously accepted invalid DNSSEC state, but the security improvement must be
documented explicitly rather than called byte-for-byte parity.

## Workstream D — encrypted transport and server-path compatibility

Requalify the DNS features that share Hickory/protocol structures even when
their network framing is SynVoid-owned:

- UDP/TCP authoritative path;
- DoT;
- DoH;
- DoQ;
- mesh+DNS feature compilation;
- resolver boot/configuration;
- query validation and canonical response construction.

Verify that no Hickory patch change causes silent downgrade of DNSSEC validation
or TLS/QUIC verification.

## Workstream E — dependency-security review

Run the current dependency-security contract after the targeted update:

```bash
cargo deny check
cargo audit
```

Record:

- exact Hickory versions;
- removed/new advisories;
- duplicate-version delta;
- any crypto-provider changes;
- any change to `ring`/aws-lc-rs or DNSSEC feature activation.

Do not add an advisory ignore to keep 0.26.1 if the supported 0.26.3 line
remediates the issue.

## Workstream F — performance/behavior sanity

Use the existing DNS benches for a bounded before/after sample:

- `cache_bench`;
- `wire_bench`;
- `zone_bench`;
- `coalescer_bench`;
- `limits_bench`.

This is a patch qualification, not a benchmark campaign. Investigate only
repeatable material regressions. Record the host/toolchain and do not overstate
single-host noise.

## Workstream G — documentation and Phase 108 handoff

Update current DNS/dependency authority with:

- resolved Hickory versions;
- security/correctness reason for the patch move;
- any observable semantic change;
- the exact implementation SHA and verification evidence.

Phase 108's delegate/retain audit must use this qualified state.

## Verification

At minimum:

```bash
cargo fmt --all -- --check
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo xtask verify
cargo xtask verify-full
cargo deny check
cargo audit
```

Use the repository's current equivalent if feature names/gates have changed.

Hosted CI + dependency-security on the proof-bearing SHA are required for
terminal CLOSED QUALIFIED status because this phase is security-motivated.

## Acceptance criteria

- all resolved production Hickory components required by SynVoid DNS are on the
  intended qualified 0.26.3 line;
- DNSSEC validation and recursive-resolution regressions are covered by focused
  evidence;
- DNS/mesh+DNS feature profiles remain green;
- no unrelated dependency churn is hidden in the update;
- dependency-security gates are green;
- current docs identify the qualified baseline for Phase 108.

## Rejection criteria

Reject a closeout that:

- stays on 0.26.1 without proving 0.26.3 is unusable;
- introduces a fork/git patch without a separately documented upstream blocker;
- weakens DNSSEC validation to preserve an old fixture;
- silently disables recursor/DNSSEC features;
- combines this patch update with the Phase 108 ownership rewrite;
- marks local-only testing as terminal security qualification.
