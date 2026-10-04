# Phase 123 Plan: Standalone-Crate Campaign Qualification and Promotion Gate

Status: **CLOSED WITH EXPLICIT QUALIFICATION RESIDUALS** (2026-10-02; closeout:
`architecture/standalone_crate_phase123_closeout.md`). No class-3 promotion or
repository-extraction follow-up was triggered. Exact-SHA hosted CI passed on
`f81182149889e21c4908b7ee38c74bc6b4518f6b`; macOS and live HSM qualification
remain explicit residuals, with no unsupported platform claim.

Registered in: `plans/roadmap.md` and
`plans/standalone_crate_generalization_roadmap.md`.

## Goal

Close Phases 115–122 with exact dependency/package/runtime evidence, classify the
resulting crates, and decide whether any later public-promotion or repository
extraction plan is justified.

This phase performs no publication or repository creation.

## Workstream A — final dependency graph

Regenerate the Phase 115 baseline and report before/after for:

- DNS;
- mesh;
- sandbox/platform;
- honeypot;
- DNSSEC keystore;
- mesh protocol.

For every new/moved crate record:

- direct SynVoid normal/optional dependencies;
- expanded dependency tree;
- feature graph;
- package contents;
- independent consumer proof;
- class/status.

Do not infer maintenance reduction from file counts.

## Workstream B — full qualification

Run:

```bash
cargo fmt --all -- --check
cargo xtask verify
cargo xtask verify-full
cargo xtask verify-release
cargo deny check
cargo audit
```

Run the bounded feature matrix and all native security workflows required by any
support statement changed during this campaign.

Hosted exact-SHA CI/dependency-security proof is required for the terminal
implementation head. Native jobs must be named separately and skipped jobs must
not become support claims.

## Workstream C — status decisions

For each primary candidate record one of:

- **INTERNAL** — application-specific, no standalone target;
- **STANDALONE CLASS 2** — packaged/consumer-qualified but no external support
  promise;
- **CLASS 3 CANDIDATE** — all technical/support prerequisites appear satisfied,
  but publication still requires a separately registered release plan;
- **RETAIN / DEFER** — blockers recorded.

Repository extraction is a separate dimension. A class-3 candidate may remain in
the monorepo indefinitely.

## Workstream D — revisit gate-only candidates

Refresh, without implementation unless triggered:

### ICMP

Check whether the following changed since Phase 112:

- second independent production consumer;
- native support matrix;
- MSRV/docs/examples;
- optional observability;
- package consumer proof.

If not, keep RETAIN.

### YARA

Check:

- official YARA-X/Wasmtime security compatibility;
- removal possibility for the temporary fork;
- second production consumer.

If either security or consumer gate is closed, keep DEFER.

### Proxy cache

Check whether an explicit supported HTTP-cache/object-cache semantic contract now
exists. If not, keep internal and avoid an RFC 9111 implication.

### Tarpit/filter/jail-protocol/native-extension

Require a concrete independent use case and maintenance benefit before registering
promotion. Small dependency-isolation crates do not need independent projects.

## Workstream E — repository-extraction test

A later separate-repository plan may be registered only if ALL hold:

1. standalone class-2 or class-3-ready package already exists;
2. no application-specific dependency points back into SynVoid;
3. independent lifecycle/release cadence is plausible;
4. at least one second real consumer OR a compelling independent security/
   stewardship reason exists;
5. synchronized unreleased commits are not required for routine development;
6. SynVoid can consume a versioned release, not a permanent git pin;
7. CI/release/security ownership for the new repository is explicitly accepted.

Otherwise keep the crate in the monorepo.

## Workstream F — documentation reconciliation

Update:

- `architecture/overview.md`;
- `architecture/crate_granularity_audit.md`;
- `architecture/final_surface_audit.md`;
- `architecture/public_crate_release_policy.md` / standalone companion;
- `docs/releasing.md`;
- root module/facade ledgers if canonical owners changed;
- `AGENTS.md` and affected skills;
- this roadmap and `plans/roadmap.md`.

Historical closeouts remain historical; use supersession notes rather than
rewriting prior evidence.

## Acceptance criteria

- all Phase 115–122 decisions have proof-bearing SHAs/status;
- dependency reductions are measured;
- outside-workspace package proof exists for every crate labeled standalone;
- no class-3 or repository claim is inferred from package location;
- any future promotion/extraction work is separately registered with explicit
  owner/scope;
- current-authority docs agree with manifests and source;
- no supported SynVoid capability regressed.

## Rejection criteria

Reject closeout that:

- counts "number of new crates" as success;
- creates a repository before the package boundary is stable;
- marks class 3 without support/MSRV/security/semver evidence;
- treats compile-only native evidence as runtime qualification;
- leaves roadmap/release/architecture classifications inconsistent;
- silently reopens a prior RETAIN/DEFER candidate without documenting the trigger.
