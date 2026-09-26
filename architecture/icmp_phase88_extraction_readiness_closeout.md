# Phase 88 Closeout: ICMP Extraction Readiness and Platform Qualification

Status: closed 2026-09-26 with disposition **RETAIN** (see the binding
decision record `architecture/icmp_policy_enforcement_extraction_readiness.md`).

Planning baseline: `81638c251592913579bd9bbce51d013c44d67910`.
Implementation SHA: `f85b7871dcd0323bc45bc1009852d501904bd2c6`
(built on Phase 87 closeout `c0f22d45`).

Plan: `plans/phase_88_icmp_extraction_readiness_and_platform_qualification.md`.
Roadmap: `plans/icmp_policy_enforcement_extraction_preparation_roadmap.md`.

## Decision

RETAIN: keep the functionality internal under `synvoid-icmp-filter`; no
extraction, promotion, publication, or external repository. The record in
§1 of the readiness document carries rationale, triggers, and residual
blockers. No class-3 support promise was marked.

## Workstream dispositions

- **A (ecosystem comparison):** re-checked on the final API (net-lattice
  1.0.0 MPL-2.0 Sep 2026, `nftables` 0.6.3, `pfctl` 0.7, adopted `wfp`,
  probe-crate layer distinction). The ICMP-semantic gap is real; the
  verdict rests on proof and burden, not duplication.
- **B (subprocess adjudication):** per-backend retain decisions recorded
  (nft atomic batch + JSON readback; pfctl anchor atomicity; `tc`
  temporary-experimental; WFP/winfw already native). No retained
  subprocess breaks the Phase 87 contract.
- **C (qualification matrix):** compile evidence for every retained lane
  (host, Linux gnu ±ebpf, Windows msvc+gnu lib+tests, macOS +icmp-pf);
  native grammar proof via platform `pfctl -n -f -` on real builder
  output (2 macOS-gated tests); privileged proof absent on all lanes
  (non-root macOS host, no Linux/Windows/BSD hosts, no containers) with
  tiers held at `experimental`/`compile-only` and NetBSD `unsupported`.
  The grammar proof caught and fixed three shipped defects plus the
  macOS rate-limit impossibility (now a typed admission rejection).
- **D (hygiene audit):** evaluated against the binding Phase 47 bar (7
  items: purpose pass, hidden-requirements mostly-pass with
  metrics/tracing note, MSRV/semver-policy/examples/consumer-docs fail,
  deterministic tests pass, burden unjustified for one consumer).
  Out-of-workspace tarball evidence collected (package assembles; 48 lib
  tests pass standalone; 3 workspace-bound tests fail standalone by
  design and re-home at extraction). No `cargo publish` of any form.
- **E (extraction shape):** recorded as future-split sketch inside the
  RETAIN record, not executed.
- **F (repository truth):** `architecture/icmp_filter.md` (tiers,
  macOS rate restriction, §8 built state, §9 residuals),
  `docs/FEATURE_STATUS.md` + `docs/PLATFORM_SUPPORT.md` (lane tiers +
  NetBSD exclusion), `icmp_filter` skill (enforce/metrics/verify
  invariants), roadmaps closed. No class-3 promise marked anywhere.

## Verification evidence (implementation head)

- `cargo fmt --all -- --check`: pass.
- `cargo test -p synvoid-icmp-filter --profile ci` (also
  `--features icmp-pf`): 51 lib (incl. 2 native syntax + 1 admission) +
  5 + 12 + 7 pass.
- `cargo test -p synvoid-icmp-filter --doc --profile ci`: 3 pass.
- `RUSTDOCFLAGS="-D warnings" cargo doc -p synvoid-icmp-filter
  --no-deps`: clean.
- `cargo check --no-default-features --features icmp-filter
  --profile ci`: pass.
- `cargo xtask test guards`: 3/3 pass.
- `cargo xtask verify`: **10/10 pass** (504s).
- `cargo deny check`: pass; `cargo audit`: no new findings.
- `cargo package -p synvoid-icmp-filter --allow-dirty --no-verify`:
  assembles (25 files).

## Campaign closeout (Phases 85–88)

All four phases implemented and closed; no plan in this campaign remains
executable. No registered future plan is blocked on this campaign: the
RETAIN verdict registers triggers, not ordered work. The roadmap
(`plans/roadmap.md` + campaign roadmap) records terminal state below.
