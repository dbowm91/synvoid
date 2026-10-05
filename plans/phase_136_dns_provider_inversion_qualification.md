# Phase 136 Plan: Campaign Qualification and Truthful Closeout

Status: **CLOSED QUALIFIED** (2026-10-05).

Closeout: `architecture/dns_provider_inversion_phase136_closeout.md`.
Campaign closeout: `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`.

> **Outcome note.** Re-running the measurement rather than carrying Phase 135's
> number forward produced **F-18**: `synvoid-mesh` is `optional`, so every
> closure figure in this campaign (838 / 827 / 717 / 552) is the
> **default-feature** closure. Under `--features mesh` the closure runs 2047
> lines and all five dependencies removed across Phases 128/129/134/135 return
> transitively through mesh. The direct-edge count of 2 is unaffected, and the
> structural result stands, but Workstream A's unqualified "absent" framing below
> is superseded — see the closeout. This also means Workstream A's own rejection
> criterion ("do not describe `synvoid-config` as absent when it is still
> transitively present") nearly fired on the claim this plan steered toward;
> the plan under-enumerated the possible states, and the correction is recorded
> rather than dropped.

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 135.
Registered in: `plans/roadmap.md`.

## Goal

Qualify the campaign terminal state: re-prove the dependency graph from
`cargo metadata` / `cargo tree`, re-run every parity ledger, run the full
qualification matrix, reconcile documentation, and record an honest class /
support decision.

## Workstream A — dependency proof

Measure, never carry forward:

```bash
cargo metadata --format-version 1 --no-deps   # direct SynVoid deps of synvoid-dns
cargo tree -p synvoid-dns -e normal | wc -l
cargo tree -p synvoid-dns -e normal -i synvoid-tls
cargo tree -p synvoid-dns -e normal -i synvoid-geoip
cargo tree -p synvoid-dns -e normal -i synvoid-config
```

Target, to be proven rather than assumed:

```text
synvoid-dns
  -> synvoid-dnssec-keystore   # deliberate security leaf
  -> synvoid-mesh (optional)   # provider inversion deferred by design
```

**Stronger than the original target, and the plan's expectation is corrected
accordingly.** The plan assumed `synvoid-tls` and `synvoid-geoip` would survive
as transitive providers behind DNS-owned traits. They did not: neither appears
anywhere in `synvoid-dns`'s normal closure, which is why the expanded tree fell
far further than two edge removals would suggest.

Trajectory, to be measured here rather than carried forward:

| Point | Direct SynVoid normal edges | Expanded `cargo tree -e normal` lines |
|---|---|---|
| Phase 123 baseline | 7 | 838 |
| Phase 130 | 4 | 827 |
| Phase 133 (evidence gate) | 4 | 827 |
| Phase 134 (TLS inverted) | 3 | 717 |
| Phase 135 (GeoIP inverted) | **2** | **552** |

Measure whether `synvoid-config` still appears in the expanded tree at all. With
both providers gone from the closure it may not, and the honest statement is
whichever the measurement shows: "absent" and "present only transitively" are
different claims, and the Phase 130 record made the second while this plan
expected it to remain true.

## Workstream B — parity

- root `tests/dns_runtime_config_parity.rs` — must remain 43/43;
- `crates/synvoid-dns/tests/runtime_config_absent_by_design.rs` — must remain
  15/15;
- `crates/synvoid-config/tests/{dns_schema_contract,example_configs_parse,encrypted_transport_schema}.rs`;
- zone-startup proof from Phase 132 re-run end to end;
- no new derive (`Serialize`, `Deserialize`, `JsonSchema`, `ToSchema`) on any
  runtime DTO type added by this campaign.

The parity suite count being **unchanged** is the point: this campaign changed
whether a setting takes effect and who owns a capability, not the
persisted→runtime projection.

## Workstream C — functional qualification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-tls --profile ci
cargo test -p synvoid-geoip --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-dnssec-keystore --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo deny check
cargo audit
cargo xtask verify
cargo xtask verify-release   # only after the tree is committed: it fails on a dirty tree
./scripts/dns/conformance.sh
```

Record every skipped or degraded lane truthfully, with the reason. Specifically
expected to remain unavailable:

- `cargo package -p synvoid-dns` fails because sibling SynVoid crates are
  unpublished to crates.io — pre-existing, not a regression;
- external DNS interop lanes (kdig, ldns-verify-zone, named-checkzone) are
  skipped when the tools are absent.

Re-run the Phase 131 repeated-run determinism matrix.

## Workstream D — documentation reconciliation

- `architecture/dns.md` — startup zone activation plus both inverted providers;
- `architecture/dns_config_runtime_matrix.md` — every finding F-1…F-12+ with its
  resolution;
- `architecture/overview.md` — DNS row and dependency counts corrected to the
  measured values;
- `architecture/dns_application_neutral_readiness_phase109.md` — supersession
  pointer, historical evidence preserved;
- `architecture/dns_runtime_dto_conversion_research.md`;
- `architecture/dns_runtime_dto_phase130_closeout.md` — corrected pointer for the
  `CertResolver` method-count error;
- `AGENTS.md`, `plans/roadmap.md`, the campaign roadmap, and this plan.

`architecture/dns_deep_dive.md` and `architecture/dns_zone_lifecycle.md` are
checked and changed only if the measured state requires it.

## Workstream D2 — the two behavior changes must be stated, not buried

Phase 135 changed runtime behavior twice, and both are operator-visible:

1. **F-1**: `GeoIpManager::new` no longer panics on `[geoip] enabled = true` with
   no download credentials.
2. **F-2**: a `GeoLocation` rule that cannot be evaluated now applies its action
   when that action is restrictive. Previously every geo rule silently became a
   no-op.

The campaign closeout must state the second prominently, because of F-17:
**`[geoip]` is constructed nowhere in composition**, so a configured restrictive
geo rule now blocks *all* DNS traffic rather than silently allowing it. That is
the correct fail-closed direction and it is loud, but it is a visible change for
an operator who has such a rule configured. The operator recourse is to disable
the rule. This belongs in the campaign closeout summary, not only in the Phase
135 closeout detail.

## Workstream E — class / support decision

`synvoid-dns` remains **class 1** unless this campaign satisfies the standalone
contract in `architecture/public_crate_release_policy.md`. With mesh still
concrete, the contract is not satisfied. Record:

- the measured dependency state;
- exactly which conditions for class 2 remain unmet;
- that no publication, repository, or support claim is made.

The outside-workspace consumer evidence is about the configuration surface
only. It is not promotion, and this plan says so explicitly.

## Acceptance criteria

- dependency state proven by `cargo metadata` / `cargo tree`, not asserted;
- parity ledgers unchanged and green;
- full qualification matrix green, or residuals recorded with reasons;
- documentation matches the measured graph;
- class/support status is not overstated;
- the campaign closeout lists every carried-forward finding and its resolution;
- both Phase 135 behavior changes are stated in the campaign closeout, and the
  F-17 consequence of F-2 is stated with it.

## Rejection criteria

Reject a closeout that:

- claims an edge is gone without `cargo metadata` / `cargo tree` proof;
- describes `synvoid-config` as absent when it is still transitively present;
- records a skipped lane as passing;
- treats the outside-workspace consumer as class-2 promotion;
- rewrites prior closeouts instead of superseding them by pointer.

## Closeout

`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`.
