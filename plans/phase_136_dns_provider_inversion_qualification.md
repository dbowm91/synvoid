# Phase 136 Plan: Campaign Qualification and Truthful Closeout

Status: **PLANNED** (2026-10-05).

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

with `synvoid-tls` and `synvoid-geoip` present only as transitive providers
behind DNS-owned traits. State the full trajectory: 7 / 838 (Phase 123) → 4 /
827 (Phase 130) → measured here.

`synvoid-config` will still appear in the expanded tree through
`synvoid-tls` and `synvoid-geoip`; that is expected and must be described
precisely rather than described as "absent".

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
cargo xtask verify-release
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
- the campaign closeout lists every carried-forward finding and its resolution.

## Rejection criteria

Reject a closeout that:

- claims an edge is gone without `cargo metadata` / `cargo tree` proof;
- describes `synvoid-config` as absent when it is still transitively present;
- records a skipped lane as passing;
- treats the outside-workspace consumer as class-2 promotion;
- rewrites prior closeouts instead of superseding them by pointer.

## Closeout

`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`.
