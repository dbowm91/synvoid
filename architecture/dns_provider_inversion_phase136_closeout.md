# Phase 136 Closeout: Campaign Qualification and Truthful Closeout

Date: 2026-10-05
Plan: `plans/phase_136_dns_provider_inversion_qualification.md`
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
Campaign closeout: `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`
Disposition: **CLOSED QUALIFIED**

## What this phase did

Phases 131–135 made changes. This phase proved what the terminal state actually
is, and corrected the record wherever the campaign had been imprecise. It wrote
no production code and changed no behavior; the one substantive thing it found
is **F-18**, and it is a finding about how the previous five phases' results
must be *stated*, not about the code.

The phase plan's own acceptance criteria required that no edge-removal claim be
made without `cargo metadata` / `cargo tree` proof, and that
`synvoid-config` not be described as absent if it were still transitively
present. The first requirement produced F-18. The second produced a correction
to the Phase 136 plan, which had expected `synvoid-config` to survive
transitively and does not.

## F-18 — the terminal closure measurement is feature-conditional

**Severity: medium. Recorded, not fixed.** It is not a defect in the code; it is
a defect in how the result was about to be described, and the phase caught it by
actually re-running the measurement rather than carrying the Phase 135 number
forward.

`synvoid-mesh` is declared `optional = true` in `crates/synvoid-dns/Cargo.toml`.
A plain `cargo tree -p synvoid-dns -e normal` therefore does not include it, and
every closure figure in the campaign closeout — 838, 827, 717, 552 — is the
**default-feature** closure. Enabling the one remaining optional edge:

```text
$ cargo tree -p synvoid-dns -e normal | wc -l
552
$ cargo tree -p synvoid-dns -e normal --features mesh | wc -l
2047
```

Under `--features mesh`, all five dependencies removed across Phases 128, 129,
134, and 135 are back in DNS's normal closure — `synvoid-config`, `synvoid-core`,
`synvoid-utils`, `synvoid-tls`, `synvoid-geoip` — and they add **1495 lines**.

Every one arrives the same way. None is a direct DNS edge:

```text
$ cargo tree -p synvoid-dns -e normal --features mesh -i synvoid-geoip
synvoid-geoip
└── synvoid-mesh -> synvoid-dns
```

So two statements are simultaneously true and must be kept apart:

- **Direct edges: 2.** Unchanged by the feature flag. `synvoid-dns` still
  depends on exactly one required sibling (`synvoid-dnssec-keystore`) plus
  optional `synvoid-mesh`. The campaign's structural work is intact.
- **Default-feature closure: 552, with all five removed crates absent.** Also
  intact.
- **Mesh-feature closure: 2047, with all five present transitively.** This is
  what a mesh-enabled build of anything depending on `synvoid-dns` actually
  links.

The campaign closeout, `AGENTS.md`, `architecture/dns.md`, and
`architecture/overview.md` all previously carried an unqualified "absent from
the normal closure". All four were corrected to say **default-feature** closure,
with the mesh figure alongside.

**Why it is not fixed:** making it true would require inverting mesh, which is
out of scope by plan and needs its own design phase. What Phase 136 can do is
make the claim honest, which it has done.

**Why it matters:** it converts the mesh blocker from a qualitative judgement
("8 concrete types, not a narrow seam") into a measured one. Mesh is the single
remaining blocker, and its cost is 1495 lines plus every dependency this
campaign spent four phases removing. That is the strongest evidence available
for the class-1 decision, and it arrived from a measurement nobody had run.

## Correction to this phase's own plan

The plan (Workstream A) said:

> Measure whether `synvoid-config` still appears in the expanded tree at all.
> With both providers gone from the closure it may not, and the honest statement
> is whichever the measurement shows.

The measurement showed it does not appear — in the default closure. The plan's
fallback position ("absent" and "present only transitively" are different
claims) turned out to under-enumerate: there is a third case, present only
under a non-default feature, and that is the one that applies. The plan's
rejection criterion — do not describe `synvoid-config` as absent when it is
still transitively present — would have been **violated** by the claim the plan
was steering toward. It is recorded here rather than quietly dropped.

## Dependency proof

```text
$ cargo metadata --format-version 1 --no-deps
synvoid-dns  -> synvoid-dnssec-keystore  optional=False
             -> synvoid-mesh             optional=True
```

| Crate | Phase 123 | Default closure | `--features mesh` |
|---|---|---|---|
| `synvoid-config` | yes | absent | present, via mesh |
| `synvoid-core` | yes | absent | present, via mesh |
| `synvoid-utils` | yes | absent | present, via mesh |
| `synvoid-tls` | yes | absent | present, via mesh |
| `synvoid-geoip` | yes | absent | present, via mesh |
| `synvoid-dnssec-keystore` | yes | present (required) | present |
| `synvoid-mesh` | yes (optional) | excluded by default | present |

Trajectory, default-feature closure, consistent across all five measurements:

| Point | Direct edges | Expanded lines |
|---|---|---|
| Phase 123 baseline | 7 | 838 |
| Phase 130 | 4 | 827 |
| Phase 133 | 4 | 827 |
| Phase 134 | 3 | 717 |
| Phase 135 | 2 | 552 |

The campaign target of 2 direct edges is met. The trajectory table is presented
as default-feature throughout so it is comparable row to row; the mesh figure is
reported separately, in its own row, rather than appended to a series it does
not belong to.

## Parity

Both ledgers unchanged, which is the point — this campaign changed whether a
setting takes effect and who owns a capability, not the persisted→runtime
projection.

| Suite | Result |
|---|---|
| root `tests/dns_runtime_config_parity.rs` | **43/43**, unchanged all campaign |
| `crates/synvoid-dns/tests/runtime_config_absent_by_design.rs` | **15/15**, unchanged |
| `synvoid-config` (`dns_schema_contract`, `example_configs_parse`, `encrypted_transport_schema`, +3) | 6 suites pass |
| root `tests/dns_zone_startup_activation.rs` (Phase 132) | 4/4 |
| no new derive on any campaign DTO | confirmed — no `Serialize`, `Deserialize`, `JsonSchema`, or `ToSchema` added to a runtime DTO type |

## Qualification matrix

Every lane below was executed in Phase 136, not carried forward from an earlier
phase. All exit 0.

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --profile ci --all-targets -- -D warnings` | clean |
| `cargo test -p synvoid-dns --profile ci` | **618** lib tests, all integration suites, 0 failed |
| `cargo test -p synvoid-dns --profile ci --features mesh` | **625** lib tests (+7 mesh-gated), 0 failed |
| `cargo test -p synvoid-tls --profile ci` | 23 pass |
| `cargo test -p synvoid-geoip --profile ci` | 23 pass |
| `cargo test -p synvoid-dnssec-keystore --profile ci` | 45 pass |
| `cargo test -p synvoid-config --profile ci` | 206 pass across 6 suites |
| `cargo nextest run -p synvoid-repo-guards` | pass |
| `cargo check --no-default-features` | clean |
| `cargo check --no-default-features --features mesh` | clean |
| `cargo check --no-default-features --features dns` | clean |
| `cargo check --no-default-features --features mesh,dns` | clean |
| `cargo deny check` | advisories/bans/licenses/sources ok, exit 0 (pre-existing `thiserror` duplicate warnings only) |
| `cargo audit` | exit 0, **6 allowed warnings, 0 vulnerabilities** |
| `cargo xtask verify` | **10/10** (fmt 2.2s, clippy 94.3s, deny 1.0s, core-compile 24.4s, repo-guards 1.2s, security-regression 142.6s, root-guards 12.5s, core-admin-tests 0.5s, admin-contract 141.9s, failure-injection) |
| `./scripts/dns/conformance.sh` | internal 10/10 (5 runnable, 5 skipped) |
| Phase 131 determinism, 10 repeated parallel runs | 10/10, 5 tests each |

### Not run, with reasons

- **`cargo package -p synvoid-dns`** — fails with `no matching package named
  'synvoid-dnssec-keystore' found`. Sibling SynVoid crates are unpublished to
  crates.io. Pre-existing and unrelated to this campaign; it is also an input to
  the class decision below, which already accounts for it.
- **`cargo xtask verify-release`** — not run. It fails on a dirty tree by
  design, and this phase's own output is necessarily uncommitted while it runs.
  It was likewise not run for Phases 133–135. Not a pass and not a failure: not
  run.
- **External DNS interop lanes** (`kdig`, `ldns-verify-zone`,
  `named-checkzone`, `delv`) — the tools are not installed on this host.
  `conformance.sh` reports them as skipped, not passed.
- **The two `#[ignore]`d Eggbench live-proof suites** — they need a separately
  built binary and cannot execute as evidence here. They still contain a local
  predict-then-bind `free_port()`; see the Phase 131 closeout residuals.
- **Hosted CI** — not run. The campaign branch is pushed, but no hosted run is
  claimed as evidence for Phase 136; every lane above is local.

## Class / support decision

**`synvoid-dns` remains class 1. No promotion, no publication claim, no external
support claim, no repository claim.**

The conditions for class 2 in `architecture/public_crate_release_policy.md` are
not met:

1. **Optional `synvoid-mesh` is still a direct, concrete edge** reaching 8 types
   across DHT record storage, routing, and signed provenance. F-18 quantifies
   its weight: it alone accounts for 1495 closure lines and the return of every
   dependency removed across Phases 128/129/134/135. This is the single
   remaining blocker.
2. **The crate cannot be packaged**, because sibling SynVoid crates are
   unpublished. That is a supply-chain fact, not a code fact, and dependency
   reduction does not change it.
3. **The public API surface is not a stable contract.** The two capabilities
   introduced by this campaign are new, and the DNS runtime DTOs they sit beside
   are new since Phase 125. There is no outside-workspace consumer evidence of
   stability. The only outside-workspace evidence that exists concerns the
   configuration surface, which is not promotion and is not described as such.

What the campaign did establish is narrower, and is stated as such: the two
narrow provider seams are inverted behind DNS-owned capabilities implemented in
composition; the dependency on the shared utility, persistence, TLS, and GeoIP
crates is gone from the default closure; the crate now depends on one required
sibling plus optional mesh. That is a real reduction in coupling and a real
improvement in testability. It is not, by itself, a step toward publication
readiness, and it is not presented as one.

## Documentation reconciliation

Updated to the measured state:

- `AGENTS.md` — DNS bullet rewritten: the "4 edges", "zones never loaded", and
  "provider inversion DEFER / unregistered campaign" statements were all stale
  and are now correct, with the F-18 feature conditional stated.
- `architecture/overview.md` — DNS row updated to 2 edges / 552 default lines,
  with the mesh figure and F-18 pointer. The Phase 116/117 sentence asserting
  that the `synvoid-config` / `synvoid-core` / `synvoid-utils` edges "remain" is
  marked historical and explicitly no longer true, because the same row now
  states they are removed — the row contradicted itself.
- `architecture/dns.md` — the "**Known gap:** `[dns.zones]` is validated and
  converted… but `DnsServer::new` discards them" paragraph was still the
  pre-Phase-132 state; replaced with the activated behavior. The "4 direct
  SynVoid normal edges" paragraph corrected. The Phase 133 provider-seam
  paragraph, which said DNS "still holds concrete `synvoid-tls` and
  `synvoid-geoip` types", moved to past tense. The claim that no provider type
  is named in `crates/synvoid-dns/src` is qualified to no `use`, path, or type
  reference, because the two seam modules' doc comments do mention them in
  prose.
- `architecture/dns_application_neutral_readiness_phase109.md` — terminal
  pointer added. Its Phase 133 pointer said "the edges are still present until
  Phases 134 and 135 land"; they have landed. Its extraction verdict is
  explicitly **unchanged and still correct**, which is the point of the pointer.
- `architecture/dns_runtime_dto_conversion_research.md` — terminal pointer added;
  its "until the later provider-inversion phase" deferral is discharged.
- `architecture/dns_config_runtime_matrix.md` — Phase 136 findings section added.
- `plans/`, campaign roadmap, and the phase plan — statuses advanced.

`architecture/dns_deep_dive.md` and `architecture/dns_zone_lifecycle.md` were
checked and require no change: neither carries an edge count, a provider
concrete-type claim, or a zone-activation claim invalidated by this campaign.

## Findings

| ID | Severity | Disposition |
|---|---|---|
| F-18 | medium | terminal closure measurement is feature-conditional; recorded, strengthens the class-1 decision |
| plan error | — | the Phase 136 plan under-enumerated the possible states of `synvoid-config`; corrected here |

## Residual work left deliberately

Unchanged from the campaign closeout, and none of it authorized by this phase:

1. **mesh provider inversion** — the single remaining blocker, now measured at
   1495 closure lines. Needs its own design phase. Not registered.
2. **Wiring `[geoip]`** — a feature change with its own phase; the tripwire guard
   `geoip_provider_is_still_unwired_by_composition` makes it impossible by
   accident.
3. **ALPN for the encrypted transports** (Phase 133 F-6) — a protocol behavior
   change, not a refactor.
4. **`prefer_post_quantum` is telemetry, not a gate** (Phase 133 F-7).
5. **Zone reload atomicity** (Phase 132 F-4) — harmless at startup.
6. **Public authoritative profile not queryable over loopback** (Phase 132 F-3).

## Supersessions applied

By pointer, never by rewriting a historical record:

- `architecture/dns_runtime_dto_phase130_closeout.md` — the "zero methods on
  `CertResolver`" error and the DEFER that followed from it.
- `architecture/dns_application_neutral_readiness_phase109.md` — "not eligible"
  superseded by Phase 133; "edges still present" superseded here.
- `architecture/dns_runtime_dto_conversion_research.md` — the injected-concrete-
  `CertResolver` note superseded by Phase 133; the "later provider-inversion
  phase" deferral superseded here.
- `architecture/dns_config_runtime_matrix.md` — F-6 resolution pointer plus the
  Phase 131–136 finding sections.
