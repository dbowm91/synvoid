# Phase 130 Closeout — DNS Runtime-DTO Qualification and Provider-Inversion Gate

Date: 2026-10-05.
Plan: `plans/phase_130_dns_runtime_dto_qualification_provider_gate.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Predecessor: Phase 129 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase129_closeout.md`).
Disposition: **CLOSED QUALIFIED**. The campaign is complete.

## Campaign result

The DNS runtime-DTO campaign is done. `synvoid-dns` consumes DNS-owned runtime
values end to end, depends only on genuine providers, and the persisted-schema
edge is gone. This phase is the terminal qualification: it re-proves the
dependency graph from `cargo metadata` / `cargo tree`, re-runs every parity
ledger, qualifies the crate functionally, reconciles documentation, and
records the provider-inversion decision.

## Workstream A — dependency proof

Measured, not carried forward from the Phase 129 closeout:

```text
cargo metadata --no-deps -p synvoid-dns  →  4 direct SynVoid normal edges
cargo tree -p synvoid-dns -e normal      →  827 expanded lines
```

| SynVoid dependency | kind | optional |
|---|---|---|
| `synvoid-tls` | normal | no |
| `synvoid-geoip` | normal | no |
| `synvoid-dnssec-keystore` | normal | no |
| `synvoid-mesh` | normal | **yes** |

Feature graph: `default = []`, `hsm = ["synvoid-dnssec-keystore/pkcs11"]`,
`mesh = ["dep:synvoid-mesh", "synvoid-mesh/mesh"]`.

`cargo tree -p synvoid-dns -e normal -i synvoid-config` gives the complete
residual picture, and it is the single most important fact in this closeout:

```text
synvoid-config
├── synvoid-geoip
│   └── synvoid-dns
└── synvoid-tls
    └── synvoid-dns
```

- `synvoid-config` — **no direct edge**. Present in the expanded tree only
  through the two provider crates.
- `synvoid-core` — **absent entirely**, direct and transitive.
- `synvoid-utils` — **absent entirely**, direct and transitive.

Campaign trajectory: **7 edges / 838 expanded lines** (Phase 123 baseline) →
**4 edges / 827 lines**. The 11-line difference from the Phase 123 count is
the removal of three direct edges whose closures were largely shared with the
surviving providers; the 9-line gap between the Phase 123 figure and the
847-line figure measured at Phase 126 was pre-existing drift, not introduced
by this campaign.

Package contents were inspected via `cargo package`; see Workstream C for the
one lane that could not complete.

## Workstream B — runtime/persistence parity

| Ledger | Result |
|---|---|
| `tests/dns_runtime_config_parity.rs` (root) | **43/43** — defaults, all shipped `examples/dns/*.toml`, every runtime group, invalid bind/port, open-resolver rejection, Phase 45 fail-closed paths |
| `crates/synvoid-dns/tests/runtime_config_absent_by_design.rs` | **15/15** — no persisted schema leaks into the runtime vocabulary |

The parity suite count is unchanged from Phase 125. That is the point: the
campaign changed *ownership*, not the persisted→runtime projection. No
persisted schema, default, or admin API drift occurred; the only intended
behavior change in the whole campaign remains Phase 125 finding F-3
(`dns.dns64.prefix` now fails closed instead of warning and defaulting).

Persisted-schema coverage relocated to `crates/synvoid-config/tests/` in Phase
128 is re-run here and green: `example_configs_parse` (7),
`encrypted_transport_schema` (5), `dns_schema_contract` (89).

## Workstream C — DNS functional qualification

All green:

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass |
| `cargo test -p synvoid-dns --profile ci` | pass — 609 lib tests + all integration suites |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass — 616 lib tests; the optional feature does not reintroduce a removed edge |
| `cargo test -p synvoid-config --profile ci` | pass — 98 + 89 + 5 + 7 + 2 |
| `cargo test -p synvoid-dnssec-keystore --profile ci` | pass — 30 + 12 + 3 |
| `cargo check --no-default-features --features dns` | pass |
| `cargo check --no-default-features --features mesh,dns` | pass |
| `cargo test -p synvoid-repo-guards --profile ci` | pass |
| `cargo deny check` | pass — advisories, bans, licenses, sources all ok |
| `cargo audit` | 6 allowed warnings, identical to the pre-campaign baseline |
| `cargo xtask verify` | **10/10** |
| `scripts/dns/conformance.sh` | **9/9 internal**, external 5 runnable / 5 skipped |

### Skipped / degraded lanes, recorded truthfully

- **`cargo package -p synvoid-dns` cannot complete.** It fails with
  `no matching package named 'synvoid-dnssec-keystore' found`, because the
  sibling SynVoid crates are not published to crates.io. This is expected for
  unpublished internal crates and is **not** a regression.
- **`cargo xtask verify-full` was not run.** It performs one full-workspace
  `nextest` run plus doctests; the campaign's bounded matrix and
  `cargo xtask verify` were green, and the phase scope did not require the
  broader lane. Recorded as not-run rather than as passing.
- **External DNS interop lanes are placeholders by design.** The script reports
  5 runnable (dig, delv, curl present) and 5 skipped (kdig,
  ldns-verify-zone, named-checkzone not installed). These are not in CI and
  each requires a running `DnsServer`; none executes live-wire assertions.

### Outside-workspace consumer (evidence only — **not** class-2 promotion)

Because `cargo package` cannot run, the consumer evidence was gathered against
a **path dependency** from a scratch crate outside the workspace. It builds and
runs, and prints `outside-workspace consumer OK`. What it proves:

1. A crate outside the workspace can build the full DNS runtime configuration
   from DNS-owned values alone, with no `synvoid-config` dependency.
2. `AuthoritativeRuntimeConfig` and `RecursiveRuntimeConfig` have **no `Default`
   impl**. An outside consumer must state every value; there is no hidden
   default that could silently diverge from the persisted schema's defaults.
   This is a deliberate property of the runtime DTO, and it is the strongest
   single piece of evidence that no hidden configuration assumption survives.
3. `net_policy::is_restricted_ip`, `time::unix_timestamp_secs`, and
   `lifecycle::LifecycleState` are reachable through the public surface, so an
   outside consumer never needs `synvoid-core` / `synvoid-utils`.

This does **not** make the crate class 2. TLS, GeoIP, and mesh concrete edges
remain, and the campaign's Workstream F forbids treating this as promotion.

## Workstream D — documentation reconciliation

Updated to the actual dependency graph:

- `architecture/dns.md` — canonical constructor, the runtime-neutral
  dependency set, and a table of the DNS-owned helper modules with
  `net_policy` flagged as a security boundary.
- `architecture/dns_config_runtime_matrix.md` — Phase 128 and Phase 129
  findings appended (F-5…F-10).
- `architecture/dns_application_neutral_readiness_phase109.md` — **superseded
  by a pointer, not rewritten**. Its Phase 109 findings and DEFER disposition
  remain intact as historical evidence; a Phase 130 pointer records that the
  prerequisite is delivered and that the DEFER stands.
- `architecture/dns_runtime_dto_conversion_research.md` — status moved to
  IMPLEMENTATION COMPLETE, with the precondition explicitly marked met and the
  provider-inversion result explicitly distinguished from it.
- `architecture/overview.md` — DNS row and dependency-count claim corrected
  from "six required" to four.
- `AGENTS.md`, `plans/roadmap.md`,
  `plans/dns_runtime_dto_conversion_roadmap.md`, the Phase 130 plan.

`architecture/dns_deep_dive.md` was checked and needed no change: it contains no
`synvoid-config` / `synvoid-core` / `synvoid-utils` or per-phase references.

## Workstream E — provider-inversion readiness: **DEFER**

The Phase 123 precondition — remove the `synvoid-config`, `synvoid-core`, and
`synvoid-utils` edges with parity proof — is now **met and proven**. That was
necessary but not sufficient. Each remaining concrete edge was evaluated
separately, against the evidence its own gate requires.

### TLS — narrow seam, missing transport evidence

The surface is remarkably small:

- `CertResolver` — stored and forwarded. DNS calls **zero** methods on it; it
  is handed to `SecureDnsServerBase`, which passes it toward rustls.
- `AcmeDnsChallenge::get_txt_value(..)` — **one** method.

So DNS is not mirroring `CertResolver`'s API; it is holding an opaque
certificate provider. That is a good sign for invertibility.

What is missing: `CertResolver` is consumed at the **rustls** boundary, so
inverting it means DNS needs a `ResolvesServerCert`-shaped capability, and none
of the gate's required evidence exists in-repo yet — SNI behavior, reload
semantics, private-key ownership, ALPN, and DoT/DoH/DoQ startup/failure parity.
None of those can be inferred from "DNS calls no methods on it", because the
behavior lives entirely on the far side of the type.

**Verdict: DEFER.** Feasible seam; evidence not yet produced.

### GeoIP — one method, one mirrorable type, no fallback proof

- `GeoIpManager::get_country_info(IpAddr) -> Option<CountryInfo>` — the only
  method called, in `server/query.rs` for mesh edge steering.
- `GeoLocation::contains(IpAddr, Option<&Arc<GeoIpManager>>)` in the firewall,
  which is itself a DNS type parameterized by the provider.

Again a narrow seam: one method, one return type (`CountryInfo` →
`code`/`name`/`subdivision`/`city`), which a DNS-owned mirror would absorb
without mirroring `GeoIpManager`.

What is missing: the gate requires missing-DB behavior, unknown location,
privacy/logging, health+Geo ordering, and deterministic fallback to be proven.
None are. The `Option<...>` threading through `startup.rs`, `query.rs`,
`firewall.rs`, and the mesh registry means the *absence* case is currently
expressed by `None` at six call sites, and no test pins what each of them does
when the database is missing.

**Verdict: DEFER.** Feasible seam; evidence not yet produced.

### Mesh — not narrow; a distributed-authority surface

Eight types, versus two for TLS and one for GeoIP:

`MeshTransport`, `RecordStoreManager`, `DhtRoutingManager`, `SignedDhtRecord`,
`SignedRecordType`, `MeshMessage`, `ZoneSyncRequest`, `MeshNodeRole`.

This is not a provider lookup surface; it is a distributed-record authority
surface, where `synvoid-dns` participates in DHT record storage, routing
decisions, and signed-record provenance. The gate's required proof —
provenance, freshness, canonical-vs-advisory authority, DNSSEC metadata
ownership, partition/failure behavior — is precisely the set of questions that
cannot be answered by a trait signature. Inverting this edge is a design
project, not a mechanical substitution.

**Verdict: DEFER.** Not a narrow seam; not ready to register.

### Terminal decision

**DEFER.** The campaign's own precondition is satisfied, so the prerequisite
work is complete and no longer blocks anything. But provider inversion is not
ready to register, for three separate and independently sufficient reasons:

1. TLS and GeoIP are narrow enough to invert, and neither has the transport /
   fallback evidence its gate requires.
2. Mesh is not a narrow seam at all and needs a design phase before it can even
   be scoped.
3. No provider-inversion plan is registered, and this phase explicitly must not
   create one.

Missing seams/evidence, for whoever picks this up:

- **TLS** — a rustls-shaped certificate capability; proof of SNI, reload,
  private-key ownership, ALPN, and DoT/DoH/DoQ startup and failure parity.
- **GeoIP** — a narrow country-lookup capability with a DNS-owned result type;
  proof of missing-DB, unknown-location, privacy/logging, health+Geo ordering,
  and deterministic fallback at all six `Option<GeoIpManager>` sites.
- **Mesh** — a typed capability for DHT record storage, routing, and signed
  provenance, preceded by a design phase covering provenance, freshness,
  canonical-vs-advisory authority, DNSSEC metadata ownership, and
  partition/failure behavior.

## Workstream F — class / support status

`synvoid-dns` **remains class 1** throughout and after this campaign. No
crates.io publication, no new repository, and no class/support/promotion claim
is authorized or made. The outside-workspace consumer build in Workstream C is
evidence about the configuration surface only; treating it as promotion is
explicitly a rejection criterion of this plan.

## Findings

### F-1: the DNS conformance script had two stale test lanes

Phase 128 moved `example_configs_parse` and `dns_interop_encrypted` from
`synvoid-dns` to `synvoid-config`, but `scripts/dns/conformance.sh` still
listed them as `synvoid-dns` targets, so the script reported failures for tests
that no longer exist there. Fixed by adding a `run_internal_pkg` helper and
pointing both lanes at their new home.

Worth noting: the lane named `dns_interop_encrypted` was **already** purely
persisted-schema round-trip assertions despite the `dns_interop_` prefix — no
wire bytes, no `handle_query()` call. So moving it lost no protocol coverage;
the name was simply misleading. The comment left at the call site records this
so the lane is not re-added by someone assuming it was deleted.

### F-2: the conformance script could not run at all on macOS

`declare -A TOOL_FOUND` (from Phase 45, commit `69a47c68`) is a bash-4
associative array. macOS ships bash 3.2, where `declare -A` is a fatal error,
so the script aborted before printing its external-lane status. Pre-existing
and unrelated to this campaign, but it meant the DNS conformance lane was
unrunnable on the primary developer platform — including for this phase, which
is required to report that lane.

Replaced with a lookup function over a fixed tool list. The script now runs
end to end on bash 3.2 and reports 9/9 internal with an honest external
summary.

### F-3: `dns_phase45_contract` is flaky under rapid successive runs

Observed failing once inside a full conformance run, then passing 5/5 standalone
and in the next full run. The cause is the documented TOCTOU race in
`free_port()`: it binds an ephemeral port, reads it, and releases it, so a
concurrently starting test can claim the same port between release and bind.
All four tests in the suite bind real loopback listeners.

Not a regression from this campaign — the same race exists in
`transport_lifecycle.rs` and predates it — but it makes the conformance lane
intermittently red, so it is recorded rather than smoothed over. A successor
should either hold the reservation socket open until the server binds, or
serialize the listener tests.

**Resolved by Phase 131** (`architecture/dns_provider_inversion_phase131_closeout.md`).
The first suggested remedy turned out to be impossible: `DnsServer::start`
binds UDP and TCP on the same port internally, so a held reservation cannot
protect it. Phase 131 removed the assumption instead — the server performs the
real bind and a new port is taken only when that bind is observed to have lost a
race. See matrix F-11.

## Campaign closeout

| Phase | Disposition | Closeout |
|---|---|---|
| 125 | CLOSED QUALIFIED | `dns_runtime_dto_phase125_closeout.md` |
| 126 | CLOSED QUALIFIED | `dns_runtime_dto_phase126_closeout.md` |
| 127 | CLOSED QUALIFIED | `dns_runtime_dto_phase127_closeout.md` |
| 128 | CLOSED QUALIFIED | `dns_runtime_dto_phase128_closeout.md` |
| 129 | CLOSED QUALIFIED | `dns_runtime_dto_phase129_closeout.md` |
| 130 | CLOSED QUALIFIED | this document |

The campaign's success criteria are met: production
`crates/synvoid-dns/src/**` contains zero `synvoid_config` references; the
normal `synvoid-config` dependency is removed; `synvoid-core` and
`synvoid-utils` are removed outright; parity is exhaustive and green; DNSSEC
custody stayed one-way through `synvoid-dnssec-keystore` throughout; and no
provider trait was implemented, no class/support status changed, and no
persisted schema, default, or admin API drifted.

The next DNS work is a **separate** provider-inversion campaign, which this
closeout records as **DEFER** and does not register.
