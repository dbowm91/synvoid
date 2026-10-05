# DNS Startup Truthfulness and Provider-Inversion Roadmap

Status: **CLOSED QUALIFIED** (2026-10-05). Phases 131–136 all closed.

Campaign closeout: `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`.

> Terminal state: the three carry-forward findings are all resolved; the two
> narrow provider seams are inverted; `synvoid-dns` stands at **2 direct SynVoid
> normal edges** (`synvoid-dnssec-keystore` + optional `synvoid-mesh`), down
> from 7, with the default-feature normal closure at **552** lines (from 838).
> `synvoid-dns` remains **class 1**. mesh inversion is the single remaining
> blocker and is not registered here. The closure figures are default-feature
> only — see **F-18** in the closeout.

Umbrella for the three findings the DNS runtime-DTO campaign
(Phases 125–130, all CLOSED QUALIFIED) explicitly carried forward rather than
fixing in place. That campaign was scoped to configuration *ownership*, so each
of these was a behavior or evidence change outside it:

| Carry-forward | Source | Nature |
|---|---|---|
| `[dns.zones]` validated and converted, then discarded | Phase 128 F-2 / matrix F-6 | product defect — shipped examples advertise zones that never load |
| `free_port()` TOCTOU makes the DNS conformance lane intermittently red | Phase 130 F-3 | test determinism |
| Provider inversion recorded **DEFER** | Phase 130 Workstream E | architecture — prerequisite now met |

## Scope

Items 1–3 below are stated as they were **registered**, in the present tense of
the problem. All three are now **closed**; the resolution is noted on each, and
the original wording is left as the record of what was carried forward.

1. **Authoritative zone startup activation.** `DnsRuntimeConfig.zones` is
   converted field-by-field by the application adapter, reaches
   `DnsServer::new(..)`, and is dropped at
   `crates/synvoid-dns/src/server/mod.rs:1775` (`zones: _`).
   `DnsServer::load_zones(Vec<ZoneSpec>)` has no production caller, and neither
   does `load_zones_from_store`. Four shipped examples —
   `examples/dns/authoritative_public.toml`, `dnssec_signed.toml`,
   `transfer_primary.toml`, `encrypted_dot_doh.toml` — declare
   `[[dns.zones.items]]`, so an operator copying one gets an authoritative
   server that serves nothing for the zone it declares.
   → **CLOSED, Phase 132.** Composition calls `load_zones` at
   `src/server/resources.rs:169` and fails startup closed. Wiring it exposed two
   hidden defects, both fixed: record names could never match, and all four
   shipped examples declared a record-less zone (now rejected by `validate()`).
2. **Provider inversion of the two narrow seams.** `synvoid-tls` and
   `synvoid-geoip` are inverted behind DNS-owned capabilities implemented in a
   composition root. `synvoid-dns` drops from 4 direct SynVoid normal edges to
   2 (`synvoid-dnssec-keystore` plus optional `synvoid-mesh`).
   → **CLOSED, Phases 133–135.** GO at 133 for both, inverted at 134 (TLS) and
   135 (GeoIP). 4 → 3 → 2 direct edges. The mesh edge remains and is heavier
   than its arity suggests — see F-18.
3. **Conformance determinism.** The `free_port()` reservation race is removed
   so the DNS conformance lane is a trustworthy evidence source for the phases
   above.
   → **CLOSED, Phase 131.** The obvious remedy (hold the reservation until
   bind) is structurally impossible, because `DnsServer::start` binds UDP and
   TCP on the same port internally. The server now performs the real bind and
   retries only on an observed lost race. 10/10 repeated parallel runs at
   terminal qualification.

## Explicit non-goals

1. **No mesh provider inversion.** Phase 130 judged the mesh edge not a narrow
   seam at all: eight types across DHT record storage, routing, and signed
   provenance. It needs a design phase and stays out of this campaign.
2. **No class/support/promotion claim.** `synvoid-dns` remains class 1
   throughout. This campaign is not authorized to change that.
3. **No persisted TOML/OpenAPI/admin schema drift**, except where Phase 132
   changes whether a *documented* setting takes effect rather than what it
   parses to.
4. **No `synvoid-config` → `synvoid-dns` dependency**, and no
   composition-owned type leaking into `synvoid-dns`.
5. **No DNSSEC custody change.** Private-key authority stays one-way through
   `synvoid-dnssec-keystore`; zone activation must not widen it.
6. **No new root module or crate** unless `architecture/root_module_ledger.md`
   requires it.

## Execution order

1. **Phase 131 — DNS conformance determinism** — `free_port()` TOCTOU
   remediation. Small, and it comes first so every later phase's evidence is
   recorded on a non-flaky lane.
2. **Phase 132 — Authoritative zone startup activation** — the product defect.
   Sequenced before inversion because it is user-visible and independent of it.
3. **Phase 133 — Provider-inversion evidence gate (TLS + GeoIP)** — produce the
   evidence Phase 130 found missing and re-gate. No inversion here.
   **CLOSED QUALIFIED — GO for both providers**
   (`architecture/dns_provider_inversion_phase133_closeout.md`). The evidence
   exists as 47 tests, and the seams are narrower than Phase 130 recorded: TLS
   is two traits over one method, GeoIP is one trait over two methods. Twelve
   findings; two are high severity and both are carried into Phase 135 as
   mandatory workstreams — a config-reachable panic in `GeoIpManager::new`
   (F-1) and a GeoLocation block rule that silently allows traffic when no
   provider is configured (F-2).
4. **Phase 134 — TLS provider inversion** — remove the `synvoid-tls` direct
   edge. **CLOSED QUALIFIED**
   (`architecture/dns_provider_inversion_phase134_closeout.md`). Direct SynVoid
   normal edges 4 → 3; expanded normal-tree lines 827 → 717. Three call sites,
   not one: DoT/DoH share `SecureDnsServerBase` and DoQ has its own QUIC copy of
   the same contract (F-12), all three converted together. `synvoid-tls` is gone
   from DNS's normal closure entirely.
5. **Phase 135 — GeoIP provider inversion** — remove the `synvoid-geoip`
   direct edge. **CLOSED QUALIFIED**
   (`architecture/dns_provider_inversion_phase135_closeout.md`). Direct SynVoid
   normal edges 3 → **2** — the campaign target; expanded normal-tree lines
   717 → 552. F-1 and F-2 are fixed (two recorded behavior changes), plus two
   new findings: F-16, an ASN-scoped geo rule was unmatchable; and F-17,
   `[geoip]` is constructed nowhere in composition, so wiring it is a feature
   change and now has a tripwire guard.
6. **Phase 136 — Campaign qualification** — terminal dependency proof, parity
   re-run, documentation reconciliation, class decision.

Each phase is a rollback and evidence boundary. Phases 134 and 135 are
independent and either may be re-scoped if its evidence gate fails. Phase 133
corrected the sizing assumption: the GeoIP seam is two methods over one result
type, and it also carries two high-severity findings (F-1, F-2) that are
mandatory Phase 135 workstreams rather than inversion work.

## Campaign success criteria

- `[[dns.zones.items]]` in a shipped example produces a served zone, proven by
  a test, with startup failing closed on an invalid zone;
- the DNS conformance lane is deterministic across repeated runs;
- the per-provider evidence Phase 130 listed as missing exists as executable
  tests, not prose;
- `synvoid-dns` has no direct normal edge on `synvoid-tls` or `synvoid-geoip`,
  proven by `cargo metadata` / `cargo tree` — **met in Phase 135**;
- the root 43-fixture adapter parity ledger and the 15-test
  `runtime_config_absent_by_design` suite are unchanged and green;
- `synvoid-tls` and `synvoid-geoip` survive in the expanded tree only as
  providers behind DNS-owned traits, implemented in composition;
- documentation matches the measured graph.

## Campaign rejection criteria

Reject a closeout that:

- activates zones without a startup failure path, or swallows a bad zone with a
  warning;
- makes `synvoid-dns` depend on a trait that leaks `synvoid-tls` or
  `synvoid-geoip` types in its signature;
- implements a provider trait inside a request-path module instead of
  composition;
- claims an edge is removed without `cargo metadata` / `cargo tree` proof;
- records a skipped lane as passing;
- changes persisted schema, defaults, or the admin API as a side effect;
- promotes `synvoid-dns` to class 2, or treats dependency reduction as
  publication readiness.

## Relationship to prior DNS campaigns

- Phases 105–114 (`plans/subsystem_boundary_extraction_roadmap.md`) — closed;
  dispositions unchanged.
- Phases 115–124 (`architecture/public_crate_release_policy.md`) — closed;
  `synvoid-dns` remains class 1.
- Phases 125–130 (`plans/dns_runtime_dto_conversion_roadmap.md`) — CLOSED
  QUALIFIED. This campaign continues from its terminal state and does not
  rewrite its evidence.

See `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md`
for the campaign closeout.

## Successor campaign (pointer, recorded 2026-10-05)

This campaign's residuals were re-scoped in
`plans/dns_residual_truthfulness_roadmap.md` (Phases 137–140), against a code audit
rather than carried forward from this plan's wording:

- **137 ALPN** — CLOSED QUALIFIED, `architecture/dns_provider_inversion_phase137_closeout.md`
- **138 GeoIP wiring** — CLOSED QUALIFIED, `architecture/dns_provider_inversion_phase138_closeout.md`
- **139 mesh coupling** — CLOSED QUALIFIED, disposition WIRE,
  `architecture/dns_provider_inversion_phase139_closeout.md`
- **140 `prefer_post_quantum`** — REGISTERED, not started

`synvoid-dns` remains **class 1** after 139. The class-1 argument is now narrower
but not closed: mesh coupling dropped from 7 types across 6 files to 3 types in 1
file, and the 2047-line `--features mesh` closure is unchanged.
