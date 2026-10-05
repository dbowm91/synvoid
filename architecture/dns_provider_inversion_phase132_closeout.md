# Phase 132 Closeout — Authoritative Zone Startup Activation

Date: 2026-10-05.
Plan: `plans/phase_132_dns_authoritative_zone_startup_activation.md`.
Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 131 `CLOSED QUALIFIED`
(`architecture/dns_provider_inversion_phase131_closeout.md`).
Disposition: **CLOSED QUALIFIED**. This is a **behavior change**.

## The gap

`[[dns.zones.items]]` was parsed, validated, converted record-by-record by the
application adapter, carried in `DnsRuntimeConfig`, handed to `DnsServer::new` —
and then dropped at the `zones: _` destructure in
`crates/synvoid-dns/src/server/mod.rs`. `DnsServer::load_zones` and
`load_zones_from_store` both had no production caller. Four shipped profiles
declared a zone, so an operator copying one got an authoritative server that
served nothing for the zone it declared.

## Workstream A — activation

`src/server/resources.rs` now clones `runtime_cfg.zones` before the config is
moved into `DnsServer::new` — the same shape as the existing TSIG key clone — and
activates them:

```rust
let configured_zones = runtime_cfg.zones.clone();
let mut dns_server = DnsServer::new(runtime_cfg, cert_resolver.clone());
dns_server.load_zones(configured_zones).map_err(|e| {
    UnifiedServerResourceError::Dns(format!(
        "failed to activate {zone_count} configured zone(s): {e}"
    ))
})?;
```

A repo guard enforces the ordering (clone before the move), the presence of the
call, and the presence of a typed failure, because the failure mode this fixes is
invisible: with the call removed, every projection test still passes.

## Workstream B — failure semantics

Startup **fails closed**. An unactivatable declared zone aborts through
`UnifiedServerResourceError::Dns`.

This is deliberately asymmetric with the TSIG wiring ten lines below it, which
warns and degrades to `None`. TSIG authorizes zone *transfers*, and losing it is
survivable; a zone the operator declared but that cannot be activated is a
configuration error. Recorded in `architecture/dns.md` so a future reader does
not "fix" one to match the other.

## What wiring it exposed — two further defects

The path had been unreachable, so two bugs sat behind it. Both had to be fixed
for the phase's own acceptance criterion (a configured zone is *served*) to be
met, and both are more serious than the original gap.

### F-1: config-declared record names could never match (fail-wrong)

The query path strips the zone origin off the qname and looks up the remainder
(`server/query.rs`), so records are keyed origin-relative: `www`, apex `@`. The
loader stored the name **as written in config**, and the adapter copied it
verbatim. A record declared `name = "www.example.com"` was filed under
`("www.example.com", A)` — a key nothing queries.

Measured before the fix, on a zone the test had just loaded and confirmed
present:

```text
PROBE rcode=3 flags=0x8503 ancount=0
```

`rcode=3` is NXDOMAIN with `AA` set. The server claimed authority over the zone
and answered NXDOMAIN for a name its own configuration declared. This is
fail-**wrong**, not fail-closed: from outside, it looks like a correctly
configured authoritative server.

No test could have caught it, because every fixture in the repo already used the
origin-relative convention (`"@"`, `"www"`, `"ns1"`). The mismatch was between
the *persisted schema*, which reads naturally as an FQDN, and the internal keying
convention — two things that had never been bridged because the path that would
have bridged them did not exist.

Fixed by `DnsServer::normalize_record_name` in `server/zone.rs`, following the
zone-file convention: `"@"` and the origin are the apex; a name containing `.` is
an FQDN that must be inside the zone and is reduced to its relative form; a name
without `.` is already relative and is kept. An FQDN **outside** the zone is a
hard error rather than a silently unreachable key. Comparison is
case-insensitive, the trailing dot is optional, and the suffix test is not a
naive `ends_with`, so `www.notexample.com` is correctly rejected for zone
`example.com`.

Normalization lives in the loader rather than the adapter deliberately: the
runtime DTO keeps the operator's spelling, and the origin-relative convention
stays an internal detail of keying.

Worth noting the gate that already existed: `validate_zone_for_activation` has
had a `NameOutsideZone` rule all along, and an FQDN name *passes* it — it
genuinely is inside the zone. Validation and keying were using different
conventions, and both were individually reasonable. That is why the parity suite
and the validation suite were both green while the feature was broken.

### F-2: all four shipped profiles declared an unactivatable zone

Each declared `zone = "example.com"` with no records. `load_zones` requires an SOA
(RFC 1035 §3.3.13), so activation turned all four into startup failures.
`authoritative_public.toml` also carried a comment that was simply false — it
claimed zone loading "is not supported via config", describing a design decision
where there was an absent one.

All four now declare an apex SOA plus NS and A records; the misleading comment is
corrected; and `DnsZonesConfig::validate` (new `DnsConfigError::InvalidZone`,
mapped to the `dns.zones` config path) rejects a record-less zone at config load,
so `--configtest` points at the file instead of startup failing later.

## Verification

| Lane | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --profile ci --all-targets -- -D warnings` | pass |
| `cargo test -p synvoid-dns --profile ci` | pass — 615 lib tests (609 + 6 new normalization tests) + all integration suites |
| `cargo test -p synvoid-dns --profile ci --features mesh` | pass — 622 lib tests |
| `cargo test -p synvoid-config --profile ci` | pass — 98 + 94 (was 89, +5 zone validation) + 5 + 7 + 2 |
| `tests/dns_runtime_config_parity.rs` | pass — **43/43**, unchanged count |
| `tests/dns_zone_startup_activation.rs` (new) | pass — 4/4 |
| `cargo test -p synvoid-repo-guards --profile ci` | pass, including 2 new Phase 132 guards |
| `scripts/dns/conformance.sh` | **10/10** internal, external 5 runnable / 5 skipped |

### Proof that a configured zone is actually served

The new root suite is the end-to-end evidence, and it is deliberately not a
projection test. It starts a real `DnsServer` from the real adapter output, dials
it over DNS-over-TCP, and asserts on the wire response:

- the zone reached the **server**, not just the adapter (`get_zones()` contains
  `example.com`, and holds exactly one zone);
- the response echoes the query ID;
- `rcode == 0`;
- **`AA` is set** — the answer is authoritative, which is the whole point;
- `ancount >= 1`;
- the answer carries the declared `192.0.2.1` rdata;
- and it is driven from `examples/dns/authoritative_public.toml`, so the shipped
  file cannot drift back into advertising a zone that never loads.

The other three cases: a record-less zone fails config validation; a zone that
passes validation but has no SOA fails `load_zones` (proving activation fails
closed rather than skipping); and no declared zones still starts and still
answers.

The parity suite's `shipped_authoritative_profile_projects_exactly` asserted
`runtime.zones[0].records.is_empty()` — it was pinning the broken state. It now
asserts the three records project exactly, with the persisted spelling intact,
which is a stronger check than the one it replaces and keeps the ledger at 43/43.

Wire format is hand-rolled in the new suite because root has no hickory edge by
design (0 root `src/` uses). It mirrors the proven TCP framing in
`crates/synvoid-dns/tests/dns_phase45_contract.rs`.

### Two operational notes, recorded not "fixed"

- **A public authoritative profile cannot be queried from loopback.**
  `authoritative_public.toml` enables the firewall with `block_internal_ips`,
  which installs a `block_loopback` rule for `127.0.0.0/8`. Correct for that
  profile, and the reason the served-answer test relaxes that one setting. The
  consequence is real: an operator cannot verify the profile locally with
  `dig @127.0.0.1` while the flag is set, and the failure is silence. Behavior
  unchanged — it is right for a public profile — but a future local verification
  lane needs to know.
- **Zone activation is not atomic across a multi-zone batch.** `load_zones_inner`
  inserts each zone as it validates and returns `Err` at the first failure, so a
  batch with a bad second entry leaves the first inserted. Harmless at startup,
  where the process exits; not harmless for a runtime reload. Pre-existing, and
  fixing it is a behavior change to the reload path, which is out of scope here.

## Guards added

| Guard | Prevents |
|---|---|
| `composition_activates_configured_zones` | the `load_zones` call, the typed failure, or the clone-before-move ordering being dropped from composition |
| `shipped_dns_examples_declare_records_for_their_zones` | a shipped profile again declaring a zone that cannot be activated |

## Acceptance criteria

| Criterion | Status |
|---|---|
| a zone declared in `main.toml` is served after startup, proven end to end | met — AA set, correct rdata, from the shipped example |
| an invalid zone aborts startup with a typed error | met — `UnifiedServerResourceError::Dns`, and `load_zones` itself is proven to error rather than skip |
| no persisted schema or admin API change | met — a new `validate()` rule and example content; the TOML/JSON shape is untouched |
| DNSSEC custody unchanged | met — no DNSSEC key authority touched; `load_zones` only sets denial-of-existence parameters and generates a per-load NSEC3 salt, as it always did |
| Phase 128 F-2 and matrix F-6 closed with evidence | met |

## Rejection criteria checked

- not warn-and-continue: startup aborts;
- not a `#[cfg(test)]` path: the call is in `src/server/resources.rs`, composition;
- not in the `src/dns/` facade: the guard enforces that too, unchanged;
- not proven by asserting on `DnsRuntimeConfig.zones`: the new suite asserts a
  served wire response;
- DNSSEC custody untouched.

## Effect on later phases

`[dns.zones]` is now functional, so the "shipped example" and "operator declares
a zone" surfaces are real. Provider inversion (Phases 133–135) does not touch
this path. Phase 136 re-runs the parity ledger at 43/43 and this suite at 4/4.

`synvoid-dns` remains class 1. No dependency edge changed, no provider was
inverted, and the only behavior changes are the two this closeout records.
