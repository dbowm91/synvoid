# Phase 132 Plan: Authoritative Zone Startup Activation

Status: **PLANNED** (2026-10-05).

Campaign: `plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`.
Predecessor: Phase 131.
Registered in: `plans/roadmap.md`.

## Goal

Make `[[dns.zones.items]]` in the persisted DNS configuration mean what it says:
a configured zone becomes a served authoritative zone at startup, and an
invalid zone fails startup closed.

This is a **behavior change** and is the reason it is a separate phase. The
setting has never taken effect, so no deployment can regress by losing zones it
was actually serving.

## Background

The persisted zone list is currently produced, validated, converted, and
discarded:

```text
main.toml [[dns.zones.items]]
  -> synvoid-config DnsConfig.zones
  -> src/server/dns_runtime_config.rs   (converted to runtime ZoneSpec, incl. record types)
  -> DnsRuntimeConfig.zones
  -> DnsServer::new(..)                 crates/synvoid-dns/src/server/mod.rs:1775  `zones: _`
  -> dropped
```

`DnsServer::load_zones(Vec<ZoneSpec>)`
(`crates/synvoid-dns/src/server/zone.rs:8`) is fully runtime-typed and already
proven by `crates/synvoid-dns/tests/metrics_wiring.rs:120`. It has no
production caller. `load_zones_from_store` (line 179) has none either.

Four shipped examples declare `[[dns.zones.items]]`:
`authoritative_public.toml`, `dnssec_signed.toml`, `transfer_primary.toml`,
`encrypted_dot_doh.toml`. All four are parsed by the root 43-fixture parity
suite, which asserts conversion only — so the suite is green while the feature
does nothing.

Composition root: `src/server/resources.rs:140`
(`crate::dns::DnsServer::new(runtime_cfg, cert_resolver.clone())`).

## Workstream A — activation at composition

- Clone the runtime zone list before the config is moved into
  `DnsServer::new`, exactly as the existing TSIG key clone at
  `src/server/resources.rs:139` does.
- Call `load_zones` on the constructed server.
- Preserve the order guarantees the startup path already depends on: zone
  activation must not run before DNSSEC runtime state the server needs, and
  must not race listener startup.

## Workstream B — failure semantics

Startup must **fail closed**, not warn and continue. A configured zone that
cannot be loaded is a configuration error, and serving authoritative DNS
without a zone an operator declared is worse than refusing to start.

- surface the failure as the existing typed resource error, not a
  `tracing::warn!` + `None`;
- decide and record whether a *partial* batch (some zones loaded, one bad) is
  rolled back or left loaded. Prefer failing the whole activation: the process
  is exiting anyway, and a half-activated authoritative set is harder to reason
  about than none.

Contrast this with the neighboring TSIG wiring at
`src/server/resources.rs:150-154`, which **does** warn and degrade. That
behavior is correct for TSIG (zone transfer authorization, not zone content)
and must not be changed here; record the asymmetry so a future reader does not
"fix" one to match the other.

## Workstream C — DNSSEC interaction

`load_zones_inner` applies global or per-zone NSEC/NSEC3 denial settings and
generates a **random NSEC3 salt per load**. Phase 132 makes this code path
reachable in production for the first time. Verify and record:

- per-zone `dnssec.enabled` false correctly inherits global denial settings;
- per-zone NSEC3 iteration override is honored, and its `unwrap_or` global
  fallback matches the persisted schema default;
- zone activation does not create, sign, or handle private keys — it only sets
  denial-of-existence parameters. DNSSEC custody stays one-way through
  `synvoid-dnssec-keystore`.

If activation turns out to require key authority, stop and record it as a
blocker rather than widening the custody boundary.

## Workstream D — proof

- a test proving a configured zone is served after activation: construct a
  server through the real composition path with a zone, start it, and assert an
  authoritative answer for a record in that zone;
- a test proving an invalid zone fails activation;
- a test proving zero configured zones still starts and behaves as before;
- extend the root parity suite so at least one shipped example's zone reaches a
  `DnsServer`, rather than only reaching the adapter;
- a guard that keeps the adapter→runtime→`load_zones` path wired, so a future
  `zones: _`-style discard cannot silently return.

## Workstream E — documentation

- `architecture/dns.md` — startup zone activation, ordering, and failure
  semantics;
- `architecture/dns_config_runtime_matrix.md` — close F-6 (matrix) and F-2
  (Phase 128) with the resolution;
- `architecture/dns_zone_lifecycle.md` — config-declared zones relative to
  store-loaded and runtime-mutated zones;
- `docs/` operator guidance: a configured zone is now authoritative, and reload
  semantics apply.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-dns --profile ci
cargo test --test dns_runtime_config_parity --profile ci
cargo test -p synvoid-dnssec-keystore --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
./scripts/dns/conformance.sh
```

## Acceptance criteria

- a zone declared in `main.toml` is served after startup, proven end to end;
- an invalid zone aborts startup with a typed error;
- no persisted schema, default, or admin API change;
- DNSSEC custody unchanged;
- Phase 128 F-2 and matrix F-6 are closed with evidence.

## Rejection criteria

Reject a closeout that:

- warns and continues on an invalid zone;
- activates zones from a `#[cfg(test)]` path or a test-only helper;
- places the call in `crates/synvoid-dns/src/**` composition or in the
  `src/dns/` facade;
- proves activation by asserting on `DnsRuntimeConfig.zones` rather than on a
  served answer;
- touches DNSSEC key custody or signing.

## Closeout

`architecture/dns_provider_inversion_phase132_closeout.md`.
