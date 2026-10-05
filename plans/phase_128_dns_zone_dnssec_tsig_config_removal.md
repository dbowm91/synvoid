# Phase 128 Plan: DNS Zone, DNSSEC, TSIG/HSM Conversion and synvoid-config Removal

Status: **CLOSED QUALIFIED** (2026-10-04). Closeout:
`architecture/dns_runtime_dto_phase128_closeout.md`. Phase 129 is unblocked.

The `synvoid-config` normal edge is gone: 6 direct SynVoid normal edges (was 7),
846 expanded `cargo tree -e normal` lines (was 847). All persisted DNS schema is
converted by `src/server/dns_runtime_config.rs`; `runtime_config_deferred.rs` is
deleted. Persisted-schema test coverage moved to `crates/synvoid-config/tests/`
rather than being dropped. Phase 129 (`synvoid-core` / `synvoid-utils`
neutralization) is unblocked with its gates already landed `#[ignore]`d.

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

Predecessor evidence: Phase 127 closeout
(`architecture/dns_runtime_dto_phase127_closeout.md`) — its persisted-type
table enumerates this phase's exact remaining scope, and finding F-1 asks this
phase to ratify deleting the dead `check_rebinding_protection`.

## Goal

Migrate the remaining persistence-owned DNS runtime types—zones, per-zone DNSSEC,
global DNSSEC policy, TSIG and HSM conversion—then remove the normal
`synvoid-config` dependency from `synvoid-dns`.

This is the campaign's first hard dependency-removal gate.

## Workstream A — DNS-owned zone specs

Replace public/runtime use of:

- `DnsZoneEntry`;
- `DnsZoneDnssecConfig`;
- `DnsRecordEntry`;
- `DnsRecordType`;

with DNS-owned zone input types.

Recommended shape:

- `ZoneSpec`;
- `ZoneRecordSpec`;
- `ZoneDnssecSpec`.

Use Hickory `RecordType` or an existing DNS-owned runtime representation rather
than duplicating the persistence enum.

The application adapter performs persisted record-type mapping.

## Workstream B — zone activation parity

Preserve the existing authoritative validation boundary:

- exactly one apex SOA;
- valid owner/origin names;
- TTL bounds;
- MX/SRV priority bounds;
- SOA field parsing;
- A/AAAA parsing;
- CNAME exclusivity;
- target-name validation;
- atomic replacement behavior;
- cache invalidation;
- zone lifecycle/health state.

Config conversion must not make invalid zone data valid.

## Workstream C — DNSSEC runtime policy

Convert global/per-zone DNSSEC settings to DNS-owned values:

- enabled/domain/key path;
- algorithm;
- key sizes;
- rollover;
- NSEC/NSEC3 policy;
- per-zone overrides.

Keep private-key generation/signing/custody in
`synvoid-dnssec-keystore`.

Do not expose raw private key material or regress sealed signing handles.

## Workstream D — HSM conversion ownership

Remove `synvoid_dns::hsm::keystore_config_from_dns()` or equivalent
persistence-type adapter from the DNS crate.

The root/application adapter constructs the keystore-owned
`synvoid_dnssec_keystore::HsmConfig`.

Preserve:

- PKCS#11 fail-closed establishment;
- no software fallback when HSM is required;
- PIN/secret redaction and zeroization behavior;
- feature gating.

## Workstream E — TSIG runtime ownership

Move runtime TSIG algorithm/key specification out of `synvoid-config`.

The application adapter should:

- convert persisted algorithm enum to DNS runtime enum;
- base64-decode/validate persisted secrets before runtime use;
- preserve minimum key-size checks;
- return secret-safe conversion errors.

DNS runtime TSIG must retain:

- constant-time MAC comparison;
- algorithm IDs/names;
- replay detection;
- timestamp/fudge behavior;
- multi-key add/remove semantics.

Do not log decoded secrets.

## Workstream F — remove synvoid-config dependency

At closeout:

- production `crates/synvoid-dns/src/**` has zero
  `synvoid_config` references;
- `Cargo.toml` has no normal `synvoid-config` dependency;
- DNS crate runtime/integration tests do not rely on `synvoid-config` merely
  to construct runtime values.

Avoid adding a dev-dependency unless a narrowly justified compatibility fixture
requires it. Prefer root adapter tests for persistence parity.

Add/extend repo guards to prevent the normal edge from returning.

## Verification

```bash
rg "synvoid_config|synvoid-config" crates/synvoid-dns/src crates/synvoid-dns/Cargo.toml
cargo tree -p synvoid-dns -e normal
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dnssec-keystore --profile ci
cargo test -p synvoid-dns --test dnssec_live_signing --profile ci
cargo test -p synvoid-dns --test dnssec_known_vectors --profile ci
cargo test -p synvoid-dns --test tsig_success_fixtures --profile ci
cargo test -p synvoid-dns --test zone_lifecycle --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

The `rg` gate should return no production-source/normal-manifest edge except
explicit historical comments/tests that are deliberately justified in closeout.

## Acceptance criteria

- normal `synvoid-config` dependency is gone;
- all production DNS config inputs are DNS-owned runtime values;
- zone/DNSSEC/TSIG/HSM parity passes;
- DNSSEC custody remains one-way through keystore abstractions;
- persisted config/admin API is unchanged;
- repo guard prevents reintroduction of the normal config edge.

## Rejection criteria

Reject implementation that:

- moves Serde/OpenAPI persisted schema wholesale into DNS;
- changes zone validation while changing ownership;
- exposes raw DNSSEC/HSM secrets;
- logs decoded TSIG secret material;
- keeps a hidden normal config edge through another adapter module;
- claims Phase 116 equivalent closure before the core/utils edge work completes.
