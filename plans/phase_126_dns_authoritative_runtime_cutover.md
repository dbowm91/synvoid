# Phase 126 Plan: DNS Authoritative and Encrypted-Transport Runtime Cutover

Status: **PLANNED / READY AFTER PHASE 125** (2026-10-04).

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

## Goal

Make the authoritative DNS server and encrypted-transport runtime consume
DNS-owned runtime DTOs instead of persisted `synvoid-config` types, while
leaving recursive/zone/DNSSEC/TSIG/HSM cleanup to later phases.

## Workstream A — canonical DnsServer constructor

Change the canonical `DnsServer` construction path to consume
`DnsRuntimeConfig` (or the Phase-125 equivalent).

Root `src/server/resources.rs` must:

- validate persisted config;
- call the canonical adapter;
- construct `DnsServer` with runtime values;
- retain concrete `CertResolver` injection until provider inversion.

Remove any public constructor that requires `synvoid_config::dns::DnsConfig`
once all callers/tests have migrated. A short private compatibility helper is
acceptable only during the same phase and must not survive closeout.

## Workstream B — authoritative runtime groups

Cut over all implemented authoritative consumers:

- bind/socket address;
- cache capacity/min/max TTL;
- serve-stale policy;
- default/min-Geo/negative TTL;
- connection/query/response limits;
- UDP buffer;
- dedicated/shared rate-limit mode;
- RRL;
- implemented firewall controls;
- ECS filtering;
- DNS64;
- query coalescing and cleanup interval;
- health flags derived from enabled transport/runtime values.

Do not create runtime fields for unsupported firewall/rebinding behavior.

## Workstream C — encrypted transports

Convert DoT/DoH/DoQ constructors to DNS-owned runtime types.

Retain only values actually consumed:

- typed bind address;
- DoH route path(s) that have real runtime consumers;
- DoQ stream and idle-time limits.

Certificate resolver/provider ownership remains unchanged in this phase.

Prove persisted `tls_cert_path`, `tls_key_path`,
`use_system_cert_store`, or other fields are either consumed through
composition/provider ownership or absent-by-design. Do not copy unused fields
into runtime DTOs.

## Workstream D — startup and lifecycle parity

Preserve:

- fail-fast invalid bind behavior;
- UDP + TCP authoritative startup;
- bounded persistent TCP behavior;
- DoT bounded connection reuse;
- DoH/DoQ startup semantics;
- shutdown idempotence;
- connection permits/drain ownership;
- cache/transport-class behavior.

No listener fallback may be introduced during conversion.

## Workstream E — test migration

Migrate authoritative DNS crate tests away from direct
`synvoid_config::dns::*` construction where their subject is runtime behavior.

Keep persisted-config validation tests in `synvoid-config` or root adapter
tests.

At phase close, no authoritative constructor/test should require a persistence
DTO solely to exercise DNS runtime behavior.

## Verification

```bash
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-dns -- transport_lifecycle --profile ci
cargo test -p synvoid-dns -- configured_bind_addr --profile ci
cargo test -p synvoid-dns -- tcp_hard_limit --profile ci
cargo test -p synvoid-dns -- truncation --profile ci
cargo test -p synvoid-dns --test dns_config_fidelity --profile ci
cargo check --no-default-features --features dns --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

## Acceptance criteria

- canonical authoritative `DnsServer` constructor consumes runtime DTOs;
- root adapter is the only persisted-config conversion path;
- authoritative and encrypted-transport behavior remains parity-tested;
- unsupported persisted fields remain absent from runtime API;
- no provider inversion or recursive/zone ownership shortcut occurs.

## Rejection criteria

Reject implementation that:

- retains a public `DnsConfig` constructor as a permanent compatibility path;
- stores the entire persisted config inside `DnsServer`;
- moves certificate management into DNS;
- silently changes listener/bind defaults;
- changes protocol behavior while changing config ownership.
