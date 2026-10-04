# Phase 129 Plan: DNS Core and Utils Neutralization

Status: **PLANNED / READY AFTER PHASE 128** (2026-10-04).

Registered in: `plans/roadmap.md` and
`plans/dns_runtime_dto_conversion_roadmap.md`.

## Goal

Remove `synvoid-core` and `synvoid-utils` from the normal
`synvoid-dns` dependency graph without creating a new generic utility crate or
changing security semantics.

## Workstream A — time helper parity

Replace DNS uses of `synvoid_core::time::current_timestamp_secs()` with a
DNS-owned internal helper.

Pin differential behavior:

- ordinary Unix time;
- pre-epoch behavior returns 0 rather than panicking;
- no new global clock singleton.

Do not introduce a public clock trait solely for dependency removal.

## Workstream B — restricted-IP semantics

Replace `synvoid_core::net::is_restricted_ip()` with a DNS-owned internal
implementation or a DNS-domain policy helper.

Differential tests must cover all current semantics, including:

IPv4:
- 0/8;
- RFC1918;
- CGNAT 100.64/10;
- loopback;
- link-local;
- 192.0/24 and 192.168/16 behavior;
- benchmark/documentation ranges currently treated as restricted;
- multicast/reserved.

IPv6:
- IPv4-mapped addresses;
- unspecified;
- loopback;
- ULA;
- link-local;
- multicast;
- 2001:db8::/32.

Do not broaden/narrow this policy silently.

## Workstream C — prefix-mask parity

Replace `ipv4_prefix_mask()` with a DNS-local helper.

Test at minimum /0, /1, /8, /31, /32 and out-of-range behavior identical to
the current helper.

No shift-by-word-size panic may be introduced.

## Workstream D — lifecycle flags

Remove DNS dependence on `synvoid_utils::{RunningFlag, DrainFlag}`.

Prefer lifecycle state owned by the connection-limit/runtime object rather than
publishing generic flag wrappers.

Preserve:

- Acquire/Release ordering;
- idempotent drain/start-stop behavior;
- query-boundary graceful shutdown;
- listener/connection semantics.

Mesh-gated timestamp calls must use the DNS-local time helper so the optional
mesh feature cannot restore the utils dependency.

## Workstream E — dependency removal and guard

Remove normal `synvoid-core` and `synvoid-utils` dependencies from
`crates/synvoid-dns/Cargo.toml`.

Add/extend a guard so the runtime-neutral dependency set cannot regress before
provider inversion.

Record before/after direct edge count and expanded normal-tree size.

## Verification

```bash
rg "synvoid_core|synvoid-core|synvoid_utils|synvoid-utils" crates/synvoid-dns/src crates/synvoid-dns/Cargo.toml
cargo tree -p synvoid-dns -e normal
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo xtask verify
cargo deny check
cargo audit
```

## Acceptance criteria

- zero normal `synvoid-core` and `synvoid-utils` edges;
- differential net/time behavior matches the previous helpers;
- lifecycle/drain behavior is unchanged;
- optional mesh does not reintroduce utils;
- direct SynVoid dependency count is reduced to the expected provider/security
  set, subject to actual metadata proof.

## Rejection criteria

Reject implementation that:

- creates a new catch-all utility crate;
- changes restricted-IP policy without separate security review;
- weakens atomic ordering/drain semantics;
- removes helper dependencies but reintroduces them transitively through a new
  SynVoid adapter crate;
- claims standalone class-2 readiness.
