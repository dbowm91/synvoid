# Phase 129 Closeout — DNS Core / Utils Neutralization

Date: 2026-10-04.
Plan: `plans/phase_129_dns_core_utils_neutralization.md`.
Campaign: `plans/dns_runtime_dto_conversion_roadmap.md`.
Predecessor: Phase 128 `CLOSED QUALIFIED`
(`architecture/dns_runtime_dto_phase128_closeout.md`).
Disposition: **CLOSED QUALIFIED**. Phase 130 is unblocked.

## What was delivered

`synvoid-dns` no longer links `synvoid-core` or `synvoid-utils`. The four
helper families those edges provided are now DNS-owned, and the manifest
carries only genuine providers:

```rust
// Before
synvoid_core::time::current_timestamp_secs()   // 30+ call sites
synvoid_core::net::is_restricted_ip(&ip)       // 3 call sites
synvoid_core::net::ipv4_prefix_mask(prefix)    // 1 call site
synvoid_utils::current_timestamp()             // 6 mesh-gated files
synvoid_utils::safe_unix_timestamp()           // 2 mesh-gated files
synvoid_utils::flags::{DrainFlag, RunningFlag} // limits.rs

// After
crate::time::unix_timestamp_secs()             // crates/synvoid-dns/src/time.rs
crate::net_policy::is_restricted_ip(&ip)       // crates/synvoid-dns/src/net_policy.rs
crate::runtime_config::dns_ipv4_prefix_mask(p) // pre-existing, corrected here
crate::lifecycle::{LifecycleState, DegradationState, Draining}
```

| Workstream | Deliverable | Location |
|---|---|---|
| A — time | `unix_timestamp_secs()` / `unix_timestamp_millis()` over `std::time`; pre-epoch returns `0`, never panics. No clock trait, no global singleton | `src/time.rs` |
| B — restricted IP | `is_restricted_ip(&IpAddr)` — a character-for-character port of the previous predicate, with every branch enumerated in differential tests | `src/net_policy.rs` |
| C — prefix mask | `dns_ipv4_prefix_mask` corrected to exact parity with `synvoid_core::net::ipv4_prefix_mask` (see F-1) | `runtime_config.rs` |
| D — lifecycle | `LifecycleState { degraded, draining }` replaces the two generic flag wrappers; `DegradationState` / `Draining` enums make the initial value part of the type | `src/lifecycle.rs` |
| E — mesh paths | The 8 mesh-gated files use the DNS time helper, so the optional feature cannot restore the utils edge | `mesh_sync/*`, `mesh_dnssec.rs`, `anycast_sync.rs` |
| F — dependency removal | `synvoid-core` and `synvoid-utils` removed from `Cargo.toml` | `Cargo.toml` |
| G — guards | The two `#[ignore]`d gates go live; a new source-level gate proves the crate cannot call the removed helpers through a re-export or alias | `tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` |

## Dependency evidence

```text
cargo metadata --no-deps -p synvoid-dns  →  4 direct SynVoid normal edges (was 6)
cargo tree -p synvoid-dns -e normal      →  827 expanded lines (was 846)
```

This is the plan's target set exactly: `synvoid-tls`, `synvoid-geoip`,
`synvoid-dnssec-keystore`, plus the optional `synvoid-mesh`. The 19-line drop
is larger than the 2 removed direct edges because those crates each
contributed closure lines that the remaining four do not reach.

`Cargo.lock` drops exactly the two `synvoid-dns` entries and nothing else — no
new package enters the graph, so `cargo deny` and `cargo audit` are unchanged
(6 pre-existing allowed warnings).

## Behavior parity

### Restricted-IP policy (security boundary)

`net_policy::is_restricted_ip` is a character-for-character port of
`synvoid_core::net::is_restricted_ip`, and the module is documented as a
security boundary. Six tests enumerate it:

- `ipv4_restricted_branches` — one address per IPv4 branch (0/8, RFC1918,
  CGNAT, loopback, link-local, 192.0/24, 192.168/16, benchmarking, two
  documentation ranges, multicast, reserved).
- `ipv4_public_addresses_are_not_restricted` — the address immediately below
  and immediately above **every** restricted range. This is the half that
  catches an off-by-one, and it is the reason the port is trusted.
- `ipv4_192_0_slash_8_is_restricted_beyond_slash_24` — pins the one place the
  policy is broader than the RFC (`192.0.x.x`, not just `192.0.0.0/24`).
- `ipv6_restricted_branches` / `ipv6_public_addresses_are_not_restricted` —
  unspecified, loopback, ULA, link-local, multicast, `2001:db8::/32`, and the
  boundaries around each.
- `ipv4_mapped_addresses_follow_the_ipv4_policy` — a mapped address is judged
  by its IPv4 value in *both* directions, so `::ffff:127.0.0.1` cannot bypass
  the IPv4 policy and `::ffff:8.8.8.8` is not over-blocked.

### Lifecycle ordering

`LifecycleState` keeps the predecessors' `Acquire` load / `Release` store
ordering verbatim, and the module documents why: `initiate_graceful_shutdown`
runs on the supervisor while request-path threads read
`is_in_graceful_shutdown`, and a weaker ordering could let a reader observe
the drain flag before the state it guards. Both `try_acquire_connection` and
`try_acquire_query` still check the drain flag first, so the query-boundary
graceful shutdown is unchanged.

Tests cover clone-shared state (a value-copied flag would let one listener
drain while another keeps serving), drain idempotence, and independence of the
degradation and drain axes.

## Findings

### F-1: `dns_ipv4_prefix_mask` diverged from the helper it replaced

The Phase 125/126 helper returned `0` for prefixes above `/32`, while
`synvoid_core::net::ipv4_prefix_mask` returns `u32::MAX`. The divergence would
have masked a client subnet to `0.0.0.0` instead of leaving it intact.

The only call site (`edns.rs` ECS truncation) cannot reach an out-of-range
length, because it is guarded by `new_prefix < subnet.prefix_len` and
`prefix_len <= 32` for IPv4. So the divergence was unreachable, and the
original test *asserted* the wrong value. Corrected to exact parity here
(`0 => 0`, `1..=32 => u32::MAX << (32 - prefix)`, `_ => u32::MAX`) and the
test now covers `/0`, `/1`, `/8`, `/24`, `/31`, `/32`, `/33`, `/64`, `/255`.

No shift-by-word-size panic is possible: the `0` case is matched before the
shift and the out-of-range case is matched before it too.

### F-2: two predecessor time helpers had a logging difference

`synvoid_core::time::current_timestamp_secs()` logs a warning on a pre-epoch
clock; `synvoid_utils::safe_unix_timestamp()` (and its alias
`current_timestamp()`) does not. The DNS helper does not log.

This is not a behavior change for any caller: the return value is `0` in both
cases, and no DNS code path branches on the warning. It is recorded because
"identical behavior" is otherwise read as byte-identical here.

### F-3: `synvoid_utils::current_timestamp` is a plain alias

`synvoid_utils::current_timestamp()` is literally
`fn current_timestamp() -> u64 { safe_unix_timestamp() }`, so the six
mesh-gated files that used it and the two that used `safe_unix_timestamp()`
were already on identical semantics. Both map to `unix_timestamp_secs()`
with no per-site judgment.

## Guards

`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` now has 4 live
gates:

- `synvoid_dns_has_no_config_edge` (Phase 128)
- `synvoid_dns_has_no_core_edge` (Phase 129, promoted from `#[ignore]`)
- `synvoid_dns_has_no_utils_edge` (Phase 129, promoted from `#[ignore]`)
- `production_source_names_neither_neutralized_helper_crate` (Phase 129) —
  the manifest gates prove the *edge* is gone; this proves the crate did not
  keep calling the removed helpers through a re-export, a `use` alias, or a
  dev-dependency escape hatch. Comments are exempt, so the module docs can
  still name what each helper replaced. Mesh-gated code is included on
  purpose, per Workstream D.

The gate was verified to actually fail: reintroducing
`use synvoid_core::net::is_restricted_ip;` into `qname.rs` makes it report the
file and line, and the file was restored afterward.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --profile ci --all-targets -- -D warnings`
- `cargo check -p synvoid-dns --features mesh` — the optional mesh feature does
  not reintroduce the utils edge
- `cargo check --no-default-features --features dns` and
  `--features mesh,dns` at the root
- `cargo test -p synvoid-dns --profile ci` — 609 lib tests (up from 595: the
  14 new time / net-policy / lifecycle tests) plus every integration suite
- `cargo test -p synvoid-repo-guards --profile ci`
- `cargo deny check`, `cargo audit` (6 pre-existing allowed warnings)
- `cargo xtask verify` — 10/10

## Phase 130 handoff

Ready to unblock. The runtime-neutral dependency set is achieved and gated;
Phase 130 rebuilds package/runtime evidence against it and decides whether a
separate provider-inversion (TLS / GeoIP / mesh) campaign is ready to register.

Measured starting point for Phase 130:

```text
4 direct SynVoid normal edges
827 expanded cargo tree lines
```

Phase 130 must re-measure both numbers rather than assume them, and must not
claim standalone class-2 readiness or any promotion on the strength of this
phase alone.
