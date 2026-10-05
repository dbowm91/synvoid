# Phase 139 Plan: Mesh DNS Coupling Disposition and Capability Inversion

Status: **REGISTERED** (2026-10-05). Not started.

Campaign: `plans/dns_residual_truthfulness_roadmap.md` (REGISTERED).
Predecessor: Phase 138. Source campaign:
`plans/dns_startup_truthfulness_and_provider_inversion_roadmap.md`
(CLOSED QUALIFIED). Registered in: `plans/roadmap.md`.

Source residual: Phase 136 **F-18** (severity medium) plus the campaign's
standing "mesh provider inversion" residual, carried in
`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` §
"Residual work this campaign deliberately left" item 1.

## Why this phase is gated on a disposition decision

`synvoid-dns` reaches `synvoid-mesh` through 7 concrete types. **All four
injection points have zero callers workspace-wide**, and the mesh-gated DNS
surface is therefore **dead at runtime today**.

This is the finding that makes the phase's shape unusual: inverting a seam for
code that never executes is wasted work, and deleting it is a behavior
decision. Neither should happen implicitly. **Workstream A is a gate: the phase
does not proceed to inversion until the disposition is decided and recorded.**

## Coupling inventory

Exhaustive. `grep -rho "synvoid_mesh::[A-Za-z0-9_:]*" crates/synvoid-dns/src |
sort -u` returns **8 path strings = 7 distinct types** across 5 files. Zero
references in `tests/` or `benches/`.

| Type | file:line | Usage shape |
|---|---|---|
| `dht::record_store::RecordStoreManager` | `mesh_sync/mod.rs:157`; `mesh_sync/registry.rs:113` | `Option<Arc<…>>` field; builder param; 7 method call sites |
| `dht::routing::manager::DhtRoutingManager` | `mesh_sync/mod.rs:159`; `mesh_sync/registry.rs:105` | `Option<Arc<…>>` field; builder param; 1 call (`verification.rs:349`) |
| `transport::MeshTransport` | `anycast_sync.rs:79,119,195,232` | field; builder param; fn params; 1 method |
| `protocol::MeshMessage` | `anycast_sync.rs:156,216,259,748,794` | **constructed** as `ZoneSyncRequest{..}` |
| `config::MeshNodeRole` | `anycast_sync.rs:165,225,271,760` | value only (`GLOBAL`) |
| `dht::SignedDhtRecord` | `mesh_sync/dht.rs:104` | struct literal |
| `dht::SignedRecordType` | `mesh_sync/dht.rs:111` | value only (`AnycastNode`) |

All concrete, no generics, and **no mesh type appears in any trait signature.**

### Correction to the registered problem statement

The Phase 136 closeout says the coupling is "8 types across DHT record storage,
routing, and signed provenance" and characterizes it as "a distributed-authority
surface, not a narrow seam". Both need qualification:

- **7 types, not 8.** The 8 is a `sort -u` line count; `MeshMessage` contributes
  two path strings. (The `get_record_verifier()` return value at
  `mesh_sync/dht.rs:119` is a plausible intended 8th but is **unverified**.)
- The three-type `MeshTransport` / `MeshMessage` / `MeshNodeRole` cluster in
  `anycast_sync.rs` is **not** covered by the "DHT storage, routing, and signed
  provenance" description at all.

The "distributed-authority surface" judgment remains **correct about the crate**
(mesh is heavy and pulls 1495 closure lines under `--features mesh`), but it
overstates the *coupling surface*: DNS's call sites are advisory DHT reads and
writes only. DNS never touches Raft, canonical state, quorum, or
`DhtRecordAuthorityClass`. That distinction is what makes the seam invertible at
all.

## The dead-code evidence

| Injection point | file:line | Callers |
|---|---|---|
| `with_mesh_registry` | `crates/synvoid-dns/src/server/zone.rs:454` | 0 |
| `with_zone_sync` | `crates/synvoid-dns/src/server/update.rs:323` | 0 |
| `MeshDnsRegistry` builder params | `crates/synvoid-dns/src/mesh_sync/registry.rs:103,111` | 0 |
| `with_dht_record_store` | `crates/synvoid-dns/src/mesh_sync/registry.rs` | 0 |

`MeshDnsRegistry::with_config` hardcodes
`dht_record_store: None, routing_manager: None, dns_resolver: None`
(`registry.rs:25-28`). Composition builds a registry
(`src/worker/unified_server/init_mesh.rs:401,446`) but never injects a DHT store,
routing manager, or transport.

## The latent reverse edge

`synvoid-mesh/Cargo.toml:19-33` declares 13 synvoid dependencies with
**`synvoid-dns` absent**, while `:14` declares an empty `dns = []` feature. The
root feature wiring (`Cargo.toml:26` → `synvoid-dns/mesh`) never enables
`synvoid-mesh/dns`.

`synvoid-mesh` contains **96 `#[cfg(feature = "dns")]` sites** referencing that
undeclared crate (`mesh/protocol.rs:1067-1079`, `mesh/backend.rs:380-381`,
`mesh/transport.rs:141-145,706-707`, `mesh/transports/quic.rs:28`). That code
**cannot compile** because the manifest edge does not exist, so it is dead and
never compiled. *Inferred from manifest + source; not confirmed by running
`cargo check -p synvoid-mesh --features dns`, which the phase must do.*

**Inversion creates no dependency cycle** — the graph is one-way
(`synvoid-dns` → `synvoid-mesh`), and the reverse sites are already non-compiling.

## Binding constraint

`architecture/distributed_state_contract.md` (binding): DHT answers "what has
been advertised?"; services consume policy outputs, not raw advisory records;
DHT must never become fallback authority. The same contract records that
`MeshMessage` protobufs **remain in `synvoid-mesh`** (`mesh/protocol.rs:14`
`include!`s the generated `OUT_DIR/mesh.rs`).

This is the reason Workstream C is not mechanical. A DNS-owned trait cannot be a
pure consumer seam while DNS *constructs* `MeshMessage::ZoneSyncRequest` — the
wire format belongs to `synvoid-mesh`.

## Workstream A — GATE: wire-or-delete disposition

**The phase does not proceed until this is decided and recorded.**

1. Prove the deadness claim on the current head: run
   `cargo check -p synvoid-mesh --features dns` to confirm the 96 reverse sites
   do not compile, and confirm the four injection points still have zero callers.
2. Decide, and record the reasoning:
   - **WIRE** — mesh DNS is an intended feature awaiting wiring. Then Phase 139
     inverts the seam and a follow-on phase wires the injection points. Note
     that wiring also activates anycast zone sync
     (`crates/synvoid-dns/src/anycast_sync.rs:686`, `update_local_zone` `:864`),
     which is currently unwired and which `architecture/worker_task_lifecycle.md:131`
     lists as "(unowned)".
   - **DELETE** — the surface is abandoned. Then the phase removes the
     mesh-gated DNS code, drops the `synvoid-mesh` edge, and closes F-18 by
     making the 552-line closure the *unconditional* figure.
   - **DEFER** — record the deadness as a finding and stop. `synvoid-dns` stays
     class 1.
3. Record the decision in the closeout, including which of the above and why.

A closeout that reaches Workstream B without a recorded disposition decision is
rejected.

## Workstream B — invert the two DHT types (conditional on WIRE)

Both are `Option<Arc<…>>` fields with no trait-signature use, so they are
textbook trait-izable:

- `RecordStoreManager` (7 methods) and `DhtRoutingManager` (1 method,
  `find_closest_global(5)`);
- define DNS-owned traits in `crates/synvoid-dns/src/mesh_sync/`, implement them
  in composition, and narrow the `Option<Arc<…>>` fields to
  `Option<Arc<dyn …>>`;
- the DNS-owned traits must not name a `synvoid-mesh` type;
- reuse the Phase 118 precedent: `MeshApplicationCapabilities` grouping in
  `tools/synvoid-repo-guards/tests/mesh_application_capability_boundary.rs`.

## Workstream C — the transport and wire cluster (conditional on WIRE)

This cluster is **not** a like-for-like inversion:

- `MeshTransport::broadcast_to_random_peers`
  (`crates/synvoid-mesh/src/mesh/transport.rs:5740`);
- `MeshMessage::ZoneSyncRequest` is **constructed** in DNS call bodies
  (`anycast_sync.rs:156,216,259,748,794`);
- `MeshNodeRole::GLOBAL` values.

Resolving this requires a **wire-ownership decision**: either broadcast moves to
composition so DNS only consumes a DNS-owned request type, or
`architecture/distributed_state_contract.md` is amended. Do not silently widen
DNS's request-path capabilities — the contract names that as a non-goal.

## Workstream D — add the missing guard

`tools/synvoid-repo-guards/tests/dns_dependency_edges.rs` **asserts nothing
about mesh**. Its five `assert_no_edge` gates (`:107,113,120,125,134`) and two
source scans (`:148,206`) cover config/core/utils/tls/geoip; its header at
`:22-25` states mesh inversion is out of scope.

**No guard pins the mesh edge** — nothing fails if it is removed and nothing
would catch a regression. Whatever the disposition, add a manifest gate and a
source-level gate using the established pattern at `:144-147`, which
deliberately includes mesh-gated code in the source scan.

## Workstream E — evidence

- `cargo test -p synvoid-dns --profile ci` and `--features mesh`;
- `cargo check -p synvoid-mesh --features dns` to record the reverse-edge result;
- `cargo test -p synvoid-mesh --profile ci` if reverse-edge code is touched;
- all four feature-profile checks;
- `./scripts/dns/conformance.sh`;
- `cargo xtask verify` (the admin contract lane runs `--features mesh,dns,icmp-filter`).

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo metadata --format-version 1 --no-deps
cargo tree -p synvoid-dns -e normal | wc -l
cargo tree -p synvoid-dns -e normal --features mesh | wc -l
cargo test -p synvoid-dns --profile ci
cargo test -p synvoid-dns --profile ci --features mesh
cargo test -p synvoid-repo-guards --profile ci
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo deny check
cargo audit
cargo xtask verify
```

## Acceptance criteria

- a recorded wire-or-delete disposition decision, with the deadness claim proven
  on the current head;
- a mesh manifest gate and source-level gate exist regardless of disposition;
- the "8 types" figure in the campaign closeout is corrected to 7 (or the real
  number, with the 8th resolved);
- the `anycast_sync.rs` cluster is named in the closeout, which the current
  "DHT storage, routing, and signed provenance" description omits.

## Rejection criteria

Reject a closeout that:

- proceeds to inversion without a recorded disposition decision;
- inverts a seam for code that has been determined dead, without recording that
  as the reason;
- moves `MeshMessage` ownership out of `synvoid-mesh` without amending
  `architecture/distributed_state_contract.md`;
- lets DNS consume raw DHT advisory records as policy input or make DHT a
  fallback authority, contrary to that contract;
- re-adds a manifest edge for a test;
- presents a class-1 → class-2 or support-bar change as a consequence of this
  phase. Inversion alone does **not** qualify `synvoid-dns` for promotion: the
  edge is `optional`, so the default-feature closure improves while the
  `--features mesh` closure does not.

## Closeout

`architecture/dns_provider_inversion_phase139_closeout.md`.
