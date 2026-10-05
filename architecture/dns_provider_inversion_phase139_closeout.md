# DNS Provider Inversion — Phase 139 Closeout: Mesh Coupling Disposition

**Status: CLOSED QUALIFIED** (2026-10-05)
**Branch:** `phase-125-dns-runtime-dto-contract`
**Disposition: WIRE** (not DELETE, not DEFER)
**Qualification: unchanged — `synvoid-dns` remains class 1.**

---

## 1. Why WIRE, and not DELETE

The assistant recommended DELETE before the phase ran. The user chose WIRE, and
that choice is correct on the evidence. Recording the reasoning is a
Workstream A acceptance requirement, so the argument is stated rather than assumed.

`MeshDnsRegistry` holds a designed advisory surface with a config, a builder pair,
and nine consuming read sites that are all written correctly. `with_config`
hardcoded the two injection points to `None`, which made every one of those reads
dead. That is the signature of a capability that **was never connected**, not of one
that was abandoned: DELETE would have deleted correct code whose only defect was an
omitted call, and would have closed F-18 by removing a capability rather than by
making it work. WIRE treats the defect as the defect it is.

---

## 2. Deadness evidence, measured on this head

| Claim | Measurement |
|-------|-------------|
| The mesh→DNS reverse edge does not compile | `cargo check -p synvoid-mesh --features dns` → **20 errors** |
| The reverse feature is declared but empty | `crates/synvoid-mesh/Cargo.toml` → `dns = []`, with **no** `synvoid-dns` dependency |
| Injection points have no callers | `with_dht_record_store`, `with_routing_manager` — 0 production callers |
| The capability was hardcoded away | `registry.rs` `with_config` set `dht_record_store`/`routing_manager` to `None` |
| Dead reads caused | **9** `if let Some(ref …)` sites: `health.rs:52,92,144`, `verification.rs:297,348,551`, `registration.rs:108,249`, `dht.rs:83` |
| Uncalled registry methods | `set_registration_sender`, `set_health_sender`, `set_shutdown_sender`, `with_verification_channel`, `start_periodic_dht_sync`, `rebuild_edge_index`, `load_trusted_certificate` — 0 callers each |
| Registry methods with 0 callers | only `build_verification_loop` was called (once), and it returns `None` without `dns_resolver`, so the **edge** registry spawned nothing at all |

### Plan corrections (recorded, not retrofitted)

The plan said **96** reverse sites and **8 types**. Re-measured:

- **88 `cfg` sites across 6 files**, not 96.
- **7 distinct types** across 8 path strings: `MeshNodeRole`, `RecordStoreManager`,
  `DhtRoutingManager`, `SignedDhtRecord`, `SignedRecordType`, `MeshMessage`,
  `MeshTransport`. The "8th" was a path segment, not a type.

---

## 3. What was built

### 3.1 The inversion (Workstream B)

`crates/synvoid-dns/src/mesh_sync/dht_capability.rs` — DNS-owned seam:

| Trait | Methods | Why these |
|-------|---------|-----------|
| `DhtRecordStore` | 7 | thin projections of the corresponding `RecordStoreManager` methods |
| `DhtGlobalLocator` | 1 (`find_closest_global`) | the only routing question DNS asks; nothing about routing policy, penalties, or the table itself |

Three provider methods returned concrete mesh types, so the traits return DNS-owned
projections rather than them: `AdvertisedAnycastNode`, `AdvertisedAnycastRecord`,
`AdvertisedDomainRegistration`, `DhtGlobalPeer`. The projections are inert data —
no behaviour, no I/O, no provider state.

**The hard case.** `get_record_verifier().verify(&SignedDhtRecord)` would have
required DNS to *construct* a signed mesh record — putting the concrete type back in
the seam. It was resolved by **inverting the direction of the question**: DNS no
longer builds a record and asks a verifier. It hands over the fields it read and asks

```rust
fn is_anycast_advertisement_authentic(&self, advertisement: &AdvertisedAnycastRecord) -> bool;
```

The provider constructs the `SignedDhtRecord` and runs the verifier. Signature
verification stays provider-side; no mesh type enters any DNS-owned signature.
`AdvertisedAnycastRecord.signer_public_key` is `Option<String>` because absence is
itself meaningful — an unsigned advertisement is not authenticated — and re-encoding
it to bytes would have lost that at the boundary.

Provider side: `src/worker/unified_server/mesh_dht_capability.rs`
(`DhtRecordStoreAdapter`, `DhtGlobalLocatorAdapter`). Unsigned, missing-key, and
no-verifier-available all return `false`; absence is never inferred as trust.

### 3.2 The wiring (deviation from the plan)

The plan expected a follow-on phase to wire the injection points. Phase 139 wired
them, because **attaching them required a late-binding cell that did not exist**, and
adding the capability without it would have left a second unreachable provider behind
— repeating the defect this phase exists to remove.

`DnsServer::new` runs before the mesh registry and the ACME manager exist, and
composition holds the server as `Arc<DnsServer>` with no setter. The consuming
builders (`with_mesh_registry`, `with_acme_dns_challenges`) could only rebind a
temporary. Hence:

```rust
pub struct LateBinding<T> { cell: Arc<OnceLock<T>> }
impl<T> LateBinding<T> {
    pub fn empty() -> Self;
    pub fn set(&self, value: T, what: &str) -> bool;  // false = already bound, first kept
    pub fn get(&self) -> Option<&T>;
}
```

`OnceLock` rather than a lock-guarded cell: `QueryContext<'_>` borrows from `self`
and **cannot return a guard** bounded by a lock, whereas `OnceLock::get` yields a
reference tied only to the `&self` borrow the context already holds. The inner `Arc`
is shared, so a binding made through any `DnsServer` clone is visible to the
`Arc<DnsServer>` the request path holds. Set-once, not last-write-wins: replacing a
live capability silently would make "which provider is authoritative" unanswerable.

Startup ordering was **checked, not assumed**: `setup_acme` at
`startup_plan.rs:164`, `init_mesh_and_threat_intel` at `:181`, `run()` (which spawns
the DNS listeners and captures the cell) at `:406`. Both bindings strictly precede
listener startup. The **global** registry is the one bound, because
`get_best_edge_for_client` selects among anycast nodes from a DHT-wide view that an
edge node's registry cannot have.

### 3.3 Defects found and repaired

These were shipped defects, not phase-introduced ones.

**F-139-1 — ACME DNS-01 was never attached.** `src/worker/unified_server/init_apps.rs`
did `let _server = (*dns_server).clone().with_acme_dns_challenges(…)` and dropped the
clone: a temporary was rebound and discarded, so the request path could not answer a
`_acme-challenge` TXT query for the life of the process — while logging
`"ACME DNS-01 challenges wired to DNS server"`. Repaired via `set_acme_dns_challenges`.

**F-139-2 — no registry could ever be observed.** `server/startup.rs` hardcoded
`mesh_registry: None` in **both** the UDP and TCP `QueryContext` builds. Even with a
registry attached, `resolve_from_mesh` would have seen `None` on the plain transports.
Both now read the bound cell; the TCP per-connection spawn clones the cell per
connection, since a single capture would be moved on the first iteration.

**F-139-3 — a trust bypass, armed by this phase's own wiring.**
`query_anycast_from_dht` set `authenticated: true` unconditionally on every
DHT-sourced node. That was unreachable while the capability was `None`. Attaching the
capability would have turned it into a live "anything in the DHT is authentic" claim,
which `architecture/distributed_state_contract.md` forbids. It now reports `false`;
the verified path is `sync_from_dht`, which sets the field from
`is_anycast_advertisement_authentic`. **Wiring a dead capability can create the defect
its removal was hiding** — this is the one finding that would have shipped silently.

### 3.4 Contract amendment (Workstream / rejection criterion)

`architecture/distributed_state_contract.md` **§3e** carries a narrow binding
amendment, DHT-A1…A7. It authorizes exactly one previously-unexercised thing — a DNS
server reading advertised DNS state through the two DNS-owned traits — and nothing
about writing, authority, or any new namespace. The load-bearing rules:

- **DHT-A2** an advertisement is not authenticated until the provider's verifier says
  so; a projection carrying no signature must not assert authenticity (F-139-3).
- **DHT-A3** the DHT is never zone authority.
- **DHT-A4** the DHT is never a resolution fallback — a local failure stays
  `SERVFAIL`/`REFUSED`/NXDOMAIN and is never rescued by a remote advertisement.
- **DHT-A5** no mesh type in a DNS-owned trait signature.

The rejection criterion *"moves `MeshMessage` ownership out of `synvoid-mesh`"* is
**not** triggered: `MeshMessage` stays in `synvoid-mesh`. The amendment governs a
consumer, not an owner.

---

## 4. Evidence

### 4.1 Tests — `crates/synvoid-dns/tests/mesh_capability_wiring.rs` (9 tests)

| Test | Pins |
|------|------|
| `a_default_registry_has_no_dht_capability` | `with_config` still leaves it unset — correct, and no longer *unreachable* |
| `the_dht_capability_is_substitutable_by_a_non_mesh_double` | a DNS trait accepts a non-mesh double |
| `a_dht_zone_query_does_not_assert_authenticity` | F-139-3 |
| `advertisement_authenticity_is_asked_of_the_capability` | unsigned rejected; decision delegated, not local |
| `a_capability_bound_after_construction_reaches_the_query_context` | the binding reaches the context `resolve_from_mesh` reads |
| `a_binding_survives_cloning_the_server` | survives the `Arc` boundary composition actually crosses |
| `a_second_binding_is_refused_and_the_first_is_kept` | set-once, pointer-identity checked |
| `the_acme_capability_binds_once_and_is_visible_to_the_query_context` | the F-139-1 capability |
| `the_global_locator_is_reachable_through_the_registry` | dyn-safety under `#[async_trait]` |

Plus 2 unit tests in `dht_capability.rs` and 1 in
`src/worker/unified_server/mesh_dht_capability.rs`.

### 4.2 Guard work required by existing enforcement

Two guards outside the DNS suite had to be satisfied. Both were satisfied by
**extending an explicit allowlist**, not by weakening a rule or moving the code to
satisfy one:

| Guard | What it required | How it was satisfied |
|-------|------------------|----------------------|
| `root_dependencies_have_path_entitlement` (`synvoid-repo-guards`) | `src/worker/unified_server/mesh_dht_capability.rs` is the first `src/worker` consumer of `synvoid-dns`; root dependencies are an explicit per-module allowlist | added `worker` to the `synvoid-dns` row in `architecture/root_dependency_ownership.md` |
| `boundary_composition_guard` (root, 3 tests) | `classify_unified_server_file` fails closed — a new file under `src/worker/unified_server/` with no explicit classification is `Unclassified` and rejected | added `mesh_dht_capability.rs` to the `CompositionRoot` list, beside `init_mesh.rs` and `mesh_attachment.rs`, which it matches in kind |

Recording these matters because they are the phase's real integration cost: the
adapter is a legitimate composition-root citizen, and both guards already knew how
to say so once the new module was named.

### 4.3 Guards — 5 new, all mutation-tested

| Guard | Pins |
|-------|------|
| `dns_names_no_mesh_provider_type_outside_the_anycast_cluster` | the inversion holds everywhere except the named residual |
| `mesh_anycast_cluster_remains_the_only_named_residual` | the carve-out is exactly the residual (3 types, 1 file) in **both** directions |
| `dht_capability_seam_is_inverted_in_the_registry` | trait declarations, `Arc<dyn …>` fields, and mesh-freedom of the trait file |
| `mesh_dht_capability_is_wired_through_composition` | both adapters exist, verifier runs provider-side, composition attaches and binds |
| `dns_server_capabilities_are_bound_on_the_live_server` | F-139-1 and F-139-2 by name |

**8 guard mutations, all fired:** reintroduced `synvoid_mesh::` outside the carve-out;
renamed a residual symbol; concrete field restored; provider type in the trait file;
`set_mesh_registry` removed; `start_periodic_dht_sync` removed; dropped-clone ACME
shape restored; `mesh_registry: None` restored.

**3 evidence mutations, all fired:** `query_context` stops reading the bound
registry; `LateBinding::clone` returns a fresh cell; `authenticated` set to `true`
again.

Two guard bugs were found and fixed during mutation testing, both real:
substring matching could not distinguish `DhtRecord` from the DNS-owned
`DhtRecordStore` (fixed with whole-token `mentions_symbol`), and two gates matched
symbols inside the doc comments that *describe* the inversion (fixed with
`code_only`).

---

## 5. Verification

| Lane | Result |
|------|--------|
| `cargo xtask verify` | **10 steps, 10 passed, 0 failed** (519.6s) — fmt → clippy → deny → core-compile → repo-guards → security-regression → root-guards → core-admin-tests → admin-contract → failure-injection |
| `cargo deny check` | clean (via the `dependency-policy` stage) |
| `cargo test -p synvoid-dns --profile ci --features mesh --lib` | **627 passed**, 0 failed |
| `cargo test -p synvoid-dns --profile ci --features mesh --test mesh_capability_wiring` | **9 passed**, 0 failed |
| `cargo test -p synvoid-repo-guards --profile ci --test dns_dependency_edges` | **21 passed** (16 pre-existing + 5 new) |
| `cargo test -p synvoid-repo-guards --cargo-profile ci --profile ci` | **156 passed** |
| `cargo test --profile ci --features mesh --test boundary_composition_guard` | **55 passed** |
| `cargo clippy --profile ci --features mesh,dns --all-targets -- -D warnings` | EXIT=0 |

**Not run, recorded as not-run:** `cargo xtask verify-full`, `verify-release`,
`cargo audit` (run by the separate CI `dependency-security` job, not by `verify`;
`cargo deny check` did run clean and the manifest is unchanged), and the extended
timeout suites listed in `AGENTS.md` (dns_stress, worker_supervision_control_flow,
fault_injection) — none of which this phase's changes touch.

---

## 6. What this phase did **not** do

| Not done | Why |
|----------|-----|
| Promote `synvoid-dns` to class 2 | Rejection criterion. The `synvoid-mesh` edge is `optional`; inversion alone does not qualify it. |
| Wire the anycast broadcast cluster | It names `MeshMessage`/`MeshTransport`/`MeshNodeRole` and is reachable only through a `None`-valued `zone_sync`. Wiring it would silently widen DNS's request-path capabilities, which this phase does not authorize. **Coupled and dead, deliberately.** |
| Fix `synvoid-mesh`'s `dns = []` feature | 20 compile errors; cannot be repaired without a dependency cycle. Left as a recorded defect for a follow-up, per the user's decision. |
| Close F-18 | The mesh closure is still 2047 lines with `--features mesh`; unchanged by this phase. |
| Fix the `metrics_wiring.rs` parallel race | Pre-existing, unrelated, deliberately not bundled — it needs its own commit. |

---

## 7. Coupling after this phase

```
$ grep -rho "synvoid_mesh::[A-Za-z0-9_:]*" crates/synvoid-dns/src | sort -u
synvoid_mesh::config::MeshNodeRole::GLOBAL
synvoid_mesh::protocol::MeshMessage::generate_timestamp
synvoid_mesh::protocol::MeshMessage::ZoneSyncRequest
synvoid_mesh::transport::MeshTransport

$ grep -rl "synvoid_mesh::" crates/synvoid-dns/src
crates/synvoid-dns/src/anycast_sync.rs
```

Four path strings, **three** types, **one** file — down from 7 types across 6 files.
That one file is the residual named above. `synvoid-dns` remains class 1, and the
remaining coupling is the anycast cluster rather than DHT storage, routing, or signed
provenance.