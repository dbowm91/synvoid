# Phase 114 Plan: Tunnel / Eggtunnel Protocol Parity and Convergence Refresh

Status: **CLOSED QUALIFIED** (2026-10-02; evidence/architecture only; terminal disposition RETAIN + DEFER relay reuse; no production migration, no cross-repo plan registered).

Registered in: `plans/roadmap.md` and
`plans/subsystem_boundary_extraction_roadmap.md`.

Planning baseline: SynVoid `main` at
`4d957b2e90c29c018430bdac8af830b9db91b19a` (2026-10-02).

Research baseline for Eggtunnel:
`eggstack/eggtunnel` `main` at
`ece46fd223265b7b0609e3640b0caa9efadd1535` (2026-10-01).

Owner: tunnel/networking / cross-repo architecture.

Predecessors:

- Phase 111 CLOSED DEFER;
- Phase 113 CLOSED QUALIFIED (docs-only reconciliation, 2026-10-02).

## Goal

Reopen only the evidence gap in Phase 111 by comparing SynVoid's actual tunnel,
VPN, and mesh-facing protocol/runtime semantics against the now-available
Eggtunnel source and Eggress-backed transports.

Produce a source-backed disposition for every overlapping capability:

- ADOPT;
- ADAPT;
- UPSTREAM;
- RETAIN;
- DEFER.

If a concrete reusable capability is missing upstream, register a focused
Eggtunnel/Eggress plan in the owning repository. Do not implement speculative
cross-repo migrations in SynVoid before the ownership and compatibility matrix is
complete.

This phase does **not** reopen the already qualified Phase 105–112 campaign
implementation.

## Why Phase 111 needs a refresh

Phase 111 closed DEFER because the implementer had no local Eggtunnel checkout.
Its evidence document therefore compared SynVoid mainly against Eggress and
explicitly stated that authenticated session, registration, wire-version, drain,
and peer-auth parity could not be inspected.

That limitation no longer applies. Current Eggtunnel source is accessible and
contains the exact mechanisms Phase 111 needed to compare.

## Researched Eggtunnel baseline

At `ece46fd223265b7b0609e3640b0caa9efadd1535`:

### Embeddable runtime

`crates/eggtunnel/src/lib.rs` exposes:

- `Client`, `ClientBuilder`, `ClientHandle`, `ClientConfig`;
- `Server`, `ServerBuilder`, `ServerHandle`, `ServerConfig`;
- `TargetConnector` and application-stream abstractions;
- `ResourceLimits`, `RuntimePolicy`, `TimeoutPolicy`;
- caller-owned Tokio runtime;
- no global tracing/runtime installation;
- `#![forbid(unsafe_code)]`.

### Authenticated session and service lifecycle

The client/server implementation owns:

- authenticated Session establishment;
- dynamic service registration/unregistration;
- reconnect supervision;
- per-session generation/state;
- `SessionId`, `ServiceId`, `ConnectionId`;
- `DataHello` stream correlation;
- ping/pong heartbeat;
- bounded shutdown/drain;
- relay task ownership.

Server internals explicitly separate accept/auth/session/control/pending/service
responsibilities.

### Wire protocol

`eggtunnel-proto` defines a runtime-neutral bounded protocol:

- magic `ETUN`;
- 14-byte fixed header;
- major/minor wire version;
- explicit message IDs;
- payload bound of 1 MiB;
- auth-token bound of 4096 bytes;
- service-name bound of 128 bytes;
- diagnostic bound of 256 bytes;
- capability list bound of 32;
- target-host bound of 253 bytes;
- typed messages for hello/auth/register/open/ping/drain/data correlation;
- credential zeroization and redacted capability IDs;
- explicit rejection of unknown major versions.

Current source wire version is **1.1** with negotiated capabilities:

1. correlated registration rejection;
2. drain deadline.

### Transport support

The current library provides:

- TCP/TLS;
- QUIC;
- WSS;
- outbound HTTP CONNECT/SOCKS5 proxy traversal through Eggress;
- optional mTLS for the TCP/TLS profile.

QUIC changes the Session transport, not the service model: registered external
services remain TCP streams.

### Critical release/version distinction

The repository's workspace/crate version remains `0.2.0`, but:

- the **published 0.2.0** crate line uses wire **1.0**;
- current repository source at the same workspace version implements wire
  **1.1**.

Therefore Phase 114 must distinguish:

- source/API parity on exact Eggtunnel `main`;
- behavior available from an actually published/released dependency.

Do not tell SynVoid to pin `eggtunnel = "0.2.0"` and assume wire 1.1
capabilities.

## SynVoid baseline that must be compared

SynVoid tunnel currently includes materially different semantics:

- QUIC `Hello` / `HelloAck` with client ID, auth token, mappings,
  server session ID, access level, and datagram capability negotiation;
- stream-level messages/framing including data chunks/ack/error paths;
- QUIC datagrams with bounded payload and fragment/sequence/source/return
  metadata;
- `UdpTunnelManager`;
- `TunnelManager` / `TunnelRouter`;
- upstream routing/config integration;
- VPN client;
- TUN/WireGuard surfaces;
- mesh consumption of SynVoid QUIC runtime/connection types.

Eggtunnel's current protocol instead separates a bounded control stream from
opaque per-connection data streams and does not expose a generic UDP service
protocol in the reviewed support contract.

This means "Eggtunnel has QUIC" is not protocol parity.

## Workstream A — exact capability and symbol matrix

Replace Phase 111's unavailable-source matrix with a source-backed matrix.

At minimum compare:

| Capability | SynVoid evidence | Eggtunnel/Eggress evidence | Required decision |
| --- | --- | --- | --- |
| wire framing/versioning | SynVoid tunnel framing/messages | ETUN 1.0/1.1 | ADAPT/RETAIN; never reinterpret |
| authentication | Hello/auth/access-level semantics | Auth/AuthOk + SessionId | map identity/authorization differences |
| service registration | mappings/registry/router | RegisterService/Ack/Reject | compare dynamic lifecycle |
| connection correlation | SynVoid connection/session IDs | SessionId/ConnectionId/DataHello | compare replay/generation rules |
| reconnect | client/runtime behavior | ReconnectSupervisor | determine reusable runtime seam |
| heartbeat | health messages | Ping/Pong + HeartbeatSnapshot | compare liveness semantics |
| drain/shutdown | SynVoid runtime cancellation | negotiated drain deadline + local ceiling | compare owner/drain guarantees |
| QUIC runtime | Quinn runtime used by tunnel/mesh | Eggress QUIC via Eggtunnel | determine whether reusable below protocol |
| stream relay | SynVoid handlers | `eggress-relay` | strongest likely adoption candidate |
| TLS / mTLS | SynVoid identity/TLS policy | Eggtunnel profiles | compare trust/custom-CA/PQ requirements |
| proxy traversal | SynVoid route/proxy integrations | Eggress outbound connector | assess direct reuse |
| UDP/datagram | explicit SynVoid datagrams/manager | no reviewed generic service-datagram contract | RETAIN or upstream-plan |
| VPN/TUN/WireGuard | SynVoid-specific | no equivalent reviewed contract | RETAIN unless proven generic |
| mesh QUIC consumption | active internal consumer | Eggtunnel has no mesh policy | preserve SynVoid adapter |
| observability | SynVoid metrics | Eggtunnel Snapshot/termination categories | map, do not leak policy upstream |

Every row must cite concrete source/test/doc evidence from both repos.

## Workstream B — wire compatibility decision

Prove explicitly that current protocols are or are not byte/semantic compatible.

Compare:

- header/magic/version fields;
- message IDs;
- serialization;
- auth ordering;
- session establishment;
- registration lifecycle;
- data-stream opening;
- error semantics;
- reconnect generation;
- heartbeat;
- drain;
- datagram capability;
- size bounds;
- replay/stale-session handling.

Expected default: they are distinct protocols.

Allowed strategies if adoption is useful:

1. **mechanism reuse below the wire** — reuse Eggress relay/transport while
   retaining SynVoid wire;
2. **parallel Eggtunnel mode** — expose Eggtunnel as a separately negotiated
   tunnel profile;
3. **versioned migration** — only with explicit mixed-version compatibility
   and a separate implementation plan.

A silent protocol replacement is prohibited.

## Workstream C — runtime/lifecycle parity

Compare ownership and cancellation semantics:

- caller-owned runtime;
- connection task ownership;
- reconnect supervision/backoff;
- registration state across reconnect;
- stale session/generation rejection;
- server session registry;
- pending connection bounds;
- shutdown cancellation;
- grace/drain ceilings;
- half-close/backpressure;
- timeout/resource-limit behavior.

Determine whether SynVoid can delegate generic lifecycle without importing
Eggtunnel's service-level policy wholesale.

## Workstream D — transport and relay reuse

Test the strongest low-risk reuse candidates first:

### Eggress relay

Compare `eggress-relay` with SynVoid stream forwarding for:

- bidirectional copy;
- half-close;
- bounded buffers;
- cancellation;
- drain;
- error mapping;
- accounting hooks.

If parity is high, estimate exact source/dependency maintenance removed by
adoption.

### Eggtunnel QUIC transport

Determine whether Eggtunnel's QUIC layer is separable as a generic connection
mechanism or inseparable from ETUN session semantics.

Because `synvoid-mesh` consumes SynVoid QUIC runtime types, do not replace that
runtime unless mesh identity/session behavior remains explicit and one-way.

## Workstream E — authenticated datagram gap

Eggtunnel current support describes TCP services even when Session transport is
QUIC. SynVoid has explicit datagram capability negotiation and UDP manager
semantics.

Determine whether SynVoid's datagram mechanism is:

- VPN/product-specific and should remain local; or
- a generic reverse-tunnel capability worth adding to Eggtunnel.

If generic, write and register a separate plan in `eggstack/eggtunnel` that
defines before implementation:

- new capability ID;
- wire messages/IDs;
- max datagram size;
- association/session identity;
- sequencing/replay rules;
- fragmentation/reassembly policy;
- queue/concurrency bounds;
- idle timeout;
- wrong-session/stale-generation behavior;
- saturation/backpressure/drop accounting;
- 1.0/1.1 mixed-version fallback;
- security/abuse tests.

Do not implement datagrams in SynVoid as a permanent fork of Eggtunnel.

## Workstream F — release-consumability gate

For every ADOPT result, distinguish current-source support from released support.

Record:

- exact Eggtunnel commit tested;
- published crate version that contains the needed API/wire behavior;
- Eggress dependency versions;
- MSRV;
- supported target matrix;
- feature flags;
- whether SynVoid can use a crates.io release rather than git dependency.

If required wire 1.1 behavior is not in a released Eggtunnel version, adoption
must remain blocked or be preceded by an Eggtunnel release plan.

Long-lived git dependencies are not the desired terminal state.

## Workstream G — proof-of-integration spike, only after matrix

If the matrix identifies a high-confidence adoption candidate, permit a
temporary non-production spike to measure:

- adapter LOC;
- dependencies removed/added;
- binary-size delta;
- build-time delta;
- test surface removed;
- runtime behavior against existing tunnel fixtures.

Remove the spike before closeout unless a separately registered implementation
plan authorizes landing it.

Do not use a spike to smuggle in protocol migration.

## Workstream H — cross-repo planning outputs

Phase 114 may terminate with one or more of:

- **RETAIN** — SynVoid semantics are materially different and no meaningful
  maintenance reduction is demonstrated;
- **ADOPT EXISTING** — a released Eggtunnel/Eggress capability is directly
  reusable; register a SynVoid implementation/adoption plan;
- **UPSTREAM FIRST** — generic capability belongs in Eggtunnel/Eggress but is
  missing; register a focused plan in that repository;
- **PARALLEL PROFILE** — Eggtunnel is useful as an additional profile but not a
  wire-compatible replacement; register a separate product/API plan if
  justified;
- **DEFER** — version/release/evidence gaps remain.

No numerical score or vague "converge later" outcome.

## Required evidence

At minimum inspect and cite:

Eggtunnel:

- `docs/PROTOCOL.md`;
- `docs/SUPPORT.md`;
- `crates/eggtunnel-proto/src/lib.rs`;
- `crates/eggtunnel/src/lib.rs`;
- client reconnect/service registration implementation;
- server accept/auth/session/control/pending/service implementation;
- QUIC transport adapter behavior;
- relay integration;
- current Cargo features/versions.

SynVoid:

- `crates/synvoid-tunnel/src/quic/**`;
- `crates/synvoid-tunnel/src/udp_manager.rs`;
- `crates/synvoid-tunnel/src/upstream.rs`;
- `crates/synvoid-vpn-client/**`;
- mesh call sites consuming tunnel QUIC types;
- tunnel/VPN integration tests and docs.

## Verification

This phase is primarily research/architecture unless a temporary spike is used.

Run SynVoid focused baselines before any recommended implementation plan:

```bash
cargo test -p synvoid-tunnel --profile ci
cargo test -p synvoid-vpn-client --profile ci
cargo test -p synvoid-mesh --profile ci
cargo check -p synvoid-tunnel --all-features
cargo deny check
cargo audit
```

Run Eggtunnel's repository verification appropriate to the exact source
baseline, including protocol mixed-version and transport profiles where
available.

If a cross-repo plan is registered, record the exact upstream proof required
before SynVoid adoption.

## Documentation outputs

Create a refreshed evidence record, preferably:

`architecture/tunnel_eggtunnel_parity_phase114.md`

It must explicitly supersede only the *evidence limitation* in
`architecture/tunnel_convergence_phase111.md`.

Do not rewrite Phase 111 as though Eggtunnel was available during that run.

Update current tunnel architecture/support docs only for conclusions actually
proven by Phase 114.

## Acceptance criteria

- Eggtunnel source is compared directly, not inferred from Eggress;
- published 0.2.0 wire 1.0 is distinguished from current-source wire 1.1;
- SynVoid and ETUN wire/session differences are explicit;
- each overlap has ADOPT/ADAPT/UPSTREAM/RETAIN/DEFER ownership;
- datagram gap has a concrete disposition;
- mesh/VPN-specific semantics stay out of Eggtunnel unless independently
  generic;
- any proposed adoption identifies a released consumable version or upstream
  release prerequisite;
- any upstream work receives its own plan in the owning repo;
- no production migration lands under this evidence phase.

## Rejection criteria

Reject a closeout that:

- repeats Phase 111's "Eggtunnel unavailable" rationale;
- assumes QUIC transport equivalence implies tunnel protocol equivalence;
- treats current unreleased wire 1.1 source as if published 0.2.0 contains it;
- replaces SynVoid wire without a versioned compatibility plan;
- pushes SynVoid mesh/VPN policy into Eggtunnel;
- adds UDP as an unbounded or implicit extension;
- uses a permanent git dependency as the convergence result;
- claims maintenance reduction without showing removed ownership/code/tests.

## Execution record (2026-10-02)

- Eggtunnel source compared directly at `ece46fd223265b7b0609e3640b0caa9efadd1535`
  (verified remote `HEAD` via `git ls-remote`; scratch clone, not vendored).
- Evidence record created: `architecture/tunnel_eggtunnel_parity_phase114.md`
  (source-backed matrix, wire-incompatibility table, runtime/lifecycle parity,
  relay/QUIC reuse analysis, datagram-gap disposition, release gate). It
  supersedes only Phase 111's source-availability limitation; Phase 111 text
  is otherwise untouched.
- Terminal dispositions: **RETAIN** for wire/session/registration/
  correlation/reconnect/heartbeat/drain/QUIC-runtime/TLS/datagram/VPN/mesh/
  observability; **DEFER** for `eggress-relay` reuse and Eggress
  outbound-connector integration (parity tests + spike measurements required
  first); no ADOPT EXISTING, no UPSTREAM FIRST, no PARALLEL PROFILE.
  Tunnel convergence overall remains DEFER (evidence basis upgraded).
- Release gate: published `0.2.0` = wire 1.0; wire 1.1 unreleased; any
  future wire-1.1 adoption needs an Eggtunnel release plan first; no git
  dependency; no cross-repo plan registered by this phase.
- No spike run (no high-confidence candidate per plan §G); no production,
  manifest, lockfile, workflow, or protocol change. Datagrams stay local;
  mesh/VPN policy stays out of Eggtunnel.
- SynVoid focused baselines (with macOS XZ `PKG_CONFIG_PATH` workaround):
  `synvoid-tunnel` 72 passed; `synvoid-vpn-client` 0 tests (no suites,
  recorded truthfully); `synvoid-mesh` 1,093 passed;
  `cargo check -p synvoid-tunnel --all-features` clean; `cargo deny check`
  clean; `cargo audit` no vulnerabilities + six allowed unmaintained
  warnings. Full `cargo xtask verify` 10/10 owned by the Phase 113 closeout
  on the same tree; `git diff --check` and `cargo fmt --all -- --check`
  run at closeout.
- Unblock check: no downstream extraction/adoption plan is unblocked. No
  Phase 115+ plan is registered; no other eligible plan file is
  ACTIVE/READY. Phase 114 registers no implementation or upstream plan, so
  there is nothing to promote.
