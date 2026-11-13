# Mesh Multi-Upstream Forwarding — Runtime Qualification Attempt

Status: **BLOCKED**. The shipped mesh data plane cannot start or route on a
real topology. Four defects were found by attempting a genuine two-node
topology; three are fixed in the working tree, one (the largest) is open.

Date: 2026-11-13. Binary: `target/ci/synvoid`, base commit `fb3fa21e` plus the
fixes listed below. Host: single Linux machine, loopback only.

Related: `plans/mesh_multi_upstream_forwarding_results.md` (static/unit
qualification), `plans/mesh_multi_upstream_forwarding_roadmap.md`.

## Topology actually built

Three real `synvoid` processes plus two distinguishable HTTP backends:

| Node | Role | Mesh port | Client listeners | Purpose |
|------|------|-----------|------------------|---------|
| `origin` | 4 (ORIGIN) | 50052/UDP | 9101 | hosts `blog-public` → `127.0.0.1:5001`, `blog-alt` → `127.0.0.1:5002` |
| `edge` | 1 (EDGE) | 50053/UDP | 9100 `edge-main`, 9103 `edge-alt` | site `mesh.test`, `[proxy.listener_backends]` maps each listener to a different service |
| `rogue` | 1 (EDGE) | 50054/UDP | 9102 | a peer that is **not** in the origin's `peered_wafs` |

Backends are a small Python harness whose `/` body differs per instance
(`hello from primary` / `hello from alt`), so a response body proves which
service served the request. Fixtures live under
`runtime/mesh-qual/{ctl.sh,qualify.sh,backend.py,origin,edge,rogue}/`.

Operational note: two `synvoid` instances on one host require **both**
`XDG_RUNTIME_DIR` (supervisor socket) and `XDG_DATA_HOME` (single-instance PID
lock) to be per-node. Otherwise the second node exits with
`synvoid is already running`.

## What the run proved

| Claim | Result |
|-------|--------|
| Config schema accepts a mesh origin with `local_upstreams` and `peered_wafs` | ✅ `--configtest` passes |
| Config schema accepts a mesh site with `listener_backends` | ✅ `--configtest` passes, admin `/api/sites` reports `mesh_service_id: blog-public` and the per-listener map |
| Mesh subsystem starts | ⚠️ logs `Mesh transport started successfully … degraded=false` but binds nothing |
| A QUIC endpoint exists | ❌ no UDP socket on 50052/50053 |
| Edge reaches the origin | ❌ `Failed to connect to seed 127.0.0.1:50052: Runtime not set` |
| A `type = "mesh"` site dispatches to the mesh instead of its direct upstream | ✅ after the D4 fix: fails closed with `Mesh Proxy Error` instead of proxying |
| Per-listener service selection reaches the dispatch layer | ✅ after the D4 fix: `edge-main` requests `blog-public`, `edge-alt` requests `blog-alt` |

## Defects

### D1 — Mesh refuses to start unless `[tunnel.mesh.authority_freshness]` is set (FIXED)

Observed:

```
ERROR init_mesh: Invalid mesh config — refusing to start mesh subsystem
  error=unknown variant ``, expected one of `fail_open_defer`,
  `fail_closed_not_actionable`, `allow_stale_with_warning` at line 1 column 3492
```

Cause: `crates/synvoid-config/src/mesh.rs` — `AuthorityFreshnessConfig` derived
`Default`, so `canonical_snapshot_stale_mode` defaulted to `""`. The field's
`#[serde(default = "default_canonical_snapshot_stale_mode")]` only applies when
the table is present; the parent field is `#[serde(default)]`, so the omitted
table used the struct `Default` instead. `realize_mesh_runtime_config`
serializes the DTO to JSON and the mesh-side
`CanonicalSnapshotStaleMode` rejects `""`.

Fix: hand-written `Default` mirroring the serde defaults, matching the
neighbouring `MeshSupervisionConfig` pattern.
Regression test: `tests/mesh_config_realization.rs` (3 tests).

### D2 — `UnifiedServer` never receives a `BlockStore`, so mesh init always bails (FIXED)

Observed:

```
WARN init_mesh: BlockStore not initialized, skipping threat intelligence setup
ERROR runtime_launch: mesh_configuration_invariant: mesh supervision policy present but no transport
```

Cause: `UnifiedServer::with_block_store` (`src/server/mod.rs:252`) had **no
caller**, so `get_block_store()` was always `None`. `init_mesh` returns an empty
`MeshInit`, and `validate_mesh_runtime_inputs` correctly refuses that
combination and shuts the worker down.

Fix: the worker composition root (`src/worker/unified_server/startup_plan.rs`)
now builds a worker-local in-memory `BlockStore` and attaches it. In-memory is
deliberate: the Supervisor owns the persisted copy and broadcasts events over
IPC (`architecture/threat_intel_consumer_actionability.md`, "WorkerIPC"), and a
second process opening the same `blocks.json` is a hazard. This also re-enables
the blocklist IPC path that logged "BlockStore not initialized".

### D3 — No QUIC runtime is ever installed on `MeshTransport` (OPEN — the blocker)

The transport reports health while owning no socket:

```
INFO synvoid_mesh::mesh::transport: Mesh transport started (lifecycle: running, degraded=false)
INFO synvoid::worker::mesh_supervision: Mesh transport started successfully generation=0
WARN synvoid_mesh::mesh::transport_connection: Network partition detected: isolated from all peers
```

yet `ss -lunp` shows no UDP socket on either mesh port, and the edge's seed dial
fails immediately:

```
INFO  synvoid_mesh::mesh::transport: Attempting to connect to verified seed: 127.0.0.1:50052
WARN  synvoid_mesh::mesh::transport: Failed to connect to seed 127.0.0.1:50052: Runtime not set
```

Code path:

- `MeshTransport { runtime: Option<Arc<QuicRuntime>> }` — `crates/synvoid-mesh/src/mesh/transport.rs:117`, initialised `None` at `:775`.
- The only setter, `MeshTransport::set_runtime` (`:1709`), has **no callers** anywhere in the workspace.
- The accept loop is gated on it: `if let Some(ref runtime) = self.runtime { runtime.start_server() … }` (`:2646`), so no listener is ever bound.
- Every dial fails closed: `.ok_or(MeshTransportError::RuntimeNotSet)` (`:4726`).
- `MeshCertManager::ensure_certs` / `set_runtime` on the cert side are likewise unused in production, so `[tunnel.mesh.tls]` has no effect on a running node.

Consequence: mesh forwarding is unreachable end to end. Everything below the
transport (service-target preface, authorization, listener mapping, streaming)
is dead code on a live process.

### D4 — `type = "mesh"` sites silently proxy to their direct upstream (FIXED)

Observed: with the site's `[site.upstream]` pointing at the *alt* backend and
`[proxy.backend] type = "mesh"`, both listeners returned `hello from alt` —
the direct upstream — instead of failing closed. No warning, no error.

Cause: `crates/synvoid-proxy` gates its router arm on its own `mesh` feature
(`crates/synvoid-proxy/src/router.rs:634,936`), but the root `mesh` feature in
`Cargo.toml` did **not** forward to `synvoid-proxy/mesh`. In the shipped binary
the arm therefore compiled to the empty
`#[cfg(not(feature = "mesh"))] BackendConfig::Mesh { .. } => {}` branch, and
routing fell through to `[site.upstream]`.

This also explains why CI stayed green: the unit tests for that arm are behind
the same cfg, so an unfeatured run reports `running 0 tests`:

```
$ cargo test -p synvoid-proxy --test mesh_listener_backends --profile ci
running 0 tests
```

Fix: root `mesh` now includes `synvoid-proxy/mesh`, pinned by
`tests/mesh_proxy_feature_guard.rs`.

After the fix, with the direct upstream still pointing at the alt backend, the
same two requests fail closed and name the service each listener selected:

```
edge-main (9100): 502 "Mesh Proxy Error: Connection failed: No route to upstream: blog-public"
edge-alt  (9103): 502 "Mesh Proxy Error: Connection failed: No route to upstream: blog-alt"
```

That also proves the Phase 03 listener mapping end to end at the dispatch
layer: the two listeners resolve to different service IDs. The hop itself still
cannot run, because of D3.

## Latent handshake defects (code-verified; unreachable until D3 is fixed)

These cannot be observed at runtime yet, but they will block the first real
session once a transport exists:

1. **`Hello.public_key` encoding mismatch.** The sender emits hex
   (`signing_public_key()` → `public_key_hex()` → `hex::encode`,
   `config_identity.rs:506-508`; used in the Hello at `transport.rs:4871`).
   Validators base64-decode it and expect 32 bytes (`peer_auth.rs:813-819`).
   A 64-char hex string decodes as 48 bytes, so validation cannot pass.
2. **Node-id ↔ key binding cannot be satisfied.** `transport.rs:4948-4961`
   compares `NodeId::from_public_key(pk)` with
   `NodeId::from_node_id_string(claimed_id)`. The two hash different inputs
   (`node_id.rs:28-45`), so the comparison fails for any normal node id and the
   peer is rejected with `AuthFailed("Node ID does not match public key")`.

The same static review reported, but this qualification did not verify:
`HelloAck` never carrying the signature/PoW material that responder-role
validation requires, `ca_path` never being loaded outside the unused
`ensure_certs`, and `[[tunnel.mesh.seeds]] public_key` being sent as an
`auth_token` that the receiver rejects because `auth_keys` is never populated.
Treat those three as leads to confirm while wiring D3, not as established facts.

## Secondary finding — `node_id` is not operator-chosen

`MeshConfig::node_id()` prefers `node_identity.node_id`, and
`load_node_identity()` overwrites it from the signing key
(`derive_node_id` → `node-<hash>`), or `mesh-<uuid>` when no identity exists
(`config_mesh.rs:141-146`, `config_identity.rs:334-407`). A realized config
built from `node_id = "origin-node"` produced `node-e93904c3ce9f8473`.

`peered_wafs` therefore must list the peer's **realized** id, obtained from
`GET /api/mesh/status` (`node_id`). The documentation previously implied the
configured `node_id` was the identity; `docs/WAF_MESH.md` now states the
derivation and how to read the real value.

## Documentation corrections made during the attempt

- `docs/WAF_MESH.md`: the mesh site example omitted `[site.upstream]`, which is
  **mandatory** (`missing field \`upstream\``) even for mesh backends.
- `docs/WAF_MESH.md`: `node_id` / `peered_wafs` semantics per the finding above.
- `[tunnel.mesh.connection] min_peer_connections` defaults to 3, which a two-node
  topology can never satisfy; the docs now call this out.

## Fixes in this working tree

| File | Change |
|------|--------|
| `crates/synvoid-config/src/mesh.rs` | manual `Default` for `AuthorityFreshnessConfig` |
| `src/worker/unified_server/startup_plan.rs` | attach a worker-local `BlockStore` |
| `Cargo.toml` | root `mesh` feature enables `synvoid-proxy/mesh` |
| `tests/mesh_config_realization.rs` | regression tests for D1 |
| `tests/mesh_proxy_feature_guard.rs` | guard for D4's feature edge |
| `docs/WAF_MESH.md` | site/identity/connection corrections |

## Remaining work to obtain the topology

1. **Wire the QUIC runtime (D3).** Build a `QuicRuntime` for mesh (bind
   `bind_address`:`port`, TLS from `[tunnel.mesh.tls]` or a generated CA), call
   `MeshTransport::set_runtime` before startup, and make `ensure_certs` run for
   non-global nodes. Until this exists, no mesh request can leave a node.
2. **Fix the handshake** (hex/base64 encoding, node-id binding, HelloAck
   authenticity) and confirm the three unverified claims above.
3. **Make the mesh routing tests actually execute in CI**, e.g. run
   `cargo test -p synvoid-proxy --features mesh` in a verify step, so an
   unfeatured build cannot pass again with zero tests.
4. Re-run this topology once 1–3 land; the matrix in `qualify.sh` (service
   selection per listener, unauthorized peer → 403, unknown service → 502, 4 MiB
   fixed and chunked bodies, 40 MiB response, failover) is ready to execute.
