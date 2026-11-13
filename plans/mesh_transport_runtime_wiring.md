# Mesh Transport Runtime Wiring — Implementation Plan

Objective: make `BackendType::Mesh` forwarding work over a real QUIC session
between two `synvoid` nodes. Today the routing/authorization/body layer is
complete and unit-tested, but no runtime carries a packet, so none of it is
reachable on a live process.

Status: **proposed**. Evidence for every claim below is in
`plans/mesh_multi_upstream_forwarding_runtime_qualification.md`.

## Current state (measured, not inferred)

| Layer | State |
|-------|-------|
| Config schema (`[tunnel.mesh]`, `local_upstreams`, `peered_wafs`, `listener_backends`, `body_policy`) | works |
| Router → `BackendType::Mesh` with per-listener service IDs | works (after the `synvoid-proxy/mesh` feature fix) |
| Service-target preface, origin authorization, streaming bodies | implemented + unit tested |
| QUIC endpoint (bind/dial) | **absent** — `runtime` is always `None` |
| Peer handshake | **cannot succeed** — encoding and binding defects |

## Work items

### W1 — Give `MeshTransport` a runtime

- `crates/synvoid-mesh/src/mesh/transport.rs:117` holds `runtime: Option<Arc<QuicRuntime>>`; the setter at `:1709` has no callers.
- Build the runtime during mesh startup (`src/worker/unified_server/init_mesh.rs`, before `MeshTransportManager::start`) and call `set_runtime`.
- Bind `[tunnel.mesh] bind_address`:`port` (currently advertised but never bound).
- Decide the TLS source: `QuicRuntime` is `synvoid_tunnel`'s type and reads `[tunnel.quic]` TLS, while mesh has its own `[tunnel.mesh.tls]`. Either add a constructor that accepts an explicit `rustls::ServerConfig`/`ClientConfig`, or implement a mesh adapter that maps `MeshTlsConfig` onto the tunnel runtime config. The former is cleaner; the mesh must not silently inherit `[tunnel.quic]` settings.

### W2 — Make certificates real

- `MeshCertManager::ensure_certs` (`cert.rs:275`) and the cert-side `set_runtime` have no production callers, so `[tunnel.mesh.tls]` has zero effect today.
- Call `ensure_certs` for non-global nodes during startup (`auto_generate` is already `auto_generate_certs && !is_global`, `cert.rs:234`).
- Implement the CA path: a `ca_mode = true` node generates a CA (`generate_ca_certificate`, `cert.rs:1031`) and issues leaves whose SAN is the peer's **realized** node id (`sign_certificate`, `cert.rs:1080`); peers load it via `ca_path`. Note `load_ca_certificate` is only reachable from `ensure_certs` (`cert.rs:300`), so wiring `ensure_certs` also fixes an empty trust store.
- For private/loopback deployments, TOFU (`tls.mode = "tofu"`, `seed_tofu`) is the documented downgrade; make it an explicit operator choice, never the default.
- Fix `Hello.public_key` encoding (W4.1) before any of this can validate.

### W3 — Startup truthfulness

- `start_mesh_generation` logs "Mesh transport started successfully" (`src/worker/mesh_supervision.rs:886`) and the phase-9 runtime block is skipped silently when `runtime` is `None` (`transport.rs:2646`).
- If mesh is enabled and the runtime could not be constructed, startup must fail (or report `degraded` with a specific reason) instead of reporting success. Add a regression test asserting that an enabled mesh with no runtime is a startup error.

### W4 — Handshake correctness

1. **Encoding.** Sender emits hex (`public_key_hex` → `hex::encode`, `config_identity.rs:506`; Hello at `transport.rs:4871`); validators base64-decode and require 32 bytes (`peer_auth.rs:813`). Pick one encoding and use it on both sides, with a decode that rejects the wrong length.
2. **Node-id binding.** `transport.rs:4948` compares `NodeId::from_public_key(pk)` against `NodeId::from_node_id_string(claimed)`, which hash different inputs and can never match. Compare against the id derived from the key, or have the peer present the key and derive its id.
3. **HelloAck authenticity.** Confirm (static review only, unverified) that `HelloAck` carries no signature/PoW material while responder role validation demands it (`peer_auth.rs:663-690, 968-980`); sign the ack or stop re-validating the responder's role.
4. **Seeds.** `bootstrap_from_seeds` sends `auth_token = seed.public_key` (`transport.rs:4693`) and the receiver rejects any `auth_token` because `auth_keys` is never populated (`transport.rs:4188`). Either populate `auth_keys` from the seed list or stop sending the token.

### W5 — CI coverage that cannot silently vanish

- `cargo test -p synvoid-proxy --test mesh_listener_backends` reports `running 0 tests` without `--features mesh`; that is how the `synvoid-proxy/mesh` gap shipped.
- Add a verify step running the proxy's mesh tests with the feature, and keep `tests/mesh_proxy_feature_guard.rs` as the manifest-level guard.
- Add the first **two-node loopback integration test**: bind ephemeral UDP ports, start origin+edge in-process, assert service selection per listener, 403 for an unpeered node, 502 for an unknown service, and a 4 MiB body round trip. This is the coverage that never existed.

### W6 — Re-run the qualification

`runtime/mesh-qual/qualify.sh` already encodes the matrix (service per
listener, unauthorized peer, unknown service, 4 MiB fixed and chunked bodies,
40 MiB response, over-cap rejection, origin failover). Run it unchanged once
W1–W4 land and record the results here and in the results document.

## Acceptance criteria

1. `ss -lunp` shows the configured UDP port on both nodes while mesh is enabled.
2. `/api/mesh/status` reports `connected_peers: 1` on the edge and the origin's realized `node_id` (today it reports `node_id: null, connected_peers: 0` even with mesh "running").
3. `GET /` on the edge main listener returns the `blog-public` backend body; the alt listener returns `blog-alt`.
4. A node absent from `peered_wafs` receives `403` and no upstream URL.
5. An unknown service ID returns `502` with no `Host` fallback.
6. 4 MiB fixed and chunked request bodies arrive intact; a 40 MiB response arrives intact.
7. Killing the origin makes edge requests fail quickly with `502`, not hang; restarting it restores forwarding.
8. `cargo xtask verify` is green **and** the new two-node test actually runs (nonzero test count).

## Decisions needed before W1

- **TLS posture**: operator-provided CA as the only strict mode, with TOFU as an
  explicit opt-in? Auto-generated self-signed leaves cannot satisfy
  `strict_certificate_validation` against an empty root store.
- **Identity source**: keep key-derived node ids (stable per key, opaque) or add
  an operator-assigned identity that `peered_wafs` can name directly? Today the
  configured `[tunnel.mesh] node_id` is silently overridden, which makes
  allowlisting awkward.
- **Scope of W1**: a mesh-specific QUIC endpoint (clean separation from
  `[tunnel.quic]`) versus extending `synvoid_tunnel::QuicRuntime` to accept an
  external TLS config (less new code, more coupling).
