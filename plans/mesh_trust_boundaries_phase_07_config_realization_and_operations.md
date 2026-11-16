# Phase 07 Plan: Config Realization and Operations

Status: **PROPOSED** (not started; findings verified at `4add005f`).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 01 (the round-trip fixture reuses the harness PKI).
Depends on: Phase 04 (signer identity) for the identity requirements below.

## The finding

**C10 (High).** The TOML-facing mesh DTO and the runtime `MeshConfig` have
diverged, and the bridge between them is a JSON round-trip
(`src/supervisor/mesh.rs:24-37`), so a field missing from the DTO is silently
dropped and a field with the wrong type is a startup failure:

- the DTO (`crates/synvoid-config/src/mesh.rs:568-624`) has no `dht`, no
  `mlkem`, and no `require_tier_claim`, and no `deny_unknown_fields`;
- the runtime has all three (`crates/synvoid-mesh/src/mesh/config.rs:888`,
  `:900`, `:906`), so `config.dht` is permanently `None`: no record store, no
  DHT routing, no ML-KEM, and the tier-claim gate is always off;
- `MeshConfig::validate()` — the genesis and unsigned-sync window checks — has
  no production caller; only tests call it.

**D4 (Medium).** `quic_port` is never bound: the runtime binds `config.port`
(`quic_runtime.rs:56`) while the field exists to name a different port.
`QuicRuntime::new` also hardcodes 300 s idle, 25 s keepalive, 100 streams, and
a 1 MiB buffer (`synvoid-tunnel/src/quic/runtime.rs:84-88`), ignoring the
values `tunnel_config_for_mesh` sets.

**D5 (Medium).** Node identity is not durable by default: without
`node_identity.private_key_path`, a key is generated in memory and never
persisted (`config_identity.rs:399-424`); the key file is written with
`std::fs::write` (0644 under a normal umask) while other mesh keys use 0600;
`realize_mesh_runtime_config` only warns when identity loading fails
(`src/supervisor/mesh.rs:30-36`); and `node_id()` then returns a fresh random
`mesh-<uuid>` on every call (`config_mesh.rs:141`).

**D6 (Medium).** `origin_signing_key` is `Option<String>` in the DTO
(`synvoid-config/src/mesh.rs:616`) but `Option<OriginSigningKeyConfig>` at
runtime (`crates/synvoid-mesh/src/mesh/config.rs:882`). Setting the documented
field fails the round-trip and mesh init returns `MeshInit::disabled()`.

**D7 (Medium).** Every worker process calls
`initialize_mesh_transports(..., listen_endpoint = true)`
(`init_mesh.rs:550-585`), and workers are separate processes. With
`unified_server_workers > 1`, only the first binds; the rest fail and never
become ready.

**D9 (Medium).** No ALPN is configured anywhere in the QUIC stack. Mesh and
tunnel endpoints are indistinguishable at the TLS layer, so a misdirected
tunnel client is accepted at transport level and reaches the mesh framing
parser.

**D10 (Medium).** The edge-replica store uses a hardcoded
`/var/lib/synvoid/edge_replica` and swallows creation failures with `.ok()`
(`backend.rs:493-500`, `raft/edge_replica.rs:751-757`), so two nodes on one host
share or lock each other out, and a failure leaves the manager silently absent.

**D12 (Medium).** `config/mesh-example.toml` sets `auto_generate_certs = true`
with no `ca_path` while the defaults are strict + `enforce_mutual_tls`, so
copying the example cannot start.

## Root cause

Two configuration models were maintained by hand and joined by serde. No test
compared them, no unknown-field rejection caught typos, and the runtime
defaults were treated as the source of truth for knobs the config also
exposed. Operational constraints (one bind per node, durable identity, ALPN)
were documented in prose rather than enforced at startup.

## Fix scope

### G1 — One configuration contract

- Add the missing fields to the DTO: `dht`, `mlkem`, `require_tier_claim`,
  `stale_cache_ttl_secs`, `ratelimit_block_advertisement`,
  `dht_access_for_edge`, and any other runtime field with no DTO counterpart.
- Fix `origin_signing_key` to the same shape as the runtime
  (`OriginSigningKeyConfig`), or to a string the runtime accepts and expands.
  Do not leave a type mismatch that only appears when the field is used.
- Add `#[serde(deny_unknown_fields)]` to the mesh DTO structs. Confirm no
  `flatten` is in use first. A typo in `[tunnel.mesh]` must be a startup error.
- Call `config.validate()` at the end of `realize_mesh_runtime_config` and
  return `Err` on failure. Mesh init already refuses to start on a realization
  error (`init_mesh.rs:207-216`); this makes validation part of that path.
- Add a fixture that sets **every** documented mesh field, realizes it, and
  asserts each value survives into the runtime struct. This is the test that
  would have caught C10 and D6.

### G2 — Bind what you advertise

- `quic_port`: bind `quic_port.unwrap_or(port)` and advertise
  `endpoint.local_addr().port()`. `local_port()` must report the bound port,
  not the configured one (`synvoid-tunnel/src/quic/runtime.rs:449-455`).
- Extend the listener conflict matrix (`crates/synvoid-config/src/listener.rs`)
  to reserve the mesh UDP port in all cases, not only when `quic_port` is set.
- Apply the runtime knobs in `create_runtime`: `with_timeouts`,
  `with_stream_limits`, and `with_datagram_size` from `[tunnel.mesh]`. A knob
  that the runtime ignores is a config lie.

### G3 — Durable identity

- Require a durable identity when mesh is enabled: either an explicit
  `node_identity.private_key_path` or an automatic path under the configured
  data dir (`<data_dir>/mesh/<node_id>/identity.key`). A node that cannot
  persist its identity fails startup; an ephemeral identity is an explicit
  dev-only flag, never the default.
- Write the key with `OpenOptions::new().mode(0o600)` and fix permissions on an
  existing file. Match the mesh cert/key handling at `cert.rs:1264-1274`.
- `realize_mesh_runtime_config` returns `Err` when identity loading fails.
  Remove the warn-and-continue path.
- Remove the random-per-call fallback in `node_id()`. Return the realized id;
  if none is realized, return a sentinel that startup rejects rather than a
  fresh UUID.
- If a configured `[tunnel.mesh] node_id` disagrees with the derived id, fail
  with both values in the message. Operators need one deterministic answer.

### G4 — Multi-worker is an explicit refusal

- When `unified_server_workers > 1` and mesh is enabled, startup fails with a
  message naming the constraint, the configured worker count, and the two
  supported options (one worker, or disable mesh).
- Do not silently let workers race for the port. Multi-worker mesh is its own
  campaign; this phase makes the boundary honest.

### G5 — ALPN

- Add an `alpn` field to `TunnelQuicConfig` and set it from the mesh and tunnel
  call sites: `synvoid-mesh/1` and `synvoid-tunnel/1`.
- Both client and server configure the protocol; a mismatch fails the
  handshake with a clear error.
- Version the identifier so a future framing change can be rolled out without
  guessing.
- Document ALPN in `docs/WAF_MESH.md` as a requirement for third-party clients.

### G6 — Data directories

- Edge-replica storage uses the configured persistence/data dir, namespaced by
  node id.
- Creation failure logs at `warn` with the error and the path. If the manager
  is required for the configured role, startup is degraded; it is never a
  silent `None`.

### G7 — Examples and documentation are executable claims

- `config/mesh-example.toml` must start. Choose one: a strict example that
  references a generated CA and certificates with a documented generation
  step, or a dev example that explicitly sets `mode = "tofu"`,
  `allow_unverified_global = false`, and a single edge. Do not ship a config
  that errors on load.
- Add a test that parses every file in `config/` that carries
  `[tunnel.mesh]`, realizes it, and validates it. Certificates come from the
  Phase 01 harness PKI.
- `docs/WAF_MESH.md` truth pass:
  - DHT-based YARA/threat distribution is **not wired**; mark it as planned,
    not available;
  - one unified worker per node;
  - realized node ids and the `peered_wafs[].role` field;
  - `quic_port` semantics, ALPN, and the durable-identity requirement;
  - replace the claim that `auth_token` authenticates non-mTLS peers
    (Phase 03 deletes it).
- Review `min_peer_connections` (default 3). A two-node topology reports
  insufficient peers forever; either default it from the configured peer count
  or document that it is a readiness threshold, not a startup gate.

## Invariants

- Every documented mesh field survives TOML -> DTO -> runtime unchanged, or is
  rejected at startup.
- Every port the node advertises is a port it bound.
- Every timeout, stream limit, and buffer size in the config is applied by the
  runtime that uses it.
- No process starts mesh with an identity it cannot reproduce after restart.
- A configuration that cannot work (multi-worker mesh, missing CA, missing
  identity) fails at startup with a specific message.
- Documentation and examples are covered by a test or are explicitly marked
  as not implemented.

## Verification

- The all-fields fixture round-trips and every assertion passes.
- An unknown key under `[tunnel.mesh]` is a startup error.
- `quic_port = 6000` binds UDP 6000 and `/api/mesh/status` reports 6000;
  `ss -lunp` agrees. Configured idle/keepalive/stream values appear in the
  runtime (assert via the runtime accessors or a startup log line).
- Identity: first start creates the key with 0600; restart reuses the same
  node id; a second node on the same host with a different data dir gets a
  different id; a read-only key path fails startup; a configured/derived
  mismatch fails startup with both values.
- `unified_server_workers = 2` + mesh fails startup with the named constraint.
- ALPN: a tunnel client pointed at the mesh port fails the handshake; a mesh
  client with the wrong ALPN fails with the expected error.
- Edge replica: two nodes on one host get distinct directories; an unwritable
  path logs a warning with the path.
- Every `config/*.toml` mesh example realizes and validates.
- `cargo xtask verify` stays green and the new fixture is part of it.

## Non-goals

- Enabling the DHT, ML-KEM, tier claims, or YARA distribution. This phase makes
  their configuration expressible and their absence explicit.
- Multi-worker mesh, worker-to-worker routing, or a shared mesh listener.
- Live reload of mesh configuration.
- Automatic key rotation or certificate renewal beyond the existing expiry
  monitoring.
