# Phase 03 Plan: Authenticated Peer Identity

Status: **IMPLEMENTED** (2026-11-14; mesh and synvoid-config suites green).

Registered in: `plans/roadmap.md`.
Campaign: `plans/mesh_trust_boundaries_roadmap.md`.
Predecessor: Phase 02 (delivery must work before identity can be exercised).
Depends on: Phase 01 harness (`forged_hello_is_rejected`).

## The finding

The handshake authenticates the QUIC channel but not the application peer.

- **C2 (High).** The dialer enforces `node_id_from_public_key(pubkey) == node_id`
  (`transport.rs:4966-5001`); the acceptor does not.
  `validate_edge_node_pow` derives the id from the key and never compares it
  (`peer_auth.rs:867`), and `validate_edge_node` returns `Ok(())` as soon as PoW
  verifies, before the Ed25519 signature is examined
  (`peer_auth.rs:709-711`). In `permissive`/`tofu` there is no certificate
  identity to fall back on (`transport.rs:603-625`), so any peer can claim any
  node id.
- **C9 (High).** `Hello.is_trusted` is a wire bool (`protocol.rs:276`) consumed
  as `trusted_status` (`transport.rs:4196`, `:4290`) and persisted with
  `peer_info.is_trusted || existing_trusted` (`topology.rs:587-604`). Trusted
  contacts bypass PoW (`dht/routing/contact.rs:155-157`) and are hub-eligible.
- **B3 (Critical, role half).** `PeerAnnounce` sets `is_global`/`is_trusted`
  from the announced role (`transport_peer.rs:3651-3681`), so a peer can enter
  the global-node set and the global-IP exemption list. Phase 04 removes the
  gossip path; this phase removes the role claim it depends on.
- **C1 (High).** `auth_token` is checked only when the sender includes it
  (`transport.rs:4212`), and `auth_keys` is constructed empty (`:724`) with no
  insert anywhere. Configuring a token therefore breaks peering, while omitting
  it bypasses the gate.
- **Network isolation is peer-optional.** `network_id` is compared only when
  the peer sends one (`transport.rs:4229-4238`, `:5066-5080`), so a peer omits
  it to cross tenant boundaries.

The pattern is one pattern: a value that the receiver could compute or look up
is instead accepted as a claim.

## Root cause

The handshake grew in layers. Certificates were added for transport
authentication, PoW for Sybil resistance, `auth_token` for a bootstrap case,
and roles/trust as topology metadata. Each mechanism was allowed to be optional
because disabling it never broke the happy path, and the acceptor was never
given the identity derivation the dialer already had.

## Fix scope

### I1 — One identity derivation, both directions, every mode

Introduce `PeerIdentity` in `peer_auth.rs`, produced before any role or PoW
logic:

```text
PeerIdentity { node_id, role, evidence, certificate_node_id }
```

Rules, in order, at accept and dial:

1. The `Hello.public_key` must decode and derive a node id
   (`node_id_from_public_key`). The derived id must equal `Hello.node_id`.
   Reject otherwise. This applies in **all** modes and needs no PKI.
2. In `strict`, the certificate must verify against `ca_path` and its SAN must
   equal the same node id (already implemented at `transport.rs:672-689`; keep
   it and make the failure terminal).
3. The `Hello.public_key` must match the key the certificate was issued for.
   If the certificate carries no key binding, reject in strict rather than
   assume agreement.

`permissive` and `tofu` remain explicit operator downgrades, but they now
enforce rule 1, so impersonation of an existing node id requires its private
key in every mode.

### I2 — Role comes from the allowlist

Extend `MeshUpstreamPeer` (`crates/synvoid-config/src/mesh.rs:194`,
`crates/synvoid-mesh/src/mesh/config.rs:244`) with:

```toml
[[tunnel.mesh.peered_wafs]]
node_id = "node-…"   # realized id
allowed = true
role = "origin"      # new: edge | origin | global; default edge
```

Resolution:

- unlisted node -> `EDGE`. A node may always join as an edge, subject to PoW and
  the service allowlist;
- `ORIGIN` or `GLOBAL` -> requires a listed entry with the matching role;
  a mismatch is rejected with both values in the log;
- `GLOBAL` in `permissive`/`tofu` additionally requires
  `tunnel.mesh.allow_unverified_global = true` (default `false`), because a
  role bit is the entire claim in those modes.

Startup must fail with a specific message when a configured seed or peer is
unlisted but claims a privileged role. Existing deployments that never listed
their origins will need one config line; that is the intended migration and
must be called out in `docs/WAF_MESH.md`.

### I3 — Trust is computed, never read

- Remove `is_trusted` from `Hello` consumption and from `MeshPeerInfo`
  construction on both paths.
- `trust = listed && allowed && role_matches`.
- Keep the proto field for compatibility; if a peer sends `true`, log once and
  ignore it. Never persist it.
- Recompute trust on every topology update; do not keep the sticky
  `|| existing_trusted` merge.

### I4 — Delete the shared-secret gate

mTLS plus the allowlist is the authentication story. A second, optional,
unpopulated gate is worse than none.

- Remove `auth_keys`, the `auth_token` check, and the seed-side send
  (`transport.rs:4693`).
- Keep the proto field reserved; log a single warning if a peer sends it, then
  ignore it.
- If a deployment genuinely needs a pre-PKI bootstrap secret, that is a future
  phase with its own config surface, not a half-wired field.

### I5 — Network isolation is mandatory when configured

If `config.network_id` is set, the peer must send a non-empty `network_id` and
it must match. Missing is a rejection, not a skip. Apply the same rule to the
`HelloAck` check.

### I6 — PoW and signature are both required for unlisted peers

- Delete the `if pow_verified { return Ok(()) }` shortcut
  (`peer_auth.rs:709-711`).
- Unlisted peer: valid PoW **and** a valid role signature over
  `edge:{node_id}:{timestamp}`.
- Listed peer with a verified certificate: PoW may be skipped, because the
  certificate is a stronger identity than a proof of work.
- Audit the organization-member-certificate path so a rejected or expired
  member certificate cannot fall through to the PoW branch; rejection must be
  final.

### I7 — The responder is authenticated too

`HelloAck` has no signature field. It must still be bound to the responder's
identity: verify the responder certificate/key with the same I1 rules before
accepting the ack, not only the role bits
(`transport.rs:5092-5097` today). A responder that cannot be bound is a failed
handshake, not a warning.

### I8 — No role changes on an established session

A node's role is fixed for the session. If topology later receives a message
claiming a different role for the same node id, reject the update rather than
overwrite the session's role. Phase 04 removes `PeerAnnounce` as an
authority; this is the defensive half.

## Invariants

- No code path may accept `Hello.node_id` without recomputing it from the
  presented key.
- No privileged role may be granted without an allowlist entry naming that
  node id and role.
- Trust is a function of local config and the session; it is never a field on
  the wire.
- A missing security field is a rejection, never a skip.
- The dialer and acceptor enforce the same identity rules.

## Verification

- Un-ignore and pass `forged_hello_is_rejected` in the Phase 01 harness, with
  three cases: strict, tofu, and permissive. Each sends a victim `node_id`
  with an attacker key and asserts the session is rejected.
- New tests: role escalation (unlisted peer claims ORIGIN/GLOBAL) rejected;
  listed ORIGIN accepted; GLOBAL in permissive rejected unless
  `allow_unverified_global`; missing `network_id` rejected when configured;
  `auth_token` present or absent has no effect; revoked member certificate
  falls through to no branch and is rejected; `HelloAck` with a mismatched
  certificate rejected.
- Live regression: the existing `runtime/mesh-qual` topology still connects
  after adding `role = "origin"` to its `peered_wafs` entry.
- `docs/WAF_MESH.md` updated: realized ids, `role` field, the migration error,
  and the fact that `auth_token` is no longer accepted.

## Non-goals

- Putting role into the X.509 certificate (a custom extension is a larger
  design; the allowlist is sufficient and auditable).
- SPIFFE/SPIRE, OIDC node attestation, or per-service peer roles.
- Changing PoW difficulty or the Sybil-resistance model.
- Multi-tenant network namespaces beyond the existing `network_id` string.

## Implementation notes (2026-11-14)

Landed as specified, with these observable consequences:

- **The mesh is allowlist-only in this release.** "Unlisted peers need PoW and a
  role signature" is implemented as written, but the edge-side role signature
  is not issued yet (it depends on the Phase 04 signing-key binding). An
  unlisted peer therefore cannot complete the handshake. Operators must list
  every peer with `role`; `docs/WAF_MESH.md` says so.
- **Seeds and HelloAck responders are subject to the same allowlist.** A seed
  that is not listed with a matching role now fails `bootstrap_from_seeds`
  instead of being trusted by role bit.
- **Role grants are per service, roles are per node.** The resolver scans every
  `local_upstreams[*].peered_wafs` entry for the node id. Conflicting grants
  (`edge` for one service, `origin` for another) are a hard rejection, not a
  union or a maximum.
- **`auth_token` is retired, not removed from the schema.** It still parses so
  existing TOML loads, but it is never sent or checked; the proto fields are
  reserved.
- **`is_trusted` is computed as `listed && allowed`.** Role matching is already
  enforced by `resolve_peer_role` before trust is assigned.
