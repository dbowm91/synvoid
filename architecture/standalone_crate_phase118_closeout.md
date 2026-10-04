# Phase 118 Closeout — Mesh Application Dispatch Inversion

Plan: `plans/phase_118_mesh_application_dispatch_capability_inversion.md`.
Date: 2026-10-02.
Disposition: **CLOSED DEFER**. No runtime, wire, or dependency behavior changed.

## Evidence and blocker

The application reachability is live and stateful:

- `crates/synvoid-mesh/src/mesh/proxy.rs` imports `is_hop_by_hop_header_name`,
  `CacheKeyBuilder`, `ProxyCache`, and `ProxyCacheSettings`; it stores and mutates
  the concrete cache and converts settings from mesh protocol preferences.
- `mesh/transport_peer.rs` dispatches inbound serverless requests to
  `ServerlessManager`, creates the caller identity, translates results to mesh
  responses, and also builds HTTP response bodies for serverless proxy requests.
- `mesh/transport.rs` retains the concrete serverless manager and tunnel QUIC
  connection types in long-lived transport state and exposes the dispatch paths.
- `mesh/backend.rs` translates site cache configuration into cache settings.
- `synvoid-mesh/Cargo.toml` therefore has direct proxy, proxy-cache, tunnel,
  serverless and application-config edges with active production uses.

Removing these edges safely needs typed async dispatch contracts that preserve
identity, result/error semantics, cancellation, payload ownership, and response
framing. Root composition must provide adapters, while tests must prove that
dispatch errors cannot look like canonical commits and advisory records remain
non-authoritative. No such end-to-end seam and differential tests were completed.
Cutting only manifest dependencies or adding a broad backend trait would violate
the phase contract and risk runtime behavior.

## Successor status

Phase 119 is **CLOSED DEFER** because its required application-dispatch
predecessor was not delivered. Its extraction decision cannot be based on a
dispatch boundary that has not been established. Phases 120, 121 and 122 were
eligible independent tracks. Phase 123 must carry both mesh track DEFERs. No
standalone or external-support claim is made for `synvoid-mesh`.
