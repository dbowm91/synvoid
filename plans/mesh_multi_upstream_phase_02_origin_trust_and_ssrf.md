# Phase 02 Plan: Origin Trust, Peering Authorization, and SSRF Policy

Status: **IMPLEMENTED** (see `plans/mesh_multi_upstream_forwarding_results.md`).
Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Depends on: Phase 01 (`mesh_multi_upstream_phase_01_service_id_and_http_wiring.md`).

## Goal

Make mesh forwarding safe once the service ID reaches the origin. The origin
must distinguish:

- an operator-configured `local_upstreams` target, which may be private;
- a peer-supplied or discovered URL, which must not be usable to reach an
  arbitrary private address;
- an authorized peer, which may use a service;
- an unauthorized peer, which must receive neither the upstream URL nor a
  proxied connection.

This phase also removes the dead/overlapping service-policy surface.

## Current state

- `is_restricted_ip` rejects private, loopback, link-local, shared, and other
  special-use ranges (`crates/synvoid-core/src/net.rs:23-45`).
- `handle_http_proxy_stream` rejects any restricted backend IP or resolved IP
  (`crates/synvoid-mesh/src/mesh/transport_peer.rs:5580-5600`).
- The shipped `local_upstreams` examples use private URLs
  (`docs/WAF_MESH.md:496-514`, `config/mesh-example.toml:62-79`).
- Route queries return local upstreams without checking `peered_wafs`
  (`crates/synvoid-mesh/src/mesh/transport_routing.rs:196-210`).
- `get_upstream_for_peer` implements the peering check
  (`crates/synvoid-mesh/src/mesh/topology.rs:1074-1096`) but the origin data
  path uses `get_upstream_info` directly.
- `MeshServicePolicy` is parsed (`crates/synvoid-config/src/mesh.rs:545`) but
  has no runtime consumer. Only `routing.allow_all_services` /
  `routing.allowed_services` are enforced (`topology.rs:1253-1259`).

## Trust model

### Trusted local upstream

A target is trusted-local when **all** of the following hold:

- the origin operator configured it in
  `[tunnel.mesh.local_upstreams.<service_id>]`;
- the service ID was selected by a route query for that origin;
- the requesting peer is authorized by the configured `peered_wafs` rule;
- the service is allowed by the single service-policy owner.

Only trusted-local targets may use loopback, RFC1918, ULA, link-local, or
other non-public addresses.

### Untrusted/discovered URL

A URL received from a route response, peer, request header, DHT record, or
other non-local source must continue to use `is_restricted_ip` and must not be
allowed to reach private addresses.

### Peer authorization

- `peered_wafs` is an allowlist of node IDs.
- An empty list means “not restricted” only if that is the documented legacy
  semantics. Prefer making the behavior explicit in this phase and pin it
  with tests.
- The origin must authorize both:
  1. route disclosure (`RouteQuery` -> `RouteResponse`);
  2. the proxied HTTP request itself, so a peer cannot bypass discovery and
     call the stream directly.
- Route hints remain advisory; the data path is the enforcement boundary.

## Workstreams

### A. Make local-upstream URLs trusted

- Resolve the service ID against the origin's `local_upstreams` before any
  peer-supplied URL is considered.
- Permit private/local addresses for that resolved URL only.
- Do not accept a peer-supplied URL for the connection when the service ID is
  unknown.
- Keep the restricted-IP check for any URL that is not a trusted local
  upstream.
- Add a typed error/log for “service unknown” and “restricted target” so the
  two cases are distinguishable.

### B. Enforce `peered_wafs` on route disclosure

- Pass the initiator/requesting node ID into the route-query handler.
- Use `get_upstream_for_peer(service_id, requester_node_id)` or an equivalent
  authorization check before returning a provider response.
- On denial return `RouteNotFound`/`RouteRejected` with no upstream URL.
- Do not leak the local upstream URL, private address, or backend port in
  denied responses.

### C. Enforce `peered_wafs` on the proxied request

- The origin's `handle_http_proxy_stream` must know the authenticated peer
  node ID.
- Re-check service authorization at request time; do not rely on a prior route
  query or a cached policy.
- Reject with 403 or a typed mesh error before opening the backend connection.
- Keep the check in composition or the mesh authorization layer; do not put
  peer identity into the generic HTTP request-path types unless required.

### D. Collapse service-policy ownership

Choose one owner:

- `routing.allow_all_services` / `routing.allowed_services` (existing runtime
  consumer), or
- `service_policy.allow` / `service_policy.deny` (currently dead).

Recommended: keep the existing `routing` allowlist as the runtime policy and:

- either wire `service_policy` into the same decision with explicit precedence,
- or remove it from the parsed schema and examples.

Do not leave two policy surfaces that appear active.

### E. Strip/ignore client-supplied mesh metadata

- The edge must remove any client-supplied service-target/mesh-identity header
  before forwarding.
- The origin must reject or ignore such a header unless it arrived through the
  typed peer target from an authenticated session.
- Test both the edge strip and the origin rejection.

## Tests

- Authorized peer can query and forward a configured local upstream.
- Unauthorized peer gets no provider and no upstream URL from route query.
- Unauthorized peer cannot bypass route query and directly proxy the service.
- `local_upstreams` with `127.0.0.1`, `10.x`, `172.16.x`, `192.168.x`, and
  ULA succeeds for an authorized peer.
- A peer-supplied URL to a private address is rejected.
- A peer-supplied URL to a public address is acceptable only if the design
  intentionally supports it; otherwise reject.
- Unknown service ID does not fall back to Host or a provider URL.
- `service_policy` behavior is either pinned or the keys are removed and the
  docs updated.

## Exit criteria

- The documented private/local `local_upstreams` example works for an
  authorized peer.
- The same private target remains unreachable for an unauthorized peer.
- Route disclosure and data forwarding both enforce the same authorization.
- There is exactly one service-policy decision path.
- No raw upstream URL is leaked on denial.

## Risks

- Allowing private addresses for configured local upstreams weakens a blanket
  SSRF rule. Restrict it to the operator-configured service map and keep the
  peer-supplied URL path strict.
- Cached route/provider entries can outlive a policy change. Enforce at the
  request path and invalidate route caches when local upstreams change.
- `peered_wafs` node IDs depend on authenticated peer identity. Do not trust a
  self-declared peer ID from an unauthenticated stream.

## Non-goals

- Service-ID transport and HTTP dispatch (Phase 01).
- Listener-scoped service mapping (Phase 03).
- Streaming/media limits (Phase 04).
- Redesigning mesh trust roots, Raft, DHT, or node admission.
