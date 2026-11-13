# Phase 01 Plan: Mesh Service ID and HTTP Backend Wiring

Status: **IMPLEMENTED** (see `plans/mesh_multi_upstream_forwarding_results.md`).
Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Depends on: research baseline `8cbf8639`.
Predecessor: none.

## Goal

Make `BackendType::Mesh` a real HTTP egress path for one or more service IDs.
The site-selected service ID must survive the edge-to-origin hop, and the
origin must resolve that service ID against its configured
`local_upstreams`.

This phase does not change authorization or media limits; it establishes the
data path and the identity contract.

## Current state

- `BackendConfig::Mesh { upstream }` exists
  (`crates/synvoid-config/src/site/backend.rs:144`).
- The router turns it into `BackendType::Mesh` with `target.upstream` set to
  the configured service string
  (`crates/synvoid-proxy/src/router.rs:633-649`, `:932-947`).
- `maybe_handle_mesh_backend` requires a `MeshBackendPool` entry
  (`crates/synvoid-http/src/mesh_backend_dispatch.rs:29-59`).
- The pool is always empty in production:
  - `MeshBackendPool::add_backend` has no production caller
    (`crates/synvoid-mesh/src/mesh/backend.rs:247-257`);
  - `init_mesh` constructs `MeshProxy` and drops it
    (`src/worker/unified_server/init_mesh.rs:276-284`);
  - `MeshInit` does not carry `proxy` or `backend_pool`
    (`init_mesh.rs:65-89`);
  - `UnifiedServer::with_mesh_backend_pool` has no production caller.
- `proxy_http_request` ignores `_target_url`
  (`crates/synvoid-mesh/src/mesh/transport.rs:5866-5871`), and the origin uses
  `Host` as `http://{host}` (`transport_peer.rs:5506-5525`).

## Service identity contract

### Canonical forms

1. **Explicit service ID** (preferred):
   - site backend: `upstream = "blog-public"`;
   - origin config: `[tunnel.mesh.local_upstreams.blog-public]`;
   - mesh request target: `blog-public`.
2. **Domain-based compatibility ID**:
   - site backend or origin key: `http://blog.example:8082`;
   - used by the original model and by existing configurations.

Explicit IDs are required when:

- two listeners share a host/port but need different backends;
- one hostname maps to multiple backends;
- a listener's public name must not be coupled to the origin's DNS name.

### Resolution order

At the edge:

1. if the site's mesh backend has an explicit service ID, send it;
2. otherwise, if it is a URL-like `http://host:port`, send that;
3. otherwise reject the route as a configuration error (do not guess from
   the client `Host`).

At the origin:

1. resolve the received service ID in `local_upstreams`;
2. if absent and the service ID is URL-like, use the legacy domain key;
3. if still absent, return 404/503 with a typed log; never fall back to
   connecting to a peer-supplied arbitrary URL.

## Workstreams

### A. Return the mesh egress handle from composition

- Add the mesh proxy (or a narrow mesh-forwarder capability) to `MeshInit`.
- Pass it into `UnifiedServer` in `build_worker_startup`.
- Store it in `ServerSharedState` and thread it to the HTTP dispatch context.
- Keep the handle worker-local and tied to the existing unified worker
  runtime.

Preferred minimum change: pass `Arc<MeshProxy>` directly because the HTTP crate
already depends on `synvoid-mesh`. If a boundary guard requires a narrow type,
introduce `MeshForwarder` in the owning crate and implement it over
`MeshProxy`.

### B. Make `BackendType::Mesh` dispatch work

- Replace the `MeshBackendPool` lookup with a direct call to
  `MeshProxy::route_request(service_id, request)`.
- Alternatively, populate one `MeshBackend` per configured service ID at mesh
  init and keep the pool API. Do not leave both paths active.
- Preserve the existing response filtering, security headers, Alt-Svc, metrics,
  and error mapping from `mesh_backend_dispatch`.
- Remove the "no pool configured" 502 path for a configured mesh service.

### C. Carry the service ID to the origin

Define one typed target contract for the peer HTTP stream. Acceptable designs,
in preference order:

1. **Typed stream preface** before the HTTP bytes:
   - version/flags;
   - service ID length + bytes;
   - original `Host` remains in the HTTP request.
   - The origin validates the preface before parsing the HTTP request.
2. **Absolute-form request target** that encodes the service ID, with a
   parser-level rule that the absolute authority is the service ID.
3. **Reserved mesh header** stripped at the edge and rejected from clients at
   the origin. This is acceptable only if the origin verifies it came from a
   trusted peer session and the edge strips any client-supplied value.

Do not keep the current behavior where `_target_url` is ignored and the origin
derives the service from `Host`.

### D. Preserve the backend `Host`

- The origin must forward the client's original `Host` to the configured
  backend unless the origin-site config explicitly rewrites it.
- Service ID and `Host` are separate fields.
- Logs and metrics should include both `service_id` and `host` without putting
  the listener name on the wire.

### E. Compatibility and validation

- Validate service IDs as non-empty, bounded, and free of control characters.
- Reject a site mesh backend with no service ID at config load.
- Keep `http://host:port` accepted.
- Do not silently convert an arbitrary string to `http://{host}`.
- If a service ID collides with a URL-like key, prefer the explicit exact key.

## Tests

- Unit: service-ID validation and resolution order.
- Unit: site `BackendType::Mesh` produces the intended `RouteTarget.upstream`.
- Integration: one edge listener -> one origin -> one `local_upstreams`
  service; the origin application receives the original `Host` and path.
- Integration: two origin `local_upstreams` services; two sites select
  different service IDs; both reach the correct backend.
- Compatibility: a URL-like `http://host:port` service still resolves.
- Negative: unknown service ID returns a typed error, not an arbitrary URL
  fallback.
- Regression: non-mesh backends are unchanged.

## Exit criteria

- A configured mesh site no longer returns the "mesh backend pool not
  available" error.
- The origin resolves the same service ID selected at the edge.
- Two distinct services can be reached through the same mesh node/worker.
- `Host` preservation is tested.
- No `ListenerId` appears in the mesh request target or service key.

## Risks

- Changing the peer stream preface is a wire-format change. Gate it behind a
  versioned target record and keep the legacy Host path as a compatibility
  branch for one release window.
- `MeshBackendPool` may still be used by Raft/transport code. Do not delete the
  type; remove only its HTTP dispatch role or populate it deliberately.
- A direct `MeshProxy` dependency in HTTP dispatch must preserve the existing
  composition-boundary guard.

## Non-goals

- Peering authorization and private-origin policy (Phase 02).
- Listener-scoped service overrides (Phase 03).
- Streaming/large bodies (Phase 04).
- Multi-worker mesh state.
