# Mesh Multi-Upstream Forwarding Roadmap

Status: **PROPOSED** (research complete; no implementation started).
Research baseline: `8cbf8639` (merged `main`), reviewed 2026-11-13.

Predecessor context:

- original mesh proxying foundation: `3b4127cf`;
- mesh backend route added without pool population: `5a596635`;
- single-listener truthfulness decision 03A: `plans/production_readiness_phase_03_http_listener_truthfulness.md`;
- canonical multi-listener restoration: `plans/multi_listener_canonical_roadmap.md`.

## Why this campaign exists

The original mesh proxying design supported **multiple domain-based upstreams**.
An origin advertised several `local_upstreams`; an edge selected one by
`http://host:port` and forwarded the request over QUIC. The peer then resolved
the local backend by the request `Host` header.

Two later changes obscured that model:

1. Production-readiness Phase 03A temporarily reduced HTTP serving to one
   listener per process. The canonical multi-listener campaign restored
   `[[http.listeners]]`, but the mesh data path was not revisited.
2. The site `BackendType::Mesh` surface was added, but the HTTP dispatch path
   was never wired to a populated mesh backend. The route-discovery machinery
   exists; the request path does not use it.

The result is a false impression that only one listener/upstream can travel
through the mesh. In reality:

- **multiple upstreams are representable** in `local_upstreams` and route
  discovery, but the HTTP egress path is not wired;
- **multiple listeners are restored** locally, but mesh identity is still
  host/port-based and does not carry listener identity;
- the origin data path resolves the backend from `Host`, not from the selected
  mesh service, so explicit service IDs do not work;
- private/local origin URLs are rejected by the mesh SSRF policy;
- request/response body limits are too small for the blog's media path.

## Target model

```text
ListenerId (local ingress identity)
  -> per-listener site table
  -> SiteConfig.backend
  -> mesh service ID (mesh-wide identity)
  -> route query / provider selection
  -> QUIC peer
  -> origin local_upstreams[service_id]
  -> origin application backend
```

Rules:

- Never send `ListenerId` over the mesh. Listener names are local config and
  are not stable across nodes.
- A listener may select a site whose backend is a mesh service. Different
  listeners may select different sites/services.
- The mesh service ID is explicit whenever a host can map to more than one
  backend or when two listeners share a host/port.
- `http://host:port` remains a compatibility service ID for the original
  domain-based model.
- `Host` is preserved for the backend's virtual-host decision; it is not the
  authoritative service ID once an explicit service ID is sent.
- Route hints are advisory. The origin authorizes the request against
  `peered_wafs` and service policy; route discovery is not authorization.
- One unified worker per node remains the supported data-plane model.

## Findings that gate the campaign

1. **The HTTP mesh backend is dead.**
   `MeshBackendPool` is constructed empty and `add_backend` has no production
   caller (`crates/synvoid-mesh/src/mesh/backend.rs:230-307`).
   `init_mesh` creates a `MeshProxy` and drops it
   (`src/worker/unified_server/init_mesh.rs:276-284`); `MeshInit` does not
   return the proxy or pool. `UnifiedServer::with_mesh_backend_pool` has no
   production call site. `maybe_handle_mesh_backend` therefore sees no pool
   and returns a 502/503.
2. **The selected service ID is lost at the peer boundary.**
   `proxy_http_request` ignores `_target_url`
   (`crates/synvoid-mesh/src/mesh/transport.rs:5866-5871`), and the origin
   derives its upstream key from `Host`
   (`crates/synvoid-mesh/src/mesh/transport_peer.rs:5506-5525`).
3. **Private/local upstreams are rejected.**
   `handle_http_proxy_stream` rejects `127.0.0.0/8`, RFC1918, loopback,
   link-local, and other restricted ranges
   (`crates/synvoid-mesh/src/mesh/transport_peer.rs:5580-5600`).
   The shipped `local_upstreams` examples use private URLs, so the documented
   model cannot reach a normal local origin.
4. **Mesh HTTP is fixed-length and body-capped.**
   Chunked requests are rejected with 501, upgrades with 503
   (`transport_peer.rs:4300-4370`). Default request/response body caps are
   64 KiB (`crates/synvoid-config/src/mesh.rs:501-511`). This cannot carry the
   blog's media or 4 MB upload chunks without a policy change.
5. **Peering authorization is not enforced on the data path.**
   `peered_wafs` is implemented in `get_upstream_for_peer`
   (`crates/synvoid-mesh/src/mesh/topology.rs:1074-1096`), but route queries
   return local upstreams without that check
   (`crates/synvoid-mesh/src/mesh/transport_routing.rs:196-210`) and the
   origin request handler uses `get_upstream_info` directly.
6. **`service_policy` is dead config.**
   It is parsed (`crates/synvoid-config/src/mesh.rs:545`) but has no runtime
   consumer. Only `routing.allow_all_services` / `allowed_services` are
   enforced.
7. **No listener-scoped backend override exists.**
   `BackendConfig` is site-level. `[site].listeners` scopes site membership,
   but the same hostname on two listeners cannot directly select two different
   mesh services without separate site identities or a new mapping.

## Decisions

| Gate | Decision |
|---|---|
| M1 — mesh identity | Mesh routing key is a stable service ID. `ListenerId` stays local and never enters the mesh wire format. |
| M2 — compatibility | Keep `http://host:port` as a service ID form for the original domain-based model. Explicit service IDs are preferred for multiple backends. |
| M3 — dispatch | The HTTP request path calls the mesh proxy directly with the service ID; do not require a populated `MeshBackendPool` for a single backend. Retire or populate the pool as part of Phase 01. |
| M4 — request metadata | Carry the selected service ID in an authenticated/typed peer request target. Do not infer it from `Host`. Preserve `Host` separately. |
| M5 — private origins | Allow private/local URLs only when they come from operator-configured `local_upstreams`. Never allow a peer-supplied arbitrary private URL. |
| M6 — authorization | Enforce `peered_wafs` and the service allowlist on route disclosure and on the actual forwarded request. Route hints are advisory. |
| M7 — media | Do not claim blog media/upload support until streaming and body policy are qualified. Fixed-body 64 KiB forwarding is a text/API path only. |
| M8 — listeners | Listener → site → service is the canonical mapping. Add a listener-scoped service override only if real same-host/different-listener cases require it. |
| M9 — worker model | Keep one `UnifiedServerWorker` per node. Mesh route/proxy tasks run on the same Tokio runtime. Multi-worker mesh state remains out of scope. |
| M10 — reload | Mesh listener/service changes are restart-required unless a later phase implements live rebinding. |

## Phase table

| Phase | Plan | Depends on | Primary outcome |
|---|---|---|---|
| 01 | `plans/mesh_multi_upstream_phase_01_service_id_and_http_wiring.md` | research | `BackendType::Mesh` works for explicit service IDs and preserves the domain-based fallback |
| 02 | `plans/mesh_multi_upstream_phase_02_origin_trust_and_ssrf.md` | 01 | trusted local upstreams, `peered_wafs`, service policy, and SSRF boundary are correct |
| 03 | `plans/mesh_multi_upstream_phase_03_listener_site_mapping.md` | 01, 02 | multiple listeners/sites can select distinct mesh services without cross-listener leakage |
| 04 | `plans/mesh_multi_upstream_phase_04_streaming_and_media_policy.md` | 01, 02 | bounded streaming or explicit exclusion for large media/chunked uploads |
| 05 | `plans/mesh_multi_upstream_phase_05_qualification_and_docs.md` | 01-04 | end-to-end multi-node qualification, docs truth, benchmark/support statement |

## Cross-phase invariants

- No production `BackendType::Mesh` request may silently return 502/503 because
  a pool was never wired.
- The route query response is not an authorization grant.
- A peer cannot make an origin connect to an arbitrary private URL.
- The mesh request target and the origin's local upstream key are the same
  service ID.
- `Host`, `:authority`, SNI, and listener name are not substitutes for the
  mesh service ID.
- A listener bind change remains restart-required.
- Every new request path preserves existing WAF, drain, metrics, and error
  response behavior.

## Verification matrix

At minimum:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --profile ci --all-targets -D warnings`
- focused `synvoid-mesh`, `synvoid-http`, `synvoid-proxy`, and `synvoid-config`
  tests
- full workspace nextest when the campaign is ready to close
- multi-node local test: edge listener -> mesh route -> origin local upstream
- multi-service test: two `local_upstreams`, two site backends, both reachable
- same-host/two-listener test for distinct services
- unauthorized peer route query and forwarded request both fail closed
- private/local origin allowed only for configured local upstream
- >64 KiB request/response and chunked-upload behavior tested or explicitly
  documented as unsupported
- `cargo xtask verify`

## Non-goals

- Sending listener identity over the mesh.
- Listener-to-listener WAF chaining as the default forwarding model.
- Replacing the mesh QUIC transport with HTTP/2/3.
- Multi-worker mesh session or route-cache sharing.
- Distributed admin sessions/CSRF state.
- Using `tunnel:` mappings as mesh service discovery.
- A new service mesh control plane separate from the existing mesh topology.
- Claiming media/upload support before Phase 04 is qualified.

## Success statement

An operator can configure multiple mesh upstreams, bind multiple listeners,
and point different listeners/sites at different mesh services. The edge
forwards the selected service over QUIC; the origin authorizes the peer,
resolves the configured local upstream, and serves the request without relying
on hostname coincidence or an empty backend pool. Large-media support is a
separate, explicit capability statement.
