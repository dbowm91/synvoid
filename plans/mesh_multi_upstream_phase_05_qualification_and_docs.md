# Phase 05 Plan: Mesh Multi-Upstream Qualification and Documentation

Status: **IN QUALIFICATION** (see `plans/mesh_multi_upstream_forwarding_results.md`).
Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Depends on: Phases 01-04.

## Goal

Qualify the restored capability end to end on a multi-node local mesh and
make the operator documentation, support statement, and evidence match the
runtime.

This phase is not complete because unit tests pass. It needs a real
edge/origin topology, multiple services, multiple listeners, an unauthorized
peer, and the chosen media policy.

## Qualification topology

Minimum local topology:

```text
global / discovery node (optional but recommended)
edge node
  - listener public
  - listener public-alt
origin node
  - local_upstreams.blog-public
  - local_upstreams.blog-alt
  - two local backends (or one backend plus a distinct health endpoint)
```

The test must prove:

- edge listener `public` selects service `blog-public`;
- edge listener `public-alt` selects service `blog-alt`;
- the same service can be selected by two listeners;
- two sites on the same listener select two services;
- the origin resolves the configured local upstream, not the client `Host`;
- the client `Host` and path reach the backend unchanged;
- unauthorized peers are denied both route disclosure and forwarding.

## Required evidence

- Config fixtures:
  - origin `local_upstreams` with multiple services;
  - edge `[[http.listeners]]` with multiple listeners;
  - per-listener/site service selection from Phase 03;
  - a compatibility `http://host:port` service.
- Tests:
  - config validation for service IDs and listener overrides;
  - service-ID routing;
  - route query and request authorization;
  - private local origin allowed for configured peers;
  - peer-supplied private URL rejected;
  - body limits/chunked/media policy from Phase 04;
  - no cross-listener service leakage.
- Runtime evidence:
  - two listeners bound on the edge;
  - one unified worker per node;
  - origin local upstream connection observed once per selected service;
  - logs/metrics show `service_id`, `listener_id`, `host`, and peer identity
    without leaking secrets;
  - failover between two providers for one service.
- Verification commands:
  - focused mesh/http/proxy/config tests;
  - full workspace nextest if closing the campaign;
  - `cargo xtask verify`.

## Documentation corrections

Update at least:

- `docs/WAF_MESH.md`:
  - multiple `local_upstreams` services;
  - explicit service IDs vs domain-based compatibility IDs;
  - listener → site → service mapping;
  - private/local upstream policy;
  - `peered_wafs` enforcement at route and data path;
  - body/streaming/media limits;
  - one unified worker per node;
  - `[tunnel.mesh]` runtime location.
- `docs/CONFIGURATION.md`:
  - mesh service examples;
  - listener/site service selection;
  - process/worker context;
  - body caps and chunked/upgrade support.
- `config/mesh-example.toml`:
  - replace arbitrary service keys with service IDs that match the supported
    target contract;
  - ensure private upstream examples are authorized and permitted.
- `architecture/mesh.md`:
  - remove the claim that `BackendType::Mesh` is fully wired until it is;
  - document the target contract and origin authorization.
- `architecture/routing_deep_dive.md`:
  - state that listener identity is local and mesh identity is the service ID.
- `architecture/http_request_pipeline.md` / request-path boundary:
  - update the mesh backend capability description.
- `plans/roadmap.md`:
  - mark the campaign and phase statuses as work lands.

## Support statement

Write one explicit sentence set:

- which mesh-backed HTTP methods/body sizes are supported;
- whether chunked request/response is supported;
- whether WebSocket/CONNECT is supported;
- whether private/local origins are supported and under what authorization;
- whether mesh is supported for blog media/uploads;
- whether multi-listener mesh selection is supported;
- whether multi-worker mesh is supported (recommended: no).

Do not say “mesh proxying supports multiple origins” without the listener,
service, authorization, and body-policy qualifiers.

## Tests / guardrails

Add guard tests that fail if:

- `BackendType::Mesh` dispatch regresses to an unpopulated pool;
- `_target_url` is ignored again;
- the origin derives the service ID from `Host` when a target ID is present;
- `peered_wafs` is bypassed on route or request;
- a peer-supplied private URL reaches a backend;
- a service silently falls back to the 64 KiB default;
- docs claim a capability that no test covers.

## Exit criteria

- Multi-node edge/origin test passes with multiple services and listeners.
- Both authorized and unauthorized peer behavior is proven.
- Private local upstream and SSRF behavior are proven.
- The chosen media/body policy is proven and documented.
- All campaign phase statuses and docs are aligned.
- `cargo xtask verify` passes.

## Risks

- A single-node test can pass while peer identity, route authorization, or
  private-upstream policy is still wrong. Use at least two nodes.
- Existing docs/examples may use the old arbitrary service-key convention.
  Correct them rather than teaching both models ambiguously.
- Multi-listener tests need ephemeral ports to avoid host conflicts.
- Multi-worker mesh state remains a non-goal; do not accidentally qualify it
  as supported.

## Non-goals

- New mesh consensus or DHT authority rules.
- Multi-worker mesh.
- H3 over the mesh peer transport.
- A new service-mesh control plane.
- Changing listener reload semantics.
