# Phase 03 Plan: Listener/Site Mapping to Multiple Mesh Services

Status: **IMPLEMENTED** (see `plans/mesh_multi_upstream_forwarding_results.md`).
Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Depends on: Phase 01 (service ID transport) and Phase 02 (origin trust).

## Goal

Allow multiple restored `[[http.listeners]]` to select distinct mesh services
without making listener identity a mesh concept.

This phase answers the practical question:

> Can listener A and listener B forward through the mesh to different
> upstreams, even when they serve the same hostname or the same port?

The answer must be yes for explicitly configured services, while preserving
the existing per-listener site tables and the one-worker model.

## Current state

- Multiple listeners are canonical and each request carries a `ListenerId`
  into `route_with_listener_id()`
  (`crates/synvoid-proxy/src/router.rs:1071-1100`).
- `[site].listeners` is an allowlist; omitted means the site is a candidate on
  every listener (`crates/synvoid-config/src/site/listen.rs`).
- `BackendConfig` is site-level or location-level; there is no
  listener-scoped backend override
  (`crates/synvoid-config/src/site/backend.rs:113-150`).
- Site identity is the first domain, and duplicate site identities are
  rejected (`crates/synvoid-config/src/listener.rs:376-392`). Two sites with
  the same first domain cannot be used to split one hostname by listener.
- The mesh wire format has no `ListenerId`; this phase must keep it that way.

## Mapping model

```text
ListenerId
  -> ListenerRoutingTable (existing)
  -> SiteConfig (existing)
  -> BackendConfig (existing site/location)
  -> mesh service ID (Phase 01)
```

### Supported cases after Phase 01/02

- Different listeners serve different sites with different mesh services.
- Different listeners serve the same site and the same mesh service.
- Different hosts on one listener select different sites/services.
- Different locations on one site select different services.

### Unsupported without this phase

- Same hostname, same site identity, different services per listener.
- Two listeners on the same address/port with different services where the
  client cannot distinguish them by host/port.
- Per-listener backend overrides expressed without duplicating the site.

## Options

### Option A — Listener-scoped backend override (recommended)

Add a listener-keyed mesh service selection to `SiteProxyConfig` or its
normalized runtime form, for example conceptually:

```toml
# Proposed schema; not implemented.
[site.proxy]
backend = { type = "mesh", upstream = "blog-default" }

[site.proxy.listener_backends]
public = "blog-public"
public-alt = "blog-alt"
```

Rules:

- the base `backend` remains the default;
- `listener_backends` entries must name declared listeners;
- the selected service must exist on the origin side;
- unknown listener names fail config validation;
- listener names remain local and are resolved before the mesh request;
- the router still produces `RouteTarget` with `BackendType::Mesh` and the
  resolved service ID;
- no `ListenerId` enters the mesh request.

This is the most direct fit for “individual listeners forward to individual
mesh services” and avoids site-identity duplication.

### Option B — Separate site identities with disjoint listener membership

This works with the current schema in some cases:

```toml
# site a
[site]
domains = ["blog.example"]
listeners = ["public"]

# site b
[site]
domains = ["alt-name.example", "blog.example"]  # first domain differs
listeners = ["public-alt"]
```

This is fragile because:

- site identity is the first domain;
- the same hostname in two sites depends on domain-map ordering and
  disjoint listener membership;
- it is easy to create a configuration that passes validation but only one
  site wins on a listener.

Use only as a documented temporary workaround if Option A is deferred.

### Option C — Treat each listener as a separate mesh service at the origin

The origin advertises one service per listener-specific backend:

```toml
# origin
[tunnel.mesh.local_upstreams.blog-public]
upstream_url = "http://127.0.0.1:5000"

[tunnel.mesh.local_upstreams.blog-alt]
upstream_url = "http://127.0.0.1:5001"
```

The edge still needs to choose which service ID each listener uses, so this
does not replace Option A; it defines the origin-side services.

## Recommended design

Adopt Option A for the edge, with Option C for origin services:

1. Normalize a `listener -> mesh service ID` override map at config load.
2. Include it in the per-listener routing table construction.
3. Resolve the final service ID when building `RouteTarget`.
4. Carry only the final service ID to the mesh request target.
5. Keep `ListenerId` for local metrics/logs and admin inventory only.

## Workstreams

### A. Config schema and validation

- Define the listener override map in `SiteProxyConfig` or a normalized
  runtime struct.
- Validate listener names against `[[http.listeners]]`.
- Validate service IDs with the Phase 01 rules.
- Reject overrides on sites that are not members of the named listener.
- Define precedence: location backend > listener override > site backend >
  legacy upstream.
- Keep the override map out of the mesh wire format and serialization used by
  peers.

### B. Routing normalization

- Extend the site/routing build input with the listener ID.
- When constructing each `ListenerRoutingTable`, apply the listener override
  to the site’s backend target.
- Ensure the same site on two listeners can produce two different
  `RouteTarget` service IDs without mutating the shared `SiteConfig`.
- Preserve `default_site` behavior per listener.

### C. Admin and observability

- Show the resolved service ID per listener/site in admin listener/site
  inventory.
- Do not show one listener’s service as another listener’s effective backend.
- Add a config test that reports the override map validation failures with
  the listener field name.

### D. Documentation

- Add a multi-listener mesh example:

```text
listener public      -> site blog-public -> mesh service blog-public
listener public-alt  -> site blog-alt    -> mesh service blog-alt
```

- State that the origin advertises services, not listeners.
- State that the same service may be used by multiple listeners.
- State that listener names are local and restart-required.

## Tests

- Two listeners, different sites, different mesh services: each request
  selects the correct service ID.
- Two listeners, same site, `listener_backends` selects different services.
- Two listeners, same site, no override: both use the site default.
- Site is not a member of the overridden listener: config error.
- Unknown listener name: config error.
- Unknown/empty service ID: config error.
- Location backend override wins over listener/site backend in the documented
  order.
- `default_site` on each listener uses that listener’s override.
- No `ListenerId` appears in the serialized mesh request target.
- Existing multi-listener routing tests remain green.

## Exit criteria

- Two listeners can reach two distinct mesh services for the same hostname
  without duplicate site identities.
- Listener identity stays local.
- The resolved service ID is visible in admin inventory and logs.
- The config schema has one documented precedence order.
- No existing multi-listener behavior regresses.

## Risks

- Applying overrides by mutating a shared `SiteConfig` would leak one
  listener’s service into another. Resolve per-listener routing tables instead.
- Site identity and domain-map ordering are already subtle; do not use
  duplicate first-domain sites as the primary solution.
- Admin inventory can misreport effective backends if it reads the site
  default instead of the per-listener override.

## Non-goals

- Sending `ListenerId` over the mesh.
- Per-listener TLS/ALPN changes (already supported by listener plans).
- Per-listener WAF policy changes.
- Multi-worker listener ownership.
- Dynamic listener rebinding.
