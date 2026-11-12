# Phase 03 Plan: HTTP Listener Truthfulness

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: none for the truthfulness work; Phase 10 consumes the outcome.

> **Product supersession (2026-11-11):** 03A remains the truthful
> remediation of the old unbound `[[site.listen]]` surface, but the product
> decision D2 has been reversed. Multi-listener support is now canonical; see
> `plans/multi_listener_canonical_roadmap.md` and its phase plans. Do not treat
> “one HTTP listener per process” as the target product model.

## The finding

`SiteListenConfig` (`crates/synvoid-config/src/site/listen.rs`) parses
per-site `address`, `port`, `ssl`, `http2`, `http3`, `default_server` and
`proxy_protocol`. `Router::build_listen_map_entry` indexes those entries, and
`Router::route` uses the request's local address to select a default site.

The startup plan does not bind them. `UnifiedServerStartupPlan::from_config_snapshot`
binds only:

- `server.host:server.port` for HTTP,
- `server.host:tls.port` when TLS is enabled,
- `server.host:http3.port` when HTTP/3 is enabled,

and the v6 variants. `listener_tasks.rs` spawns exactly those addresses. A
site that declares `listen.port = 8081` therefore has a routing entry for an
address that never accepts a connection. There is also no runtime support for
`SiteListenConfig::proxy_protocol`; the flag is parsed but never consumed.

This means the truthful production statement today is: **one HTTP listener per
process, with virtual-host routing; multiple HTTP ports require separate
processes.**

## Decision D2

Recommended for the 1.1 remediation: keep one HTTP listener per process,
remove or reject the unbound per-site `listen` surface, and document virtual
hosts as the multi-service HTTP model. Multiple listener ports are a separate
feature; do not ship a config shape that implies they exist.

If multiple HTTP ports are a hard product requirement, implement 03B below
instead of 03A. Do not do both halfway.

## 03A — Truthful single-listener model (recommended)

1. Remove `SiteInfo.listen` or restrict it to fields that are actually
   enforced on the global listener. If `default_server` is useful, keep it as
   an explicit global-listener option; if it is not, remove the whole field.
2. Make `configtest` reject `site.listen.address`, `port`, `ssl`, `http2`,
   `http3`, `proxy_protocol` values that the runtime cannot honor, with a
   typed error that says the process binds one HTTP listener.
3. Remove the corresponding admin site-editor controls and OpenAPI schema
   fields; regenerate `admin-ui/dist` only if the UI exposes them.
4. Update `docs/CONFIGURATION.md`, `docs/ARCHITECTURE.md`,
   `architecture/networking_deep_dive.md` and `architecture/routing_deep_dive.md`
   to state the single-listener model and how to run multiple ports
   (separate processes with separate config directories, or a fronting
   load balancer).
5. Add a config test: a site with a non-default `listen.port` fails with the
   typed error, and a normal vhost config still validates.

## 03B — Multiple HTTP listener feature (only if required)

1. Add an explicit listener plan type, for example:
   ```text
   HttpListenerPlan {
       addr: SocketAddr,
       tls: bool,
       http2: bool,
       http3: bool,
       proxy_protocol: bool,
       default_server: bool,
       site_ids: Vec<String>,
   }
   ```
2. Collect the global listener plus every `site.listen` entry in
   `UnifiedServerStartupPlan`, normalize duplicate addresses, reject
   conflicting TLS/HTTP3 settings and privileged-port conflicts, and reject
   `proxy_protocol = true` until a PROXY-protocol parser exists.
3. Replace the scalar `http_addr`/`https_addr`/`http3_addr` fields on
   `UnifiedServer` with a listener-plan collection. Spawn one task per plan in
   `listener_tasks.rs`; keep the admin and metrics listeners separate.
4. Reuse the existing cert resolver for every TLS listener; select ALPN
   (`h1`/`h2`) per plan. HTTP/3 needs one UDP socket per HTTP/3 plan and must
   not collide with the global DNS/QUIC listeners.
5. Keep `Router` local-address routing; add the default-server fallback for
   each listener plan and test it.
6. If `proxy_protocol` is required, add a parser that consumes the PROXY
   header before HTTP parsing and records the real client address; this is a
   separate security-sensitive parser and must not be faked.
7. Tests: two HTTP ports with different default sites; TLS and plaintext
   listeners; H2-only and H3-only plans; duplicate-address rejection; v4/v6;
   startup rollback when one bind fails; config reload behavior.

## Non-goals

- Virtual-host routing changes; the current domain map and wildcard router are
  reusable.
- A new reverse-proxy fronting layer.
- PROXY protocol unless 03B explicitly includes it.
- Changing the admin/metrics listener model.

## Risks

- Removing `listen` is a config/API break; provide a migration note and a
  clear error rather than silently ignoring fields.
- 03B expands listener lifecycle, drain and shutdown ownership; every listener
  must register with `UnifiedServerRuntimeHandles` and drain with the existing
  shutdown broadcast.
- Per-listener TLS/H3 multiplies sockets and certificate/ALPN state; test
  resource ownership under restart and reload.

## Exit criteria

- A site config can no longer claim a port the process does not bind.
- The documented multi-service HTTP model matches the runtime.
- If 03B is selected, starting the process with two configured HTTP ports
  serves both, routes by local address, and shuts both down cleanly.

## Completion evidence

Implemented 2026-11-11 using 03A. `[[site.listen]]` is rejected by typed config
validation (`site.listen is not supported ... one HTTP listener`) and is hidden
from serialization/OpenAPI; router listener maps were removed. Documentation
(`docs/ARCHITECTURE.md`, `docs/CONFIGURATION.md`,
`architecture/networking_deep_dive.md`, `architecture/routing_deep_dive.md`)
now states one HTTP listener per process, vhosts by `[site] domains`, and how to
run another port via a separate process or fronting load balancer. The benchmark
harness records `multi-listener` as unsupported with that reason rather than
starting an invalid config.

