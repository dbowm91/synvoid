# Phase 03 Plan: Listener-Aware Routing and Site Membership

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: Phase 01 (schema/plan) and Phase 02 (bound listeners).
Depends on: the listener id introduced by Phase 01 and carried by Phase 02.

## Scope

Route each request using the listener that accepted it, not a global domain map
or a connection's `local_addr`.

Deliver:

- stable `ListenerId` propagation;
- per-listener exact/wildcard domain tables;
- per-listener `default_site`;
- optional `[site].listeners` membership;
- no cross-listener site leakage when membership is explicit;
- HTTP/3 uses the same listener identity.

## Current state

- Router ignores `local_addr`: `crates/synvoid-proxy/src/router.rs:983-997`.
- Routing is global by Host: `crates/synvoid-proxy/src/router.rs:210-243`.
- `Router` carries an unused scalar `_server_port`:
  `crates/synvoid-proxy/src/router.rs:46,135,1039`.
- HTTP accept passes `stream.local_addr()` into request handling:
  `src/http/server/accept_loop.rs:90`.
- TLS captures `stream.local_addr()` before handshake:
  `src/tls/server.rs:401-406`.
- HTTP/3 does not carry a local listener identity into request handling.
- The old per-listener maps were removed because they were keyed by
  configured addresses and did not match wildcard connections.

## Why not `local_addr`

`local_addr()` is `getsockname()` for the accepted connection:

- `0.0.0.0:8080` reports a concrete destination such as
  `192.0.2.10:8080`, not `0.0.0.0:8080`;
- `[::]:8080` may report a v4-mapped address for IPv4 clients;
- `SO_REUSEPORT` may distribute connections across sockets that share an
  endpoint.

`local_addr` remains useful for logs, forwarded protocol, and destination
diagnostics. It is not listener identity.

## Listener identity

Carry `ListenerId` from the normalized plan through:

- `BoundHttpListener` in Phase 02;
- the HTTP accept loop;
- `HttpServerRuntime` / request context;
- `EggserveH1Service` and the H2 request path;
- the HTTPS path;
- the HTTP/3 request dispatch path;
- router lookup, metrics, logs, and admin inventory.

The request context should carry an optional listener id for compatibility with
internal callers and tests. Production requests must always carry one.

## Router model

Replace the single global table with per-listener tables:

```text
ListenerRoutingTable {
    exact: HashMap<domain, Arc<SiteConfig>>,
    wildcard: MatchRouter<Arc<SiteConfig>>,
    default_site: Option<Arc<SiteConfig>>,
}
Router {
    listeners: HashMap<ListenerId, ListenerRoutingTable>,
    fallback: FallbackMode,
    // shared static handlers / site map / plugin manager
}
```

Routing precedence on a listener:

1. exact Host;
2. wildcard/suffix Host;
3. listener `default_site` when the Host is unmatched;
4. global `[fallback]`.

If `[site].listeners` is omitted, the site is inserted into every listener
table. If it is present, the site appears only in the named listener tables.
Do not fall through to a combined global table for a request that carries an
explicit listener id and an explicit membership.

Define the fallback behavior precisely:

- `default_site` applies to any unmatched Host, not only an empty or `*` Host.
  The old `default_server` behavior was too narrow.
- If a listener has no matching site and no default site, return the configured
  fallback/404. Do not pick an arbitrary site from another listener.
- If membership is omitted, a global Host match remains valid on that listener.

Keep `Router::route(host, path)` for tests and internal callers that have no
listener context. It may use a combined compatibility table. Document that it
is not the production entry point.

Remove `_server_port`; it has no remaining routing meaning.

## Site construction

For each site:

- resolve listener membership names to `ListenerId`s;
- reject unknown listener names;
- reject empty membership;
- insert into exact/wildcard tables per listener;
- validate duplicate domains on the same listener;
- validate `default_site` membership.

`SiteConfig::site_id()` remains the first domain. Duplicate first-domain site
ids must fail rather than silently overwrite `ConfigManager` entries.

## HTTP/3 parity

HTTP/3 currently hardcodes the request scheme and does not pass a listener
identity through dispatch. Phase 03 must:

- pass `ListenerId` into `prepare_http3_request_dispatch` and the H3 request
  context;
- route with that identity;
- preserve scheme `https`;
- use the listener id for logs/metrics, not the QUIC remote address.

## Tests

Add router tests:

- two listeners, same Host, different default sites;
- exact Host wins over default site;
- wildcard Host wins over default site;
- unmatched Host uses the listener default site;
- unmatched Host with no default site does not fall through to another
  listener's default;
- site membership restricts a site to one listener;
- omitted membership makes a site available on all listeners;
- unknown listener name and empty membership are rejected;
- duplicate domains on one listener are rejected;
- same domain on different listeners with distinct sites is deterministic.

Add service tests:

- two HTTP ports with different default sites and different Host maps;
- request to port A never resolves a site that is only bound to port B;
- `local_addr` wildcard bind still routes through the listener id;
- HTTPS listener uses the same listener routing table;
- HTTP/3 routes through the same listener id.

Update guard references:

- `tests/http_normalization_ownership_guard.rs:198` names
  `route_with_local_addr`; update only if the entry point is renamed.
- `crates/synvoid-http/src/request_preparation.rs:167` must pass listener
  identity rather than relying on `local_addr`.

## Exit criteria

- A request is routed by the listener that accepted it.
- Listener-specific default sites work.
- Site membership prevents cross-listener leakage.
- Wildcard bind addresses route correctly.
- HTTP/HTTPS/H3 all use the same listener identity.
- Global fallback behavior remains explicit and tested.

## Risks

- Duplicating domain maps per listener increases memory; share `Arc<SiteConfig>`
  values and keep the table per listener.
- If every site is inserted into every listener by default, a large site set
  multiplies tables. The compatibility default is intentional; measure and
  document before changing it.
- Changing default-site semantics may surprise operators who relied on the old
  empty-Host-only behavior. Document the change in the config reference.
