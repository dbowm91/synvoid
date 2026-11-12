# Phase 05 Plan: Admin, Observability, Documentation and Benchmarks

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: Phase 02, Phase 03, Phase 04.
Depends on: bound listeners, listener-aware routing, working TLS/H3.

## Scope

Make multi-listener support visible and truthful:

- admin inventory for HTTP/HTTPS/H3 listeners;
- per-listener metrics and structured logs;
- config and admin UI surfaces;
- documentation and fixture migration;
- benchmark support for `multi-listener`;
- accurate TCP/UDP multi-port evidence.

## Admin inventory

Current admin only inventories TCP/UDP:
`src/admin/handlers/tcp_udp.rs:44-90`; route
`src/admin/routes.rs:333-336`.

Add a process-local HTTP listener registry, mirroring the TCP/UDP snapshot
pattern (`src/tcp/listener.rs:270-300`,
`src/udp/listener.rs:196-224`).

Each row should expose:

- listener id and name;
- transport (`http`, `https`, `http3`);
- configured address/port;
- actual bound address/port;
- TLS, HTTP/2, HTTP/3 flags;
- default site;
- site membership summary;
- state: planned / bound / failed / shutting-down;
- accept loops or worker count where applicable;
- active connections where available.

Add an endpoint such as `/api/http/listeners` or a generalized `/api/listeners`.
Do not overload `/tcp-udp/listeners` with HTTP entries unless the response
schema is deliberately generalized.

Update:

- `src/admin/handlers/api_discovery.rs:677-699`;
- `src/admin/openapi.rs` schema and path registration;
- `tests/admin_route_contract.rs` route and empty-before-bind contract;
- admin UI navigation/types/services:
  `admin-ui/src/app.rs`, `admin-ui/src/components/layout/sidebar.rs`,
  `admin-ui/src/pages/tcp_udp.rs`, `admin-ui/src/types/mod.rs:852-875`,
  `admin-ui/src/services/api.rs:1187-1201`.

If the site editor exposes listener membership, it must use a typed
read/modify/write contract. Do not repeat the current full-document/partial-
request mismatch in `src/admin/handlers/sites.rs:254-301`.

## Metrics and logs

Current runtime metrics label only owner/class/status:
`src/server/runtime_handles.rs:87-168`; names are `&'static str`.
HTTP/TCP/H3 counters are mostly unlabeled.

Add a low-cardinality `listener` label using the configured listener id:

- runtime task registered/exited/failed;
- accepted connections / active connections;
- TLS handshakes and ALPN result;
- HTTP/3 connections;
- listener bind failures.

Do not use raw addresses or arbitrary Host values as labels. Update
`architecture/security_observability.md` for new prefixes/labels; guards in
`tests/security_guard.rs` enforce the inventory.

Startup logs should include one structured line per bound listener:

```text
listener=public-https transport=tcp addr=0.0.0.0:443 tls=true alpn=h2,http/1.1 h3=443 default_site=example.com
```

Log the actual bound address, not only the configured one. A single startup
summary should list all data-plane listeners.

## Configuration and admin docs

Update:

- `docs/CONFIGURATION.md` — replace the one-listener model and the retired
  `site.listen` explanation with `[[http.listeners]]` and `[site].listeners`;
- `docs/ARCHITECTURE.md`;
- `architecture/routing_deep_dive.md`;
- `architecture/networking_deep_dive.md`;
- `architecture/config_deep_dive.md`;
- `architecture/config.md`;
- `docs/HTTP3.md`;
- `docs/PERFORMANCE.md`;
- `docs/DEPLOYMENT.md`;
- `benchmarks/multi_service/README.md`;
- `benchmarks/multi_service/results/RESULTS_TEMPLATE.md`;
- `config/main.toml` and `config/main.toml.example`;
- `config/sites/example.com.toml` if membership is documented there.

Document:

- the canonical listener array;
- legacy synthesis;
- the fact that listener changes are restart-required;
- HTTPS/H3 same-port TCP/UDP pairing;
- site membership and default-site behavior;
- shared TLS certificate behavior;
- multi-worker H3 limitation until Phase 06;
- that TCP/UDP remain global maps and are not per-site listener owners.

## Fixtures and generated configs

Replace stale `[[site.listen]]` usage or explicitly mark fixtures as
historical:

- `tests/fixtures/ops/sites/test.localhost.toml:7-8`;
- `tools/xtask/src/eggbench_qualification.rs:1546-1550` and its assertions at
  `:2609-2615`;
- `benchmarks/multi_service/driver.py:925-934`;
- `benchmarks/multi_service/config/templates/site.toml.tpl:7`;
- `benchmarks/multi_service/scripts/generate_sites.py:81-90`;
- `benchmarks/multi_service/config/examples/multi-listener.toml:1-20`.

If a historical fixture must remain, it needs an explicit test asserting the
retired schema is rejected, not silently loaded.

## Benchmark harness

Current state:

- `multi-listener` is hard-coded unsupported:
  `benchmarks/multi_service/driver.py:2015-2018,2292-2306`.
- `run_multi_listener` uses hard-coded `5.0` duration / `1` concurrency:
  `:1843-1904`.
- TCP/UDP multi-port workloads measure only the first port:
  `:1785,1789`.
- `allocate_ports()` allocates one `extra` port: `:143-170`.
- README says multi-listener is unsupported: `:69`.

Required:

- allocate N extra listener ports;
- generate the canonical `[[http.listeners]]` config;
- start a real server with multiple listeners;
- drive load on every listener;
- record per-listener results, not just one `http` object;
- iterate all TCP/UDP multi ports and assert each is bound;
- remove the stale “extra listener is not bound” reason;
- remove the stale TCP/UDP “no add_listener call site” reason;
- add a new dated result; never rewrite existing dated evidence;
- update `docs/PERFORMANCE.md` supported/unsupported counts.

## Tests

- Admin inventory returns bound HTTP/HTTPS/H3 listeners and no fabricated
  planned rows.
- OpenAPI includes the listener schema/endpoint.
- Runtime metrics include listener labels with bounded cardinality.
- Startup logs include each listener and its actual address.
- Admin UI types compile against the new endpoint.
- Config round-trips and docs examples parse.
- Fixtures/generators no longer emit retired `[[site.listen]]`.
- Benchmark config generation parses and starts multiple listeners.
- New benchmark result marks `multi-listener` supported.

## Exit criteria

- Operators can see every actual listener without reading logs.
- Metrics distinguish listeners without high-cardinality labels.
- Docs and examples describe the canonical model, not 03A.
- No shipped fixture or benchmark generator uses retired `site.listen`.
- `multi-listener` benchmark is supported with per-listener evidence.
- TCP/UDP multi-port benchmark exercises all configured ports.

## Risks

- New admin endpoints and UI increase the surface area; keep the first version
  read-only.
- Listener labels can explode cardinality if names are user-controlled or
  addresses are used. Use the validated listener id and cap the count.
- Benchmark results are append-only evidence; an old unsupported result must
  remain visible as history.
