# Phase 01 Plan: Canonical Listener Configuration Model

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: none. This phase must land first.
Depends on: completed `plans/production_readiness_remediation_roadmap.md`; no
runtime multi-listener support is implied by this phase.

## Scope

Define the canonical listener schema, normalize it into one plan, make legacy
single-listener configuration a synthesis path, and make cross-family
conflicts fail in `configtest` before any socket is opened.

This phase does not bind sockets or change routing. It makes the runtime able
to receive an unambiguous listener list in Phase 02.

## Current state

- `SiteInfo.listen` is a rejected field:
  `crates/synvoid-config/src/site/listen.rs:11-48`.
- `SiteConfig::validate` does not validate listener entries:
  `crates/synvoid-config/src/site/mod.rs:205-219`.
- `ServerConfig` has scalar `host`, `port`, and optional `host_v6`:
  `crates/synvoid-config/src/server.rs:6-13`.
- `TlsConfig` has one `port`: `crates/synvoid-config/src/tls.rs:47-48`.
- `Http3Config` has one `port` and optional `host_v6`:
  `crates/synvoid-config/src/http.rs:162-174`.
- `UnifiedServerStartupPlan` encodes scalar HTTP/HTTPS/H3 addresses:
  `src/server/startup_plan.rs:13-33`.
- `configtest` validates `MainConfig` and sites but does not build the startup
  plan: `src/commands/one_shot.rs:215-256`, so cross-section listener conflicts
  escape it.
- `parse_host_port` accepts literal IPs only: `src/utils.rs:216-239`.

## Canonical schema

Add a listener array under `[http]`:

```toml
[[http.listeners]]
name = "public-http"          # required; unique; stable identity
address = "0.0.0.0"           # required; literal IPv4/IPv6
port = 80                     # required; 1..=65535
tls = false                   # default false
http2 = false                 # default false for plaintext
http3 = false                 # default false; requires tls = true
default_site = "example.com"  # optional; first domain / site id
ipv6_only = false             # only meaningful for "::"
```

Fields intentionally absent in this phase:

- `proxy_protocol` — no parser exists. Do not add a field that cannot be
  enforced.
- per-listener certificate paths — shared `[tls]` resolver is the first
  implementation; Phase 04 decides whether profiles are required.
- `reuse_port` — a worker/deployment concern, not operator listener identity.

Add optional site membership:

```toml
[site]
domains = ["example.com", "www.example.com"]
listeners = ["public-http", "public-https"]  # optional; omitted means all
```

Semantics:

- `listeners` omitted: the site is a candidate on every listener.
- `listeners = []`: rejected. A site must be reachable somewhere.
- An unknown listener name is an error.
- `default_site` must be a member of that listener.
- Duplicate `default_site` on one listener is an error.
- Site identity remains `SiteConfig::site_id()` (first domain). Add duplicate
  first-domain/domain validation rather than a new `[site].name` field in this
  phase.

## Normalized plan

Introduce one normalized plan type, owned by `synvoid-config` so validation
and runtime consume the same result:

```text
ListenerId(String)
HttpListenerPlan {
    id: ListenerId,
    addr: SocketAddr,
    tls: bool,
    http2: bool,
    http3: bool,
    ipv6_only: bool,
    default_site: Option<String>,
    site_ids: Vec<String>,
}
```

The root startup plan should carry `Vec<HttpListenerPlan>` and derive HTTPS/H3
tasks from the entries. Do not keep scalar `http_addr` / `https_addr` /
`http3_addr` as a second authority.

Use `std::net::SocketAddr` after parsing. Reject hostnames for explicit
listeners; deterministic conflict checks and bind identity require literal
addresses. The legacy synthesis path may continue to use the current
`server.host` rules.

## Legacy synthesis

When `[[http.listeners]]` is absent or empty:

1. Synthesize `default-http` from `[server] host` + `port`.
2. If `[server] host_v6` is set, synthesize `default-http-v6` using
   `host_v6` + `port` (or record one logical listener with two addresses; the
   plan must define which; prefer two explicit entries for one routing
   identity).
3. If `[tls].enabled`, synthesize `default-https` from `server.host` +
   `tls.port`; synthesize the v6 variant when `server.host_v6` is set.
4. If `[http3].enabled`, synthesize `default-http3` from `server.host` +
   `http3.port`; use `http3.host_v6` for the v6 variant. H3 requires TLS.
5. Site membership is empty, meaning all sites are candidates on each
   synthesized listener.

When the array is present:

- it is the only socket authority;
- `[server]`, `[tls]`, and `[http3]` are compatibility defaults only
  (trusted proxies, certificate paths, ACME, Alt-Svc max age, H3 max request
  size);
- `server.host`, `server.port`, and `server.host_v6` remain required by the
  current schema, but must not synthesize or bind any socket when the array is
  present;
- `tls.port` and `http3.port` must not synthesize or bind any socket when the
  array is present;
- `tls.enabled` must be true when any listener has `tls = true`;
- `http3.enabled` no longer creates a socket; only a listener with
  `http3 = true` does;
- log one warning when legacy listener values are present but not used, so the
  compatibility defaults cannot be mistaken for an extra listener.

Making `[server]` optional/array-only is a separate schema change. Do not
require it for this campaign; the shipped `config/main.toml` keeps `[server]`
as a compatibility default.

Document that `[[site.listen]]` remains rejected and points at
`[[http.listeners]]` plus `[site].listeners`.

## Validation

Implement one normalized listener validator and call it from
`MainConfig::validate()` and `configtest`.

### Listener-local rules

- Unique, non-empty listener name; reject case-insensitive duplicates if names
  are treated as identifiers.
- Unique `(transport, canonical address, port)` endpoint.
- Port 0 rejected. Privileged ports allowed with a warning; binding may still
  require `CAP_NET_BIND_SERVICE`.
- `address` must parse as a literal IP.
- `ipv6_only` is rejected on IPv4.
- `http2 = true` on a plaintext listener is rejected until h2c exists.
- `http3 = true` requires `tls = true` and a usable certificate source
  (`[tls].enabled` with cert/key or ACME).
- `default_site` references an existing site and is a member.
- A listener with no sites and no `default_site` is rejected; a listener with
  no sites but a valid `default_site` is allowed.
- Duplicate domains/site ids on the same listener are rejected.

### Address rules

- Normalize IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4.
- A wildcard address claims the whole family on that port. Reject a wildcard
  and a concrete address on the same family/port.
- Treat `::` as dual-stack unless `ipv6_only = true`. The platform bind
  helpers do not set `IPV6_V6ONLY`: `crates/synvoid-platform/src/socket_bind.rs:49-95`.
- Same port on different concrete addresses is allowed.
- Same address/port across TCP and UDP may be allowed when the transports
  differ (notably HTTPS TCP + HTTP/3 UDP). HTTP/HTTPS vs HTTP/HTTPS on the same
  endpoint is a conflict.

### Cross-family conflict matrix

The validator must cover every configured listener family, not only HTTP:

| Family | Transport | Must check against |
|---|---|---|
| HTTP | TCP | HTTPS, raw TCP protocols, admin, metrics, DNS TCP, DoT/DoH TCP, mesh TCP |
| HTTPS | TCP | HTTP, raw TCP, admin, metrics, DNS TCP, DoT/DoH TCP, mesh TCP; may share with HTTP/3 UDP |
| HTTP/3 | UDP | raw UDP protocols, DNS UDP, DoQ, tunnel QUIC, WireGuard, mesh QUIC |
| Admin/metrics | TCP | HTTP, HTTPS, raw TCP, DNS TCP, DoT/DoH, mesh TCP |
| Raw TCP | TCP | all TCP families |
| Raw UDP | UDP | all UDP families |

Current checks are insufficient:

- `src/server/startup_plan.rs:173-213` compares exact scalar addresses only.
- `src/worker/unified_server/state.rs:213-285` probes numeric ports on
  `127.0.0.1` over TCP only.
- `check_ports_available` is TCP/loopback-only:
  `crates/synvoid-ipc/src/manager.rs:2541-2573`.
- TCP/UDP duplicate checks stop at their own section:
  `crates/synvoid-config/src/network.rs:323-458`.

Do not extend the loopback probe into the source of truth. Use the normalized
plan plus actual bind as the final authority.

### Validation gaps to close

- `ServerConfig::validate` does not validate `host_v6`
  (`crates/synvoid-config/src/server.rs:21-46`).
- `TlsConfig::validate` does not reject `port = 0`
  (`crates/synvoid-config/src/tls.rs:89-127`).
- `Http3Config` has no `validate()` (`crates/synvoid-config/src/http.rs:162-186`).
- `configtest` does not build the plan (`src/commands/one_shot.rs:215-256`).

## Admin and schema surfaces

- `SiteInfo` gains `listeners: Vec<String>` with `#[serde(default)]`.
- Update every hardcoded `SiteInfo` constructor, including
  `SiteConfig::default_fallback_site`
  (`crates/synvoid-config/src/site/mod.rs:136-147`) and admin create-site
  (`src/admin/handlers/sites.rs:122-133`).
- `[[site.listen]]` stays rejected and skipped from serialization.
- `/config/schema` must include the new listener schema through the normal
  `schemars` path.
- Site DTOs should expose listener membership read-only in this phase; editing
  can wait for Phase 05.
- Update `config/main.toml` / `config/main.toml.example` with a commented
  listener example. Keep the legacy `[server]` example working.
- No admin UI rebuild is required in this phase unless the site DTO rejects a
  full read/modify/write round-trip.

## Tests

Add or extend:

- `crates/synvoid-config/tests/` or module tests:
  - two listeners parse and normalize;
  - legacy config synthesizes exactly the current listeners;
  - duplicate name/endpoint rejected;
  - wildcard vs concrete conflict;
  - `::` dual-stack vs IPv4 conflict;
  - port 0, bad IP, `ipv6_only` on IPv4;
  - `http2` plaintext rejected;
  - `http3` without TLS rejected;
  - unknown site membership, empty membership, invalid default site;
  - HTTP vs HTTPS same TCP endpoint rejected; HTTPS vs H3 same numeric port
    allowed;
  - HTTP vs raw TCP/admin conflict; H3 vs raw UDP/DNS conflict;
  - legacy `[[site.listen]]` still rejected with a migration pointer.
- `src/server/startup_plan.rs` tests for the normalized plan, once Phase 02
  consumes it.
- `crates/synvoid-config/tests/tracked_config_compatibility.rs` round-trip
  coverage for `config/main.toml`, `config/main.toml.example`, and site files.
- `crates/synvoid-config/tests/serde_defaults_match_rust_defaults.rs` for new
  defaults.
- `configtest` test proving a cross-section conflict fails before bind.

## Exit criteria

- `[[http.listeners]]` parses, validates, and normalizes to one plan.
- Existing single-listener config is synthesized identically.
- `configtest` rejects duplicate, overlapping, and cross-family conflicts.
- `[[site.listen]]` still fails with a migration message that names the new
  schema.
- No runtime socket behavior changes are claimed by this phase.

## Risks

- The schema is public configuration. Choose field names and defaults before
  Phase 02 depends on them.
- Raw TOML presence checks can be lost if configuration is constructed only
  from typed structs. Validation must work for both file-loaded and
  test-constructed configs.
- Site identity remains first-domain-based. Duplicate validation is required
  until a stable `[site].name` is introduced.
