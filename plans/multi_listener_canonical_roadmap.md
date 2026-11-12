# Multi-Listener Canonical Support Roadmap

Status: **COMPLETE** (2026-11-11). All six phases are implemented and the
`cargo xtask verify` gate passes; the focused multi-listener benchmark is
`benchmarks/multi_service/results/2026-11-11/2026-11-11T230416Z-fe8be0-summary.md`.

Campaign baseline: the working tree after the completed
`plans/production_readiness_remediation_roadmap.md`, on top of
`d507fefa` (SynVoid 1.1.0).

Predecessor: `plans/production_readiness_remediation_roadmap.md`.

Supersedes:

- decision **D2** in `plans/production_readiness_remediation_roadmap.md`;
- Phase 03's **03A** as the terminal product model in
  `plans/production_readiness_phase_03_http_listener_truthfulness.md`.

03A remains the correct truthful remediation of the old unbound
`[[site.listen]]` surface. It is not the target product model. Multi-listener
support is now the canonical path.

## The finding

The current process binds one HTTP listener, one HTTPS listener, and one
HTTP/3 listener. Sites are virtual hosts on that one HTTP surface. The current
configuration model rejects `[[site.listen]]` and documents separate processes
or a fronting load balancer for another HTTP port.

That is truthful, but it is a product regression: SynVoid is intended to
support many simultaneous TCP, HTTP, HTTPS, HTTP/3, and UDP listeners in one
deployment.

TCP/UDP already expand multiple ports and address families from the global
`[tcp.protocols.*]` / `[udp.protocols.*]` maps. The missing canonical pieces are:

- multiple HTTP/HTTPS/HTTP/3 sockets;
- one conflict model across all listener families;
- listener-aware routing and default-site selection;
- TLS ALPN and HTTP/3 qualification;
- listener identity in lifecycle, admin, metrics, and benchmarks.

## The old `[[site.listen]]` surface is not a working implementation to revert

At `d507fefa`, `SiteListenConfig` parsed `address`, `port`, `ssl`, `http2`,
`http3`, `default_server`, and `proxy_protocol`, but:

- startup never bound those addresses or ports;
- `http2`, `http3`, and `proxy_protocol` had no runtime consumer;
- `ssl` did not select a TLS socket;
- `default_server` only applied to an empty or `*` Host;
- the old IP-based router maps were keyed by configured addresses, while the
  accepted connection reports a concrete `local_addr`; wildcard entries such
  as `0.0.0.0:8080` therefore did not match.

Removing the rejection alone would recreate a configuration surface that
claims sockets the process does not bind and flags it does not honor. This
campaign builds the real model.

## Canonical model

Listeners are process-wide resources. Sites reference listeners; sites do not
own sockets.

```toml
# main.toml
[[http.listeners]]
name = "public-http"
address = "0.0.0.0"
port = 80
tls = false
default_site = "example.com"

[[http.listeners]]
name = "public-https"
address = "0.0.0.0"
port = 443
tls = true
http2 = true
http3 = true
default_site = "example.com"

[[http.listeners]]
name = "internal-https"
address = "127.0.0.1"
port = 8443
tls = true
http2 = true
```

```toml
# sites/example.com.toml
[site]
domains = ["example.com", "www.example.com"]
listeners = ["public-http", "public-https"]  # optional allowlist
```

Rules:

- `[[http.listeners]]` is the single socket authority when present.
- When the array is absent, synthesize the current legacy listeners from
  `[server]`, `[tls]`, and `[http3]` so existing configurations keep working.
- `[server]`, `[tls]`, and `[http3]` become process-wide defaults, not
  additional sockets.
- `[[site.listen]]` remains rejected with a migration error pointing at
  `[[http.listeners]]` and `[site].listeners`.
- TCP/UDP remain configured through `[tcp.protocols.*]` / `[udp.protocols.*]`.
  Per-site TCP/UDP listener ownership is not part of this campaign.

## Decisions

| Gate | Decision |
|---|---|
| ML1 — listener ownership | Global `[[http.listeners]]`; sites reference listeners. Do not restore per-site socket ownership. |
| ML2 — legacy configuration | Synthesize the current scalar listeners when the array is absent. No second owner when it is present. |
| ML3 — routing identity | Carry a stable `ListenerId` from plan to accept loop to router. Never use `local_addr` as listener identity. |
| ML4 — site selection | Per-listener domain table, then listener `default_site`, then `[fallback]`. Optional `[site].listeners` allowlist. |
| ML5 — TLS | One listener plan gets one `ServerConfig`/ALPN policy. HTTP/3 gets a separate QUIC `ServerConfig` with `h3` ALPN. |
| ML6 — HTTP/3 addressing | HTTPS/TCP and HTTP/3/UDP may share the same address and port. The current conflict rule is wrong. |
| ML7 — multi-worker | Every worker receives the same listener plan. `reuse_port` is per-plan and enabled only for worker sharing. |
| ML8 — HTTP/3 multi-worker | Keep HTTP/3 on one deterministic worker until migration-safe multi-owner behavior is qualified. Default one worker remains unaffected. |
| ML9 — reload | Listener definitions are restart-required in this campaign. Do not claim live rebinding. |
| ML10 — deferred protocols | No PROXY protocol parser, no cleartext h2c, no per-site TCP/UDP ownership in this campaign. |

## Phase table

| Phase | Plan | Depends on | Primary outcome |
|---|---|---|---|
| 01 | `multi_listener_phase_01_configuration_model.md` | none | Canonical listener schema, normalized plan, validation, legacy synthesis |
| 02 | `multi_listener_phase_02_bind_and_lifecycle.md` | 01 | All listeners bound before readiness; dynamic tasks; rollback; clean shutdown |
| 03 | `multi_listener_phase_03_routing_and_membership.md` | 01, 02 | Listener-aware routing, site membership, default site |
| 04 | `multi_listener_phase_04_tls_alpn_http3.md` | 01, 02, 03 | Working HTTPS ALPN, HTTP/2, HTTP/3, per-listener Alt-Svc |
| 05 | `multi_listener_phase_05_admin_observability_benchmarks.md` | 02, 03, 04 | Truthful inventory, metrics, docs, fixtures, benchmark support |
| 06 | `multi_listener_phase_06_multiworker_and_qualification.md` | 02, 04 | Multi-worker semantics, restart-only reload, full qualification |

## Cross-phase invariants

- One owner for a socket. A configured listener is either bound by this
  process or is a typed configuration error.
- One owner for listener identity. Routing, metrics, logs, admin inventory, and
  benchmarks use the same `ListenerId`.
- Every listener that binds is registered, drained, and joined.
- A failed listener bind fails startup before readiness.
- No listener surface exposes a flag the runtime does not enforce.
- HTTP/HTTPS/H3, TCP/UDP, admin, metrics, DNS, mesh, and tunnel endpoints share
  one conflict matrix.
- `[[site.listen]]` never returns as an owner. At most it can be a compiler
  into the global plan if a later compatibility decision demands it.
- The one-worker default remains the supported, simple deployment.

## Target behavior

A minimal production setup must work out of the box:

```toml
[[http.listeners]]
name = "public-http"
address = "0.0.0.0"
port = 80

[[http.listeners]]
name = "public-https"
address = "0.0.0.0"
port = 443
tls = true
http2 = true
http3 = true

[tls]
enabled = true
cert_path = "/etc/synvoid/certs/server.crt"
key_path = "/etc/synvoid/certs/server.key"
```

The current schema still requires `[server]`; when `[[http.listeners]]` is
present its `host`/`port` are compatibility defaults only and bind nothing. The
snippet above is the listener/TLS portion of a complete `main.toml`.

Expected:

- both HTTP and HTTPS bind;
- Host routing works on both;
- HTTPS negotiates HTTP/1.1 and HTTP/2 according to ALPN;
- HTTP/3 binds UDP 443 and is advertised only when bound;
- all ports are released on shutdown;
- a duplicate or conflicting listener is rejected by `configtest`.

## Acceptance matrix

| Check | Evidence |
|---|---|
| Legacy single-listener config still validates and binds | config tests plus existing listener integration |
| Two plaintext HTTP ports serve independently | new service test |
| Two TLS ports serve with SNI/ALPN | new TLS integration |
| HTTP/3 completes a handshake when enabled | HTTP/3 transport test |
| HTTPS and HTTP/3 share 443 without conflict | startup-plan test |
| Wildcard and concrete listeners conflict correctly | config/plan tests |
| Listener-specific default site and membership work | router tests |
| TCP/UDP listeners still bind alongside HTTP | service tests |
| No partial service after one bind failure | startup rollback test |
| Shutdown releases every port | lifecycle test |
| Admin inventory reports only bound listeners | admin contract test |
| Benchmark `multi-listener` is supported | new dated benchmark run |
| `cargo xtask verify` passes | final gate |

## Non-goals

- Live add/remove/rebind of listeners without restart.
- PROXY protocol parsing.
- Cleartext HTTP/2 (h2c).
- Per-site TCP/UDP listener declarations.
- Per-listener certificate overrides unless Phase 04 records a requirement.
- A new reverse-proxy fronting layer.
- Rewriting the completed production-readiness plan history.

## Risks

- **Socket ambiguity:** `SO_REUSEPORT` is currently unconditional. Duplicate
  listener definitions can bind successfully and split traffic. Validation
  must reject duplicates before bind.
- **Readiness:** the current worker reports ready before `server_run` starts
  listeners. A multi-listener implementation must move readiness after the
  bind barrier.
- **ALPN:** HTTPS HTTP/2 is currently not negotiated because
  `CertResolver::build_server_config` sets no ALPN. HTTP/3 uses the same
  no-ALPN config for QUIC. This is a prerequisite, not a stretch goal.
- **Lifecycle:** listener tasks are currently detached and
  `stop_accepting_tx` has no subscribers. N listeners multiply that debt.
- **Routing identity:** using `local_addr` as a listener key is incorrect for
  wildcard binds and dual-stack sockets.
- **H3 multi-worker:** QUIC migration and `SO_REUSEPORT` ownership are not
  equivalent to TCP worker sharing. Do not promise multi-worker H3 without
  qualification.
- **Configuration ambiguity:** if both the array and legacy listener keys are
  accepted as socket owners, the process has two authorities. Reject or
  explicitly define defaults only.
