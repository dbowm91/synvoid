# Phase 04 Plan: TLS, ALPN, HTTP/2 and HTTP/3

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: Phase 01, Phase 02, Phase 03.
Depends on: bound listeners and listener-aware routing.

## Scope

Make each TLS listener select the protocols its plan advertises, and make each
HTTP/3 plan a qualified QUIC endpoint.

This phase is a hard prerequisite for exposing `http2` and `http3` listener
fields. The current repository explicitly asserts that no ALPN is configured,
so HTTPS HTTP/2 and HTTP/3 cannot be claimed as working until this changes.

## Current state and defects

- `CertResolver::build_server_config` sets protocol versions, optional client
  auth, and a certificate resolver, but no ALPN:
  `crates/synvoid-tls/src/cert_resolver.rs:264-333`.
- A test pins the absence:
  `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:530-580`.
- HTTPS selects HTTP/2 only if ALPN negotiated `h2`:
  `src/tls/server.rs:440-443`. With no ALPN, the H1 branch always wins.
- HTTP/3 converts the same no-ALPN `ServerConfig` into a QUIC config:
  `src/server/mod.rs:707`; `crates/synvoid-http3/src/server.rs:75-78`.
  QUIC requires ALPN; an `h3` client cannot negotiate.
- HTTPS and HTTP/3 are rejected when their numeric ports match:
  `src/server/startup_plan.rs:181-196`; a test pins the wrong rule at
  `src/server/startup_plan.rs:399-414`. HTTPS is TCP and H3 is UDP; sharing
  port 443 is normal.
- H3 silently does not start when TLS/cert resources are absent:
  `src/server/resources.rs:111-128`; `src/server/listener_tasks.rs:121-152`.
- Alt-Svc is derived from the global H3 port and attached only to plaintext
  HTTP: `src/server/mod.rs:550-557`; HTTPS passes `alt_svc: None`
  (`src/tls/server.rs:548,716,741`). It can advertise an H3 endpoint that did
  not bind.

## ALPN model

Change the TLS builder so ALPN is a parameter, not a global absence:

```text
build_server_config(alpn: &[&[u8]]) -> Arc<ServerConfig>
```

Per listener:

- HTTPS listener with `http2 = true`: `["h2", "http/1.1"]`.
- HTTPS listener with `http2 = false`: `["http/1.1"]`.
- HTTP/3 listener: `["h3"]`, TLS 1.3, QUIC-compatible settings.

Use separate `ServerConfig` values per listener. Do not share one server config
between HTTPS and HTTP/3; their ALPN and transport requirements differ.

The certificate resolver remains shared unless per-listener certificate
overrides are explicitly approved. It already resolves SNI certificates from
one map (`crates/synvoid-tls/src/cert_resolver.rs:335-355`), which is sufficient
for multiple TLS listeners that share the same certificate set.

### Certificate handling

- Validate TLS material before readiness for every TLS listener.
- If `[tls].enabled = false` and any listener has `tls = true`, fail at config
  validation, not by silently skipping the listener.
- If a certificate load fails, fail startup. Do not serve plaintext as a
  fallback.
- Decide whether `[tls].watch_dir` reload applies to all listeners; it should,
  because the resolver is shared. Document that ALPN/protocol changes are
  restart-required.

## HTTP/2

- HTTPS H2 becomes reachable when `h2` ALPN is negotiated.
- H2 request handling must receive the `ListenerId` from Phase 03.
- Plaintext `http2 = true` remains rejected until an h2c driver exists. Do not
  claim cleartext HTTP/2.
- Update the HTTPS banner and any docs that unconditionally say
  “HTTP/1.1 + HTTP/2”; print the actual per-listener ALPN offer.

## HTTP/3

Each `http3 = true` listener creates a UDP plan paired with its TLS listener:

- bind `UDP addr:port`;
- build a QUIC config from an `h3`-ALPN `ServerConfig`;
- use TLS 1.3;
- pass the listener id and local address into request dispatch;
- count connections for drain/shutdown;
- close the endpoint on shutdown and join in-flight connection tasks within the
  global deadline.

If H3 uses a different port from HTTPS, the plan must still reference the same
logical listener identity for routing and default-site purposes.

### Same port

Allow:

```text
HTTPS TCP 0.0.0.0:443
HTTP/3 UDP 0.0.0.0:443
```

Reject only collisions within the same transport:

- two TCP listeners on one endpoint;
- two UDP listeners on one endpoint;
- H3 UDP vs raw UDP/DNS/DoQ/tunnel QUIC/WireGuard/mesh UDP.

Invert the existing startup-plan test.

### Alt-Svc

- Advertise `h3=":<port>"` only on listeners that have a successfully bound
  H3 plan.
- Attach it to both HTTP and HTTPS responses for that listener.
- Use the H3 port for that listener, not the global `http3.port`.
- Do not advertise `h3` if binding failed or H3 is disabled.
- Keep `alt_svc_max_age` from `[http3]` as the default unless a listener-level
  override is added later.
- Remove or wire the unused `Http3Server::alt_svc_header` duplicate
  (`crates/synvoid-http3/src/server.rs:279-288`).

## Multi-worker H3

Default `unified_server_workers = 1` is the supported path.

For workers > 1, do not silently share H3 across `SO_REUSEPORT` endpoints.
QUIC connection migration can move a flow to a different worker. Phase 06 must
choose one of:

- one deterministic H3 owner worker; or
- a qualified shared-QUIC design.

Until then, validate `http3 = true` + `workers > 1` as unsupported, with a
clear error.

## Tests

- `build_server_config` with `h2`/`http1.1` advertises and negotiates the
  expected protocol.
- HTTPS listener with `http2 = false` does not negotiate `h2`.
- HTTPS request paths route correctly on both H1 and H2.
- HTTP/3 handshake completes with `h3` ALPN and serves a request.
- HTTPS TCP and H3 UDP on the same numeric port both bind and serve.
- H3 without TLS is rejected at configuration time.
- Certificate load failure fails startup before readiness.
- Alt-Svc appears only for listeners with a bound H3 plan and names the
  correct port.
- H3 shutdown closes the endpoint and does not leave the UDP port bound.
- `workers > 1` + H3 is rejected until Phase 06 approves a model.

Update existing tests:

- `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:530-580` must
  stop asserting “no ALPN”; split the contract into explicit ALPN outcomes.
- `src/server/startup_plan.rs:399-414` must invert the H3/HTTPS conflict.
- `tests/eggserve_tls_h1_convergence.rs` / `tests/http_h1_tls_transport.rs`
  fixtures may need ALPN values aligned with the new builder.
- `docs/HTTP3.md` metric/banner claims must match actual behavior.

## Exit criteria

- HTTPS HTTP/2 works when configured.
- HTTP/3 completes a real handshake and request.
- HTTPS and H3 can share the normal 443 TCP/UDP pair.
- Alt-Svc is per listener and only advertises bound H3 endpoints.
- No listener exposes `http2`/`http3` flags the runtime cannot honor.
- ALPN tests describe the new contract instead of asserting absence.

## Risks

- Adding ALPN changes wire behavior for existing HTTPS clients; verify H1
  fallback and browser behavior.
- Per-listener `ServerConfig` values increase TLS state slightly; share the
  certificate resolver and key material.
- HTTP/3 qualification can expose QUIC/TLS version or ALPN configuration
  errors that were previously hidden by the unsupported path.
- Multi-worker H3 remains a product decision; do not accidentally imply it is
  solved by `SO_REUSEPORT`.
