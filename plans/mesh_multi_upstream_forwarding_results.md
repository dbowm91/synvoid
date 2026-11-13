# Mesh Multi-Upstream Forwarding — Implementation Results

Status: Phases 01–04 **IMPLEMENTED**; Phase 05 **IN QUALIFICATION**
(operator docs and static guards complete; multi-node runtime qualification
still open).

Campaign: `plans/mesh_multi_upstream_forwarding_roadmap.md`.
Research baseline: `8cbf8639`. Implementation date: 2026-11-13.

## Phase outcomes

### Phase 01 — Service ID and HTTP wiring

- New wire contract `crates/synvoid-mesh/src/mesh/service_target.rs`:
  `0x1F 'M' 'S' 'V'`, version 1, reserved flags, `u16` length, 255-byte
  bounded service ID, control characters rejected. The first byte cannot
  collide with an HTTP method or a control-message length prefix (bounded at
  10 MiB, so its top byte is always `0x00`).
- `MeshTransport::proxy_http_request` writes the preface before the HTTP/1.x
  bytes. `proxy_to_peer` sends the site's service ID, not the resolved target
  URL.
- The origin reads the preface in `handle_peer_message`, then authorizes and
  resolves the service before any backend connection. An explicit unknown ID
  returns `502` and never falls back to `Host`. Legacy peers without a preface
  keep the `http://<Host>` compatibility key.
- `MeshInit` now returns the worker-local `MeshProxy`; `UnifiedServer` installs
  it once (set-once handle) and the HTTP dispatch calls
  `MeshProxy::route_request(service_id, request)`. The handle reaches the
  plaintext H1 lane and the TLS H1/H2 lanes (`src/tls/server.rs`), so a
  mesh-backed site behaves the same on HTTP and HTTPS listeners. The
  `MeshBackendPool` HTTP dispatch role is retired; the pool type remains for
  Raft/transport use.
- Config load rejects an empty, over-long, or control-character mesh service
  ID (`proxy.backend.upstream`, location backends included).

### Phase 02 — Origin trust, authorization, SSRF policy

- `MeshTopology::authorize_local_upstream` is the single origin data-path
  decision: unknown service, service-policy denial, and `peered_wafs` denial
  are distinct outcomes. It does not short-circuit on `is_local`, so an origin
  cannot skip the peer allowlist for its own upstream.
- Route disclosure is authorized on both datagram and stream paths. A denied
  peer receives `RouteNotFound` and no URL. Forwarded (multi-hop) route
  responses omit the operator's upstream URL.
- Only operator-configured `local_upstreams` are connectable; no peer-supplied
  URL reaches `TcpStream::connect`. Private, loopback, RFC1918, and ULA targets
  therefore work for configured services without reopening SSRF.
- `service_policy` is no longer dead config: `can_forward_service` applies
  `deny` → `allow` → `routing.allow_all_services`/`allowed_services`.
- Peer-facing errors are URL-free (`unknown service` 502, `not authorized`
  403, `service denied by policy` 403).

### Phase 03 — Listener/site/service mapping

- `[proxy.listener_backends]` maps local listener names to mesh service IDs.
  Validation rejects unknown listeners, overrides on sites that are not
  members of that listener, empty service IDs, and overrides on non-mesh site
  backends.
- The router resolves the override per listener table without mutating the
  shared `SiteConfig`. Precedence: location backend → listener override →
  site backend. `default_site` uses each listener's override.
- `ListenerId` never enters the mesh request; only the resolved service ID is
  forwarded.
- `GET /sites` exposes `mesh_service_id` and `mesh_listener_backends` so
  inventory does not report one listener's service as another's backend.

### Phase 04 — Body and media policy

- `local_upstreams.<id>.body_policy` adds `max_request_body_bytes`,
  `max_response_body_bytes`, `streaming`, `allow_chunked`,
  `allow_transforms`. Unset caps inherit the connection caps (64 KiB
  defaults).
- Request path: fixed-length bodies stream to the backend incrementally;
  chunked bodies are forwarded with framing preserved when enabled (else
  `501`); buffered mode remains for compatibility. A declared body over the
  service cap returns `413` before the backend connect.
- Response path: fixed-length, chunked, and close-delimited bodies stream to
  the QUIC stream incrementally with cap enforcement. Only fixed-length
  responses within `min(service cap, 1 MiB)` are buffered for transforms;
  larger/chunked bodies bypass transforms with
  `synvoid.mesh.proxy.transforms_bypassed_streaming` and a log.
- Copy buffers are 16 KiB per stream, so origin memory does not scale with
  body size.
- The buffered mesh dispatch now strips the client's `Transfer-Encoding` and
  sets `Content-Length` to the buffered body length, so a chunked client
  request is sent to the origin with correct fixed-length framing instead of
  arriving bodyless.

## Verification evidence

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy -p synvoid-mesh -p synvoid-config -p synvoid-http -p synvoid-proxy --profile ci --all-targets --features synvoid-proxy/mesh,synvoid-http/mesh -- -D warnings` | pass |
| `cargo clippy -p synvoid --profile ci --all-targets -- -D warnings` | pass |
| `cargo test -p synvoid-mesh --test mesh_service_target --profile ci` | 8 pass |
| `cargo test -p synvoid-mesh --test mesh_body_streaming --profile ci` | 6 pass |
| `cargo test -p synvoid-mesh --test mesh_forwarding_guard --profile ci` | 7 pass |
| `cargo test -p synvoid-proxy --features mesh --test mesh_listener_backends --profile ci` | 5 pass |
| `cargo test -p synvoid-proxy --test listener_routing --profile ci` | 5 pass |
| `cargo test -p synvoid-config --test mesh_service_validation --profile ci` | 9 pass |
| `cargo test --test boundary_composition_guard --test mesh_id_boundary_guard --profile ci --features mesh` | 55 + 5 pass |
| `cargo test -p synvoid-mesh --test mesh_http_framing --profile ci` | 77 pass |
| `cargo test --test mesh_startup_rollback --profile ci --features mesh` | 114 pass |
| `cargo deny check` | advisories / bans / licenses / sources ok |
| `cargo xtask verify` | **10/10 steps pass** (fmt, workspace clippy, dependency-policy, core-compile, repo-guards, security-regression, root-guards, core-admin-tests, admin-contract, failure-injection) |

The static guard suite pins: direct proxy dispatch (no pool), preface emission,
`_target_url` not ignored, origin authorization (not `Host`/`get_upstream_info`),
route disclosure authorization on both paths, per-service caps/streaming calls,
and shared service-ID rules between config and the wire contract.

## Verification gate adjustment

`cargo deny check` initially failed on a **pre-existing** advisory, not on this
campaign: RUSTSEC-2026-0538 in `quinn-udp 0.5.14` (receive-loop spin after a
truncated datagram; affected platforms are Apple without `fast-apple-datapath`,
the BSDs, Solaris/illumos). `Cargo.lock` was updated to `quinn-udp 0.5.16`,
which is the advisory's patch release; the resolver also unified `socket2` to
0.5.10 and adjusted `windows-sys` edges for quinn/hyper-util and related
crates. No Rust source change was needed for the bump, and all verify steps
pass with the updated lockfile.

## Known limitations and unqualified areas

- **Multi-node runtime qualification is not complete.** The local prodtest
  configuration has no `[tunnel.mesh]` section, so no edge→origin QUIC
  topology was exercised. The two-node service/listener matrix, unauthorized
  peer behavior over a real session, and failover remain to be proven on a
  live topology.
- **Edge buffering ceilings.** The edge still buffers the mesh request body
  for provider retry (8 MiB) and the mesh response body (50 MiB). Origin-side
  streaming bounds origin memory but does not remove those ceilings, so service
  caps above 8 MiB request / 50 MiB response are accepted but not reachable
  through an edge.
- **Blog media.** The 4 MiB upload chunk is below the request ceiling and fits
  the documented policy, but no blog-through-mesh end-to-end run was performed.
  The 666 MB video is explicitly unsupported through mesh and stays
  direct-to-origin.
- **WebSocket/CONNECT** remain rejected with `503`.
- **HTTP/3 client ingress** does not dispatch `BackendType::Mesh`; it has its
  own pipeline with no mesh backend capability. Mesh-backed sites must be
  served on H1/H2 listeners until the H3 lane is extended.
- **Multi-worker mesh** remains unsupported; the egress handle is worker-local.
- **Legacy peers** keep the `http://<Host>` compatibility key until they send a
  preface. The compatibility form is documented as migration-only because the
  client `Host` then chooses the configured service. Only the old-edge →
  new-origin direction is compatible: a new edge always sends the preface, so a
  mixed-version mesh must upgrade origins before edges (or run one release
  everywhere) for mesh HTTP forwarding.
- `cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz`
  was not run in this pass; the focused suites plus the full `cargo xtask
  verify` contract are the evidence recorded here.

## Remaining work to close Phase 05

1. Two-node edge/origin topology on ephemeral ports with two
   `local_upstreams` services and two listeners; prove per-listener service
   selection, `Host`/path preservation, and no cross-listener leakage.
2. End-to-end unauthorized-peer denial for both route query and forwarded
   request.
3. Blog 4 MiB chunk upload through mesh with a raised service cap (≤ 8 MiB),
   recorded as supported or explicitly excluded.
4. `cargo nextest run --workspace --cargo-profile ci --profile ci --exclude synvoid-fuzz`
   (the full-suite closeout run; `cargo xtask verify` already passes).
