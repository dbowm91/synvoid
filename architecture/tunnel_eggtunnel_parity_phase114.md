# Phase 114: Tunnel / Eggtunnel Protocol Parity and Convergence Refresh

Status: **CLOSED QUALIFIED** (2026-10-02; evidence/architecture only; no production migration).

Plan: `plans/phase_114_tunnel_eggtunnel_protocol_parity_and_convergence_refresh.md`.

Supersedes: only the *evidence limitation* in
`architecture/tunnel_convergence_phase111.md` (Eggtunnel source was
unavailable to Phase 111). Phase 111 remains historically truthful; it is
not rewritten as though Eggtunnel had been available.

## Baselines compared

- SynVoid planning baseline: `main` at
  `4d957b2e90c29c018430bdac8af830b9db91b19a` (2026-10-02). Evidence below
  is read from that tree (`crates/synvoid-tunnel`, `crates/synvoid-vpn-client`,
  `crates/synvoid-mesh` consumers, root dispatch shims).
- Eggtunnel research baseline: `eggstack/eggtunnel` `main` at
  `ece46fd223265b7b0609e3640b0caa9efadd1535` (2026-10-01), verified as
  remote `HEAD` via `git ls-remote` during this phase and cloned to a
  scratch directory (not vendored into SynVoid). All Eggtunnel citations
  below refer to that commit.

## Critical release/version distinction (verified)

Eggtunnel's workspace/crate version remains `0.2.0`, but the wire behavior
differs between artifact and source:

- Published `eggtunnel-proto 0.2.0` / `eggtunnel 0.2.0` (crates.io,
  2026-09-24; `CHANGELOG.md` "Wire protocol compatibility remains version
  1.0") implement wire **1.0**: baseline serial registration, generic
  `Error`, local-only drain timing.
- Current repository source at the same workspace version implements wire
  **1.1** (`crates/eggtunnel-proto/src/lib.rs:21-22`
  `PROTOCOL_MAJOR = 1`, `PROTOCOL_MINOR = 1`; `docs/PROTOCOL.md:1-15`):
  capability negotiation (IDs 1–2), correlated `RegisterReject`
  (message 15), drain deadline. A 1.1 peer interoperates with a 1.0 peer
  at exact 1.0 baseline semantics (`docs/PROTOCOL.md:76-80`,
  `docs/SUPPORT.md:3-15`).

Consequence: SynVoid must never pin `eggtunnel = "0.2.0"` and assume wire
1.1 capabilities. Any future adoption of capability 1 or 2 behavior is
blocked until an Eggtunnel release containing wire 1.1 is published, or is
preceded by an Eggtunnel release plan. Long-lived git dependencies are not
an acceptable terminal state (see Release-consumability gate below).

Eggress dependency line in the reviewed source: `eggress-core`,
`eggress-relay`, `eggress-transport-tls` at `=1.0.8`;
`eggress-transport-quic`, `eggress-protocol-websocket`, `eggress-outbound`
at `=1.0.8` with feature gates (`Cargo.toml` workspace dependencies).
Eggtunnel MSRV is `1.89` (workspace `rust-version`). Supported binary
targets are `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`; Windows, musl, armv7,
Raspberry Pi / Le Potato variants are unsupported/unevaluated
(`docs/SUPPORT.md:54-68`). SynVoid pins no `rust-version` in the root
manifest; this phase ran under toolchain 1.98.1. No MSRV conflict is
claimed as a blocker; the release gate below blocks on wire version, not
MSRV.

## Wire compatibility decision (Workstream B)

The two protocols are **distinct protocols**: not byte-compatible and not
semantically interchangeable.

### SynVoid wire (reviewed source)

- Framing: 4-byte big-endian length prefix + one postcard payload; no
  magic, no version field
  (`crates/synvoid-tunnel/src/quic/messages.rs:144-163`
  `encode_with_length`/`decode_with_length`;
  `crates/synvoid-tunnel/src/quic/framing.rs:37-60`
  `read_with_max`, `:62-83` write path; `DEFAULT_MAX_MESSAGE_SIZE = 1 MiB`
  at `framing.rs:8`; validation bounds `MAX_AUTH_TOKEN_LEN = 1024`,
  `MAX_IDENTIFIER_LEN = 256` at `validation.rs:4-10`).
- Vocabulary (~25 variants, `quic/messages.rs:7-106`): `Hello{client_id,
  auth_token, mappings, supports_datagrams}`, `HelloAck{server_session_id,
  server_mappings, supports_datagrams, max_datagram_size, access_level}`,
  `PeerHello`/`PeerHelloAck` (peer mesh-facing pair), `AuthFailure`,
  `KeepAlive`/`KeepAliveAck`, `PortOpen`/`PortClose`/`PortData`,
  `RequestProxy`/`ProxyResponse`, `StreamOpen{identifier, port, protocol,
  tls_passthrough}`/`StreamOpenAck`/`StreamClose`,
  `DataChunk{identifier, sequence: u64, data, fin}`/`DataAck`,
  `UdpTunnelOpen`/`UdpTunnelOpenAck`/`UdpTunnelClose`/`UdpData`/`UdpClose`,
  `Error{code, message}`, plus `DatagramMessage{identifier, sequence, data,
  port, source_addr, return_addr?, fragment_info?, hop_count}`
  (`messages.rs:215-224`) with `FragmentInfo` (`:227-232`) and
  `MAX_DATAGRAM_PAYLOAD = 1200` (`:4`). Zero-copy `DataChunk` fast path
  uses a `msg_type = 100` marker (`:165-212`). There is no `Drain`,
  `Ping`/`Pong`, `Register`/`Unregister`, `SessionId`/`ServiceId`/
  generation, `DataHello`, replay/nonce, or version field anywhere in the
  variant list.
- Serialization is postcard throughout (`serialization.rs:1-24`; the
  `serialize_bincode` names are postcard aliases, not bincode).

### Eggtunnel wire (reviewed source)

- Framing: ASCII magic `ETUN` + major (u16 BE) + minor (u16 BE) + message
  ID (u16 BE) + payload length (u32 BE) = 14-byte fixed header, then one
  postcard payload (`crates/eggtunnel-proto/src/lib.rs:565-579`
  `encode_frame`, `:583-635` `decode_frame`; `docs/PROTOCOL.md:17-34`).
  Payload cap 1 MiB checked before copy/deserialize (`:597-599`);
  major-version mismatch rejected (`:592-594`); unknown IDs and malformed
  payloads are typed errors.
- Bounds: auth token 4096 bytes, service name 128 bytes, diagnostic 256
  bytes, capability list 32 entries, target host 253 bytes
  (`lib.rs:13-20`; `docs/PROTOCOL.md:34`).
- Stable message IDs 1–15 (`lib.rs:314-332`; pinned by test
  `documented_wire_version_and_message_ids_are_pinned`): 1 ClientHello,
  2 ServerHello, 3 Auth, 4 AuthOk, 5 RegisterService, 6 RegisterAck,
  7 UnregisterService, 8 Open, 9 OpenReject, 10 Ping, 11 Pong, 12 Drain,
  13 Error, 14 DataHello, 15 RegisterReject (extension-only, capability 1).
- Session establishment order: `ClientHello`/`ServerHello` (capability
  advertisement + intersection) → `Auth` (zeroized on drop, redacted
  debug, `lib.rs:368-410`) → `AuthOk{session_id}` (`:411-414`) →
  `RegisterService{service_id, name, requested_bind, target}` /
  `RegisterAck{service_id, effective_bind}` or correlated
  `RegisterReject{service_id, code, diagnostic}` (`:415-468`) →
  `Open{service_id, connection_id}` / `OpenReject` → `DataHello{
  session_id, service_id, connection_id}` (`:469-474`), after which data
  streams carry opaque application bytes (`docs/PROTOCOL.md:43-46`).
  Registration stays valid throughout the Session
  (`docs/PROTOCOL.md:48-54`); Ping/Pong correlate by nonce.
- Capability negotiation 1.1 (`docs/PROTOCOL.md:56-80`): client advertises,
  server returns intersection; unknown IDs ignored; emission sorted +
  deduped (`lib.rs:230-272`). ID 1 = correlated registration rejection
  (multiple in-flight registrations, bounded, generation-scoped; without
  it the serial one-in-flight fallback applies). ID 2 = drain deadline
  (`Drain.deadline_ms` is relative grace, effective wait is
  `min(peer, local shutdown ceiling)`; without it local-only timing).
  Mixed 1.1↔1.0 pairs use exact 1.0 baseline.

### Field-by-field verdict

| Aspect | Verdict |
| --- | --- |
| Header/magic/version | Incompatible: SynVoid has no magic/version; ETUN requires `ETUN` + major 1 and rejects other majors. |
| Message IDs | Incompatible: disjoint numeric spaces and semantics (SynVoid `msg_type = 100` zero-copy marker vs ETUN 1–15 registry; no shared ID table). |
| Serialization | Same library (postcard), different framing and DTOs: not a compatibility argument. |
| Auth ordering | Different: SynVoid app `Hello`/`PeerHello` carrying token + mappings in one step vs ETUN hello/version/capability exchange then `Auth` then `AuthOk{session_id}`. |
| Session establishment | Different: SynVoid uuid session id + registry insert + `HelloAck` with access level vs ETUN `SessionId` capability + generation-scoped session with `AuthOk`. |
| Registration lifecycle | Different: SynVoid port mappings/registry/router vs ETUN `ServiceId`-keyed dynamic register/unregister with correlated reject and effective-bind assignment. |
| Data-stream opening | Different: SynVoid `StreamOpen`/`StreamOpenAck` + `DataChunk{seq, fin}` / `UdpTunnel*` vs ETUN `Open`/`OpenReject` + `DataHello{session, service, connection}` then opaque bytes. |
| Error semantics | Different: SynVoid `Error{code, message}` + `AuthFailure{reason}` + ack-false patterns vs ETUN typed `Error{code, diagnostic}` + `OpenReject{code}` + capability-gated `RegisterReject{service_id, code, diagnostic}` with a shared registration-category code vocabulary. |
| Reconnect generation | Different: SynVoid retry/backoff + health-monitor predicates (no generation counter on the wire) vs ETUN per-session generation counter (`Counters::begin_session`, `common.rs:425-443`) scoping registration/heartbeat, with exhaustion failing closed. |
| Heartbeat | Different mechanism, similar purpose: SynVoid per-stream `KeepAlive`/`KeepAliveAck` + `QuicHealthMonitor` quality/RTT/loss vs ETUN nonce-correlated `Ping`/`Pong` + `HeartbeatSnapshot{session_generation, last_pong_age_ms, latest_rtt_ms, missed_heartbeats}` (`common.rs:179-187`). |
| Drain | Different: SynVoid runtime cancellation/close codes vs ETUN negotiated `Drain.deadline_ms` with `min(peer, local ceiling)` (`client.rs:1096-1101`, `server/control.rs:261-267`; ceilings are `shutdown_grace` for open-task/control-loop joins and `relay_drain` for in-flight relay bytes). |
| Datagram capability | SynVoid has explicit negotiated datagrams (1200 B, fragmentation, UDP manager); ETUN has no generic service-datagram contract (see Datagram gap). |
| Size bounds | Same order (1 MiB control payload both sides) but different bound sets otherwise (SynVoid 1024 B token / 256 B identifier vs ETUN 4096 B token / 128 B service name / 256 B diagnostic / 32 caps / 253 B host). Not interchangeable. |
| Replay/stale-session handling | Different: SynVoid has no wire generation/nonce enforcement (`server.rs:29` `DEFAULT_AUTH_WINDOW_SECS` is a dead constant) vs ETUN generation-scoped correlation + `ConnectionId::constant_time_eq` (`lib.rs:79-87`) + transport-specific wrong-session/stale-session/replay qualification (`docs/SUPPORT.md:22`). |

Expected default confirmed: **distinct protocols**. "Eggtunnel has QUIC"
is transport equivalence, not protocol parity (QUIC changes the Session
transport; registered external services remain TCP streams,
`docs/SUPPORT.md:26-28`).

Allowed strategies if adoption ever becomes useful (none authorized by
this phase):

1. **Mechanism reuse below the wire** — reuse Eggress relay/transport
   while retaining the SynVoid wire.
2. **Parallel Eggtunnel mode** — expose Eggtunnel as a separately
   negotiated tunnel profile.
3. **Versioned migration** — only with explicit mixed-version
   compatibility and a separate implementation plan.

A silent protocol replacement is prohibited. No spike was run and no
migration lands under this evidence phase.

## Capability and symbol matrix (Workstream A)

Every row cites concrete source from both repos. Dispositions use the
plan vocabulary: ADOPT (released reusable capability), ADAPT (reuse the
pattern, not the code), UPSTREAM (generic capability belongs upstream but
is missing), RETAIN (SynVoid semantics stay local), DEFER (evidence gaps
remain).

| Capability | SynVoid evidence | Eggtunnel/Eggress evidence | Decision |
| --- | --- | --- | --- |
| Wire framing/versioning | 4 B BE len + postcard, no magic/version; `messages.rs:144-163`; `framing.rs:37-83`; bounds `validation.rs:4-10` | `ETUN` 14 B header, major/minor, 15 typed IDs, 1 MiB bound; `eggtunnel-proto/src/lib.rs:13-22,314-332,565-635`; `docs/PROTOCOL.md:17-42` | **RETAIN**; never reinterpret. Distinct protocols per table above. |
| Authentication | `Hello`/`PeerHello` app tokens + `access_level` (Admin/General + TCP/UDP port allowlists); constant-time `secure_token_compare` (`validation.rs:12-17`); per-client/global/whitelist/allow-unauthenticated-confirmed ladder + peer-token check (`server.rs:1327-1415`); auth rate limiter (`server.rs:31-63`); `VpnAccessLevel::{General, Admin}` + `QuicVpnAccessConfig` defaults (`synvoid-config`, see baseline) | `Auth`/`AuthOk{session_id}`; `SecretToken` 1..=4096 B, redacted, zeroized (`common.rs:19-53`); fixed-width constant-time `verify_token` incl. length (`common.rs:519-540`); server rejects bad token before session creation (`docs/SECURITY.md:5`); `Auth` zeroizes on drop (`lib.rs:387-392`) | **RETAIN**; map only. Identity models differ (SynVoid port-scoped access levels + mesh/VPN policy vs ETUN session capability + `BindPolicy`). No credential-format migration. |
| Service registration | Port mappings in `Hello`, `QUIC_TUNNEL_REGISTRY` (`registry.rs:11-112`), `TunnelRouter::resolve_tunnel_backend` (`router.rs:149-169`), `TunnelManager` sessions (`lib.rs:92-175`) | `RegisterService`/`RegisterAck{effective_bind}`/`UnregisterService` valid throughout Session; correlated `RegisterReject` under cap 1; `ServiceId`-keyed, generation-scoped (`docs/PROTOCOL.md:48-54`; `client/service_state.rs`; `server/service.rs`, `server/control.rs`) | **RETAIN**. Service models differ (SynVoid port-mapping + route/mesh adapter vs ETUN name + requested/effective bind + `BindPolicy` admission). Correlated-reject concurrency is at most a future **ADAPT** pattern study, not code adoption. |
| Connection correlation | `identifier` + `sequence: u64` + `DataChunk{fin}` / `UdpData`; zero-copy `msg_type = 100` (`messages.rs:62-71,99-105,165-212`); UDP-manager pending/DNS tracking (`udp_manager.rs:213-242,281-349`) | `SessionId`/`ServiceId`/`ConnectionId` triple + `DataHello`; `ConnectionId::constant_time_eq` (`lib.rs:48-93,469-474`); generation-scoped, redacted debug | **RETAIN**; compare only. No ID-format migration. |
| Reconnect | `manage_peer_connection`: max 10 retries, `1s/60s/2.0` backoff, reset on success, session/conn insert + health register (`client.rs:143-238`); `JitteredBackoff` ±30% (`validation.rs:191-242`); VPN `run_with_auto_reconnect` (`vpn-client/lib.rs:481-568`) | `ReconnectSupervisor` shared by all transports: attempt accounting, disconnected-command drain, bounded jittered backoff reset on ready Session, terminal auth handling, per-generation counter/bind cleanup (`client/reconnect.rs:1-120`); private `Transport` trait, not a plug-in surface (`:43-52`) | **RETAIN**. No reusable seam: the supervisor is `pub(super)` and transport adapters own only establishment/closure. Delegation would import ETUN service policy wholesale. |
| Heartbeat | Per-stream `KeepAlive`/`KeepAliveAck` (`client.rs:490-522`, `server.rs:636-641`); `QuicHealthMonitor` quality/RTT/loss/failure-threshold/recovery (`health.rs:13-211,229-449`); `should_reconnect` is a predicate only (`:60-62`) | Nonce-correlated `Ping`/`Pong` + bounded `HeartbeatSnapshot` per current Session, reset per generation (`common.rs:179-194,425-461`; `client/heartbeat.rs`, `client.rs:762-988`) | **RETAIN**; map liveness semantics only. Different layering, no shared timer contract. |
| Drain/shutdown | `shutdown_tx` cancellation, close codes `0/"…"` (`client.rs:180-196,627-634`; `server.rs:1448-1459`; `runtime.rs:485-507` `stop_server` + `endpoint.close`, pinned by `tests/mesh_startup_rollback.rs:553`) | Negotiated `Drain.deadline_ms` as `min(peer, local ceiling)`; ceilings are `shutdown_grace` (open-task/control-loop joins) and `relay_drain` (in-flight bytes via `eggress-relay`) (`docs/PROTOCOL.md:68-74`; `client.rs:1096-1101`; `server/control.rs:261-267`) | **RETAIN**. The `min(peer, local)` ceiling is a good pattern for future SynVoid drain work (**ADAPT** study only); no behavior change now. A peer can never extend the other's shutdown (`docs/PROTOCOL.md:71-74`). |
| QUIC runtime | `QuicRuntime` (Quinn 0.11): endpoint mgmt, `high_throughput_mode`/BBR note, idle 300 s, keepalive 25 s, streams 100, 1 MiB buffers (`runtime.rs:26-175,177-309`); consumed by `synvoid-mesh` (`mesh/transport.rs:74,117,1709-1745,4032-4112,4734-4771`: `QuicRuntime`, `IncomingConnection`, `connect_to_peer`) | Eggress QUIC via Eggtunnel: one UDP QUIC connection per Session, one control stream + one bidi stream per external TCP connection; services remain TCP (`docs/SUPPORT.md:21-22,26-28`); QUIC profile rejects custom CA/mTLS (`:27-30`); transport-specific wrong-session/stale-session/replay/saturation/half-close qualified (`:22`) | **RETAIN**; never swap the mesh-consumed runtime. Eggtunnel's QUIC layer is inseparable from ETUN session semantics (private transport adapters + generation/registration coupling). Eggress QUIC is proxy/H3 transport, not a generic authenticated-tunnel runtime. |
| Stream relay | `proxy_bidirectional` quic↔tcp with len gates + zero-copy `DataChunk` fast path (`server.rs:1192-1325`); `proxy_tcp_through_peer_with_tls` 64 KiB cap (`client.rs:695-812`); UDP-manager stream fallback (`udp_manager.rs:351-384`); root dispatch shims (`src/http_client/quic_tunnel_dispatch.rs`, `src/tcp/listener.rs`, `src/udp/listener.rs`) | `eggress-relay` `relay_with_options(external, data, RelayOptions::bounded(16 KiB, relay_drain))` on both client and server relay paths (`client.rs:4`, `server/service.rs:5,124`) | **DEFER**. Strongest low-risk reuse candidate, but semantic parity is unproven for SynVoid's zero-copy `DataChunk{seq, fin}` framing, UDP-fallback, access-level checks, and metrics/accounting hooks. Adoption requires parity tests + exact LOC/dependency/accounting evidence first (Workstream D). No maintenance reduction is claimed now. |
| TLS / mTLS | rustls 0.23 / Quinn; `QuicTlsConfig` maps SynVoid tunnel config (cert/key/CA, `require_client_cert`, `verify_server` hard-require, autogen certs with 0600 keys, `generate_client_cert` always `Err`) (`tls.rs:16-304`); app-token auth assumed above TLS | TCP/TLS: system roots or custom CA, SNI verified; mTLS supported with `mtls` feature + provisioned client CA (`docs/SUPPORT.md:21`; `docs/SECURITY.md:52-53`); QUIC: platform roots, SNI verified, no custom CA, no mTLS (`docs/SUPPORT.md:22`; `docs/SECURITY.md:65-67`); WSS: no mTLS (`:23`); outbound proxy + mTLS unsupported (`:24`) | **RETAIN**. Trust models differ (SynVoid custom-CA + hard `verify_server` + mesh peer policy vs ETUN profile-gated mTLS). No PQ requirement exists in either reviewed scope. Compare trust/custom-CA needs only. |
| Proxy traversal | SynVoid route/proxy integrations (`router.rs`, `upstream.rs`, proxy `QuicTunnel` upstream) | Eggress outbound connector: single-hop HTTP CONNECT/SOCKS5 locally qualified (incl. auth success/failure), multi-hop via `__`-separated pproxy URIs (one two-hop test), env-var creds (redacted), proxy+QUIC and proxy+mTLS rejected (`docs/SUPPORT.md:24,29-35`; `docs/SECURITY.md:98`) | **DEFER** (potential future integration, not tunnel parity). No tunnel-specific parity proof; any use needs its own scoped plan. |
| UDP/datagram | Explicit negotiated datagrams: `supports_datagrams`/`max_datagram_size` in `Hello`/`HelloAck`/`PeerHelloAck`; `DatagramMessage` + fragmentation (`messages.rs:215-314`); `UdpTunnelManager` (timeout 60 s, 1200 B, 128 B overhead, DNS tracking, pending maps, idle cleanup) (`udp_manager.rs:15-446`); server `handle_udp_tunnel` (10000 mappings / 1000 DNS IDs / 100 pending / 300 s TTL, backpressure, expiry sweeps) (`server.rs:885-1190`); `MAX_DATAGRAM_SIZE = 1200` in runtime/client | No generic service-datagram contract in reviewed source: `grep -ril datagram` over `crates/eggtunnel/src` returns nothing; services are TCP even when the Session transport is QUIC (`docs/SUPPORT.md:26-28`); Eggress outbound UDP association is proxy semantics, not negotiated authenticated tunnel datagrams (Phase 111 evidence, unchanged) | **RETAIN**; never model as TCP half-close. See Datagram gap: no upstream plan (product-specific, not generic). |
| VPN/TUN/WireGuard | `tun.rs` stub (`is_tun_available = false`) + `wireguard/` kernel/userspace selection, `WgImplementation::Auto`, session/stats registries, `TunnelTransport` impl; `VpnClient` QUIC-vs-WireGuard switch + `LocalListener` TCP/UDP port mappings (`vpn-client/*`, tunnel `lib.rs:22-27,38-82`) | No equivalent reviewed contract (no TUN/WireGuard surfaces in `crates/eggtunnel*`, `docs/*`) | **RETAIN** unless proven generic. SynVoid-specific product behavior. |
| Mesh QUIC consumption | Active internal consumer: `synvoid-mesh` holds `Option<Arc<QuicRuntime>>`, accepts `IncomingConnection`, dials via `runtime.connect_to_peer` with TOFU cert check (`mesh/transport.rs` sites above); mesh also has its own `QuicMeshTransport` wrapper distinct from tunnel QUIC | Eggtunnel has no mesh policy; `TargetConnector` resolves client-owned services to app streams (`client/config.rs:27-49`), not mesh peers | **RETAIN**; preserve the SynVoid adapter. Never push mesh identity/session behavior into Eggtunnel. |
| Observability | SynVoid tunnel/mesh metrics (session gauges, health events, byte/packet counters, `VpnStatsTracker`) | `Snapshot` (connected/sessions/services/pending/active/handshakes, high-waters, task panics, `last_termination`, `heartbeat`, `resource_limits`, reconnects/rejected/bytes, effective binds) + `TerminationCategory{12}` + `HeartbeatSnapshot` (`common.rs:153-211`); secrets redacted; proxy creds redacted from diagnostics/`Snapshot` (`docs/SUPPORT.md:34-35`) | **RETAIN** both; map only. Keep SynVoid labels/policy at any future adapter; do not leak policy upstream. |

## Runtime/lifecycle parity (Workstream C)

Ownership and cancellation compared directly:

- Caller-owned runtime: both. Eggtunnel uses the caller's Tokio runtime
  and installs no global runtime/tracing state (`src/lib.rs:1-6`;
  `docs/API.md:61`; `docs/EMBEDDING.md:37`). SynVoid's `QuicRuntime` is
  likewise caller-constructed (`QuicRuntime::new` + `with_*` builders,
  `runtime.rs:62-131`) and shut down via handles/tokens. No gap.
- Connection task ownership: Eggtunnel server splits
  accept/auth/session/control/pending/service (`server/accept.rs`,
  `auth.rs`, `session.rs`, `control.rs`, `pending.rs`, `service.rs`);
  the control loop holds the only strong `SessionContext` reference and
  `SessionGuard` cleans exactly once on any exit (`session.rs:37-138`).
  SynVoid splits accept/auth/`session_loop`/`handle_stream`/UDP-tunnel
  loops with `active_streams` accounting and registry + gauge cleanup on
  every exit (`server.rs:555-622,624-883`). Equivalent discipline,
  different types. No delegation without importing policy.
- Reconnect supervision/backoff: SynVoid 10-attempt / 1 s→60 s ×2.0 +
  ±30% jitter (`client.rs:143-238`; `validation.rs:191-242`) vs Eggtunnel
  bounded jittered backoff reset on ready Session + disconnected-command
  drain + terminal-auth handling (`client/reconnect.rs:1-120`). Both
  bounded; parameters and reset conditions differ.
- Registration state across reconnect: SynVoid re-registers mappings per
  new session (`connect_as_client`, `manage_peer_connection`); Eggtunnel
  `ServiceState` persists only after matching ack and replays across
  generations (`client/service_state.rs`; `CHANGELOG.md` dynamic
  registration notes). Different ack-correlation guarantees (serial 1.0
  fallback vs cap-1 correlated).
- Stale session/generation rejection: SynVoid has no wire generation
  enforcement; Eggtunnel generations scope registration/heartbeat and
  `begin_session` exhaustion fails closed (`common.rs:425-443`), with
  transport-specific wrong-session/stale-session/replay qualification
  (`docs/SUPPORT.md:22`).
- Server session registry: Eggtunnel weak-reference bounded map with
  dead-entry pruning + `SessionGuard` removal on every path
  (`session.rs:26-138`); SynVoid `DashMap` sessions + `QUIC_TUNNEL_REGISTRY`
  + gauge add/remove (`server.rs:374-420,572-574`; `runtime.rs:525-588`).
  Both bounded; different lifetime mechanics.
- Pending connection bounds: Eggtunnel `pending_per_session` /
  `accepted_handshakes` / `client_open_tasks` / queue ceilings
  (`common.rs:213-262`) + `PendingEntry` map (`server/pending.rs`) vs
  SynVoid semaphore `max_connections` (`server.rs:127-161,238-245`),
  `MAX_STREAM_POOL_SIZE = 8` (`client.rs:22`), UDP-manager 100-pending /
  10000-mapping ceilings (`server.rs:905-908`). Both bounded;
  numbers/policies differ.
- Shutdown cancellation: Eggtunnel `CancellationToken` per session +
  `min(peer, local ceiling)` drain (`client.rs:1096-1101`);
  SynVoid `shutdown_tx` + close codes + `stop_server` close. Different
  drain guarantees; Eggtunnel's ceiling pattern is the only ADAPT-study
  item, not an adoption.
- Half-close/backpressure: Eggtunnel relay is bounded (16 KiB +
  `relay_drain`) with typed termination categories; WebSocket relay is
  explicitly not TCP half-close equivalent (`docs/SUPPORT.md:39-45`).
  SynVoid uses `DataChunk{fin}` + zero-copy paths + UDP-manager
  `try_acquire` backpressure (`server.rs:977-987`) + 64 KiB stream caps.
  Parity unproven — this is why relay reuse stays DEFER.
- Timeout/resource-limit behavior: Eggtunnel `TimeoutPolicy` (connect 10
  s, handshake 10 s, control-idle 90 s, pending 30 s, relay-drain 15 s,
  shutdown-grace 1 s, reconnect 0.5 s→30 s, heartbeat 20 s;
  `common.rs:264-319`) validated (nonzero, ≤24 h, `reconnect_initial ≤
  reconnect_max`, `heartbeat < control_idle`) vs SynVoid per-layer
  timeouts (auth 10 s, connect 10 s, handshake 5 s, idle 300 s, keepalive
  25 s, UDP 60 s/300 s, `high_throughput_mode` windows). Same order,
  different policy. No shared-policy argument.

Conclusion: SynVoid cannot delegate generic lifecycle without importing
Eggtunnel's service-level policy wholesale. The reconnect supervisor and
transport adapters are intentionally private (`reconnect.rs:43-52`).

## Transport and relay reuse (Workstream D)

### Eggress relay

`eggress-relay` (`=1.0.8`) is integrated on both Eggtunnel relay paths
via `relay_with_options` with `RelayOptions::bounded(16 KiB,
relay_drain)` (`client.rs:4`; `server/service.rs:5,124`). In-flight relay
bytes drain under `relay_drain` inside `eggress-relay`
(`docs/PROTOCOL.md:69`). SynVoid's forwarding (`proxy_bidirectional`,
`proxy_tcp_through_peer_with_tls`, UDP-manager stream fallback) adds
SynVoid-specific framing (`DataChunk{seq, fin}` zero-copy), access-level
checks, DNS/pending tracking, and metrics hooks that have no demonstrated
Eggress equivalent. Parity for bidirectional copy, half-close, bounded
buffers, cancellation, drain, error mapping, and accounting hooks is
therefore **unproven**. No adapter LOC, dependency, binary-size,
build-time, test-surface, or behavioral delta is claimed, because none was
measured — claiming maintenance reduction now would violate the plan's
rejection criteria. A future scoped plan must run the parity tests and the
Workstream G spike measurements before any adoption is registered.

### Eggtunnel QUIC transport

Not separable as a generic connection mechanism. The QUIC adapters
(`client.rs:39,68,365` `QuicTransport`; `server_tests/quic.rs`) run the
shared reconnect/session/registration/heartbeat/drain lifecycle; QUIC
changes the Session transport while services stay TCP. Because
`synvoid-mesh` consumes SynVoid QUIC runtime types (`QuicRuntime`,
`IncomingConnection`), replacing that runtime would entangle mesh
identity/session behavior with ETUN semantics. **Do not replace.**

## Authenticated datagram gap (Workstream E)

Eggtunnel current support describes TCP services even when the Session
transport is QUIC. No generic service-datagram contract exists in the
reviewed source. SynVoid's datagram mechanism (negotiated capabilities,
1200 B payload, fragmentation/reassembly, sequencing, UDP-manager
association/session handling, DNS tracking, idle expiry,
saturation/backpressure/drop accounting) is **VPN/product-specific**:
it serves the VPN client, UDP port mappings, local-listener UDP paths,
and tunnel route policy — not a generic reverse-tunnel primitive.

Disposition: **RETAIN locally; no upstream plan registered.** Writing an
Eggtunnel datagram plan (new capability ID, wire messages/IDs, max size,
association/identity, sequencing/replay, fragmentation, queue bounds,
idle timeout, wrong-session/stale-generation behavior,
saturation/backpressure/drop accounting, 1.0/1.1 fallback,
security/abuse tests) is not justified, because the mechanism has not
been shown to be generic. Do not implement datagrams in SynVoid as a
permanent fork of Eggtunnel, and do not add UDP as an unbounded or
implicit extension to ETUN.

## Release-consumability gate (Workstream F)

For every matrix row, current-source support vs released support:

- Exact Eggtunnel commit tested: `ece46fd223265b7b0609e3640b0caa9efadd1535`.
- Published crate containing the needed behavior: `eggtunnel 0.2.0` /
  `eggtunnel-proto 0.2.0` contain **wire 1.0 only**. Wire 1.1
  (capabilities 1–2, `RegisterReject`, drain deadline) is **unreleased**.
- Eggress dependency versions: `=1.0.8` line (see workspace
  dependencies above).
- MSRV: Eggtunnel `1.89`; no SynVoid-side MSRV conflict established.
- Target matrix: four supported targets (see above); Windows/musl/armv7/
  Pi-class unsupported — matches the no-new-native-claim rule.
- Feature flags: `client`, `server`, `tls` (default `client` + `tls`),
  `quic`/`quic-client`/`quic-server`/`quic-transport`,
  `websocket*`, `outbound-proxy`, `mtls`. Role-specific slices allow a
  QUIC/WebSocket client without server runtime code.
- Registry vs git: SynVoid can only consume a crates.io release. A
  git dependency is not an acceptable terminal state.

Since the matrix returns no ADOPT result (see below), the gate blocks
nothing today — but it constrains tomorrow: any future adoption of wire
1.1 behavior (correlated reject, drain deadline) must wait for (or be
preceded by) an Eggtunnel release plan. Adoption of 1.0-baseline behavior
would still need the Workstream D parity proof first.

## Proof-of-integration spike (Workstream G)

No spike was run. The matrix identifies no high-confidence adoption
candidate: relay reuse is DEFER pending parity tests, and every other
overlap is RETAIN. Per the plan, no spike is permitted without such a
candidate, and no spike artifacts exist to remove.

## Cross-repo planning outputs (Workstream H)

- **RETAIN** — SynVoid wire/session/registration/correlation/reconnect/
  heartbeat/drain/QUIC-runtime/TLS/datagram/VPN/mesh/observability
  semantics are materially different; no maintenance reduction is
  demonstrated. This is the terminal disposition for those rows.
- **DEFER** — `eggress-relay` reuse and Eggress outbound-connector
  integration remain version/release/evidence-gated. A future scoped
  SynVoid plan may register the parity tests + spike measurements; no
  such plan is registered by this phase.
- **ADOPT EXISTING** — none. No released Eggtunnel/Eggress capability
  meets the released + parity + maintenance-reduction bar.
- **UPSTREAM FIRST** — none. No generic missing Eggtunnel/Eggress
  capability was proven (datagrams are product-specific).
- **PARALLEL PROFILE** — none. Exposing Eggtunnel as an additional tunnel
  profile is not justified: it would add a permanent dual-protocol burden
  with no product requirement.

No numerical score and no vague "converge later" outcome. Tunnel remains
**DEFER** convergence overall (unchanged from Phase 111); the only thing
that changed is the evidence basis, from "Eggtunnel unavailable" to the
source-backed matrix above.

## Required evidence checklist

Eggtunnel (all inspected at `ece46fd`):

- `docs/PROTOCOL.md` — wire 1.1, 14 B header, IDs 1–15, caps 1–2, mixed-version rule.
- `docs/SUPPORT.md` — 1.0/1.1 matrix, four transport profiles, limitations, release targets.
- `docs/API.md`, `docs/EMBEDDING.md`, `docs/SECURITY.md`, `docs/DISTRIBUTION.md`, `CHANGELOG.md` (0.2.0 = wire 1.0).
- `crates/eggtunnel-proto/src/lib.rs` — bounds, IDs, `encode_frame`/`decode_frame`, pinned tests.
- `crates/eggtunnel/src/lib.rs` — `Client`/`ClientBuilder`/`ClientHandle`/`ClientConfig`, `Server`/`ServerBuilder`/`ServerHandle`/`ServerConfig`, `TargetConnector`, `ResourceLimits`/`RuntimePolicy`/`TimeoutPolicy`, caller-owned runtime, `#![forbid(unsafe_code)]`.
- Client: `client.rs` (session/heartbeat/registration/drain handling, `eggress-relay` use), `client/config.rs` (`TargetConnector`, `ClientBuilder`), `client/reconnect.rs` (`ReconnectSupervisor`, private `Transport`), `client/service_state.rs`, `client/heartbeat.rs`, `client/open.rs`.
- Server: `server/accept.rs`, `auth.rs`, `control.rs`, `pending.rs`, `service.rs` (relay use), `session.rs` (registry/guard/generation), `server/config.rs` (`ServerBuilder`, profile validation).
- Transports/relay: QUIC/WebSocket/TCP server tests (`server_tests/{tcp,quic,websocket}.rs`), outbound-proxy qualification, `eggress-relay` integration both directions.
- Cargo features/versions: workspace `0.2.0`, `rust-version 1.89`, Eggress `=1.0.8`, feature matrix above.

SynVoid (planning-baseline tree):

- `crates/synvoid-tunnel/src/quic/{mod,messages,framing,validation,client,server,runtime,registry,health,tls,ipc}.rs` (see matrix + baseline inventory).
- `crates/synvoid-tunnel/src/{lib,udp_manager,upstream,router,tun,quic_adapter,serialization}.rs` + `wireguard/`.
- `crates/synvoid-vpn-client/src/{lib,config,local_listener,events,stats}.rs`.
- Mesh consumers: `crates/synvoid-mesh/src/mesh/transport.rs` (`QuicRuntime`, `IncomingConnection`, `connect_to_peer`), `transports/{mod,quic,stack,manager,backend}.rs`; declared dep `synvoid-mesh/Cargo.toml:29`.
- Root dispatch: `src/tunnel/mod.rs` (facade), `src/http_client/quic_tunnel_dispatch.rs`, `src/tcp/listener.rs`, `src/udp/listener.rs`, `src/tls/server.rs`, `src/proxy/mod.rs`.
- Tests/docs: in-crate unit pins (`messages`, `validation`, `ipc`, `tun`, `wireguard/*`); root guards (`mesh_startup_rollback`, `config_capability_preflight_guard`, `admin_route_contract`, `facade_disposition_guard`, `OWNERSHIP.toml`); `docs/TUNNELS.md`; Phase 111 evidence doc (superseded only for its source-availability limitation).

## Verification (this phase)

Research/architecture phase; no production code changed.

SynVoid focused baselines (with `PKG_CONFIG_PATH=/usr/local/opt/xz/lib/pkgconfig` per the macOS XZ workaround):

- `cargo test -p synvoid-tunnel --profile ci` — 72 passed.
- `cargo test -p synvoid-vpn-client --profile ci` — 0 tests (crate ships no test suites; recorded truthfully, not as a pass claim for behavior).
- `cargo test -p synvoid-mesh --profile ci` — 1,093 passed.
- `cargo check -p synvoid-tunnel --all-features` — clean.
- `cargo deny check` — clean (advisories/bans/licenses/sources ok).
- `cargo audit` — no vulnerabilities; six allowed unmaintained warnings (unchanged campaign baseline).

Eggtunnel repository verification was reviewed from its docs/test record
(protocol round-trip/pinning/capability/adversarial tests in
`eggtunnel-proto`; lifecycle/churn/transport qualification per
`docs/SUPPORT.md` and `CHANGELOG.md`), not re-executed here; any future
adoption plan must record the exact upstream proof required before SynVoid
adoption. No cross-repo plan was registered, so no upstream proof gate is
opened by this phase.

`cargo fmt` / `cargo xtask verify` full runs are owned by the Phase 113
closeout on the same tree (10/10 passed); this phase adds one
documentation file plus plan-status text and runs the focused suites
above. Final `git diff --check` and `cargo fmt --all -- --check` are run
at closeout.

## Acceptance / rejection self-check

- Eggtunnel source compared directly (commit `ece46fd`), not inferred from Eggress. ✓
- Published 0.2.0 wire 1.0 distinguished from current-source wire 1.1. ✓
- SynVoid and ETUN wire/session differences explicit (field table). ✓
- Each overlap has ADOPT/ADAPT/UPSTREAM/RETAIN/DEFER ownership (matrix; ADAPT appears only as future pattern study, never as code reuse). ✓
- Datagram gap has a concrete disposition (RETAIN local, no upstream plan, reasons given). ✓
- Mesh/VPN-specific semantics stay out of Eggtunnel (explicit RETAIN rows). ✓
- Any proposed adoption identifies a released version or upstream release prerequisite (none proposed; gate constrains future work). ✓
- Any upstream work receives its own plan in the owning repo (none warranted; none registered). ✓
- No production migration lands under this evidence phase. ✓
- Does not repeat "Eggtunnel unavailable"; does not equate QUIC transport with protocol parity; does not treat unreleased 1.1 as published 0.2.0; no silent wire replacement; no mesh/VPN policy pushed upstream; no unbounded UDP extension; no git dependency; no unmeasured maintenance claim. ✓
