# Phase 02 Plan: TCP/UDP Service Wiring

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: none for implementation; Phase 01 for release.

## The finding

The TCP/UDP pools are constructed (`src/server/resources.rs::create_tcp_pool`,
`create_udp_pool`) and started (`src/server/listener_tasks.rs::spawn_aux_pools`),
but **no production caller adds a listener**. `TcpListenerPool::add_listener`
and `UdpListenerPool::add_listener` exist and are exercised only by their own
modules. Enabling `[tcp]`/`[udp]` therefore creates an empty pool that logs zero
listeners.

The surviving implementation also has defects that would surface immediately
after wiring:

- `TcpListenerPool::start` spawns one accept loop per listener and never reads
  `TcpListenerPoolConfig::worker_pool_size`.
- `connection_timeout_secs` is unused; proxied TCP has no idle timeout, so a
  slow client can hold a task and connection permit indefinitely.
- `TcpListenerConfig::strict_mode` and the protocol-specific filter action are
  not propagated; the pool builds `ProtocolFilter` from `Default::default()`.
- UDP forwards client datagrams to the upstream socket and never reads the
  upstream response. There is no `recv_from` on the upstream socket, so it
  cannot proxy request/response datagrams.
- `UdpListenerPoolConfig::worker_pool_size` and `max_packets_per_second` are
  unused; `workers_per_listener` is hard-coded to 1 in `resources.rs`.
- Global `[tcp.protocols]`/`[udp.protocols]` and per-site `[tcp.ports]`/
  `[udp.ports]` are two different schemas. The admin TCP/UDP handlers edit the
  site schema, which no runtime code consumes.

## Decision D1

Recommended: implement TCP first and UDP request/response second, keep both
**Beta** until the service tests and a soak pass. If raw UDP is not a product
requirement, stop after the TCP work, remove the UDP docs/config, and mark UDP
unsupported rather than shipping a send-only proxy.

## Work items

### 02.1 Choose one listener source of truth

- Make global `[tcp.protocols]` / `[udp.protocols]` the runtime listener
  definitions. They are the only place a port, protocol and upstream format
  are declared today.
- Remove the site-level `SiteTcpConfig`/`SiteUdpConfig` runtime claim, or
  repurpose the admin TCP/UDP page to edit the global config. Raw TCP has no
  `Host` header, so a per-site listener mapping cannot be routed the way HTTP
  sites are.
- If the site schema is removed, update `config/sites/example.com.toml`, the
  admin API handlers (`src/admin/handlers/tcp_udp.rs`), the admin UI, and the
  config reference.

### 02.2 Build listener specifications

Add a composition-level builder (in `src/server/resources.rs` or a small
`src/server` helper) that turns each protocol entry into a
`TcpListenerConfig` / `UdpListenerConfig`:

- port from `TcpProtocolConfig.ports` / `UdpProtocolConfig.ports`;
- bind address from `[server] host` (v4) and `host_v6` (v6), or an explicit
  per-protocol bind field if the product needs one;
- `expected_protocol` = the protocol map key;
- upstream = `upstream_format` with `{port}` substituted, and
  `upstream_format_v6` for the v6 listener;
- `filter_enabled`/`strict_mode` = the configured protocol policy;
- socket options from `[tcp.socket]` / `[udp.socket]`.

Validate invalid upstream formats, duplicate port/protocol pairs, privileged
ports and v4/v6 conflicts at startup, not at first packet.

### 02.3 Fix the TCP pool lifecycle

- Make `add_listener` register configuration only; perform the single bind in
  `start` (today `add_listener` binds and then `start` binds a second socket).
- Spawn `worker_pool_size` accept loops. Either share one `Arc<TcpListener>`
  across tasks (Tokio supports concurrent `accept`) or create one
  `SO_REUSEPORT` socket per worker and let the kernel balance. Record the
  choice; do not silently ignore the knob.
- Use `connection_timeout_secs` for the upstream connect and add an idle
  read/write timeout around `copy_bidirectional_native` (or a small
  timeout-aware copy helper). Do not use one whole-connection timeout for
  long-lived protocols.
- Keep the connection semaphore global per pool; add a per-listener connection
  cap if `max_connections` is intended to be per service.
- Pass the protocol filter configuration per listener. `ProtocolFilter` is
  currently a single pool field built from `Default::default()`; either make
  the pool hold one filter per listener or construct the filter in
  `add_listener`.
- Preserve the QUIC-tunnel upstream path and its existing zero-copy framing.

### 02.4 Implement the UDP request/response path

- Keep an `Arc<UdpSocket>` for the client-facing listener so a reply task can
  send back to the original `SocketAddr`.
- Introduce a bounded flow map keyed by `(client_addr, upstream_addr,
  listener_port)`. On the first datagram, bind a connected upstream
  `UdpSocket`, send the payload, and spawn a reply task that reads from the
  upstream socket and sends back through the listener socket.
- Add an idle timeout and a max-flow cap; clean up flows and report metrics
  (`udp.flows.active`, `udp.flows.reaped`, `udp.reply_errors`).
- Check `max_packet_size` before protocol detection and before allocating a
  flow. Bound the rate-limiter map and share it across workers, or explicitly
  document that the limit is per worker.
- Keep the existing QUIC-tunnel datagram path as an upstream alternative; do
  not duplicate its framing.
- If a per-flow socket is too expensive for the target workload, a shared
  upstream socket per listener cannot distinguish clients without a protocol
  demultiplexer; document that limit rather than shipping a broken generic
  proxy.

### 02.5 Make admin and config truthful

- The admin `list_listeners` endpoint must report actual listeners and real
  `active_connections`, not site-config rows.
- `create_listener`/`delete_listener` must mutate the source of truth and
  schedule a listener reload, or be removed.
- `configtest` must fail when `[tcp].enabled = true` but no protocol/port is
  defined, and when an upstream format cannot produce a valid address.
- Log the bound address, protocol, upstream and worker count at startup.

### 02.6 Tests

- TCP echo integration: connect, protocol detection, forward, response,
  half-close and idle timeout.
- Protocol mismatch: drop/stall behavior and metrics.
- Connection cap and accept-loop count; verify `worker_pool_size` is
  observable.
- UDP request/response: echo server, two concurrent clients, IPv4/IPv6,
  oversized packet, rate limit, idle flow cleanup, max-flow rejection.
- QUIC-tunnel upstream regression if that path remains enabled.
- Config tests for duplicate ports, missing upstream, privileged ports and
  invalid `{port}` substitution.
- `cargo test -p synvoid` focused targets plus `cargo xtask verify`.

## Non-goals

- HTTP listener changes (Phase 03).
- A generic UDP NAT for arbitrary protocols beyond the configured ports.
- Replacing the dedicated DNS server with the UDP pool.
- A new crate or dependency without the root ledger and ownership process.

## Risks

- Per-flow UDP sockets cost file descriptors; the cap and idle timeout are
  part of the safety case.
- TCP idle timeouts must not break long-lived SMTP/IMAP/MySQL sessions; choose
  protocol-aware defaults and make them configurable.
- The admin UI currently edits a dead site schema; removing it is a visible
  behavior change and needs a migration note.

## Exit criteria

- Starting with `[tcp].enabled = true` opens the configured ports and proxies
  a real client/response.
- Starting with `[udp].enabled = true` proxies a request and returns the
  upstream response to the client, or UDP is explicitly marked unsupported and
  its config surface is removed.
- `worker_pool_size`, connection limits and timeouts have observable effects.
- The admin UI no longer claims listeners it did not create.

## Completion evidence

Implemented 2026-11-11. Global `[tcp.protocols.*]` / `[udp.protocols.*]` now
expand into listeners in `src/server/aux_listener_config.rs`; `[tcp].enabled`
and `[udp].enabled` bind at startup. TCP uses one shared bound socket with
`worker_pool_size` accept loops, connect/idle timeouts and per-listener protocol
filtering; UDP uses a bounded per-client request/response flow map with reply
tasks, max packet/flow/idle limits and flow metrics. `filter_enabled` and
`strict_mode` are configurable per protocol for custom services. Admin inventory
reports actual bound listeners and live connections. `tcp_udp_service_test`
passes (TCP echo, protocol mismatch, idle timeout, UDP two-client/IPv6/oversize/
rate-limit/flow cap), and the benchmark smoke reports TCP 55k/53k pps and UDP
985/864 pps with zero/near-zero errors. UDP remains labelled Beta.

