# Phase 02 Plan: Listener Binding, Readiness and Lifecycle

Status: **COMPLETE** (2026-11-11).
Campaign: `plans/multi_listener_canonical_roadmap.md`.
Predecessor: Phase 01 (`plans/multi_listener_phase_01_configuration_model.md`).

## Scope

Make the normalized listener plan real and safe:

- replace scalar HTTP/HTTPS/H3 addresses with a listener collection;
- bind every planned socket before readiness;
- fail startup and release all sockets if any bind fails;
- register and join each listener with a dynamic identity;
- make shutdown stop accepting, drain connections, close every listener, and
  release every port.

This phase does not implement site membership routing or ALPN. It establishes
ownership. Phase 03 and Phase 04 consume it.

## Current state

- `UnifiedServer` stores scalar addresses:
  `src/server/mod.rs:91-97`.
- `run()` spawns a fixed task set:
  `src/server/mod.rs:446-457`.
- `spawn_http_listeners`, `spawn_https_listeners`, `spawn_http3_listeners` use
  fixed names: `src/server/listener_tasks.rs:17-153`.
- `NamedRuntimeHandle.name` is `&'static str`:
  `src/server/runtime_handles.rs:25-29`.
- HTTP binds inside its accept loop:
  `src/http/server/accept_loop.rs:52-58`.
- HTTPS binds inside `HttpsServer::serve`:
  `src/tls/server.rs:276-291`.
- HTTP/3 binds inside `Http3Server::serve`:
  `crates/synvoid-http3/src/server.rs:67-101`.
- `spawn_registered` does not observe task failure:
  `src/server/runtime_handles.rs:140-153`.
- Readiness is sent before `server_run` is spawned:
  `src/worker/unified_server/startup_plan.rs:371-412`.
- `stop_accepting_tx` is created with a dropped receiver and has no
  subscribers: `src/server/mod.rs:162-163,315-321`.
- Worker shutdown sends stop-accepting but never sends
  `UnifiedServer`'s `shutdown_tx`:
  `src/worker/unified_server/shutdown_executor.rs:190-214`,
  `src/worker/unified_server/lifecycle.rs:774-808`.
- `shutdown_and_join` applies the timeout per handle and drops timed-out
  handles instead of aborting: `src/server/runtime_handles.rs:78-126`.

These are existing lifecycle defects. N listeners multiply their impact and
must not be layered on top unchanged.

## Binding model

Bind first, then spawn. Do not let each task discover a bind error after the
worker has reported ready.

Introduce a bound-listener value, for example:

```text
BoundHttpListener {
    plan: HttpListenerPlan,
    socket: std::net::TcpListener,   // already bound, nonblocking
    protocol: PlainHttp | Tls | Http3Udp,
}
```

For each plan:

1. Resolve the address from Phase 01.
2. Bind the socket synchronously through the platform helper.
3. Set nonblocking mode.
4. For TLS, load/validate the certificate resolver before readiness.
5. For HTTP/3, bind the UDP socket before readiness.
6. Only after all plans bind, construct tasks and report ready.

Use `synvoid_platform::socket_bind::bind_tcp_reuse` /
`bind_udp_reuse` where their reuse semantics are correct. Do not make
`SO_REUSEPORT` the reason duplicate definitions silently succeed; Phase 01
must reject duplicates before this point.

### Rollback

- If any bind fails, close all sockets bound by this attempt.
- Report the failing listener id, address, transport, and error.
- Do not register any listener task.
- Do not send worker ready.
- Do not leave a partially serving process.

This mirrors `TcpListenerPool::bind_all()`'s local-socket rollback behavior,
but applies to HTTP/HTTPS/H3 as one transaction.

## Runtime ownership

Replace the scalar fields on `UnifiedServer` with:

```text
http_listeners: Vec<BoundHttpListener>
admin_addr: Option<SocketAddr>   // remains a separate control-plane listener
```

`spawn_*_listeners` becomes a single loop over the bound collection, or a small
set of helpers that take one bound listener each.

Required task identity:

- names must be dynamic: `http:<id>`, `https:<id>`, `h3:<id>`;
- `NamedRuntimeHandle.name` must support owned or interned strings;
- metrics labels must distinguish listener identity without using raw
  high-cardinality addresses;
- registration must preserve the listener's class (`CriticalServer` for the
  HTTP/HTTPS data plane, `ProtocolListener` for auxiliary protocols).

Do not deep-clone the entire `Router` per listener. Current code clones routing
maps at `src/server/mod.rs:562-569,635-644,690-697`. Share `Arc<Router>`,
`Arc<WafCore>`, flood protector, drain state, metrics, and a single upstream
client registry unless a measured reason requires per-listener pools.

Decide and document:

- whether `[http].max_connections` is per listener or process-wide; today each
  listener creates its own semaphore (`src/http/server.rs:131`,
  `src/tls/server.rs:194`);
- whether per-listener accept loops need their own upstream registry or share
  one.

For the first implementation, prefer a process-wide connection budget and one
shared upstream registry. Per-listener overrides can be added later with a
named field, not by silently multiplying limits.

## Shutdown and drain

- Every accept loop must select on both global shutdown and stop-accepting.
- `stop_accepting_tx` must have real subscribers. Do not keep the current
  dropped-receiver pattern.
- Worker shutdown must invoke the same `UnifiedServer` shutdown path that stops
  access logs, closes listeners, and joins tasks. Do not rely on dropping the
  `run()` future to detach tasks.
- Use one global drain deadline, not one timeout per listener.
- On deadline expiry, abort and await remaining listener tasks explicitly.
- Track HTTP/3 connections in the drain state; today the H3 path has no
  `WorkerDrainState` and detaches connection tasks.
- Close listening sockets before waiting for connection drain so new
  connections cannot arrive while draining.
- Verify ports are released after shutdown.

## Readiness

Move worker readiness after all listeners are bound.

Expected sequence:

1. load config;
2. build normalized plan;
3. bind all data-plane listeners;
4. load TLS material;
5. bind admin/metrics as configured;
6. spawn listener tasks;
7. mark ready;
8. serve.

The exact order of admin/metrics may remain separate, but readiness must not
precede a data-plane bind failure.

## Multi-worker pre-bind

Update `validate_ports_or_skip_for_shared_port`
(`src/worker/unified_server/state.rs:213-285`) or replace it with the Phase 01
plan validator plus actual binds:

- check every planned HTTP/HTTPS/H3 listener, not only scalar ports;
- check TCP and UDP separately;
- use the actual bind address, not `127.0.0.1` only;
- do not skip checks for all listeners merely because multi-worker reuse is
  enabled; skip only the "address already in use" probe for endpoints that are
  intentionally shared by workers.
- keep single-worker startup strict.

Multi-worker H3 ownership is qualified in Phase 06.

## Tests

- Two plaintext listeners bind on ephemeral ports; both tasks register.
- One HTTP and one HTTPS listener bind; both tasks register.
- One HTTP/3 UDP listener binds alongside HTTPS TCP on the same numeric port.
- A bind failure on listener N leaves no listener N-1 socket bound and does
  not report ready.
- Shutdown sends stop-accepting, joins all listener tasks, and releases every
  port.
- A listener task failure before shutdown surfaces as a startup/runtime error
  rather than a silent no-op.
- Dynamic names do not collide when two listeners share a port on different
  addresses.
- Existing single-listener HTTP/HTTPS/H3 tests remain green.
- Multi-worker pre-bind accepts intentional reuse and rejects a duplicate
  endpoint that is not marked for worker sharing.
- TCP/UDP pools still bind alongside HTTP listeners; no regression in
  `tests/tcp_udp_service_test.rs`.

## Exit criteria

- All planned listeners bind before readiness.
- A partial bind failure rolls back and fails startup.
- Every listener is registered with a unique dynamic identity.
- Shutdown closes listeners, drains, joins, and releases ports.
- No listener is left detached after `run()` returns.
- Existing single-listener behavior remains green.

## Risks

- Moving bind time earlier can change certificate-load/startup ordering.
- Binding in the parent before spawning tasks must preserve nonblocking and
  reuse semantics.
- Sharing `Router`/upstream state changes ownership assumptions; verify no
  request-path state is accidentally per-listener.
- Worker readiness changes may expose tests that depend on the old premature
  ready signal.
- HTTP/3 drain tracking is a new responsibility; do not claim graceful H3
  shutdown until connection tasks are counted.
