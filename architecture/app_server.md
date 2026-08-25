# App Server (`synvoid-app-server`) — Granian Management

## 1. Purpose and Responsibility

`crates/synvoid-app-server` manages **Granian** — an external Python application server (ASGI/RSGI/WSGI) used as a backend type for Python applications behind SynVoid. The crate owns the child-process lifecycle; request bytes flow through normal proxy dispatch.

## 2. Main Types

| Type | Role |
|------|------|
| `GranianInterface` | Interface mode selection: `Asgi`, `AsgiNl`, `Rsgi`, `Wsgi` |
| `GranianProcess` | Managed child process with health monitoring and restart logic |

## 3. Capabilities

- Process spawn/supervision with log buffering (capped at 1000 lines).
- Health monitoring with automatic restart on failure.
- Atomic counters (`AtomicU32`/`AtomicU64`) for request tracking.
- Root compat facade: `src/app_server/` re-exports this crate.

## 4. Integration

Selected via `BackendType::AppServer` in the HTTP pipeline's backend dispatch (see [`http_request_pipeline.md`](./http_request_pipeline.md)). WebSocket upgrades can be proxied to the Granian listener (see [`streaming.md`](./streaming.md)).

## 5. Related Docs

- [`app_handlers.md`](./app_handlers.md)
- [`http_deep_dive.md`](./http_deep_dive.md)
