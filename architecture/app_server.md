# App Server (`synvoid-app-server`) — Granian Management

## 1. Purpose and Responsibility

`crates/synvoid-app-server` manages **Granian** — an external Python application server (ASGI/RSGI/WSGI) used as a backend type for Python applications behind SynVoid. The crate owns the child-process lifecycle; request bytes flow through normal proxy dispatch.

## 2. Main Types

| Type | Role |
|------|------|
| `GranianInterface` | Interface mode selection: `Asgi` (default), `AsgiNl`, `Rsgi`, `Wsgi` |
| `GranianSupervisor` | Owns the managed child process (`tokio::process::Child`) plus health state, restart/failure counters, shutdown broadcast, PID, and the log buffer |
| `GranianConfig` | Resolved runtime deployment config (`granian.rs:165`) — distinct from the TOML-parsed `AppServerConfig` (`lib.rs:46`) |
| `GranianLogLevel` / `GranianLogFormat` | Granian logging verbosity and output format selectors (`granian.rs:71`, `granian.rs:121`) |

There is no separate `GranianProcess` type: process state is held inline in `GranianSupervisor` fields.

## 3. Capabilities

- Process spawn/supervision with log buffering (capped at 1000 lines via `MAX_LOG_BUFFER_LINES`, `granian.rs:6`).
- Health monitoring with automatic restart on failure (`healthy`/`running` flags, `restart_count`, `consecutive_failures`, `consecutive_successes`).
- Auto-install of Granian and pip requirements, controlled by `auto_install_granian` / `auto_install_requirements` (default `true`).
- Atomic counters (`AtomicU32`/`AtomicU64`) for request tracking.
- Root compat facade: `src/app_server/` re-exports this crate.

## 4. Integration

Selected via `BackendType::AppServer` in the HTTP pipeline's backend dispatch (see [`http_request_pipeline.md`](./http_request_pipeline.md)). WebSocket upgrades can be proxied to the Granian listener (see [`streaming.md`](./streaming.md)).

## 5. Related Docs

- [`app_handlers.md`](./app_handlers.md)
- [`http_deep_dive.md`](./http_deep_dive.md)
