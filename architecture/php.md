# PHP Handler Architecture

## 1. Purpose and Responsibility

The PHP module (canonical: `crates/synvoid-app-handlers/src/php/`; `src/fastcgi/` only re-exports the
shared FastCGI layer) is a **PHP-FPM-specialized adapter over generic FastCGI**. It auto-detects the FPM
socket, merges location-level PHP config, translates PHP INI settings into FastCGI params, and then
delegates to the same `FastCgiPool` / `FastCgiClient` infrastructure as `BackendType::FastCgi`.

**Core Responsibilities:**
- FPM socket auto-detection across distros and custom paths
- Location-level PHP config merging (26 override fields)
- PHP INI forwarding via `PHP_VALUE` / `PHP_ADMIN_VALUE` FastCGI params
- FPM status queries (`pm_status_path`) and admin pool observability

## 2. Key Data Structures

| Item | Location | Role |
|------|----------|------|
| `PhpClient` | `php/mod.rs:59` | Single-field (`config: PhpConfig`) executor; `new()`, `execute()`, `execute_status()` |
| `PhpConfig` | `synvoid-config/src/site/backend.rs:38` | 25 optional fields: socket/host/port, root/index, timeouts, ini settings, env vars, `php_admin_value` hardening, PM settings, drain config |
| `PhpLocationConfig` | `synvoid-config/src/site/backend.rs:206` | Per-location mirror of `PhpConfig` for overrides |
| `FastCgiConfig` | `synvoid-config/src/site/backend.rs:12` | Shared pool config the PHP layer converts into |
| `PhpPoolStatus` | `src/admin/handlers/php.rs:15` | Admin API response type for pool listing |

## 3. Socket Auto-Detection (`php/mod.rs:11-92`)

`COMMON_PHP_SOCKETS` is a `LazyLock<Vec<PathBuf>>` of known FPM socket paths plus a dynamic
`/run/php` scan for `*-fpm.sock` files. `auto_detect_socket()` (`:68`) resolves in priority order:

1. Explicit `socket` from config
2. `host:port` when both are set
3. `host:9000` when only a host is set
4. First existing path in `COMMON_PHP_SOCKETS`
5. Fallback `/run/php/php-fpm.sock`

Unix-socket detection is a mode-bit check (`is_unix_socket`, `:47`). `create_php_client()` (`:245`)
bails with `None` when no explicit socket/host exists **and** `has_available_php_socket()` (`:342`)
finds nothing — so PHP backends fail closed at dispatch (502) instead of dialing a phantom socket.

## 4. Config Translation (`php/mod.rs:142-263`)

`build_fcgi_config()` converts `PhpConfig` → `FastCgiConfig`: `root` + script → `script_filename`,
timeouts forwarded, and PHP settings encoded as params — INI values as `PHP_VALUE:*` /
`PHP_ADMIN_VALUE:*` (e.g. `disable_functions`, `open_basedir`, `memory_limit`,
`upload_max_filesize`), env vars as `FCGI_ENV:*`. `merge_php_location_config()` (`:263`) overlays the
26 `PhpLocationConfig` fields onto a cloned site config; the router threads
`RouteTarget::php_location_config` (`synvoid-proxy/src/router.rs:92`) from match to dispatch.

## 5. Request Flow

1. **Routing** — `Router::resolve()` sets `BackendType::Php` + `php_location_config`.
2. **Dispatch** — `backend_dispatch.rs` calls `maybe_handle_fastcgi_or_php_backend()`
   (`synvoid-http/src/fastcgi_php_backend_dispatch.rs:17`), which returns `None` for other backends
   and 502s when `target.backend_socket` is absent.
3. **Client creation** — `create_php_client(site_config, php_location_config)` merges config and
   auto-detects the socket.
4. **Pool checkout** — `get_pool()` → global `FastCgiPoolManager::get_or_create_pool()` (semaphore-bounded,
   shared with generic FastCGI).
5. **Execute** — `pool.execute()` → semaphore acquire → `FastCgiClient::execute()` over the Unix/TCP
   FPM socket with params + body; `parse_response()` splits the `\r\n\r\n` boundary, extracts `Status:`,
   and strips forbidden headers (`server`, `x-powered-by`, `connection`, `keep-alive`).
6. **Post-processing** — same path as FastCGI: WASM transform → image rights → security headers →
   `FastCgiResponse::into_http_response()`.

## 6. PHP vs Generic FastCGI

| Aspect | `BackendType::Php` | `BackendType::FastCgi` |
|--------|-------------------|----------------------|
| Config source | `site_config.proxy.php` (`PhpConfig`) | `site_config.proxy.fastcgi` (`FastCgiConfig`) |
| Socket resolution | `auto_detect_socket()` probe list | Direct from config |
| INI forwarding | `PHP_VALUE:*` / `PHP_ADMIN_VALUE:*` | Raw `params` map only |
| Location merge | 26 fields (`merge_php_location_config`) | `FastCgiLocationConfig` (8 fields) |
| Status probe | `execute_status()` via `pm_status_path` (default `/status`) | None built-in |
| Admin API | `GET /system/php-pools`, `POST /system/php-pools/reload` | No dedicated endpoints |

## 7. Admin Integration (`src/admin/handlers/php.rs`)

- `list_php_pools` (`GET /system/php-pools`, `:35`) delegates to `fastcgi::get_all_pool_statuses()`.
- `reload_php_pool` (`POST /system/php-pools/reload`, `:64`) drains and reloads via
  `fastcgi::drain_and_reload_pool()` (start drain → poll in-use → finish).

## 8. Related Docs

- [`fastcgi.md`](./fastcgi.md) (shared pool/client infrastructure) · [`cgi.md`](./cgi.md) ·
  [`app_handlers.md`](./app_handlers.md) (dispatch overview)
