# Application Handlers Review Plan

**Reviewed:** 2026-05-28
**Documents:** `architecture/app_handlers.md`, `architecture/static_files.md`, `architecture/fastcgi.md`, `architecture/cgi.md`, `architecture/mime.md`, `architecture/theme.md`

## Verified Correct Items

- **BackendType enum** (`src/router.rs:66-78`): All 11 variants match exactly: `Upstream`, `FastCgi`, `Php`, `Cgi`, `AxumDynamic`, `AppServer`, `Static`, `QuicTunnel`, `Serverless`, `Mesh`, `Spin`.
- **BackendType dispatch line numbers**: All 11 dispatch points in `src/http/server.rs` verified correct (off by ±1 line in some cases, functionally accurate).
- **GranianConfig** (`src/app_server/granian.rs:165`): Struct location and fields match documentation.
- **Granian file line count**: `src/app_server/granian.rs` is exactly 1047 lines as claimed.
- **GranianSupervisor**: Exists at `src/app_server/granian.rs:299` (not referenced in docs by line, but struct exists).
- **FastCGI singleton pool manager**: `LazyLock<RwLock<FastCgiPoolManager>>` confirmed at `src/fastcgi/mod.rs:18-19`.
- **FastCGI pool functions**: `get_pool()`, `remove_pool()`, `close_all_pools()`, `drain_and_reload_pool()`, `get_all_pool_statuses()` all exist with correct signatures.
- **FastCGI streaming**: `StreamingFastCgiClient` and `FastCgiResponseStream` (with `futures::Stream` impl at line 122) exist in `src/fastcgi/streaming.rs`.
- **FastCGI pool health checks**: `start_health_check()` at `src/fastcgi/pool.rs:149` confirmed.
- **FastCGI pool drain**: `drain_with_timeout()` at `src/fastcgi/pool.rs:117` confirmed.
- **FastCGI parse_socket_address()**: Exists at `src/fastcgi/mod.rs:332`, supports unix/tcp detection correctly.
- **FastCgiPoolConfig fields**: All documented fields exist in `src/fastcgi/pool.rs:31-39`.
- **FastCgiPoolStatus fields**: All documented fields exist in `src/fastcgi/pool.rs:16-29`.
- **CGI path traversal protection**: Canonicalize + prefix check at `src/cgi/mod.rs:117-138`.
- **CGI extension validation**: `validate_script_path()` at `src/cgi/mod.rs:151-183`.
- **CGI timeout enforcement**: `tokio::time::timeout()` wrapping in `spawn_script()` at `src/cgi/mod.rs:304`.
- **CGI sanitize_cgi_path()**: Exists at `src/cgi/mod.rs:10`, removes `.` and `..` components correctly.
- **MIME singleton**: `LazyLock<RwLock<MimeRegistry>>` at `src/mime/mod.rs:8-9`.
- **MIME FileCategory enum**: All 9 variants match: `Image`, `Video`, `Audio`, `Document`, `Archive`, `Font`, `Code`, `Executable`, `Unknown`.
- **MIME public API methods**: `get_mime_for_extension()`, `get_extensions_for_mime()`, `get_category()`, `get_info()`, `normalize_mime()`, `is_mime_allowed()`, `mime_matches_pattern()`, `detect_from_bytes()`, `detect_from_bytes_with_fallback()` all exist.
- **MIME infer crate usage**: `detect_from_bytes()` at `src/mime/mod.rs:413` uses `infer::get()` for magic-byte detection.
- **ThemeRenderer**: `struct ThemeRenderer` with `config: ThemeConfig` field at `src/theme/renderer.rs:3-5`.
- **ChallengePageTemplate**: Exists at `src/theme/template.rs:5`, has builder methods `.title()`, `.subtitle()`, `.content()`, `.render()`.
- **DirectoryListingTemplate**: Exists at `src/theme/dir_listing.rs:42`.
- **ServerlessInstancePool**: Exists at `src/serverless/instance_pool.rs:89` with per-function pools, idle timeout, autoscaling.
- **InstancePoolConfig fields**: `min_instances`, `max_instances`, `idle_timeout_seconds` all exist.
- **ServerlessRoute**: Exists at `src/serverless/routing.rs:112` with `matcher`, `method`, `priority`, `function_name`.
- **Mesh DHT integration**: `store_and_announce()` called at `src/serverless/manager.rs:505`, `announce_serverless()` at `src/mesh/transport.rs:1041`.
- **DHT key format**: `serverless_function:{name}` confirmed at `src/mesh/dht/keys.rs:350`.
- **SpinAppsManager::register()**: Exists at `src/spin/handler.rs:188`.
- **SpinHttpHandler**: Referenced at `src/http/server.rs:2425` in Spin dispatch.
- **SpinManifest**: Spin manifest parsing exists at `src/spin/manifest.rs`.
- **QuicTunnel variant**: `UpstreamAddress::QuicTunnel` at `src/upstream/address.rs:27`.

## Discrepancies Found

### static_files.md

1. **NormalizedLocation struct fields wrong** (lines 30-36): Documented as having `index: Vec<String>` and `cache_ttl: u64`. Actual code (`src/static_files/mod.rs:32-39`) has `index: Option<String>`, `cache_ttl: Option<u64>`, and an additional `theme: Option<SiteStaticThemeConfig>` field not documented.

2. **StaticFileHandler fields severely underdocumented** (lines 22-28): Documented with 5 fields (`locations`, `compression`, `minification`, `mesh_config`, `theme`). Actual struct (`src/static_files/mod.rs:42-65`) has 16 fields including `gzip_types`, `max_file_size`, `gzip_level`, `gzip_min_size`, `allow_symlinks`, `block_hidden_files`, `enable_compression`, `gzip_on_the_fly`, `directory_listing`, `default_cache_ttl`, `site_id`, `minified_cache_dir`, `enable_zero_copy`, `directory_template_path`, `minifier_client`, `image_poison_config`. The documented `compression` and `minification` fields do not exist as named; mesh-related config uses separate `mesh_image_protection`, `mesh_compression`, `mesh_minification` fields.

3. **StaticResponse enum wrong** (lines 38-41): Documented as `InMemory { content: Bytes, headers: Headers }` and `Buffered { path: PathBuf, headers: Headers }`. Actual code (`src/static_files/mod.rs:96-105`) defines `StaticResponseBody` enum (separate from `StaticResponse` struct), where `StaticResponse` has `status: StatusCode`, `headers: Vec<(String, String)>`, and `body: StaticResponseBody` as separate fields. The documented variant fields are incorrect.

4. **StaticError variants wrong** (lines 43-50): Documented as simple unit variants (e.g., `NotFound`, `Forbidden`). Actual code (`src/static_files/mod.rs:67-81`) has tuple variants with `String` payloads (e.g., `NotFound(String)`, `Forbidden(String)`).

### fastcgi.md

5. **FastCgiClient struct fields wrong** (lines 19-23): Documented with `socket: String`, `is_unix: bool`, `timeout: Duration`. Actual code (`src/fastcgi/mod.rs:51-54`) has `socket_path: String`, `is_tcp: bool` (no `timeout` field, different field name for TCP detection).

6. **FastCgiPool struct fields wrong** (lines 25-29): Documented with `connections: Vec<FastCgiClient>`. Actual code (`src/fastcgi/pool.rs:60-67`) uses `connections: RwLock<VecDeque<PooledConnection>>` (a `VecDeque` of `PooledConnection`, not a `Vec` of `FastCgiClient`), plus additional `closed` and `draining` fields.

### mime.md

7. **MimeRegistry struct fields wrong** (lines 19-22): Documented with `extension_to_mime: HashMap<String, MimeTypeInfo>`. Actual code (`src/mime/mod.rs:76-80`) has `extension_to_mime: HashMap<String, String>` (maps extension to MIME string, not to `MimeTypeInfo`), plus `mime_categories: HashMap<String, FileCategory>` not documented. The `MimeTypeInfo` is not stored as a field; it's constructed on demand via `get_info()`.

8. **MimeTypeInfo::extensions field type** (lines 24-28): Documented with `extensions: Vec<String>` as a field. This field exists but the documented struct structure implies it's a direct lookup field within `MimeRegistry`, which is incorrect (see item 7).

### theme.md

9. **DirectoryEntry fields wrong** (lines 47-53): Documented with `modified: Option<DateTime<Utc>>` and `size: Option<u64>`. Actual code (`src/theme/dir_listing.rs:32-40`) has `modified: String` and `size: String`, plus additional `modified_timestamp: u64` and `size_bytes: u64` fields not documented.

### app_handlers.md

10. **SpinHttpHandler line number off by 1** (line 71): Documented as `src/http/server.rs:2421-2503`. Actual dispatch starts at line 2420 (the `if matches!` check). The handler creation is at line 2425. Minor inaccuracy.

## Bugs Identified

1. **StreamingFastCgiClient is not truly streaming** (`src/fastcgi/streaming.rs:258-273`): The `do_execute_stream()` method reads the entire request body into `stdin_buffer` before sending to FastCGI. The `FastCgiResponseStream` is a wrapper around pre-collected chunks. The architecture doc (`fastcgi.md:79`) claims "FCGI record-level streaming (not HTTP chunked)" which is misleading — the implementation buffers both request and response fully in memory. This limits memory efficiency for large request/response bodies.

2. **StaticFileHandler::into_response() double-reads Buffered body** (`src/static_files/mod.rs:867-880`): The `into_response()` method reads `StaticResponseBody::Buffered(path)` via `std::fs::read(&path)`, but `serve_file()` already set this body from the file. This means for zero-copy responses, the file is read twice — once in `serve_file()` to get metadata and determine zero-copy eligibility, and again in `into_response()`. The zero-copy optimization is effectively negated.

3. **CgiHandler::execute_script() is blocking** (`src/cgi/mod.rs:342-358`): The `execute_script()` method uses `tokio::task::spawn_blocking` with `wait_with_output()`, which blocks the entire thread pool thread for the duration of script execution. This is correct for CGI but the timeout mechanism (line 304) uses `tokio::time::timeout` around a blocking task, which may not cancel the underlying OS process on timeout.

4. **FastCgiPool health_check() is trivial** (`src/fastcgi/pool.rs:283-294`): The `health_check()` method only checks if the socket string starts with `/` or `unix:` or contains `:`. It doesn't actually test connectivity. The architecture doc (`fastcgi.md:78`) claims "Periodic connection health validation" but the actual health check only validates the socket format, not connectivity.

5. **FastCgiPool::execute_stream() drops permit immediately** (`src/fastcgi/pool.rs:229`): The semaphore permit is acquired then immediately dropped with `drop(permit)` before the streaming execution. This means streaming requests bypass the concurrency limit entirely, potentially causing resource exhaustion under load.

## Suggested Improvements

1. **Update static_files.md** to accurately reflect the 16-field `StaticFileHandler` struct, correct `NormalizedLocation` field types (`Option<String>` index, `Option<u64>` cache_ttl), fix `StaticResponse`/`StaticResponseBody` enum structure, and add `StaticError` tuple variant payloads.

2. **Update fastcgi.md** to fix `FastCgiClient` field names (`socket_path`/`is_tcp`), fix `FastCgiPool` internal structure (use `RwLock<VecDeque<PooledConnection>>`), and document additional pool fields (`closed`, `draining`).

3. **Update mime.md** to fix `MimeRegistry` internal structure — `extension_to_mime` maps `String → String`, not `String → MimeTypeInfo`. Document the `mime_categories` field.

4. **Update theme.md** to fix `DirectoryEntry` field types (`String` for `modified`/`size`, plus `modified_timestamp: u64` and `size_bytes: u64`).

5. **Add FastCgiPool health check caveat**: Document that `health_check()` validates socket format only, not actual connectivity. Consider adding TCP/Unix socket connect test.

6. **Fix FastCgiPool::execute_stream() concurrency**: The semaphore permit should be held for the duration of the streaming execution to enforce connection limits, not dropped immediately.

7. **Document StaticFileHandler into_response() double-read**: The zero-copy path (`Buffered`) re-reads the file in `into_response()`. Consider either eliminating `into_response()` in favor of inline response construction (which the HTTP server already does at `src/http/server.rs:2246-2259`) or accepting the double-read as a trade-off for API simplicity.

8. **Add CGI process cancellation note**: Document that `tokio::time::timeout` cannot cancel the spawned OS process on timeout. Consider using `kill()` on the child process handle.

9. **Consider adding `StreamingFastCgiClient` streaming body forwarding**: The current implementation buffers the entire body before sending. True streaming would require forwarding body chunks as they arrive from the client.

## Stale Content

1. **app_handlers.md line 71**: `SpinHttpHandler` referenced at line 2421-2503; actual `if matches!` is at line 2420, handler creation at 2425. Minor line drift.

2. **app_handlers.md line 87**: `Cgi` documented at `src/http/server.rs:2747`. Actual is at line 2746. Off by 1.

3. **app_handlers.md line 88**: `AppServer` documented at `src/http/server.rs:2821`. Actual is at line 2820. Off by 1.

4. **app_handlers.md line 93**: `Mesh` documented at `src/http/server.rs:2872`. Actual is at line 2871. Off by 1.

5. **fastcgi.md line 38**: Documents `StreamingFastCgiClient` with comment `/* FCGI record-level streaming */`. The streaming is not truly record-level streaming (see Bug 1).

## Cross-Reference Status

- **AGENTS.md "APP-15 FastCGI streaming"**: Fixed. `src/fastcgi/streaming.rs` exists with `StreamingFastCgiClient` and `FastCgiResponseStream`. The implementation is functional but has the buffering limitation noted in Bug 1.
- **AGENTS.md "APP-3 Serverless InstancePool"**: Confirmed. `src/serverless/instance_pool.rs:11` (actually struct is at line 89, config at line 11). Features match: per-function pools, idle timeout (300s default), autoscaling, pre-warm.
- **AGENTS.md "APP-5 BackendType"**: Verified. All 11 variants at `src/router.rs:66-78` match exactly.
- **AGENTS.md "APP-6 Mesh Distribution"**: Verified. `ServerlessManager` uses `RecordStoreManager::store_and_announce()` and `MeshTransport::announce_serverless()`. DHT key format `serverless_function:{name}` confirmed.
- **AGENTS.md "Granian IS integrated"**: Confirmed. 1047-line implementation with full process management.
- **No security issues found**: No secrets, auth tokens, or crypto operations in the reviewed modules. The CGI module properly sanitizes paths and validates script extensions. The static file handler correctly prevents path traversal.
- **No stale feature flags found**: `#[cfg(feature = "mesh")]` gates are consistently applied across serverless and static file modules.
