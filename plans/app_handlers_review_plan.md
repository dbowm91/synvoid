# App Handlers Architecture Review Plan

## Verified Correct
- StaticFileHandler location: `src/static_files/mod.rs:42` - struct definition exists at correct location
- StaticFileHandler directory listings: Implemented via `src/static_files/directory.rs` with template support
- StaticFileHandler path normalization: `directory.rs:49` implements traversal detection via `path_str.contains("..")`
- StaticFileHandler MIME type mapping: Uses `crate::mime::MIME_REGISTRY` (referenced in mod.rs)
- StaticFileHandler gzip/brotli compression: Config fields `gzip_level`, `gzip_on_the_fly` present in struct
- StaticFileHandler IPC delegation to StaticWorker: Minifier client exists (`src/static_files/client.rs`)
- Granian file location: `src/app_server/granian.rs` is 1047 lines (matches documentation exactly)
- GranianSupervisor: Struct and implementation exists in `src/app_server/granian.rs:299`
- GranianConfig: Config struct present in `src/app_server/mod.rs:45`
- Granian auto-install support: Implemented via `ensure_granian_installed()` method
- BackendType enum has 11 variants including Spin, Serverless, Php, FastCgi, Cgi, etc.
- SpinHttpHandler location: `src/spin/handler.rs:117` - SpinHttpHandler struct defined
- SpinAppsManager::register(): Present at `src/spin/handler.rs:188`
- APP-15 (FastCGI buffering): Listed in deferred items in `skills/deferred_items_knowledge.md:30` - confirmed known limitation
- Spin manifest parsing: `src/spin/manifest.rs` exists and is imported in spin module

## Discrepancies Found
- **Generic WASM Handler Name**: Documentation mentions `WasmiHandler` at `src/spin/handler.rs:117` but actual handler is `SpinHttpHandler`. No generic WASM handler named `WasmiHandler` exists in codebase. The generic serverless WASM runtime uses `SpinRuntime` but is not named `WasmiHandler`.
- **Instance Pooling Claim Incomplete**: Documentation states "(Note: Instance pooling is supported for WAF plugins; the Spin runtime does not use instance pooling)" but the serverless module also has instance pooling (`src/serverless/instance_pool.rs`). The generic WASM edge functions use the serverless instance pool, not WAF plugin pool.
- **"Mesh Distribution" Claim**: Documentation states WASM modules can be distributed globally across mesh for serverless WASM backend, but it is unclear if this is implemented. Code shows `#[cfg(feature = "mesh")] pub use manager::{...}` pattern, suggesting serverless manager is mesh-gated but actual mesh distribution implementation not verified.
- **Spin vs Generic WASM table**: Row for "Generic WASM Edge Functions" / "HTTP Dispatch" column shows `WasmiHandler` but no such handler exists. The generic serverless backend uses `handle_serverless_function` with `ServerlessRoute` matching (not WasmiHandler).

## Bugs Identified
- **Low: Minifier Parameters Silently Ignored**: `src/static_files/mod.rs:134-138` - `new_with_minifier()` accepts `_minifier_cache` and `_async_minifier_client` (both prefixed with underscore indicating unused) and `minifier_client`. These parameters appear to be silently ignored. Per `skills/deferred_items_knowledge.md:44`, this is a known incomplete item - minification not fully wired.

## Suggested Improvements
- Update documentation to remove reference to `WasmiHandler` - this handler does not exist. The generic WASM edge functions use `ServerlessRoute` routing with `ServerlessManager::handle_serverless_function()`.
- Clarify documentation about instance pooling: Currently implies only WAF plugins have pooling, but serverless module also has `InstancePool` at `src/serverless/instance_pool.rs:11` used by generic WASM edge functions.
- Consider adding explicit line numbers to some handler implementations for easier verification.
- Add documentation about BackendType variants to show which handlers use which backend types.
- Clarify whether mesh distribution for WASM modules is actually implemented or is future work.
