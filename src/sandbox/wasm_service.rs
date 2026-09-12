//! Compatibility facade over `synvoid-jail-runtime` (Phase 29).
//!
//! Canonical owner: `synvoid_jail_runtime::WasmJailService`
//! (`crates/synvoid-jail-runtime/src/wasm_service.rs`). This root module is a
//! pure re-export facade so existing `synvoid::sandbox::` paths keep
//! compiling; new code must import `synvoid_jail_runtime` directly. Root must
//! not reintroduce engine implementation here (enforced by
//! `jail_runtime_boundary` repo guards).

pub use synvoid_jail_runtime::WasmJailService;
