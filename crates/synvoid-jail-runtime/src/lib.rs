//! Jail runtime: child-side WASM/YARA execution package (Phase 29).
//!
//! Explicit process-boundary owner for sandboxed child execution. The wire
//! protocol and parent supervision live in `synvoid-ipc`; the parent
//! policy/composition lives in the root `synvoid::sandbox`; this crate owns:
//!
//! - child-side handler dispatch (`WasmJailService`, `YaraJailService`);
//! - WASM/YARA service implementations over the narrow engine crates
//!   (`synvoid-plugin-runtime`, `synvoid-yara`);
//! - sandbox-entry sequencing (`sandbox_entry`: capture stdio → apply
//!   `Strict` isolation → framed request loop, fail-closed);
//! - child-only observability (stderr logs; stdout is framed IPC).
//!
//! This crate must never import root `synvoid::`, supervisor, admin, or mesh
//! implementation paths (enforced by `jail_runtime_boundary` repo guards).
//! It depends only on `synvoid-ipc`, `synvoid-platform`, and the narrow
//! engine crates.
//!
//! Binaries: `synvoid-wasm-jail` (requires `wasm` feature) and
//! `synvoid-yara-jail` (requires `yara` feature). Each links only its own
//! engine; the WASM jail does not link YARA and vice versa. Parent processes
//! resolve these binaries via `synvoid_ipc::resolve_jail_binary` (exe-dir
//! lookup, no CWD/PATH/writable-dir search) with fallback to the legacy
//! `synvoid --wasm-jail` / `--yara-jail` compat shims.

pub mod headers;
pub mod sandbox_entry;
#[cfg(feature = "wasm")]
pub mod wasm_service;
#[cfg(feature = "yara")]
pub mod yara_service;

pub use headers::headers_to_guest_json;
#[cfg(feature = "wasm")]
pub use sandbox_entry::run_wasm_jail_main;
#[cfg(feature = "yara")]
pub use sandbox_entry::run_yara_jail_main;
pub use sandbox_entry::{
    init_jail_logging_stderr, JAIL_PERMIT_NO_SANDBOX_ENV, JAIL_RUNTIME_VERSION,
};
#[cfg(feature = "wasm")]
pub use wasm_service::WasmJailService;
#[cfg(feature = "yara")]
pub use yara_service::YaraJailService;
