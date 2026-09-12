//! Sandbox module: parent policy/composition for supervised jail processes.
//!
//! Canonical child execution owner (Phase 29): `synvoid-jail-runtime`
//! (`crates/synvoid-jail-runtime/`). This root module retains only:
//!
//! - parent policy/composition (`policy::JailClient`, routing via
//!   `synvoid_ipc::IsolationPolicy`);
//! - compatibility facades re-exporting the child services
//!   (`WasmJailService`, `YaraJailService`, `headers_to_guest_json`);
//! - internal forwarding shims for the legacy `--wasm-jail` / `--yara-jail`
//!   flags, which delegate to `synvoid-jail-runtime` entry sequencing.
//!   Production spawns the dedicated `synvoid-wasm-jail` /
//!   `synvoid-yara-jail` binaries (resolved via
//!   `synvoid_ipc::resolve_jail_binary`, exe-dir only, no CWD/PATH search).
//!   The legacy flags remain only as forwarding shims with no alternate
//!   unisolated execution path. Removal target: require dedicated binaries
//!   once installers ship them atomically (Part G).
//!
//! Normative spec: `architecture/sandbox_jail_protocol.md`.

pub mod policy;
pub mod wasm_service;
pub mod yara_service;

pub use policy::{headers_to_guest_json, JailClient};
pub use synvoid_jail_runtime::{
    WasmJailService, YaraJailService, JAIL_PERMIT_NO_SANDBOX_ENV, JAIL_RUNTIME_VERSION,
};

/// Legacy compat shim: `synvoid --wasm-jail` forwards to the
/// `synvoid-jail-runtime` WASM child entry. Prefer spawning the dedicated
/// `synvoid-wasm-jail` binary; this shim exists only for hermetic tests and
/// dev builds and runs the same isolated entry sequencing (never
/// unisolated).
pub fn run_wasm_jail_mode() -> ! {
    synvoid_jail_runtime::run_wasm_jail_main();
}

/// Legacy compat shim: `synvoid --yara-jail` forwards to the
/// `synvoid-jail-runtime` YARA child entry. Prefer spawning the dedicated
/// `synvoid-yara-jail` binary.
pub fn run_yara_jail_mode() -> ! {
    synvoid_jail_runtime::run_yara_jail_main();
}
