//! Explicit unsafe in-process native extension loading.
//!
//! Phase 28 capability isolation: the ordinary sandboxed WASM plugin runtime
//! (`synvoid-plugin-runtime`) no longer links `libloading` unconditionally.
//! All shared-library loading authority lives here, behind both:
//!
//! - a compile-time gate: depend on this crate (and enable the
//!   `unsafe-native-extensions` feature on `synvoid-plugin-runtime` / the root
//!   `synvoid` crate) to compile native support in; and
//! - runtime gates: `enabled`, production `allow_in_production` + exact
//!   [`RISK_ACKNOWLEDGEMENT`], non-empty `allowed_dirs`, canonical-path
//!   enforcement, symlink/world-writable policy, extension allowlist and hash
//!   checks, generation-aware handle lifetime, and a separate hot-reload gate.
//!
//! In-process native code runs with full host process authority and is NOT
//! sandboxed. `catch_unwind` around the factory call catches Rust panics only;
//! arbitrary native UB can still corrupt or crash the process. Prefer the
//! future external-host seam ([`external_seam`]) for production extensibility.

pub mod backend;
pub mod error;
pub mod external_seam;
pub mod loader;
pub mod metrics;

pub use backend::{InProcessNativeBackend, NativeExtensionBackend, NativeExtensionHandle};
pub use error::{AxumPluginError, UnsafeNativePluginError};
pub use external_seam::{
    validate_external_host_request, ExternalHostCapabilities, ExternalHostDecision,
    ExternalHostRequest, ExternalSeamError, DEFAULT_EXTERNAL_HOST_MAX_INFLIGHT,
    DEFAULT_EXTERNAL_HOST_TIMEOUT_MS, EXTERNAL_HOST_CONTRACT_VERSION,
    MAX_EXTERNAL_REQUEST_BODY_BYTES, MAX_EXTERNAL_REQUEST_HEADERS_BYTES,
};
pub use loader::{
    create_plugin_library_example, current_generation, drain_audit_events,
    get_global_unsafe_native_config, is_production_env, load_plugin, peek_audit_events,
    record_audit_event, set_global_unsafe_native_config, UnsafeNativeAuditEvent,
    UnsafeNativeAuditEventKind, UnsafeNativeExtension, UnsafeNativeExtensionConfig,
    UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus, RISK_ACKNOWLEDGEMENT,
};
pub use metrics::{
    record_unsafe_native_extension_load_failed, record_unsafe_native_extension_loaded,
    record_unsafe_native_extension_reloaded, record_unsafe_native_extension_request,
};
