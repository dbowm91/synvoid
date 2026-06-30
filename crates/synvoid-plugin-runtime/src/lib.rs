//! WASM plugin runtime and sandbox integration.

pub mod axum_loader;
pub mod global;
pub mod instance_pool;
pub mod mesh_callbacks;
pub mod plugin_manager;
pub mod pool;
pub mod sandbox;
pub mod spin;
pub mod streaming_body;
pub mod wasm_metrics;
pub mod wasm_runtime;

pub use global::{
    get_global_plugin_manager, GlobalPluginManager, GlobalWasmMemoryBudget, MemoryBudgetError,
};
pub use instance_pool::WasmInstancePool;
pub use pool::{PooledInstance, WasmPool};
pub use sandbox::policy::{
    limits_from_manifest, EffectivePluginPolicy, PluginSourceIdentity, PreparedPluginLoad,
};
pub use sandbox::types::{
    compute_binary_hash, compute_manifest_hash, compute_manifest_signing_payload,
    enforce_plugin_load_policy, verify_plugin_signature, CapabilityViolation, FilesystemViolation,
    ManifestError, ManifestWarning, NetworkViolation, PluginCapabilities, PluginCapability,
    PluginFailureClass, PluginFailurePolicy, PluginInvocationGuard, PluginInvokeError,
    PluginLimits, PluginLoadConfig, PluginLoadError, PluginManifest, PluginRuntimeState,
    PluginSignatureAlgorithm, PluginSignatureConfig, PluginSignatureError,
    PluginSignatureVerification, PluginTrustTier, ResourceLimitError, SigningPolicy,
    SigningViolation, TrustedPluginKey, VerifiedPluginSignature,
};
pub use wasm_metrics::{get_all_wasm_metrics, get_wasm_metrics, WasmPluginMetrics};
pub use wasm_runtime::{PluginInfo, WasmPluginManager, WasmResourceLimits, WasmRuntime};
pub use wasm_runtime::{WasmFilterResult, WasmPluginError};
