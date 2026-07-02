//! WASM plugin runtime and sandbox integration.

pub mod abi_frame;
pub mod global;
pub mod instance_pool;
pub mod mesh_callbacks;
pub mod plugin_manager;
pub mod pool;
pub mod sandbox;
pub mod spin;
pub mod streaming_body;
pub mod unsafe_native_loader;
pub mod wasm_metrics;
pub mod wasm_runtime;

pub use abi_frame::{
    build_request_frame, record_serialization_rejection, request_frame_policy_from_limits,
    response_frame_policy_from_limits, serialize_headers_canonical,
    validate_response_transform_output, FailOpenPolicy, PluginBodyMode, PluginHttpView,
    PluginResponseMutationPolicy, RequestFrame, RequestFramePolicy, ResponseFramePolicy,
    SerializationError, SerializationFailureClass, ValidatedResponseTransform,
};
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
    PluginSignatureVerification, PluginStateModel, PluginTrustTier, ResourceLimitError,
    SigningPolicy, SigningViolation, TrustedPluginKey, VerifiedPluginSignature,
};
pub use unsafe_native_loader::{
    current_generation, get_global_unsafe_native_config, is_production_env,
    set_global_unsafe_native_config, UnsafeNativeExtension, UnsafeNativeExtensionConfig,
    UnsafeNativeExtensionStatus, UnsafeNativeGlobalStatus,
};
pub use wasm_metrics::{
    get_all_wasm_metrics, get_wasm_metrics, record_concurrency_limit_exceeded,
    record_epoch_timeout, record_fresh_instance, record_fuel_exhausted, record_host_call_timeout,
    record_plugin_pool_stats, record_pool_drop, record_pool_hit, record_pool_miss,
    WasmPluginMetrics,
};
pub use wasm_runtime::{
    wait_for_stable_file, FileStabilityPolicy, HotReloadConfig, LifecycleTransition,
    LoadedPluginGeneration, PluginDetail, PluginGenerationId, PluginLifecycleState,
    PluginReloadOutcome, PluginReplacePolicy,
};
pub use wasm_runtime::{
    ExecutionInterruptPolicy, GuestAbiInfo, GuestAbiPolicy, HostCallBudget, WasmFilterResult,
    WasmPluginError,
};
pub use wasm_runtime::{PluginInfo, WasmPluginManager, WasmResourceLimits, WasmRuntime};

#[cfg(test)]
pub mod test_fixtures;
