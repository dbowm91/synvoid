use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;

use super::types::{
    PluginCapabilities, PluginLimits, PluginManifest, PluginTrustTier, VerifiedPluginSignature,
};
use crate::wasm_runtime::WasmResourceLimits;

// ═══════════════════════════════════════════════════════════════════════════════
// Source Identity
// ═══════════════════════════════════════════════════════════════════════════════

/// Cryptographic and provenance metadata for a loaded plugin.
/// Phase 1 populates path/name/version/trust_tier; Phase 2 will expand
/// with binary_sha256, manifest_sha256, and key_id.
#[derive(Debug, Clone, Default)]
pub struct PluginSourceIdentity {
    /// Filesystem path to the `.wasm` binary, if file-based.
    pub path: Option<PathBuf>,
    /// SHA-256 of the plugin binary (hex). Populated in Phase 2.
    pub binary_sha256: Option<String>,
    /// SHA-256 of the manifest signing payload (hex). Populated in Phase 2.
    pub manifest_sha256: Option<String>,
    /// Trusted key ID used for signature verification. Populated in Phase 2.
    pub key_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Effective Plugin Policy
// ═══════════════════════════════════════════════════════════════════════════════

/// The complete, immutable runtime policy for a loaded plugin.
///
/// Constructed from the plugin's `PluginManifest` merged with operator-supplied
/// defaults. This is the single source of truth for all runtime enforcement:
/// `WasmRuntime`, `WasmInstancePool`, host functions, and invocation checks
/// all read from this policy.
#[derive(Debug, Clone)]
pub struct EffectivePluginPolicy {
    /// Canonical plugin name (from manifest).
    pub name: String,
    /// Plugin version string (from manifest).
    pub version: String,
    /// Trust tier that was enforced at load time.
    pub trust_tier: PluginTrustTier,
    /// Effective capabilities — exactly those declared in the manifest.
    pub capabilities: Arc<PluginCapabilities>,
    /// Effective WASM resource limits derived from manifest + defaults.
    pub limits: WasmResourceLimits,
    /// Original manifest limits (for introspection).
    pub manifest_limits: PluginLimits,
    /// Provenance metadata for the loaded plugin.
    pub source: PluginSourceIdentity,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Prepared Plugin Load
// ═══════════════════════════════════════════════════════════════════════════════

/// Returned by `prepare_plugin_load()` after policy enforcement.
///
/// The caller uses these effective limits to construct the `WasmRuntime`,
/// ensuring the same manifest used for admission checks is also the source
/// of truth for runtime configuration.
#[derive(Debug, Clone)]
pub struct PreparedPluginLoad {
    /// The validated manifest that passed load policy enforcement.
    pub manifest: PluginManifest,
    /// Effective WASM resource limits derived from the manifest.
    pub effective_limits: WasmResourceLimits,
    /// Source identity for provenance tracking.
    pub source: PluginSourceIdentity,
    /// The verified WASM bytes. File loads read once and instantiate from these
    /// bytes to close TOCTOU. Memory loads store the provided slice.
    pub wasm_bytes: Bytes,
    /// Cryptographic verification metadata, if the plugin was signature-verified.
    pub verified_signature: Option<VerifiedPluginSignature>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Manifest → Runtime Conversion
// ═══════════════════════════════════════════════════════════════════════════════

/// Convert a `PluginManifest` into `WasmResourceLimits` by merging
/// manifest-declared values with operator-supplied defaults.
///
/// Invariant: The resulting `capabilities` field is always set from the
/// manifest — never from the defaults. This ensures per-plugin capability
/// enforcement at runtime.
pub fn limits_from_manifest(
    manifest: &PluginManifest,
    defaults: &WasmResourceLimits,
) -> WasmResourceLimits {
    let mut limits = defaults.clone();

    // Timeout: manifest is ms, WasmResourceLimits is seconds. Round up to
    // avoid silently losing precision — a 50ms manifest timeout becomes 1s
    // in the runtime, which is the minimum granularity.
    limits.timeout_seconds = manifest.limits.timeout_ms.div_ceil(1000).max(1);

    // Concurrency: manifest.max_concurrency → runtime.max_instances
    limits.max_instances = manifest.limits.max_concurrency.max(1);

    // Capabilities: always from the manifest, never from defaults.
    limits.capabilities = Arc::new(manifest.capabilities.clone());

    // Fuel: manifest overrides default if present.
    if let Some(fuel) = manifest.limits.fuel {
        limits.max_cpu_fuel = fuel;
    }

    // Memory pages: convert 64 KiB pages to MB, rounding up.
    if let Some(memory_pages) = manifest.limits.memory_pages {
        let bytes = memory_pages as usize * 64 * 1024;
        limits.max_memory_mb = bytes.div_ceil(1024 * 1024).max(1);
    }

    // Mesh capability & DHT prefixes:
    // - mesh = false: always clear prefixes (plugin has no mesh access).
    // - mesh = true: DO NOT inherit global prefixes. The manifest must
    //   explicitly declare allowed prefixes (Phase 2 feature). For now,
    //   mesh=true grants the capability flag only, not prefix access.
    limits.allowed_dht_prefixes.clear();

    limits
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limits() -> WasmResourceLimits {
        WasmResourceLimits::default()
    }

    fn minimal_manifest() -> PluginManifest {
        PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            ..Default::default()
        }
    }

    #[test]
    fn minimal_manifest_defaults_to_all_deny_capabilities() {
        let manifest = minimal_manifest();
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert!(!limits.capabilities.request_inspect);
        assert!(!limits.capabilities.request_mutate);
        assert!(!limits.capabilities.response_inspect);
        assert!(!limits.capabilities.response_mutate);
        assert!(!limits.capabilities.metrics);
        assert!(!limits.capabilities.persistence);
        assert!(limits.capabilities.filesystem_read.is_empty());
        assert!(limits.capabilities.filesystem_write.is_empty());
        assert!(limits.capabilities.network.is_empty());
        assert!(!limits.capabilities.mesh);
        assert!(!limits.capabilities.admin_events);
    }

    #[test]
    fn request_inspect_maps_correctly() {
        let mut manifest = minimal_manifest();
        manifest.capabilities.request_inspect = true;
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert!(limits.capabilities.request_inspect);
        assert!(!limits.capabilities.request_mutate);
    }

    #[test]
    fn mesh_false_deny_even_if_defaults_have_mesh() {
        let mut manifest = minimal_manifest();
        manifest.capabilities.mesh = false;
        let mut defaults = default_limits();
        defaults.allowed_dht_prefixes = vec!["threat_indicator:".into()];
        let limits = limits_from_manifest(&manifest, &defaults);
        assert!(!limits.capabilities.mesh);
        assert!(limits.allowed_dht_prefixes.is_empty());
    }

    #[test]
    fn mesh_true_does_not_inherit_broad_prefixes() {
        let mut manifest = minimal_manifest();
        manifest.capabilities.mesh = true;
        let mut defaults = default_limits();
        defaults.allowed_dht_prefixes = vec!["threat_indicator:".into(), "yara_rule:".into()];
        let limits = limits_from_manifest(&manifest, &defaults);
        assert!(limits.capabilities.mesh);
        // Global prefixes are NOT inherited — mesh=true only grants the
        // capability flag, not sensitive prefix access.
        assert!(limits.allowed_dht_prefixes.is_empty());
    }

    #[test]
    fn fuel_maps_to_max_cpu_fuel() {
        let mut manifest = minimal_manifest();
        manifest.limits.fuel = Some(1234);
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.max_cpu_fuel, 1234);
    }

    #[test]
    fn fuel_none_keeps_default() {
        let manifest = minimal_manifest();
        let defaults = default_limits();
        let limits = limits_from_manifest(&manifest, &defaults);
        assert_eq!(limits.max_cpu_fuel, defaults.max_cpu_fuel);
    }

    #[test]
    fn memory_pages_maps_to_effective_limit() {
        let mut manifest = minimal_manifest();
        manifest.limits.memory_pages = Some(32);
        let limits = limits_from_manifest(&manifest, &default_limits());
        // 32 pages * 64 KiB = 2 MiB → max_memory_mb = 2
        assert_eq!(limits.max_memory_mb, 2);
    }

    #[test]
    fn memory_pages_rounds_up() {
        let mut manifest = minimal_manifest();
        manifest.limits.memory_pages = Some(1); // 64 KiB
        let limits = limits_from_manifest(&manifest, &default_limits());
        // 64 KiB rounds up to 1 MB minimum
        assert_eq!(limits.max_memory_mb, 1);
    }

    #[test]
    fn max_concurrency_maps_to_max_instances() {
        let mut manifest = minimal_manifest();
        manifest.limits.max_concurrency = 3;
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.max_instances, 3);
    }

    #[test]
    fn timeout_ms_rounds_up_to_seconds() {
        let mut manifest = minimal_manifest();
        manifest.limits.timeout_ms = 50; // 50ms → 1s minimum
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.timeout_seconds, 1);
    }

    #[test]
    fn timeout_ms_1500_becomes_2_seconds() {
        let mut manifest = minimal_manifest();
        manifest.limits.timeout_ms = 1500;
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.timeout_seconds, 2);
    }

    #[test]
    fn timeout_ms_zero_becomes_1_second_minimum() {
        let mut manifest = minimal_manifest();
        manifest.limits.timeout_ms = 0;
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.timeout_seconds, 1);
    }

    #[test]
    fn max_concurrency_zero_becomes_1_minimum() {
        let mut manifest = minimal_manifest();
        manifest.limits.max_concurrency = 0;
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert_eq!(limits.max_instances, 1);
    }

    #[test]
    fn filesystem_read_maps_correctly() {
        let mut manifest = minimal_manifest();
        manifest.capabilities.filesystem_read = vec!["/tmp/*".into()];
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert!(limits
            .capabilities
            .permits(super::super::types::PluginCapability::FilesystemRead));
    }

    #[test]
    fn network_maps_correctly() {
        let mut manifest = minimal_manifest();
        manifest.capabilities.network = vec!["api.example.com:443".into()];
        let limits = limits_from_manifest(&manifest, &default_limits());
        assert!(limits
            .capabilities
            .permits(super::super::types::PluginCapability::Network));
    }

    #[test]
    fn policy_source_identity_populated_from_manifest() {
        let mut manifest = minimal_manifest();
        manifest.trust_tier = PluginTrustTier::SignedSandboxed;
        let source = PluginSourceIdentity {
            path: Some(PathBuf::from("/plugins/test.wasm")),
            ..Default::default()
        };
        let policy = EffectivePluginPolicy {
            name: manifest.name.clone(),
            version: manifest.version.clone(),
            trust_tier: manifest.trust_tier,
            capabilities: Arc::new(manifest.capabilities.clone()),
            limits: limits_from_manifest(&manifest, &default_limits()),
            manifest_limits: manifest.limits.clone(),
            source,
        };
        assert_eq!(policy.trust_tier, PluginTrustTier::SignedSandboxed);
        assert_eq!(
            policy.source.path,
            Some(PathBuf::from("/plugins/test.wasm"))
        );
    }
}
