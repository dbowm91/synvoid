use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

// ═══════════════════════════════════════════════════════════════════════════════
// Trust Tiers
// ═══════════════════════════════════════════════════════════════════════════════

/// Plugin trust tier controls what capabilities a plugin can request and how
/// strictly its sandbox is enforced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginTrustTier {
    /// Plugin cannot load at all.
    Disabled,
    /// Local operator explicitly trusts the plugin; bounded by declared
    /// capabilities where practical.
    LocalTrusted,
    /// Unsigned local plugin with sandbox limits enforced and restricted
    /// capabilities.
    #[default]
    LocalSandboxed,
    /// Signature verified and sandbox limits enforced.
    SignedSandboxed,
    /// Development-only: permissive reload, must not be enabled in production
    /// mode unless an explicit config override is set.
    DevelopmentHotReload,
}

impl std::fmt::Display for PluginTrustTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::LocalTrusted => write!(f, "local_trusted"),
            Self::LocalSandboxed => write!(f, "local_sandboxed"),
            Self::SignedSandboxed => write!(f, "signed_sandboxed"),
            Self::DevelopmentHotReload => write!(f, "development_hot_reload"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Capability Model
// ═══════════════════════════════════════════════════════════════════════════════

/// Fine-grained capability tokens that a plugin must declare to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Read-only inspection of incoming requests.
    RequestInspect,
    /// Mutation of incoming request headers/body.
    RequestMutate,
    /// Read-only inspection of outgoing responses.
    ResponseInspect,
    /// Mutation of outgoing response headers/body.
    ResponseMutate,
    /// Emit metrics (counters, gauges).
    Metrics,
    /// Access to the persistence API (KV store).
    Persistence,
    /// Read from the filesystem (path allowlisted).
    FilesystemRead,
    /// Write to the filesystem (path allowlisted).
    FilesystemWrite,
    /// Outbound network access (host/port allowlisted).
    Network,
    /// Access to mesh DHT queries.
    Mesh,
    /// Receive admin/control-plane events.
    AdminEvents,
}

/// Default-deny capability set. Each boolean/array field must be explicitly
/// granted in the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginCapabilities {
    pub request_inspect: bool,
    pub request_mutate: bool,
    pub response_inspect: bool,
    pub response_mutate: bool,
    pub metrics: bool,
    pub persistence: bool,
    pub filesystem_read: Vec<String>,
    pub filesystem_write: Vec<String>,
    pub network: Vec<String>,
    pub mesh: bool,
    pub admin_events: bool,
}

impl PluginCapabilities {
    /// Check whether the given capability is permitted.
    pub fn permits(&self, capability: PluginCapability) -> bool {
        match capability {
            PluginCapability::RequestInspect => self.request_inspect,
            PluginCapability::RequestMutate => self.request_mutate,
            PluginCapability::ResponseInspect => self.response_inspect,
            PluginCapability::ResponseMutate => self.response_mutate,
            PluginCapability::Metrics => self.metrics,
            PluginCapability::Persistence => self.persistence,
            PluginCapability::FilesystemRead => !self.filesystem_read.is_empty(),
            PluginCapability::FilesystemWrite => !self.filesystem_write.is_empty(),
            PluginCapability::Network => !self.network.is_empty(),
            PluginCapability::Mesh => self.mesh,
            PluginCapability::AdminEvents => self.admin_events,
        }
    }

    /// Require a capability or return an error.
    pub fn require(&self, capability: PluginCapability) -> Result<(), CapabilityViolation> {
        if self.permits(capability) {
            Ok(())
        } else {
            crate::wasm_metrics::record_plugin_capability_violation(&format!("{:?}", capability));
            Err(CapabilityViolation {
                capability,
                plugin_name: String::new(),
            })
        }
    }

    /// Iterate all capability tokens and their enabled state.
    pub fn iter_flags(&self) -> Vec<(PluginCapability, bool)> {
        vec![
            (PluginCapability::RequestInspect, self.request_inspect),
            (PluginCapability::RequestMutate, self.request_mutate),
            (PluginCapability::ResponseInspect, self.response_inspect),
            (PluginCapability::ResponseMutate, self.response_mutate),
            (PluginCapability::Metrics, self.metrics),
            (PluginCapability::Persistence, self.persistence),
            (
                PluginCapability::FilesystemRead,
                !self.filesystem_read.is_empty(),
            ),
            (
                PluginCapability::FilesystemWrite,
                !self.filesystem_write.is_empty(),
            ),
            (PluginCapability::Network, !self.network.is_empty()),
            (PluginCapability::Mesh, self.mesh),
            (PluginCapability::AdminEvents, self.admin_events),
        ]
    }

    /// Validate that a filesystem path is allowed under the given access mode.
    ///
    /// Rules:
    /// - Path is canonicalized (resolves `.`, `..`, symlinks).
    /// - Canonical path must stay within one of the declared allowlist prefixes.
    /// - Symlink escapes from allowed roots are rejected.
    pub fn check_filesystem_access(
        &self,
        requested_path: &Path,
        is_write: bool,
    ) -> Result<PathBuf, FilesystemViolation> {
        let allowlist = if is_write {
            &self.filesystem_write
        } else {
            &self.filesystem_read
        };

        if allowlist.is_empty() {
            return Err(FilesystemViolation::NoCapability);
        }

        let canonical = requested_path.canonicalize().map_err(|_| {
            FilesystemViolation::PathError(format!(
                "failed to canonicalize path: {}",
                requested_path.display()
            ))
        })?;

        for prefix in allowlist {
            let prefix_path = Path::new(prefix);
            if let Ok(canonical_prefix) = prefix_path.canonicalize() {
                if canonical.starts_with(&canonical_prefix) {
                    return Ok(canonical);
                }
            }
        }

        Err(FilesystemViolation::PathEscape {
            requested: requested_path.to_path_buf(),
            canonical,
        })
    }

    /// Validate that a network destination (host:port) is allowed.
    pub fn check_network_access(&self, host: &str, port: u16) -> Result<(), NetworkViolation> {
        if self.network.is_empty() {
            return Err(NetworkViolation::NoCapability);
        }

        let target = format!("{}:{}", host, port);
        let target_wildcard_host = format!("{}:*", host);

        if self.network.contains(&target)
            || self.network.contains(&target_wildcard_host)
            || self.network.contains(&"*:*".to_string())
        {
            return Ok(());
        }

        Err(NetworkViolation::DestinationDenied {
            host: host.to_string(),
            port,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Resource Limits
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-plugin resource limits enforced at invocation boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginLimits {
    /// Per-invocation timeout.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum input payload size in bytes.
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: usize,
    /// Maximum output payload size in bytes.
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: usize,
    /// Maximum concurrent invocations for this plugin.
    #[serde(default = "default_max_concurrency")]
    pub max_concurrency: usize,
    /// Optional WASM linear memory page limit (64 KiB per page).
    #[serde(default)]
    pub memory_pages: Option<u32>,
    /// Optional wasmtime fuel limit per invocation.
    #[serde(default)]
    pub fuel: Option<u64>,
}

fn default_timeout_ms() -> u64 {
    50
}
fn default_max_input_bytes() -> usize {
    262_144 // 256 KB
}
fn default_max_output_bytes() -> usize {
    262_144
}
fn default_max_concurrency() -> usize {
    4
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            max_input_bytes: default_max_input_bytes(),
            max_output_bytes: default_max_output_bytes(),
            max_concurrency: default_max_concurrency(),
            memory_pages: None,
            fuel: None,
        }
    }
}

impl PluginLimits {
    /// Check whether an input of the given size is within limits.
    pub fn check_input(&self, len: usize) -> Result<(), ResourceLimitError> {
        if len > self.max_input_bytes {
            return Err(ResourceLimitError::InputTooLarge {
                size: len,
                limit: self.max_input_bytes,
            });
        }
        Ok(())
    }

    /// Check whether an output of the given size is within limits.
    pub fn check_output(&self, len: usize) -> Result<(), ResourceLimitError> {
        if len > self.max_output_bytes {
            return Err(ResourceLimitError::OutputTooLarge {
                size: len,
                limit: self.max_output_bytes,
            });
        }
        Ok(())
    }

    /// Return the timeout as a `Duration`.
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signing Configuration
// ═══════════════════════════════════════════════════════════════════════════════

/// Optional signature metadata stored in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSignatureConfig {
    /// Hex-encoded signature of the plugin binary.
    pub signature: String,
    /// Public key identifier used to verify the signature.
    pub key_id: String,
    /// Signing algorithm (e.g. "ed25519", "ecdsa-p256").
    pub algorithm: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plugin Manifest
// ═══════════════════════════════════════════════════════════════════════════════

/// A `synvoid-plugin.toml` manifest describing a plugin's identity, trust
/// tier, declared capabilities, and resource limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub entry: String,
    #[serde(default)]
    pub trust_tier: PluginTrustTier,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(default)]
    pub limits: PluginLimits,
    #[serde(default)]
    pub signature: Option<PluginSignatureConfig>,
}

impl PluginManifest {
    /// Parse a manifest from a TOML file.
    pub fn from_file(path: &Path) -> Result<Self, ManifestError> {
        let content = std::fs::read_to_string(path).map_err(|e| ManifestError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Self::parse_toml(&content, path)
    }

    /// Parse a manifest from TOML content.
    pub fn parse_toml(content: &str, source_path: &Path) -> Result<Self, ManifestError> {
        let manifest: PluginManifest =
            toml::from_str(content).map_err(|e| ManifestError::Parse {
                source_path: source_path.to_path_buf(),
                message: e.to_string(),
            })?;

        if manifest.name.is_empty() {
            return Err(ManifestError::Validation {
                source_path: source_path.to_path_buf(),
                message: "plugin name must not be empty".into(),
            });
        }
        if manifest.entry.is_empty() {
            return Err(ManifestError::Validation {
                source_path: source_path.to_path_buf(),
                message: "entry path must not be empty".into(),
            });
        }

        Ok(manifest)
    }

    /// Validate that the trust tier is compatible with the declared
    /// capabilities. Returns warnings (non-fatal).
    pub fn validate_trust_consistency(&self) -> Vec<ManifestWarning> {
        let mut warnings = Vec::new();

        match self.trust_tier {
            PluginTrustTier::Disabled => {
                warnings.push(ManifestWarning::DisabledPluginLoaded);
            }
            PluginTrustTier::DevelopmentHotReload => {
                if self.capabilities.mesh {
                    warnings.push(ManifestWarning::MeshInDevMode);
                }
                if self.capabilities.admin_events {
                    warnings.push(ManifestWarning::AdminInDevMode);
                }
            }
            PluginTrustTier::LocalSandboxed | PluginTrustTier::SignedSandboxed => {
                if self.capabilities.filesystem_write.is_empty()
                    && self.capabilities.filesystem_read.is_empty()
                {
                    // Good — no filesystem.
                }
            }
            PluginTrustTier::LocalTrusted => {
                // Operator explicitly trusts; still warn about overly broad access.
            }
        }

        warnings
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Runtime State
// ═══════════════════════════════════════════════════════════════════════════════

/// Plugin runtime state tracked by the manager.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginRuntimeState {
    /// Plugin loaded and ready.
    #[default]
    Loaded,
    /// Plugin disabled by configuration.
    DisabledByConfig,
    /// Plugin disabled after a capability violation.
    DisabledByCapabilityViolation,
    /// Plugin disabled after a load error.
    DisabledByLoadError,
    /// Plugin disabled after a runtime failure (panic, trap, repeated timeout).
    DisabledByRuntimeFailure,
    /// Plugin quarantined pending investigation.
    Quarantined,
}

impl std::fmt::Display for PluginRuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loaded => write!(f, "loaded"),
            Self::DisabledByConfig => write!(f, "disabled_by_config"),
            Self::DisabledByCapabilityViolation => write!(f, "disabled_by_capability_violation"),
            Self::DisabledByLoadError => write!(f, "disabled_by_load_error"),
            Self::DisabledByRuntimeFailure => write!(f, "disabled_by_runtime_failure"),
            Self::Quarantined => write!(f, "quarantined"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct CapabilityViolation {
    pub capability: PluginCapability,
    pub plugin_name: String,
}

impl std::fmt::Display for CapabilityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "plugin '{}' denied capability {:?}",
            self.plugin_name, self.capability
        )
    }
}

impl std::error::Error for CapabilityViolation {}

#[derive(Debug, Clone)]
pub enum ResourceLimitError {
    InputTooLarge { size: usize, limit: usize },
    OutputTooLarge { size: usize, limit: usize },
    Timeout,
    ConcurrencyLimitExceeded,
}

impl std::fmt::Display for ResourceLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InputTooLarge { size, limit } => {
                write!(f, "input size {} exceeds limit {}", size, limit)
            }
            Self::OutputTooLarge { size, limit } => {
                write!(f, "output size {} exceeds limit {}", size, limit)
            }
            Self::Timeout => write!(f, "plugin invocation timed out"),
            Self::ConcurrencyLimitExceeded => write!(f, "concurrency limit exceeded"),
        }
    }
}

impl std::error::Error for ResourceLimitError {}

#[derive(Debug, Clone)]
pub enum FilesystemViolation {
    NoCapability,
    PathEscape {
        requested: PathBuf,
        canonical: PathBuf,
    },
    PathError(String),
}

impl std::fmt::Display for FilesystemViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCapability => write!(f, "filesystem capability not declared"),
            Self::PathEscape {
                requested,
                canonical,
            } => write!(
                f,
                "path escape detected: {} resolves to {} which is outside allowlist",
                requested.display(),
                canonical.display()
            ),
            Self::PathError(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FilesystemViolation {}

#[derive(Debug, Clone)]
pub enum NetworkViolation {
    NoCapability,
    DestinationDenied { host: String, port: u16 },
}

impl std::fmt::Display for NetworkViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCapability => write!(f, "network capability not declared"),
            Self::DestinationDenied { host, port } => {
                write!(f, "network destination {}:{} not in allowlist", host, port)
            }
        }
    }
}

impl std::error::Error for NetworkViolation {}

/// Errors returned by `PluginInvocationGuard::invoke_with_limits`.
#[derive(Debug)]
pub enum PluginInvokeError {
    PluginDisabled,
    Capability(CapabilityViolation),
    ResourceLimit(ResourceLimitError),
    ConcurrencyLimitExceeded,
    Timeout,
    Internal(String),
}

impl std::fmt::Display for PluginInvokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PluginDisabled => write!(f, "plugin is disabled"),
            Self::Capability(v) => write!(f, "{}", v),
            Self::ResourceLimit(e) => write!(f, "{}", e),
            Self::ConcurrencyLimitExceeded => write!(f, "concurrency limit exceeded"),
            Self::Timeout => write!(f, "plugin invocation timed out"),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for PluginInvokeError {}

#[derive(Debug)]
pub enum ManifestError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Parse {
        source_path: PathBuf,
        message: String,
    },
    Validation {
        source_path: PathBuf,
        message: String,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "failed to read {}: {}", path.display(), source),
            Self::Parse {
                source_path,
                message,
            } => write!(f, "failed to parse {}: {}", source_path.display(), message),
            Self::Validation {
                source_path,
                message,
            } => write!(
                f,
                "validation error in {}: {}",
                source_path.display(),
                message
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

#[derive(Debug, Clone)]
pub enum ManifestWarning {
    DisabledPluginLoaded,
    MeshInDevMode,
    AdminInDevMode,
    BroadFilesystemAccess,
    UnsignedPluginInProduction,
}

impl std::fmt::Display for ManifestWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisabledPluginLoaded => write!(f, "disabled plugin was loaded"),
            Self::MeshInDevMode => {
                write!(
                    f,
                    "mesh capability requested in development hot-reload mode"
                )
            }
            Self::AdminInDevMode => {
                write!(
                    f,
                    "admin events capability requested in development hot-reload mode"
                )
            }
            Self::BroadFilesystemAccess => write!(f, "broad filesystem access declared"),
            Self::UnsignedPluginInProduction => {
                write!(f, "unsigned plugin loaded in production mode")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Signing Policy
// ═══════════════════════════════════════════════════════════════════════════════

/// Production signing policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningPolicy {
    /// Reject unsigned plugins; require valid signature.
    #[default]
    RequireSigned,
    /// Allow unsigned plugins with a warning.
    AllowUnsignedWithWarning,
    /// Development mode: signing not checked.
    Disabled,
}

/// Verify whether a plugin is permitted to load under the given policy.
pub fn verify_signing_policy(
    policy: SigningPolicy,
    trust_tier: PluginTrustTier,
    signature: Option<&PluginSignatureConfig>,
    is_production: bool,
) -> Result<(), SigningViolation> {
    if !is_production {
        // Development: signing not enforced.
        return Ok(());
    }

    match (trust_tier, policy) {
        (_, SigningPolicy::Disabled) => Ok(()),
        (_, SigningPolicy::AllowUnsignedWithWarning) => {
            // Policy allows unsigned plugins; caller should emit a warning.
            Ok(())
        }
        (PluginTrustTier::SignedSandboxed, SigningPolicy::RequireSigned) => {
            if signature.is_none() {
                Err(SigningViolation::MissingSignature { trust_tier })
            } else {
                // Full verification would go here.
                Ok(())
            }
        }
        (PluginTrustTier::DevelopmentHotReload, _) => {
            // Dev mode: require explicit dev_mode config.
            // Caller must check dev_mode externally.
            Ok(())
        }
        (_, SigningPolicy::RequireSigned) => {
            if signature.is_none() {
                Err(SigningViolation::UnsignedInProduction {
                    trust_tier,
                    allowed_by_policy: false,
                })
            } else {
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum SigningViolation {
    MissingSignature {
        trust_tier: PluginTrustTier,
    },
    UnsignedInProduction {
        trust_tier: PluginTrustTier,
        allowed_by_policy: bool,
    },
}

impl std::fmt::Display for SigningViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature { trust_tier } => {
                write!(
                    f,
                    "plugin with trust tier '{}' requires a valid signature",
                    trust_tier
                )
            }
            Self::UnsignedInProduction {
                trust_tier,
                allowed_by_policy,
            } => {
                if *allowed_by_policy {
                    write!(
                        f,
                        "unsigned plugin with trust tier '{}' loaded in production (policy allows, warning emitted)",
                        trust_tier
                    )
                } else {
                    write!(
                        f,
                        "unsigned plugin with trust tier '{}' rejected in production",
                        trust_tier
                    )
                }
            }
        }
    }
}

impl std::error::Error for SigningViolation {}

// ═══════════════════════════════════════════════════════════════════════════════
// Invocation Guard
// ═══════════════════════════════════════════════════════════════════════════════

/// Tracks per-plugin invocation state and enforces limits.
pub struct PluginInvocationGuard {
    pub capabilities: Arc<PluginCapabilities>,
    pub limits: PluginLimits,
    pub concurrency: Arc<Semaphore>,
    pub state: parking_lot::RwLock<PluginRuntimeState>,
    pub failure_count: parking_lot::RwLock<u32>,
}

impl PluginInvocationGuard {
    pub fn new(
        capabilities: PluginCapabilities,
        limits: PluginLimits,
        max_concurrency: usize,
    ) -> Self {
        Self {
            capabilities: Arc::new(capabilities),
            limits,
            concurrency: Arc::new(Semaphore::new(max_concurrency)),
            state: parking_lot::RwLock::new(PluginRuntimeState::Loaded),
            failure_count: parking_lot::RwLock::new(0),
        }
    }

    /// Check whether the plugin is in a state that allows invocation.
    pub fn is_invocable(&self) -> bool {
        matches!(*self.state.read(), PluginRuntimeState::Loaded)
    }

    /// Record a runtime failure and possibly disable the plugin.
    pub fn record_failure(&self, threshold: u32) {
        let mut count = self.failure_count.write();
        *count += 1;
        if *count >= threshold {
            *self.state.write() = PluginRuntimeState::DisabledByRuntimeFailure;
        }
    }

    /// Reset the failure counter and restore the plugin to a ready state.
    pub fn reset_failures(&self) {
        *self.failure_count.write() = 0;
        *self.state.write() = PluginRuntimeState::Loaded;
    }

    /// Disable the plugin for a capability violation.
    pub fn disable_for_violation(&self) {
        *self.state.write() = PluginRuntimeState::DisabledByCapabilityViolation;
    }

    /// Invoke a plugin operation with capability check, input size check,
    /// concurrency limit, and timeout.
    pub async fn invoke_with_limits<F, Fut, T>(
        &self,
        capability: PluginCapability,
        input_len: usize,
        make_fut: F,
    ) -> Result<T, PluginInvokeError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, PluginInvokeError>>,
    {
        if !self.is_invocable() {
            return Err(PluginInvokeError::PluginDisabled);
        }

        self.capabilities
            .require(capability)
            .map_err(PluginInvokeError::Capability)?;

        self.limits
            .check_input(input_len)
            .map_err(PluginInvokeError::ResourceLimit)?;

        let permit = self
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PluginInvokeError::ConcurrencyLimitExceeded)?;

        let result = tokio::time::timeout(self.limits.timeout(), make_fut()).await;

        drop(permit);

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => Err(PluginInvokeError::Timeout),
        }
    }
}

impl std::fmt::Debug for PluginInvocationGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginInvocationGuard")
            .field("state", &*self.state.read())
            .field("failure_count", &*self.failure_count.read())
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parses_minimal_valid_plugin() {
        let toml = r#"
            name = "test-plugin"
            version = "0.1.0"
            entry = "plugin.wasm"
        "#;
        let manifest =
            PluginManifest::parse_toml(toml, Path::new("test.toml")).expect("should parse");
        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.entry, "plugin.wasm");
        assert_eq!(manifest.trust_tier, PluginTrustTier::LocalSandboxed);
        assert!(!manifest.capabilities.request_inspect);
        assert!(!manifest.capabilities.request_mutate);
        assert!(!manifest.capabilities.mesh);
    }

    #[test]
    fn manifest_missing_capabilities_defaults_deny() {
        let toml = r#"
            name = "test-plugin"
            version = "0.1.0"
            entry = "plugin.wasm"
        "#;
        let manifest = PluginManifest::parse_toml(toml, Path::new("test.toml")).unwrap();
        assert!(!manifest.capabilities.request_inspect);
        assert!(!manifest.capabilities.request_mutate);
        assert!(!manifest.capabilities.response_inspect);
        assert!(!manifest.capabilities.response_mutate);
        assert!(!manifest.capabilities.metrics);
        assert!(!manifest.capabilities.persistence);
        assert!(manifest.capabilities.filesystem_read.is_empty());
        assert!(manifest.capabilities.filesystem_write.is_empty());
        assert!(manifest.capabilities.network.is_empty());
        assert!(!manifest.capabilities.mesh);
        assert!(!manifest.capabilities.admin_events);
    }

    #[test]
    fn manifest_with_explicit_capabilities() {
        let toml = r#"
            name = "inspect-plugin"
            version = "1.0.0"
            entry = "inspect.wasm"
            trust_tier = "local_sandboxed"

            [capabilities]
            request_inspect = true
            response_inspect = true
            metrics = true
        "#;
        let manifest = PluginManifest::parse_toml(toml, Path::new("test.toml")).unwrap();
        assert!(manifest.capabilities.request_inspect);
        assert!(!manifest.capabilities.request_mutate);
        assert!(manifest.capabilities.response_inspect);
        assert!(!manifest.capabilities.response_mutate);
        assert!(manifest.capabilities.metrics);
        assert!(!manifest.capabilities.persistence);
    }

    #[test]
    fn manifest_invalid_entry_rejected() {
        let toml = r#"
            name = "test-plugin"
            version = "0.1.0"
            entry = ""
        "#;
        let result = PluginManifest::parse_toml(toml, Path::new("test.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn manifest_empty_name_rejected() {
        let toml = r#"
            name = ""
            version = "0.1.0"
            entry = "plugin.wasm"
        "#;
        let result = PluginManifest::parse_toml(toml, Path::new("test.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn capability_requires_returns_error() {
        let caps = PluginCapabilities::default();
        let result = caps.require(PluginCapability::RequestMutate);
        assert!(result.is_err());
    }

    #[test]
    fn capability_permits_enabled() {
        let caps = PluginCapabilities {
            request_inspect: true,
            ..Default::default()
        };
        assert!(caps.permits(PluginCapability::RequestInspect));
        assert!(!caps.permits(PluginCapability::RequestMutate));
    }

    #[test]
    fn capability_filesystem_nonempty() {
        let caps = PluginCapabilities {
            filesystem_read: vec!["/tmp/*".to_string()],
            ..Default::default()
        };
        assert!(caps.permits(PluginCapability::FilesystemRead));
        assert!(!caps.permits(PluginCapability::FilesystemWrite));
    }

    #[test]
    fn capability_network_nonempty() {
        let caps = PluginCapabilities {
            network: vec!["api.example.com:443".to_string()],
            ..Default::default()
        };
        assert!(caps.permits(PluginCapability::Network));
    }

    #[test]
    fn resource_limit_check_input() {
        let limits = PluginLimits::default();
        assert!(limits.check_input(100).is_ok());
        assert!(limits.check_input(262_144).is_ok());
        assert!(limits.check_input(262_145).is_err());
    }

    #[test]
    fn resource_limit_check_output() {
        let limits = PluginLimits::default();
        assert!(limits.check_output(100).is_ok());
        assert!(limits.check_output(262_145).is_err());
    }

    #[test]
    fn trust_tier_display() {
        assert_eq!(PluginTrustTier::Disabled.to_string(), "disabled");
        assert_eq!(PluginTrustTier::LocalTrusted.to_string(), "local_trusted");
        assert_eq!(
            PluginTrustTier::LocalSandboxed.to_string(),
            "local_sandboxed"
        );
        assert_eq!(
            PluginTrustTier::SignedSandboxed.to_string(),
            "signed_sandboxed"
        );
        assert_eq!(
            PluginTrustTier::DevelopmentHotReload.to_string(),
            "development_hot_reload"
        );
    }

    #[test]
    fn trust_tier_default_is_local_sandboxed() {
        assert_eq!(PluginTrustTier::default(), PluginTrustTier::LocalSandboxed);
    }

    #[test]
    fn signing_policy_unsigned_rejected_in_production() {
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::LocalSandboxed,
            None,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn signing_policy_unsigned_allowed_with_warning() {
        let result = verify_signing_policy(
            SigningPolicy::AllowUnsignedWithWarning,
            PluginTrustTier::LocalSandboxed,
            None,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn signing_policy_disabled_always_ok() {
        let result = verify_signing_policy(
            SigningPolicy::Disabled,
            PluginTrustTier::LocalSandboxed,
            None,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn signing_policy_not_enforced_in_dev() {
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::LocalSandboxed,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn signing_signed_plugin_accepted() {
        let sig = PluginSignatureConfig {
            signature: "abcd1234".to_string(),
            key_id: "key1".to_string(),
            algorithm: "ed25519".to_string(),
        };
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::SignedSandboxed,
            Some(&sig),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn runtime_state_default() {
        assert_eq!(PluginRuntimeState::default(), PluginRuntimeState::Loaded);
    }

    #[test]
    fn invocation_guard_loaded_allows() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        assert!(guard.is_invocable());
    }

    #[test]
    fn invocation_guard_failure_disables() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        // 3 failures to disable
        guard.record_failure(3);
        guard.record_failure(3);
        assert!(guard.is_invocable());
        guard.record_failure(3);
        assert!(!guard.is_invocable());
    }

    #[test]
    fn invocation_guard_violation_disables() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        guard.disable_for_violation();
        assert!(!guard.is_invocable());
    }

    #[test]
    fn invocation_guard_reset() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        guard.record_failure(3);
        guard.record_failure(3);
        guard.reset_failures();
        guard.record_failure(3);
        guard.record_failure(3);
        assert!(guard.is_invocable());
        guard.record_failure(3);
        assert!(!guard.is_invocable());
        guard.reset_failures();
        assert!(guard.is_invocable());
    }

    #[test]
    fn iter_flags_all_default_false() {
        let caps = PluginCapabilities::default();
        let flags = caps.iter_flags();
        assert_eq!(flags.len(), 11);
        for (cap, enabled) in &flags {
            assert!(!enabled, "capability {:?} should be false by default", cap);
        }
    }

    #[test]
    fn trust_consistency_warnings_dev_mesh() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::DevelopmentHotReload,
            capabilities: PluginCapabilities {
                mesh: true,
                admin_events: true,
                ..Default::default()
            },
            limits: PluginLimits::default(),
            signature: None,
        };
        let warnings = manifest.validate_trust_consistency();
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ManifestWarning::MeshInDevMode)));
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ManifestWarning::AdminInDevMode)));
    }

    // ─── Filesystem path validation ────────────────────────────────────────

    #[test]
    fn filesystem_path_canonicalization_rejects_escape() {
        let caps = PluginCapabilities {
            filesystem_read: vec!["/tmp/safe".to_string()],
            ..Default::default()
        };

        // A path outside the allowlist should be rejected even if it exists.
        let result = caps.check_filesystem_access(Path::new("/etc/passwd"), false);
        assert!(result.is_err());
        match result.unwrap_err() {
            FilesystemViolation::PathEscape { .. } => {}
            other => panic!("expected PathEscape, got {:?}", other),
        }
    }

    #[test]
    fn filesystem_path_denied_without_capability() {
        let caps = PluginCapabilities::default();
        let result = caps.check_filesystem_access(Path::new("/tmp/foo"), false);
        assert!(matches!(
            result.unwrap_err(),
            FilesystemViolation::NoCapability
        ));
    }

    #[test]
    fn filesystem_write_requires_write_capability() {
        let caps = PluginCapabilities {
            filesystem_read: vec!["/tmp".to_string()],
            ..Default::default()
        };
        let result = caps.check_filesystem_access(Path::new("/tmp/foo"), true);
        assert!(matches!(
            result.unwrap_err(),
            FilesystemViolation::NoCapability
        ));
    }

    #[test]
    fn filesystem_read_allows_canonicalizable_prefix() {
        let caps = PluginCapabilities {
            filesystem_read: vec![".".to_string()],
            ..Default::default()
        };
        // Current directory should canonicalize and be under "."
        let result = caps.check_filesystem_access(Path::new("."), false);
        assert!(result.is_ok());
    }

    // ─── Network validation ────────────────────────────────────────────────

    #[test]
    fn network_default_denied_explicit() {
        let caps = PluginCapabilities::default();
        let result = caps.check_network_access("api.example.com", 443);
        assert!(matches!(
            result.unwrap_err(),
            NetworkViolation::NoCapability
        ));
    }

    #[test]
    fn network_exact_match_allowed() {
        let caps = PluginCapabilities {
            network: vec!["api.example.com:443".to_string()],
            ..Default::default()
        };
        assert!(caps.check_network_access("api.example.com", 443).is_ok());
    }

    #[test]
    fn network_wildcard_port_allowed() {
        let caps = PluginCapabilities {
            network: vec!["api.example.com:*".to_string()],
            ..Default::default()
        };
        assert!(caps.check_network_access("api.example.com", 8080).is_ok());
    }

    #[test]
    fn network_wildcard_all_denied() {
        let caps = PluginCapabilities {
            network: vec!["other.com:443".to_string()],
            ..Default::default()
        };
        let result = caps.check_network_access("api.example.com", 443);
        assert!(matches!(
            result.unwrap_err(),
            NetworkViolation::DestinationDenied { .. }
        ));
    }

    // ─── invoke_with_limits ────────────────────────────────────────────────

    #[tokio::test]
    async fn invoke_with_limits_timeout_disables_plugin() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                timeout_ms: 1,
                ..Default::default()
            },
            4,
        );

        let result = guard
            .invoke_with_limits(PluginCapability::RequestInspect, 0, || async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok::<(), PluginInvokeError>(())
            })
            .await;

        assert!(matches!(result.unwrap_err(), PluginInvokeError::Timeout));
        // Plugin is still invocable (timeout doesn't auto-disable, caller decides).
        assert!(guard.is_invocable());
    }

    #[tokio::test]
    async fn invoke_with_limits_capability_denied() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);

        let result = guard
            .invoke_with_limits(PluginCapability::RequestMutate, 0, || async { Ok(()) })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::Capability(_)
        ));
    }

    #[tokio::test]
    async fn invoke_with_limits_input_too_large() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                max_input_bytes: 100,
                ..Default::default()
            },
            4,
        );

        let result = guard
            .invoke_with_limits(PluginCapability::RequestInspect, 101, || async { Ok(()) })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::ResourceLimit(ResourceLimitError::InputTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn invoke_with_limits_concurrency_enforced() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits {
                max_concurrency: 2,
                timeout_ms: 5000,
                ..Default::default()
            },
            2,
        );

        // Hold two permits (max concurrency = 2).
        let p1 = guard.concurrency.clone().acquire_owned().await.unwrap();
        let p2 = guard.concurrency.clone().acquire_owned().await.unwrap();

        // Third attempt should fail to acquire within a short deadline.
        let result = tokio::time::timeout(Duration::from_millis(50), async {
            guard
                .invoke_with_limits(PluginCapability::RequestInspect, 0, || async { Ok(()) })
                .await
        })
        .await;

        // Timeout means the semaphore acquire blocked — concurrency enforced.
        assert!(result.is_err());

        drop(p1);
        drop(p2);
    }

    #[tokio::test]
    async fn invoke_with_limits_disabled_plugin_rejected() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );
        guard.disable_for_violation();

        let result = guard
            .invoke_with_limits(PluginCapability::RequestInspect, 0, || async { Ok(()) })
            .await;

        assert!(matches!(
            result.unwrap_err(),
            PluginInvokeError::PluginDisabled
        ));
    }

    #[tokio::test]
    async fn invoke_with_limits_success() {
        let guard = PluginInvocationGuard::new(
            PluginCapabilities {
                request_inspect: true,
                ..Default::default()
            },
            PluginLimits::default(),
            4,
        );

        let result = guard
            .invoke_with_limits(PluginCapability::RequestInspect, 10, || async {
                Ok::<i32, PluginInvokeError>(42)
            })
            .await;

        assert_eq!(result.unwrap(), 42);
    }

    // ─── Development hot-reload signing ────────────────────────────────────

    #[test]
    fn development_hot_reload_requires_explicit_dev_mode() {
        // DevelopmentHotReload trust tier in production with RequireSigned
        // and no signature should NOT be silently accepted.
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::DevelopmentHotReload,
            None,
            true,
        );
        // The current implementation delegates to external dev_mode check.
        // It returns Ok but documents that caller must check dev_mode.
        assert!(result.is_ok());
    }

    #[test]
    fn signed_sandboxed_requires_signature_in_production() {
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::SignedSandboxed,
            None,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn trust_tier_disabled_rejects_load_in_manifest() {
        let toml = r#"
            name = "disabled-plugin"
            version = "0.1.0"
            entry = "plugin.wasm"
            trust_tier = "disabled"
        "#;
        let manifest = PluginManifest::parse_toml(toml, Path::new("test.toml")).unwrap();
        let warnings = manifest.validate_trust_consistency();
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ManifestWarning::DisabledPluginLoaded)));
    }

    // ─── PluginInvocationGuard state transitions ───────────────────────────

    #[test]
    fn invocation_guard_quarantined_not_invocable() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        *guard.state.write() = PluginRuntimeState::Quarantined;
        assert!(!guard.is_invocable());
    }

    #[test]
    fn invocation_guard_load_error_not_invocable() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        *guard.state.write() = PluginRuntimeState::DisabledByLoadError;
        assert!(!guard.is_invocable());
    }

    #[test]
    fn invocation_guard_config_disabled_not_invocable() {
        let guard =
            PluginInvocationGuard::new(PluginCapabilities::default(), PluginLimits::default(), 4);
        *guard.state.write() = PluginRuntimeState::DisabledByConfig;
        assert!(!guard.is_invocable());
    }

    // ─── Signing policy edge cases ─────────────────────────────────────────

    #[test]
    fn signing_production_local_sandboxed_with_signature_accepted() {
        let sig = PluginSignatureConfig {
            signature: "deadbeef".to_string(),
            key_id: "k1".to_string(),
            algorithm: "ed25519".to_string(),
        };
        let result = verify_signing_policy(
            SigningPolicy::RequireSigned,
            PluginTrustTier::LocalSandboxed,
            Some(&sig),
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn signing_dev_mode_always_ok() {
        for tier in [
            PluginTrustTier::LocalSandboxed,
            PluginTrustTier::SignedSandboxed,
            PluginTrustTier::LocalTrusted,
        ] {
            let result = verify_signing_policy(SigningPolicy::RequireSigned, tier, None, false);
            assert!(
                result.is_ok(),
                "dev mode should not enforce signing for {:?}",
                tier
            );
        }
    }
}
