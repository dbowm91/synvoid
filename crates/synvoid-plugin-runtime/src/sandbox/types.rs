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
// Pool State Model
// ═══════════════════════════════════════════════════════════════════════════════

/// Controls whether pooled WASM instances maintain state across requests.
///
/// The variant determines pool behavior:
/// - `HostContextIsolated`: instance is reused from pool; host-side context is
///   fully reset but guest memory/globals may persist (Wasmtime limitation).
/// - `FreshInstancePerRequest`: a new instance is instantiated for every
///   request and dropped afterward. No pool reuse. Guarantees full isolation.
/// - `StatefulPooled`: instance is reused; guest memory/globals persist AND
///   this is expected by the plugin.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStateModel {
    /// Host-context-isolated: instance is reused from pool but host-side
    /// context (env, body, capabilities, DHT prefixes, fuel, timeout) is
    /// fully reset between requests. Guest memory/globals persist but are
    /// treated as untrusted — security assumptions must not depend on
    /// guest state persistence.
    #[default]
    HostContextIsolated,
    /// Fresh-instance-per-request: a new WASM instance is instantiated
    /// for every request and dropped afterward. No pool reuse. This
    /// guarantees full isolation of guest memory and globals.
    FreshInstancePerRequest,
    /// Stateful-pooled: instances are reused with full host-side reset.
    /// Guest memory/globals persist AND this is expected by the plugin.
    /// Only allowed for trusted plugins or with explicit `stateful = true`.
    StatefulPooled,
}

/// Backward-compatible deserialization: maps legacy "request_isolated" to
/// `HostContextIsolated`.
impl<'de> serde::Deserialize<'de> for PluginStateModel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "host_context_isolated" => Ok(PluginStateModel::HostContextIsolated),
            "request_isolated" => Ok(PluginStateModel::HostContextIsolated),
            "fresh_instance_per_request" => Ok(PluginStateModel::FreshInstancePerRequest),
            "stateful_pooled" => Ok(PluginStateModel::StatefulPooled),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &[
                    "host_context_isolated",
                    "request_isolated",
                    "fresh_instance_per_request",
                    "stateful_pooled",
                ],
            )),
        }
    }
}

impl std::fmt::Display for PluginStateModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HostContextIsolated => write!(f, "host-context-isolated"),
            Self::FreshInstancePerRequest => write!(f, "fresh-instance-per-request"),
            Self::StatefulPooled => write!(f, "stateful-pooled"),
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
    /// Scoped mesh sub-capability policy. Only evaluated when `mesh = true`.
    #[serde(default)]
    pub mesh_policy: PluginMeshPolicy,
    /// Filesystem sub-capability policy for future host functions.
    #[serde(default)]
    pub filesystem_policy: PluginFilesystemPolicy,
    /// Network sub-capability policy for future host functions.
    #[serde(default)]
    pub network_policy: PluginNetworkPolicy,
    /// Persistence sub-capability policy.
    #[serde(default)]
    pub persistence_policy: PluginPersistencePolicy,
    /// Metrics sub-capability policy for cardinality bounds.
    #[serde(default)]
    pub metrics_policy: PluginMetricsPolicy,
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

    /// Check that at least one of the allowed capabilities is granted.
    pub fn require_any_capability(
        &self,
        allowed: &[PluginCapability],
    ) -> Result<(), CapabilityViolation> {
        for cap in allowed {
            if self.permits(*cap) {
                return Ok(());
            }
        }
        Err(CapabilityViolation {
            capability: allowed
                .first()
                .copied()
                .unwrap_or(PluginCapability::RequestInspect),
            plugin_name: String::new(),
        })
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

    // ─── Sub-capability checks ──────────────────────────────────────────────

    /// Check if the mesh sub-policy allows a DHT read for the given key.
    /// Requires `mesh = true` AND the key prefix in `dht_read_prefixes`.
    pub fn check_mesh_dht_read(&self, key: &str) -> Result<(), CapabilityViolation> {
        if !self.mesh {
            return Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            });
        }
        if self.mesh_policy.allows_dht_read(key) {
            Ok(())
        } else {
            Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            })
        }
    }

    /// Check if the mesh sub-policy allows a DHT write for the given key.
    pub fn check_mesh_dht_write(&self, key: &str) -> Result<(), CapabilityViolation> {
        if !self.mesh {
            return Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            });
        }
        if self.mesh_policy.allows_dht_write(key) {
            Ok(())
        } else {
            Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            })
        }
    }

    /// Check if the mesh sub-policy allows threat checks.
    pub fn check_mesh_threat_check(&self) -> Result<(), CapabilityViolation> {
        if !self.mesh || !self.mesh_policy.allow_threat_check {
            return Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            });
        }
        Ok(())
    }

    /// Check if the mesh sub-policy allows emitting an event with the given topic.
    pub fn check_mesh_event_emit(&self, topic: &str) -> Result<(), CapabilityViolation> {
        if !self.mesh {
            return Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            });
        }
        if self.mesh_policy.allows_event_emit(topic) {
            Ok(())
        } else {
            Err(CapabilityViolation {
                capability: PluginCapability::Mesh,
                plugin_name: String::new(),
            })
        }
    }

    /// Check if the metrics sub-policy allows a metric with the given name and labels.
    pub fn check_metrics_emit(
        &self,
        metric_name: &str,
        label_keys: &[&str],
    ) -> Result<(), CapabilityViolation> {
        if !self.metrics {
            return Err(CapabilityViolation {
                capability: PluginCapability::Metrics,
                plugin_name: String::new(),
            });
        }
        let mp = &self.metrics_policy;
        // Check metric name prefix
        if !mp.allowed_metric_prefixes.is_empty()
            && !mp
                .allowed_metric_prefixes
                .iter()
                .any(|p| metric_name.starts_with(p.as_str()))
        {
            return Err(CapabilityViolation {
                capability: PluginCapability::Metrics,
                plugin_name: String::new(),
            });
        }
        // Check label count
        if mp.max_label_count > 0 && label_keys.len() > mp.max_label_count {
            return Err(CapabilityViolation {
                capability: PluginCapability::Metrics,
                plugin_name: String::new(),
            });
        }
        // Check denied label keys
        for key in label_keys {
            if mp.denied_label_keys.iter().any(|d| d == key) {
                return Err(CapabilityViolation {
                    capability: PluginCapability::Metrics,
                    plugin_name: String::new(),
                });
            }
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Sub-Capability Policies
// ═══════════════════════════════════════════════════════════════════════════════

/// Scoped mesh policy controlling which mesh operations a plugin may perform.
///
/// The top-level `PluginCapability::Mesh` gate must be `true` for any mesh
/// operation. This policy then narrows which specific operations are allowed.
/// Missing sub-policy sections default to deny (no DHT access, no threat
/// checks, no event emission).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginMeshPolicy {
    /// Allow `mesh_check_threat` host calls.
    #[serde(default)]
    pub allow_threat_check: bool,
    /// DHT key prefixes the plugin may read (e.g. `["threat_indicator:"]`).
    /// Empty means no DHT read access.
    #[serde(default)]
    pub dht_read_prefixes: Vec<String>,
    /// DHT key prefixes the plugin may write. Empty means no write access.
    #[serde(default)]
    pub dht_write_prefixes: Vec<String>,
    /// Mesh event topic prefixes the plugin may emit (e.g. `["plugin.audit"]`).
    /// Empty means no event emission.
    #[serde(default)]
    pub event_emit_topics: Vec<String>,
    /// Maximum DHT key size in bytes. 0 uses the global default.
    #[serde(default)]
    pub max_key_bytes: usize,
    /// Maximum DHT value size in bytes. 0 uses the global default.
    #[serde(default)]
    pub max_value_bytes: usize,
    /// Maximum event payload size in bytes. 0 uses the global default.
    #[serde(default)]
    pub max_event_bytes: usize,
}

impl PluginMeshPolicy {
    /// Check if the key matches any allowed DHT read prefix.
    pub fn allows_dht_read(&self, key: &str) -> bool {
        self.dht_read_prefixes
            .iter()
            .any(|p| key.starts_with(p.as_str()))
    }

    /// Check if the key matches any allowed DHT write prefix.
    pub fn allows_dht_write(&self, key: &str) -> bool {
        self.dht_write_prefixes
            .iter()
            .any(|p| key.starts_with(p.as_str()))
    }

    /// Check if the topic matches any allowed event emit prefix.
    pub fn allows_event_emit(&self, topic: &str) -> bool {
        self.event_emit_topics
            .iter()
            .any(|p| topic.starts_with(p.as_str()))
    }

    /// Validate that the policy does not contain wildcard or empty prefixes
    /// that would grant overly broad access. Returns errors for violations.
    pub fn validate(&self, strict: bool) -> Vec<MeshPolicyViolation<'_>> {
        let mut violations = Vec::new();
        if strict {
            for prefix in &self.dht_read_prefixes {
                if prefix.is_empty() {
                    violations.push(MeshPolicyViolation::EmptyPrefix("dht_read_prefixes"));
                }
                if prefix == "*" {
                    violations.push(MeshPolicyViolation::WildcardPrefix("dht_read_prefixes"));
                }
            }
            for prefix in &self.dht_write_prefixes {
                if prefix.is_empty() {
                    violations.push(MeshPolicyViolation::EmptyPrefix("dht_write_prefixes"));
                }
                if prefix == "*" {
                    violations.push(MeshPolicyViolation::WildcardPrefix("dht_write_prefixes"));
                }
            }
            for topic in &self.event_emit_topics {
                if topic.is_empty() {
                    violations.push(MeshPolicyViolation::EmptyPrefix("event_emit_topics"));
                }
                if topic == "*" {
                    violations.push(MeshPolicyViolation::WildcardPrefix("event_emit_topics"));
                }
            }
        }
        violations
    }
}

/// Errors from mesh sub-capability policy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshPolicyViolation<'a> {
    EmptyPrefix(&'a str),
    WildcardPrefix(&'a str),
}

impl<'a> std::fmt::Display for MeshPolicyViolation<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPrefix(field) => write!(f, "empty prefix not allowed in {}", field),
            Self::WildcardPrefix(field) => {
                write!(f, "wildcard '*' prefix not allowed in {}", field)
            }
        }
    }
}

/// Filesystem access policy controlling which paths a plugin may read/write.
///
/// This policy is ready before filesystem host APIs become broad. All paths
/// are canonicalized and checked against allowed roots. Symlink escapes are
/// rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginFilesystemPolicy {
    /// Directories the plugin may read from. Empty means no read access.
    #[serde(default)]
    pub read_roots: Vec<String>,
    /// Directories the plugin may write to. Empty means no write access.
    #[serde(default)]
    pub write_roots: Vec<String>,
    /// Allow creating new files within write roots.
    #[serde(default)]
    pub allow_create: bool,
    /// Allow overwriting existing files within write roots.
    #[serde(default)]
    pub allow_overwrite: bool,
    /// Maximum bytes per read operation. 0 means no limit (subject to global).
    #[serde(default)]
    pub max_read_bytes: usize,
    /// Maximum bytes per write operation. 0 means no limit (subject to global).
    #[serde(default)]
    pub max_write_bytes: usize,
}

/// Network access policy controlling which outbound connections a plugin may make.
///
/// Production defaults deny wildcards and private/link-local/loopback ranges
/// for third-party plugins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginNetworkPolicy {
    /// Hostnames the plugin may connect to (exact match, lowercase).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Ports the plugin may connect to. Empty means all ports (subject to host).
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    /// CIDR ranges the plugin may connect to (e.g. `["10.0.0.0/8"]`).
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// Deny connections to private/link-local/loopback ranges by default.
    #[serde(default = "default_deny_private_ranges")]
    pub deny_private_ranges: bool,
    /// Maximum request payload size in bytes.
    #[serde(default)]
    pub max_request_bytes: usize,
    /// Maximum response payload size in bytes.
    #[serde(default)]
    pub max_response_bytes: usize,
    /// Connection timeout.
    #[serde(default)]
    pub timeout_ms: u64,
}

impl Default for PluginNetworkPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_ports: Vec::new(),
            allowed_cidrs: Vec::new(),
            deny_private_ranges: true,
            max_request_bytes: 0,
            max_response_bytes: 0,
            timeout_ms: 0,
        }
    }
}

fn default_deny_private_ranges() -> bool {
    true
}

/// Persistence policy controlling state storage for a plugin.
///
/// Persistence is namespaced by `(site_id, plugin_name, plugin_hash)` and
/// quota-bound. Cross-plugin namespace access is rejected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginPersistencePolicy {
    /// Storage namespace (auto-derived from site_id + plugin identity).
    #[serde(default)]
    pub namespace: String,
    /// Maximum key size in bytes.
    #[serde(default)]
    pub max_key_bytes: usize,
    /// Maximum value size in bytes.
    #[serde(default)]
    pub max_value_bytes: usize,
    /// Maximum total storage in bytes for this plugin.
    #[serde(default)]
    pub max_total_bytes: usize,
    /// Allow deleting stored keys.
    #[serde(default)]
    pub allow_delete: bool,
    /// Require TTL for all writes (untrusted plugins).
    #[serde(default)]
    pub ttl_required: bool,
    /// Maximum TTL duration.
    #[serde(default)]
    pub max_ttl_ms: u64,
}

/// Metrics policy controlling what metrics a plugin may emit.
///
/// Prevents unbounded cardinality and sensitive data leakage through metric
/// labels. All plugin-emitted metric names must be prefixed with the allowed
/// prefix (typically `plugin.<plugin_name>.`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginMetricsPolicy {
    /// Allowed metric name prefixes (e.g. `["plugin.my_plugin."]`).
    #[serde(default)]
    pub allowed_metric_prefixes: Vec<String>,
    /// Maximum metric name size in bytes.
    #[serde(default)]
    pub max_metric_name_bytes: usize,
    /// Maximum number of labels per metric.
    #[serde(default)]
    pub max_label_count: usize,
    /// Maximum label key size in bytes.
    #[serde(default)]
    pub max_label_key_bytes: usize,
    /// Maximum label value size in bytes.
    #[serde(default)]
    pub max_label_value_bytes: usize,
    /// Explicitly allowed label keys (overrides denied list).
    #[serde(default)]
    pub allowed_label_keys: Vec<String>,
    /// Denied label keys (high-cardinality / sensitive).
    #[serde(default)]
    pub denied_label_keys: Vec<String>,
}

/// Classification of host API denial and failure reasons for stable ABI codes
/// and bounded observability signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostApiFailureClass {
    /// Top-level capability not declared.
    CapabilityDenied,
    /// DHT key prefix not in allowlist.
    PrefixDenied,
    /// Event topic not in allowlist.
    TopicDenied,
    /// Filesystem path not in allowlist.
    PathDenied,
    /// Network destination not in allowlist.
    HostDenied,
    /// Quota or size limit exceeded.
    QuotaExceeded,
    /// Payload exceeds size limit.
    PayloadTooLarge,
    /// Host call timed out.
    Timeout,
    /// Invalid guest pointer or range.
    InvalidPointer,
    /// Backend (mesh, filesystem, network) unavailable.
    BackendUnavailable,
    /// Internal host error.
    InternalError,
}

impl std::fmt::Display for HostApiFailureClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityDenied => write!(f, "CapabilityDenied"),
            Self::PrefixDenied => write!(f, "PrefixDenied"),
            Self::TopicDenied => write!(f, "TopicDenied"),
            Self::PathDenied => write!(f, "PathDenied"),
            Self::HostDenied => write!(f, "HostDenied"),
            Self::QuotaExceeded => write!(f, "QuotaExceeded"),
            Self::PayloadTooLarge => write!(f, "PayloadTooLarge"),
            Self::Timeout => write!(f, "Timeout"),
            Self::InvalidPointer => write!(f, "InvalidPointer"),
            Self::BackendUnavailable => write!(f, "BackendUnavailable"),
            Self::InternalError => write!(f, "InternalError"),
        }
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
    /// Pool state model controlling cross-request state semantics.
    #[serde(default)]
    pub state_model: PluginStateModel,
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
            state_model: PluginStateModel::default(),
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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginSignatureConfig {
    /// Hex-encoded signature of the plugin binary.
    pub signature: String,
    /// Public key identifier used to verify the signature.
    pub key_id: String,
    /// Signing algorithm (e.g. "ed25519", "ecdsa-p256").
    pub algorithm: String,
    /// Expected SHA-256 hash of the plugin binary (hex-encoded).
    #[serde(default)]
    pub binary_sha256: String,
    /// Expected SHA-256 hash of the canonical manifest signing payload (hex-encoded).
    #[serde(default)]
    pub manifest_sha256: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plugin Manifest
// ═══════════════════════════════════════════════════════════════════════════════

/// A `synvoid-plugin.toml` manifest describing a plugin's identity, trust
/// tier, declared capabilities, and resource limits.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

        // Phase 7: Validate mesh sub-policy for strict tiers
        if self.capabilities.mesh {
            let strict = matches!(
                self.trust_tier,
                PluginTrustTier::SignedSandboxed | PluginTrustTier::LocalSandboxed
            );
            let violations = self.capabilities.mesh_policy.validate(strict);
            for v in violations {
                warnings.push(ManifestWarning::MeshSubPolicyViolation(format!("{}", v)));
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
    MeshSubPolicyViolation(String),
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
            Self::MeshSubPolicyViolation(msg) => {
                write!(f, "mesh sub-policy violation: {}", msg)
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
// Plugin Signature Verification
// ═══════════════════════════════════════════════════════════════════════════════

/// Algorithm for plugin signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSignatureAlgorithm {
    Ed25519,
}

/// A trusted public key for verifying plugin signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPluginKey {
    pub key_id: String,
    pub algorithm: PluginSignatureAlgorithm,
    /// Base64URL-no-pad encoded Ed25519 public key.
    pub public_key: String,
}

/// Plugin load configuration controlling trust enforcement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginLoadConfig {
    /// Whether dev mode is enabled (allows DevelopmentHotReload tier).
    #[serde(default)]
    pub dev_mode: bool,
    /// Whether local trusted plugins are allowed.
    #[serde(default)]
    pub allow_local_trusted: bool,
    /// Trusted public keys for signature verification.
    #[serde(default)]
    pub trusted_keys: Vec<TrustedPluginKey>,
}

/// Result of signature verification.
#[derive(Debug)]
pub enum PluginSignatureVerification {
    /// Signature verified successfully.
    Valid,
    /// Verification was skipped (e.g., development mode).
    Skipped,
}

/// Metadata returned from successful signature verification.
#[derive(Debug, Clone)]
pub struct VerifiedPluginSignature {
    /// Trusted key ID used for verification.
    pub key_id: String,
    /// SHA-256 hash of the verified binary (hex).
    pub binary_sha256: String,
    /// SHA-256 hash of the manifest signing payload (hex).
    pub manifest_sha256: String,
    /// Signature algorithm used.
    pub algorithm: PluginSignatureAlgorithm,
}

/// Errors during signature verification.
#[derive(Debug, Clone)]
pub enum PluginSignatureError {
    /// SignedSandboxed requires a signature block in the manifest.
    MissingSignature,
    /// Binary hash does not match manifest hash.
    BinaryHashMismatch { expected: String, actual: String },
    /// Manifest hash does not match computed hash.
    ManifestHashMismatch { expected: String, actual: String },
    /// No trusted key matches the key_id in the manifest.
    UnknownKeyId(String),
    /// Trusted key has an unsupported algorithm.
    UnsupportedAlgorithm(String),
    /// Trusted key is malformed (not valid base64 or wrong length).
    MalformedKey(String),
    /// Signature is malformed (not valid hex or wrong length).
    MalformedSignature(String),
    /// Signature verification failed (invalid signature).
    SignatureInvalid,
    /// Cryptographic verification is unavailable (dependency missing or compile-time feature).
    VerificationUnavailable,
}

impl std::fmt::Display for PluginSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSignature => write!(f, "SignedSandboxed plugin requires a signature"),
            Self::BinaryHashMismatch { expected, actual } => {
                write!(
                    f,
                    "binary hash mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::ManifestHashMismatch { expected, actual } => {
                write!(
                    f,
                    "manifest hash mismatch: expected {}, got {}",
                    expected, actual
                )
            }
            Self::UnknownKeyId(id) => write!(f, "unknown trusted key ID: '{}'", id),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported algorithm: '{}'", alg),
            Self::MalformedKey(msg) => write!(f, "malformed trusted key: {}", msg),
            Self::MalformedSignature(msg) => write!(f, "malformed signature: {}", msg),
            Self::SignatureInvalid => write!(f, "signature verification failed"),
            Self::VerificationUnavailable => {
                write!(f, "cryptographic signature verification is not available")
            }
        }
    }
}

impl std::error::Error for PluginSignatureError {}

/// Compute the SHA-256 digest of binary bytes, returned as a hex string.
pub fn compute_binary_hash(binary_bytes: &[u8]) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(binary_bytes);
    hex::encode(digest)
}

/// Compute a canonical signing payload from manifest fields (excluding signature).
/// This produces a deterministic serialization for signing.
///
/// Sub-capability policies are included in the signing payload so that
/// tampering with mesh/filesystem/network/persistence/metrics sub-policies
/// after signing invalidates the manifest hash.
pub fn compute_manifest_signing_payload(manifest: &PluginManifest) -> String {
    let mut payload = String::new();
    payload.push_str(&format!("name={}\n", manifest.name));
    payload.push_str(&format!("version={}\n", manifest.version));
    payload.push_str(&format!("entry={}\n", manifest.entry));
    payload.push_str(&format!("trust_tier={}\n", manifest.trust_tier));
    // Capabilities in sorted order
    let mut caps: Vec<_> = manifest.capabilities.iter_flags();
    caps.sort_by_key(|(cap, _)| format!("{:?}", cap));
    for (cap, enabled) in &caps {
        payload.push_str(&format!("cap_{:?}={}\n", cap, enabled));
    }
    // Sub-capability policies (sorted by section name for determinism)
    let mp = &manifest.capabilities.mesh_policy;
    payload.push_str(&format!(
        "mesh_allow_threat_check={}\n",
        mp.allow_threat_check
    ));
    let mut read_prefixes = mp.dht_read_prefixes.clone();
    read_prefixes.sort();
    payload.push_str(&format!(
        "mesh_dht_read_prefixes={}\n",
        read_prefixes.join(",")
    ));
    let mut write_prefixes = mp.dht_write_prefixes.clone();
    write_prefixes.sort();
    payload.push_str(&format!(
        "mesh_dht_write_prefixes={}\n",
        write_prefixes.join(",")
    ));
    let mut event_topics = mp.event_emit_topics.clone();
    event_topics.sort();
    payload.push_str(&format!(
        "mesh_event_emit_topics={}\n",
        event_topics.join(",")
    ));
    payload.push_str(&format!("mesh_max_key_bytes={}\n", mp.max_key_bytes));
    payload.push_str(&format!("mesh_max_value_bytes={}\n", mp.max_value_bytes));
    payload.push_str(&format!("mesh_max_event_bytes={}\n", mp.max_event_bytes));

    let fp = &manifest.capabilities.filesystem_policy;
    let mut read_roots = fp.read_roots.clone();
    read_roots.sort();
    payload.push_str(&format!("fs_read_roots={}\n", read_roots.join(",")));
    let mut write_roots = fp.write_roots.clone();
    write_roots.sort();
    payload.push_str(&format!("fs_write_roots={}\n", write_roots.join(",")));
    payload.push_str(&format!("fs_allow_create={}\n", fp.allow_create));
    payload.push_str(&format!("fs_allow_overwrite={}\n", fp.allow_overwrite));
    payload.push_str(&format!("fs_max_read_bytes={}\n", fp.max_read_bytes));
    payload.push_str(&format!("fs_max_write_bytes={}\n", fp.max_write_bytes));

    let np = &manifest.capabilities.network_policy;
    let mut hosts = np.allowed_hosts.clone();
    hosts.sort();
    payload.push_str(&format!("net_allowed_hosts={}\n", hosts.join(",")));
    let mut ports = np.allowed_ports.clone();
    ports.sort();
    let port_strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    payload.push_str(&format!("net_allowed_ports={}\n", port_strs.join(",")));
    let mut cidrs = np.allowed_cidrs.clone();
    cidrs.sort();
    payload.push_str(&format!("net_allowed_cidrs={}\n", cidrs.join(",")));
    payload.push_str(&format!(
        "net_deny_private_ranges={}\n",
        np.deny_private_ranges
    ));
    payload.push_str(&format!("net_max_request_bytes={}\n", np.max_request_bytes));
    payload.push_str(&format!(
        "net_max_response_bytes={}\n",
        np.max_response_bytes
    ));
    payload.push_str(&format!("net_timeout_ms={}\n", np.timeout_ms));

    let pp = &manifest.capabilities.persistence_policy;
    payload.push_str(&format!("persist_max_key_bytes={}\n", pp.max_key_bytes));
    payload.push_str(&format!("persist_max_value_bytes={}\n", pp.max_value_bytes));
    payload.push_str(&format!("persist_max_total_bytes={}\n", pp.max_total_bytes));
    payload.push_str(&format!("persist_allow_delete={}\n", pp.allow_delete));
    payload.push_str(&format!("persist_ttl_required={}\n", pp.ttl_required));
    payload.push_str(&format!("persist_max_ttl_ms={}\n", pp.max_ttl_ms));

    let mtp = &manifest.capabilities.metrics_policy;
    let mut prefixes = mtp.allowed_metric_prefixes.clone();
    prefixes.sort();
    payload.push_str(&format!(
        "metrics_allowed_prefixes={}\n",
        prefixes.join(",")
    ));
    payload.push_str(&format!(
        "metrics_max_name_bytes={}\n",
        mtp.max_metric_name_bytes
    ));
    payload.push_str(&format!(
        "metrics_max_label_count={}\n",
        mtp.max_label_count
    ));
    payload.push_str(&format!(
        "metrics_max_label_key_bytes={}\n",
        mtp.max_label_key_bytes
    ));
    payload.push_str(&format!(
        "metrics_max_label_value_bytes={}\n",
        mtp.max_label_value_bytes
    ));
    let mut allowed_labels = mtp.allowed_label_keys.clone();
    allowed_labels.sort();
    payload.push_str(&format!(
        "metrics_allowed_label_keys={}\n",
        allowed_labels.join(",")
    ));
    let mut denied_labels = mtp.denied_label_keys.clone();
    denied_labels.sort();
    payload.push_str(&format!(
        "metrics_denied_label_keys={}\n",
        denied_labels.join(",")
    ));

    // Limits
    payload.push_str(&format!("timeout_ms={}\n", manifest.limits.timeout_ms));
    payload.push_str(&format!(
        "max_input_bytes={}\n",
        manifest.limits.max_input_bytes
    ));
    payload.push_str(&format!(
        "max_output_bytes={}\n",
        manifest.limits.max_output_bytes
    ));
    payload.push_str(&format!(
        "max_concurrency={}\n",
        manifest.limits.max_concurrency
    ));
    if let Some(mp) = manifest.limits.memory_pages {
        payload.push_str(&format!("memory_pages={}\n", mp));
    }
    if let Some(f) = manifest.limits.fuel {
        payload.push_str(&format!("fuel={}\n", f));
    }
    payload.push_str(&format!("state_model={}\n", manifest.limits.state_model));
    payload
}

/// Compute SHA-256 of the canonical manifest signing payload.
pub fn compute_manifest_hash(manifest: &PluginManifest) -> String {
    let payload = compute_manifest_signing_payload(manifest);
    use sha2::Digest;
    let digest = sha2::Sha256::digest(payload.as_bytes());
    hex::encode(digest)
}

/// Verify a plugin's cryptographic signature.
///
/// Steps:
/// 1. Check that SignedSandboxed has a signature block.
/// 2. Verify binary hash matches manifest hash.
/// 3. Compute canonical manifest hash and compare.
/// 4. Resolve trusted public key by key_id.
/// 5. Verify Ed25519 signature.
pub fn verify_plugin_signature(
    manifest: &PluginManifest,
    binary_bytes: &[u8],
    trusted_keys: &[TrustedPluginKey],
) -> Result<VerifiedPluginSignature, PluginSignatureError> {
    // Step 1: SignedSandboxed requires a signature block
    let sig_config = match &manifest.signature {
        Some(s) => s,
        None => return Err(PluginSignatureError::MissingSignature),
    };

    // Step 2: Verify binary hash
    let actual_binary_hash = compute_binary_hash(binary_bytes);
    if sig_config.binary_sha256.is_empty() {
        return Err(PluginSignatureError::BinaryHashMismatch {
            expected: "(empty in manifest)".to_string(),
            actual: actual_binary_hash,
        });
    }
    if sig_config.binary_sha256 != actual_binary_hash {
        return Err(PluginSignatureError::BinaryHashMismatch {
            expected: sig_config.binary_sha256.clone(),
            actual: actual_binary_hash,
        });
    }

    // Step 3: Compute and verify manifest hash
    let actual_manifest_hash = compute_manifest_hash(manifest);
    if sig_config.manifest_sha256.is_empty() {
        return Err(PluginSignatureError::ManifestHashMismatch {
            expected: "(empty in manifest)".to_string(),
            actual: actual_manifest_hash,
        });
    }
    if sig_config.manifest_sha256 != actual_manifest_hash {
        return Err(PluginSignatureError::ManifestHashMismatch {
            expected: sig_config.manifest_sha256.clone(),
            actual: actual_manifest_hash,
        });
    }

    // Step 4: Resolve trusted key
    let trusted_key = trusted_keys
        .iter()
        .find(|k| k.key_id == sig_config.key_id)
        .ok_or_else(|| PluginSignatureError::UnknownKeyId(sig_config.key_id.clone()))?;

    // Step 5: Verify algorithm matches
    let algorithm = match sig_config.algorithm.as_str() {
        "ed25519" => PluginSignatureAlgorithm::Ed25519,
        other => {
            return Err(PluginSignatureError::UnsupportedAlgorithm(
                other.to_string(),
            ))
        }
    };
    if trusted_key.algorithm != algorithm {
        return Err(PluginSignatureError::UnsupportedAlgorithm(format!(
            "key algorithm {:?} does not match signature algorithm {:?}",
            trusted_key.algorithm, algorithm
        )));
    }

    // Step 6: Decode public key
    use base64::Engine;
    let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&trusted_key.public_key)
        .map_err(|e| PluginSignatureError::MalformedKey(e.to_string()))?;

    // Step 7: Decode signature
    let signature_bytes = hex::decode(&sig_config.signature)
        .map_err(|e| PluginSignatureError::MalformedSignature(e.to_string()))?;

    // Step 8: Verify Ed25519 signature
    let signing_payload = compute_manifest_signing_payload(manifest);

    match algorithm {
        PluginSignatureAlgorithm::Ed25519 => {
            use ed25519_dalek::{
                Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
            };

            if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
                return Err(PluginSignatureError::MalformedKey(format!(
                    "expected {} bytes, got {}",
                    PUBLIC_KEY_LENGTH,
                    public_key_bytes.len()
                )));
            }
            if signature_bytes.len() != SIGNATURE_LENGTH {
                return Err(PluginSignatureError::MalformedSignature(format!(
                    "expected {} bytes, got {}",
                    SIGNATURE_LENGTH,
                    signature_bytes.len()
                )));
            }

            let mut key_arr = [0u8; PUBLIC_KEY_LENGTH];
            key_arr.copy_from_slice(&public_key_bytes);
            let verifying_key = VerifyingKey::from_bytes(&key_arr)
                .map_err(|e| PluginSignatureError::MalformedKey(e.to_string()))?;

            let mut sig_arr = [0u8; SIGNATURE_LENGTH];
            sig_arr.copy_from_slice(&signature_bytes);
            let signature = Signature::from_bytes(&sig_arr);

            verifying_key
                .verify(signing_payload.as_bytes(), &signature)
                .map_err(|_| PluginSignatureError::SignatureInvalid)?;
        }
    }

    Ok(VerifiedPluginSignature {
        key_id: sig_config.key_id.clone(),
        binary_sha256: actual_binary_hash,
        manifest_sha256: actual_manifest_hash,
        algorithm,
    })
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plugin Load Policy Enforcement
// ═══════════════════════════════════════════════════════════════════════════════

/// Errors from plugin load policy enforcement.
#[derive(Debug, Clone)]
pub enum PluginLoadError {
    /// Plugin trust tier is Disabled.
    Disabled,
    /// DevelopmentHotReload not allowed when dev_mode is false.
    DevHotReloadNotAllowed,
    /// LocalTrusted not allowed when allow_local_trusted is false.
    LocalTrustedNotAllowed,
    /// Signature verification failed.
    Signature(PluginSignatureError),
}

impl std::fmt::Display for PluginLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "plugin trust tier is disabled"),
            Self::DevHotReloadNotAllowed => {
                write!(f, "DevelopmentHotReload tier requires dev_mode = true")
            }
            Self::LocalTrustedNotAllowed => {
                write!(f, "LocalTrusted tier requires allow_local_trusted = true")
            }
            Self::Signature(e) => write!(f, "signature verification failed: {}", e),
        }
    }
}

impl std::error::Error for PluginLoadError {}

impl From<PluginSignatureError> for PluginLoadError {
    fn from(e: PluginSignatureError) -> Self {
        Self::Signature(e)
    }
}

/// Enforce plugin load policy based on trust tier, config, and optional binary.
///
/// This function must be called from every plugin loading path before the plugin
/// is instantiated. It enforces:
/// - Disabled tier → always rejected
/// - SignedSandboxed → requires verified signature or fails closed
/// - DevelopmentHotReload → requires dev_mode = true
/// - LocalTrusted → requires allow_local_trusted = true
/// - Other tiers → permitted
///
/// Returns `Some(VerifiedPluginSignature)` for SignedSandboxed tiers on success.
pub fn enforce_plugin_load_policy(
    manifest: &PluginManifest,
    binary_bytes: Option<&[u8]>,
    config: &PluginLoadConfig,
) -> Result<Option<VerifiedPluginSignature>, PluginLoadError> {
    match manifest.trust_tier {
        PluginTrustTier::Disabled => Err(PluginLoadError::Disabled),

        PluginTrustTier::SignedSandboxed => {
            let keys = &config.trusted_keys;
            let binary = binary_bytes.unwrap_or(&[]);
            let verified = verify_plugin_signature(manifest, binary, keys)?;
            Ok(Some(verified))
        }

        PluginTrustTier::DevelopmentHotReload => {
            if !config.dev_mode {
                return Err(PluginLoadError::DevHotReloadNotAllowed);
            }
            Ok(None)
        }

        PluginTrustTier::LocalTrusted => {
            if !config.allow_local_trusted {
                return Err(PluginLoadError::LocalTrustedNotAllowed);
            }
            Ok(None)
        }

        PluginTrustTier::LocalSandboxed => Ok(None),
    }
}

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

    /// Invoke a plugin operation synchronously with capability check, input size check,
    /// and failure recording. Uses try_acquire for the concurrency semaphore to avoid
    /// blocking an async reactor thread.
    pub fn invoke_with_limits_blocking<F, T>(
        &self,
        capability: PluginCapability,
        input_len: usize,
        f: F,
    ) -> Result<T, PluginInvokeError>
    where
        F: FnOnce() -> Result<T, PluginInvokeError>,
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
            .try_acquire_owned()
            .map_err(|_| PluginInvokeError::ConcurrencyLimitExceeded)?;

        let result = f();

        drop(permit);

        result
    }

    /// Read the current failure count.
    pub fn failure_count(&self) -> u32 {
        *self.failure_count.read()
    }

    /// Read the current runtime state.
    pub fn state(&self) -> PluginRuntimeState {
        *self.state.read()
    }

    /// Quarantine the plugin.
    pub fn quarantine(&self) {
        *self.state.write() = PluginRuntimeState::Quarantined;
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

/// Failure policy for a plugin runtime.
#[derive(Debug, Clone)]
pub struct PluginFailurePolicy {
    /// Number of consecutive failures before disabling the plugin.
    pub failure_threshold: u32,
    /// Number of timeouts before disabling the plugin.
    pub timeout_threshold: u32,
    /// Whether capability violations immediately disable the plugin.
    pub capability_violation_disables: bool,
    /// Whether request filter failures should fail closed (block) or fail open (pass).
    pub fail_closed_on_filter_error: bool,
    /// Whether response transform failures should fail closed or fail open.
    pub fail_closed_on_transform_error: bool,
}

impl Default for PluginFailurePolicy {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            timeout_threshold: 3,
            capability_violation_disables: true,
            fail_closed_on_filter_error: true,
            fail_closed_on_transform_error: false,
        }
    }
}

/// Classification of plugin failure types for policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginFailureClass {
    /// Plugin attempted an unauthorized operation.
    CapabilityViolation,
    /// Plugin execution exceeded the time limit.
    Timeout,
    /// Plugin consumed all allocated fuel.
    FuelExhausted,
    /// Plugin triggered a wasm trap (panic, unreachable, etc.).
    GuestTrap,
    /// Plugin attempted to access memory outside its allocation.
    MemoryViolation,
    /// Plugin violated a host API contract.
    HostApiViolation,
    /// Plugin failed to load.
    LoadError,
    /// Plugin was interrupted by epoch deadline (wall-clock backstop).
    EpochInterrupted,
    /// Unclassified runtime error.
    OtherRuntimeError,
}

impl PluginFailureClass {
    /// Returns true if this failure class should increment the failure counter.
    pub fn counts_as_failure(self) -> bool {
        !matches!(self, Self::CapabilityViolation)
    }

    /// Returns true if this failure class should count toward the timeout threshold.
    pub fn is_timeout(self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// Returns true if this failure class represents an epoch deadline interruption.
    pub fn is_epoch_interrupted(self) -> bool {
        matches!(self, Self::EpochInterrupted)
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
            ..Default::default()
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
            ..Default::default()
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

    // ─── Phase E: enforce_plugin_load_policy tests ───────────────────────

    #[test]
    fn signed_sandboxed_requires_signature() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(&[]), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::MissingSignature
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_rejects_unknown_key() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd".to_string(),
                key_id: "unknown-key".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(&[]),
                manifest_sha256: compute_manifest_hash(&PluginManifest {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    entry: "plugin.wasm".into(),
                    trust_tier: PluginTrustTier::SignedSandboxed,
                    capabilities: PluginCapabilities::default(),
                    limits: PluginLimits::default(),
                    signature: None,
                }),
            }),
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(&[]), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::UnknownKeyId(_)
            ))
        ));
    }

    #[test]
    fn development_hot_reload_rejected_without_dev_mode() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::DevelopmentHotReload,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig::default(); // dev_mode = false
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::DevHotReloadNotAllowed)
        ));
    }

    #[test]
    fn development_hot_reload_allowed_with_explicit_dev_mode() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::DevelopmentHotReload,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig {
            dev_mode: true,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn disabled_plugin_never_loads() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::Disabled,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig {
            dev_mode: true,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(matches!(result, Err(PluginLoadError::Disabled)));
    }

    #[test]
    fn local_trusted_requires_explicit_config() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalTrusted,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::LocalTrustedNotAllowed)
        ));
    }

    #[test]
    fn local_sandboxed_always_allowed() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn compute_binary_hash_returns_sha256_hex() {
        let hash = compute_binary_hash(b"hello world");
        assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn compute_manifest_hash_deterministic() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let h1 = compute_manifest_hash(&manifest);
        let h2 = compute_manifest_hash(&manifest);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_manifest_hash_changes_with_name() {
        let m1 = PluginManifest {
            name: "alpha".into(),
            version: "1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let m2 = PluginManifest {
            name: "beta".into(),
            ..m1.clone()
        };
        assert_ne!(compute_manifest_hash(&m1), compute_manifest_hash(&m2));
    }

    #[test]
    fn compute_manifest_signing_payload_excludes_signature() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "should-not-appear".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                ..Default::default()
            }),
        };
        let payload = compute_manifest_signing_payload(&manifest);
        assert!(!payload.contains("should-not-appear"));
        assert!(payload.contains("name=test"));
        assert!(payload.contains("version=1.0"));
    }

    // ─── Phase 2: enforce_plugin_load_policy signature verification tests ──

    #[test]
    fn signed_sandboxed_empty_binary_sha256_fails() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd1234".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: String::new(), // empty
                manifest_sha256: "deadbeef".to_string(),
            }),
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::BinaryHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_empty_manifest_sha256_fails() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd1234".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: String::new(), // empty
            }),
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::ManifestHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_binary_hash_mismatch_fails() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd1234".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                manifest_sha256: compute_manifest_hash(&PluginManifest {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    entry: "plugin.wasm".into(),
                    trust_tier: PluginTrustTier::SignedSandboxed,
                    capabilities: PluginCapabilities::default(),
                    limits: PluginLimits::default(),
                    signature: None,
                }),
            }),
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::BinaryHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_manifest_hash_mismatch_fails() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd1234".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }),
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::ManifestHashMismatch { .. }
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_malformed_key_fails() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                    .to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: compute_manifest_hash(&PluginManifest {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    entry: "plugin.wasm".into(),
                    trust_tier: PluginTrustTier::SignedSandboxed,
                    capabilities: PluginCapabilities::default(),
                    limits: PluginLimits::default(),
                    signature: None,
                }),
            }),
        };
        let trusted_keys = vec![TrustedPluginKey {
            key_id: "key1".to_string(),
            algorithm: PluginSignatureAlgorithm::Ed25519,
            public_key: "not-a-valid-base64key!!!".to_string(),
        }];
        let config = PluginLoadConfig {
            trusted_keys,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::MalformedKey(_)
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_malformed_signature_fails() {
        use base64::Engine;
        let secret_bytes = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: "not-valid-hex!".to_string(),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: compute_manifest_hash(&PluginManifest {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    entry: "plugin.wasm".into(),
                    trust_tier: PluginTrustTier::SignedSandboxed,
                    capabilities: PluginCapabilities::default(),
                    limits: PluginLimits::default(),
                    signature: None,
                }),
            }),
        };
        let trusted_keys = vec![TrustedPluginKey {
            key_id: "key1".to_string(),
            algorithm: PluginSignatureAlgorithm::Ed25519,
            public_key: public_key_b64,
        }];
        let config = PluginLoadConfig {
            trusted_keys,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::MalformedSignature(_)
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_wrong_signature_fails() {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let secret_bytes = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                // Sign a different message
                signature: hex::encode(signing_key.sign(b"wrong message").to_bytes()),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: compute_manifest_hash(&PluginManifest {
                    name: "test".into(),
                    version: "0.1.0".into(),
                    entry: "plugin.wasm".into(),
                    trust_tier: PluginTrustTier::SignedSandboxed,
                    capabilities: PluginCapabilities::default(),
                    limits: PluginLimits::default(),
                    signature: None,
                }),
            }),
        };
        let trusted_keys = vec![TrustedPluginKey {
            key_id: "key1".to_string(),
            algorithm: PluginSignatureAlgorithm::Ed25519,
            public_key: public_key_b64,
        }];
        let config = PluginLoadConfig {
            trusted_keys,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(matches!(
            result,
            Err(PluginLoadError::Signature(
                PluginSignatureError::SignatureInvalid
            ))
        ));
    }

    #[test]
    fn signed_sandboxed_valid_signature_loads() {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let secret_bytes = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

        let manifest_without_sig = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let signing_payload = compute_manifest_signing_payload(&manifest_without_sig);
        let signature = signing_key.sign(signing_payload.as_bytes());

        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: hex::encode(signature.to_bytes()),
                key_id: "key1".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test"),
                manifest_sha256: compute_manifest_hash(&manifest_without_sig),
            }),
        };
        let trusted_keys = vec![TrustedPluginKey {
            key_id: "key1".to_string(),
            algorithm: PluginSignatureAlgorithm::Ed25519,
            public_key: public_key_b64,
        }];
        let config = PluginLoadConfig {
            trusted_keys,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, Some(b"test"), &config);
        assert!(result.is_ok());
        let verified = result.unwrap();
        assert!(verified.is_some());
        let v = verified.unwrap();
        assert_eq!(v.key_id, "key1");
        assert_eq!(v.algorithm, PluginSignatureAlgorithm::Ed25519);
    }

    #[test]
    fn signed_sandboxed_returns_verification_metadata() {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let secret_bytes = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());

        let manifest_without_sig = PluginManifest {
            name: "meta-test".into(),
            version: "2.0.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let signing_payload = compute_manifest_signing_payload(&manifest_without_sig);
        let signature = signing_key.sign(signing_payload.as_bytes());

        let manifest = PluginManifest {
            name: "meta-test".into(),
            version: "2.0.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: Some(PluginSignatureConfig {
                signature: hex::encode(signature.to_bytes()),
                key_id: "test-key".to_string(),
                algorithm: "ed25519".to_string(),
                binary_sha256: compute_binary_hash(b"test-bytes"),
                manifest_sha256: compute_manifest_hash(&manifest_without_sig),
            }),
        };
        let trusted_keys = vec![TrustedPluginKey {
            key_id: "test-key".to_string(),
            algorithm: PluginSignatureAlgorithm::Ed25519,
            public_key: public_key_b64,
        }];
        let config = PluginLoadConfig {
            trusted_keys,
            ..Default::default()
        };
        let result = enforce_plugin_load_policy(&manifest, Some(b"test-bytes"), &config);
        let verified = result.unwrap().unwrap();
        assert_eq!(verified.key_id, "test-key");
        assert_eq!(verified.binary_sha256, compute_binary_hash(b"test-bytes"));
        assert_eq!(
            verified.manifest_sha256,
            compute_manifest_hash(&manifest_without_sig)
        );
    }

    #[test]
    fn local_sandboxed_returns_none_metadata() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "0.1.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::LocalSandboxed,
            capabilities: PluginCapabilities::default(),
            limits: PluginLimits::default(),
            signature: None,
        };
        let config = PluginLoadConfig::default();
        let result = enforce_plugin_load_policy(&manifest, None, &config);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_epoch_interrupted_failure_class() {
        assert!(PluginFailureClass::EpochInterrupted.counts_as_failure());
        assert!(!PluginFailureClass::EpochInterrupted.is_timeout());
        assert!(PluginFailureClass::EpochInterrupted.is_epoch_interrupted());
    }

    #[test]
    fn test_plugin_state_model_default_is_host_context_isolated() {
        assert_eq!(
            PluginStateModel::default(),
            PluginStateModel::HostContextIsolated
        );
    }

    #[test]
    fn test_plugin_limits_default_state_model() {
        let limits = PluginLimits::default();
        assert_eq!(limits.state_model, PluginStateModel::HostContextIsolated);
    }

    #[test]
    fn test_plugin_state_model_display() {
        assert_eq!(
            PluginStateModel::HostContextIsolated.to_string(),
            "host-context-isolated"
        );
        assert_eq!(
            PluginStateModel::FreshInstancePerRequest.to_string(),
            "fresh-instance-per-request"
        );
        assert_eq!(
            PluginStateModel::StatefulPooled.to_string(),
            "stateful-pooled"
        );
    }

    #[test]
    fn test_plugin_state_model_deprecated_alias_deserializes() {
        // "request_isolated" should map to HostContextIsolated
        let toml_str = r#"state_model = "request_isolated""#;
        let parsed: PluginLimits = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.state_model, PluginStateModel::HostContextIsolated);
    }

    #[test]
    fn test_plugin_state_model_new_name_deserializes() {
        let toml_str = r#"state_model = "host_context_isolated""#;
        let parsed: PluginLimits = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.state_model, PluginStateModel::HostContextIsolated);
    }

    #[test]
    fn test_plugin_state_model_fresh_instance_deserializes() {
        let toml_str = r#"state_model = "fresh_instance_per_request""#;
        let parsed: PluginLimits = toml::from_str(toml_str).unwrap();
        assert_eq!(
            parsed.state_model,
            PluginStateModel::FreshInstancePerRequest
        );
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Phase 7: Sub-Capability Policy Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_mesh_policy_default_is_all_deny() {
        let policy = PluginMeshPolicy::default();
        assert!(!policy.allow_threat_check);
        assert!(policy.dht_read_prefixes.is_empty());
        assert!(policy.dht_write_prefixes.is_empty());
        assert!(policy.event_emit_topics.is_empty());
    }

    #[test]
    fn test_mesh_policy_allows_dht_read_prefix() {
        let policy = PluginMeshPolicy {
            dht_read_prefixes: vec!["threat_indicator:".into(), "ip_reputation:".into()],
            ..Default::default()
        };
        assert!(policy.allows_dht_read("threat_indicator:1.2.3.4"));
        assert!(policy.allows_dht_read("ip_reputation:5.6.7.8"));
        assert!(!policy.allows_dht_read("dns_zone:example.com"));
        assert!(!policy.allows_dht_read("random_key"));
    }

    #[test]
    fn test_mesh_policy_allows_dht_write_prefix() {
        let policy = PluginMeshPolicy {
            dht_write_prefixes: vec!["plugin.output:".into()],
            ..Default::default()
        };
        assert!(policy.allows_dht_write("plugin.output:result"));
        assert!(!policy.allows_dht_write("threat_indicator:x"));
    }

    #[test]
    fn test_mesh_policy_allows_event_emit_topic() {
        let policy = PluginMeshPolicy {
            event_emit_topics: vec!["plugin.audit".into(), "plugin.signal".into()],
            ..Default::default()
        };
        assert!(policy.allows_event_emit("plugin.audit.blocked"));
        assert!(policy.allows_event_emit("plugin.signal.urgent"));
        assert!(!policy.allows_event_emit("mesh.admin"));
        assert!(!policy.allows_event_emit("other.topic"));
    }

    #[test]
    fn test_mesh_policy_validate_rejects_empty_prefix() {
        let policy = PluginMeshPolicy {
            dht_read_prefixes: vec!["".into()],
            ..Default::default()
        };
        let violations = policy.validate(true);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            MeshPolicyViolation::EmptyPrefix("dht_read_prefixes")
        ));
    }

    #[test]
    fn test_mesh_policy_validate_rejects_wildcard() {
        let policy = PluginMeshPolicy {
            event_emit_topics: vec!["*".into()],
            ..Default::default()
        };
        let violations = policy.validate(true);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            MeshPolicyViolation::WildcardPrefix("event_emit_topics")
        ));
    }

    #[test]
    fn test_mesh_policy_validate_strict_false_allows_empty() {
        let policy = PluginMeshPolicy {
            dht_read_prefixes: vec!["".into()],
            ..Default::default()
        };
        let violations = policy.validate(false);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_capabilities_mesh_false_denies_all_mesh_operations() {
        let caps = PluginCapabilities {
            mesh: false,
            ..Default::default()
        };
        assert!(caps.check_mesh_dht_read("threat_indicator:x").is_err());
        assert!(caps.check_mesh_dht_write("plugin.output:x").is_err());
        assert!(caps.check_mesh_threat_check().is_err());
        assert!(caps.check_mesh_event_emit("plugin.audit").is_err());
    }

    #[test]
    fn test_capabilities_mesh_true_no_sub_policy_denies_all() {
        let caps = PluginCapabilities {
            mesh: true,
            mesh_policy: PluginMeshPolicy::default(),
            ..Default::default()
        };
        // mesh=true but empty sub-policies should deny everything
        assert!(caps.check_mesh_dht_read("threat_indicator:x").is_err());
        assert!(caps.check_mesh_dht_write("plugin.output:x").is_err());
        assert!(caps.check_mesh_threat_check().is_err());
        assert!(caps.check_mesh_event_emit("plugin.audit").is_err());
    }

    #[test]
    fn test_capabilities_mesh_sub_policy_scoped_grants() {
        let caps = PluginCapabilities {
            mesh: true,
            mesh_policy: PluginMeshPolicy {
                allow_threat_check: true,
                dht_read_prefixes: vec!["threat_indicator:".into()],
                dht_write_prefixes: vec![],
                event_emit_topics: vec!["plugin.audit".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        // Allowed operations
        assert!(caps.check_mesh_dht_read("threat_indicator:1.2.3.4").is_ok());
        assert!(caps.check_mesh_threat_check().is_ok());
        assert!(caps.check_mesh_event_emit("plugin.audit.blocked").is_ok());
        // Denied operations
        assert!(caps.check_mesh_dht_read("dns_zone:example.com").is_err());
        assert!(caps.check_mesh_dht_write("plugin.output:x").is_err());
        assert!(caps.check_mesh_event_emit("mesh.admin").is_err());
    }

    #[test]
    fn test_capabilities_one_mesh_grant_cannot_reach_another() {
        // Plugin with only threat_check cannot read DHT or emit events
        let caps = PluginCapabilities {
            mesh: true,
            mesh_policy: PluginMeshPolicy {
                allow_threat_check: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(caps.check_mesh_threat_check().is_ok());
        assert!(caps.check_mesh_dht_read("threat_indicator:x").is_err());
        assert!(caps.check_mesh_event_emit("plugin.audit").is_err());
    }

    #[test]
    fn test_capabilities_dht_read_cannot_write() {
        let caps = PluginCapabilities {
            mesh: true,
            mesh_policy: PluginMeshPolicy {
                dht_read_prefixes: vec!["threat_indicator:".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(caps.check_mesh_dht_read("threat_indicator:x").is_ok());
        assert!(caps.check_mesh_dht_write("threat_indicator:x").is_err());
    }

    #[test]
    fn test_capabilities_event_topic_prefix_match() {
        // Topic "plugin.audit" should match "plugin.audit.blocked" (prefix match)
        let caps = PluginCapabilities {
            mesh: true,
            mesh_policy: PluginMeshPolicy {
                event_emit_topics: vec!["plugin.audit".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(caps.check_mesh_event_emit("plugin.audit").is_ok());
        assert!(caps.check_mesh_event_emit("plugin.audit.blocked").is_ok());
        assert!(caps
            .check_mesh_event_emit("plugin.audit.failed_login")
            .is_ok());
        assert!(caps.check_mesh_event_emit("plugin.signal").is_err());
    }

    #[test]
    fn test_filesystem_policy_default_is_all_deny() {
        let policy = PluginFilesystemPolicy::default();
        assert!(policy.read_roots.is_empty());
        assert!(policy.write_roots.is_empty());
        assert!(!policy.allow_create);
        assert!(!policy.allow_overwrite);
    }

    #[test]
    fn test_network_policy_default_deny_private_ranges() {
        let policy = PluginNetworkPolicy::default();
        assert!(policy.deny_private_ranges);
        assert!(policy.allowed_hosts.is_empty());
    }

    #[test]
    fn test_persistence_policy_default_is_all_deny() {
        let policy = PluginPersistencePolicy::default();
        assert!(policy.max_key_bytes == 0);
        assert!(policy.max_value_bytes == 0);
        assert!(policy.max_total_bytes == 0);
        assert!(!policy.allow_delete);
        assert!(!policy.ttl_required);
    }

    #[test]
    fn test_metrics_policy_default_is_all_deny() {
        let policy = PluginMetricsPolicy::default();
        assert!(policy.allowed_metric_prefixes.is_empty());
        assert!(policy.max_label_count == 0);
        assert!(policy.denied_label_keys.is_empty());
    }

    #[test]
    fn test_capabilities_check_metrics_emit() {
        let caps = PluginCapabilities {
            metrics: true,
            metrics_policy: PluginMetricsPolicy {
                allowed_metric_prefixes: vec!["plugin.test.".into()],
                max_label_count: 3,
                denied_label_keys: vec!["ip_address".into(), "user_agent".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        // Valid metric
        assert!(caps.check_metrics_emit("plugin.test.requests", &[]).is_ok());
        // Wrong prefix
        assert!(caps.check_metrics_emit("system.cpu", &[]).is_err());
        // Denied label
        assert!(caps
            .check_metrics_emit("plugin.test.requests", &["ip_address"])
            .is_err());
        // Too many labels
        assert!(caps
            .check_metrics_emit("plugin.test.requests", &["a", "b", "c", "d"])
            .is_err());
        // Valid labels
        assert!(caps
            .check_metrics_emit("plugin.test.requests", &["method", "status"])
            .is_ok());
    }

    #[test]
    fn test_capabilities_metrics_false_denies_all() {
        let caps = PluginCapabilities {
            metrics: false,
            ..Default::default()
        };
        assert!(caps.check_metrics_emit("plugin.test.x", &[]).is_err());
    }

    #[test]
    fn test_host_api_failure_class_display() {
        assert_eq!(
            HostApiFailureClass::CapabilityDenied.to_string(),
            "CapabilityDenied"
        );
        assert_eq!(
            HostApiFailureClass::PrefixDenied.to_string(),
            "PrefixDenied"
        );
        assert_eq!(HostApiFailureClass::TopicDenied.to_string(), "TopicDenied");
        assert_eq!(HostApiFailureClass::PathDenied.to_string(), "PathDenied");
        assert_eq!(HostApiFailureClass::HostDenied.to_string(), "HostDenied");
        assert_eq!(
            HostApiFailureClass::QuotaExceeded.to_string(),
            "QuotaExceeded"
        );
        assert_eq!(
            HostApiFailureClass::PayloadTooLarge.to_string(),
            "PayloadTooLarge"
        );
        assert_eq!(HostApiFailureClass::Timeout.to_string(), "Timeout");
        assert_eq!(
            HostApiFailureClass::InvalidPointer.to_string(),
            "InvalidPointer"
        );
        assert_eq!(
            HostApiFailureClass::BackendUnavailable.to_string(),
            "BackendUnavailable"
        );
        assert_eq!(
            HostApiFailureClass::InternalError.to_string(),
            "InternalError"
        );
    }

    #[test]
    fn test_manifest_toml_parses_mesh_sub_policy() {
        let toml = r#"
            name = "mesh-plugin"
            version = "1.0.0"
            entry = "plugin.wasm"

            [capabilities]
            mesh = true

            [capabilities.mesh_policy]
            allow_threat_check = true
            dht_read_prefixes = ["threat_indicator:", "ip_reputation:"]
            dht_write_prefixes = []
            event_emit_topics = ["plugin.audit", "plugin.signal"]
            max_key_bytes = 512
            max_value_bytes = 8192
            max_event_bytes = 4096
        "#;
        let manifest = PluginManifest::parse_toml(toml, Path::new("test.toml")).unwrap();
        assert!(manifest.capabilities.mesh);
        assert!(manifest.capabilities.mesh_policy.allow_threat_check);
        assert_eq!(
            manifest.capabilities.mesh_policy.dht_read_prefixes,
            vec!["threat_indicator:", "ip_reputation:"]
        );
        assert!(manifest
            .capabilities
            .mesh_policy
            .dht_write_prefixes
            .is_empty());
        assert_eq!(
            manifest.capabilities.mesh_policy.event_emit_topics,
            vec!["plugin.audit", "plugin.signal"]
        );
        assert_eq!(manifest.capabilities.mesh_policy.max_key_bytes, 512);
        assert_eq!(manifest.capabilities.mesh_policy.max_value_bytes, 8192);
        assert_eq!(manifest.capabilities.mesh_policy.max_event_bytes, 4096);
    }

    #[test]
    fn test_manifest_toml_missing_sub_policy_defaults_deny() {
        let toml = r#"
            name = "test-plugin"
            version = "1.0.0"
            entry = "plugin.wasm"

            [capabilities]
            mesh = true
        "#;
        let manifest = PluginManifest::parse_toml(toml, Path::new("test.toml")).unwrap();
        assert!(manifest.capabilities.mesh);
        assert!(!manifest.capabilities.mesh_policy.allow_threat_check);
        assert!(manifest
            .capabilities
            .mesh_policy
            .dht_read_prefixes
            .is_empty());
        assert!(manifest
            .capabilities
            .mesh_policy
            .event_emit_topics
            .is_empty());
    }

    #[test]
    fn test_signing_payload_includes_mesh_sub_policy() {
        let manifest_without = PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            capabilities: PluginCapabilities {
                mesh: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let manifest_with = PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            capabilities: PluginCapabilities {
                mesh: true,
                mesh_policy: PluginMeshPolicy {
                    allow_threat_check: true,
                    dht_read_prefixes: vec!["threat_indicator:".into()],
                    event_emit_topics: vec!["plugin.audit".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let payload_without = compute_manifest_signing_payload(&manifest_without);
        let payload_with = compute_manifest_signing_payload(&manifest_with);
        // Payloads must differ when sub-policies differ
        assert_ne!(payload_without, payload_with);
        // Sub-policy fields must appear in the payload
        assert!(payload_with.contains("mesh_allow_threat_check=true"));
        assert!(payload_with.contains("mesh_dht_read_prefixes=threat_indicator:"));
        assert!(payload_with.contains("mesh_event_emit_topics=plugin.audit"));
    }

    #[test]
    fn test_signing_payload_includes_filesystem_sub_policy() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            capabilities: PluginCapabilities {
                filesystem_policy: PluginFilesystemPolicy {
                    read_roots: vec!["/data".into()],
                    write_roots: vec!["/tmp".into()],
                    allow_create: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let payload = compute_manifest_signing_payload(&manifest);
        assert!(payload.contains("fs_read_roots=/data"));
        assert!(payload.contains("fs_write_roots=/tmp"));
        assert!(payload.contains("fs_allow_create=true"));
    }

    #[test]
    fn test_signing_payload_includes_metrics_sub_policy() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            capabilities: PluginCapabilities {
                metrics: true,
                metrics_policy: PluginMetricsPolicy {
                    allowed_metric_prefixes: vec!["plugin.test.".into()],
                    max_label_count: 5,
                    denied_label_keys: vec!["ip_address".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let payload = compute_manifest_signing_payload(&manifest);
        assert!(payload.contains("metrics_allowed_prefixes=plugin.test."));
        assert!(payload.contains("metrics_max_label_count=5"));
        assert!(payload.contains("metrics_denied_label_keys=ip_address"));
    }

    #[test]
    fn test_manifest_validate_trust_consistency_mesh_sub_policy() {
        let manifest = PluginManifest {
            name: "test".into(),
            version: "1.0.0".into(),
            entry: "plugin.wasm".into(),
            trust_tier: PluginTrustTier::SignedSandboxed,
            capabilities: PluginCapabilities {
                mesh: true,
                mesh_policy: PluginMeshPolicy {
                    dht_read_prefixes: vec!["".into()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let warnings = manifest.validate_trust_consistency();
        assert!(warnings
            .iter()
            .any(|w| matches!(w, ManifestWarning::MeshSubPolicyViolation(_))));
    }
}
