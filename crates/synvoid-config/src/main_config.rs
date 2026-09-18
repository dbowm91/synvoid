#![allow(
    clippy::collapsible_if,
    clippy::redundant_closure,
    clippy::manual_range_contains
)]

#[allow(unused_imports)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(feature = "icmp-filter")]
use crate::icmp_filter::IcmpFilterConfig;

use super::admin::{AdminConfig, AdminCorsConfig, AdminRateLimitConfig, MetricsConfig};
use super::defaults::DefaultsConfig;
#[cfg(feature = "dns")]
use super::dns::DnsConfig;
use super::honeypot_port::HoneypotPortConfig;
use super::http::{Http3Config, HttpConfig, TokioConfig};
use super::limits::{BlocklistLimitsConfig, ProxyLimitsConfig, RateLimitMemoryConfig};
use super::logging::LoggingConfig;
use super::network::{TarpitDefaults, TcpDefaults, UdpDefaults};
use super::plugins::PluginConfig;
use super::process::{ProcessManagerConfig, SupervisorConfig};
use super::protection::{
    IpFeedConfig, MimesConfig, RuleFeedConfig, ThreatLevelConfig, YaraRuleFeedConfig,
};
use super::security::{MainSecurityConfig, MainStaticConfig};
use super::server::{FallbackConfig, ServerConfig};
use super::serverless::ServerlessConfig;
use super::tls::TlsConfig;
use super::traffic::TrafficShapingConfig;
use super::tunnel::TunnelConfig;
use super::upgrade::UpgradeConfig;
use super::validation::ConfigValidationError;

pub use super::defaults::{
    GlobalRateLimitConfig as MainGlobalRateLimitConfig,
    HoneypotProbingDefaults as MainHoneypotProbingDefaults,
    IpRateLimitConfig as MainIpRateLimitConfig, SuspiciousWordsConfig as MainSuspiciousWordsConfig,
    UpstreamErrorsConfig as MainUpstreamErrorsConfig, WorkerPoolDefaults as MainWorkerPoolDefaults,
};
pub use super::http::{
    Http3Config as MainHttp3Config, HttpConfig as MainHttpConfig, TokioConfig as MainTokioConfig,
};
pub use super::process::{
    ProcessManagerConfig as MainProcessManagerConfig,
    SupervisorConfig as MainSupervisorCompatConfig, SupervisorConfig as MainSupervisorConfig,
};
pub use super::protection::{
    IpFeedConfig as MainIpFeedConfig, RuleFeedConfig as MainRuleFeedConfig,
    ThreatLevelConfig as MainThreatLevelConfig, ThreatLevelEscalation,
    YaraRuleFeedConfig as MainYaraRuleFeedConfig,
};
pub use super::server::{FallbackConfig as MainFallbackConfig, ServerConfig as MainServerConfig};
pub use super::serverless::ServerlessConfig as MainServerlessConfig;
pub use super::tls::{
    AcmeConfig as MainAcmeConfig, ClientAuthConfig as MainClientAuthConfig,
    TlsConfig as MainTlsConfig,
};
pub use super::traffic::{
    ConnectionLimitsConfig as MainConnectionLimitsConfig,
    TrafficShapingConfig as MainTrafficShapingConfig,
    TrafficShapingDefaults as MainTrafficShapingDefaults,
};
pub use super::tunnel::{
    PortMappingConfig as MainPortMappingConfig, TunnelConfig as MainTunnelConfig,
    TunnelQuicClientConfig as MainTunnelQuicClientConfig, TunnelQuicConfig as MainTunnelQuicConfig,
    TunnelQuicPeerConfig as MainTunnelQuicPeerConfig, TunnelVpnConfig as MainTunnelVpnConfig,
    VpnAccessLevel as MainVpnAccessLevel, WireGuardPeerConfig as MainWireGuardPeerConfig,
};

#[derive(Debug, Deserialize, Serialize, Clone, JsonSchema)]
pub struct MainConfig {
    pub server: ServerConfig,
    pub fallback: FallbackConfig,
    pub admin: AdminConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tokio: TokioConfig,
    #[serde(default)]
    pub http: HttpConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub http3: Http3Config,
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub threat_level: ThreatLevelConfig,
    #[serde(default)]
    pub ip_feeds: IpFeedConfig,
    #[serde(default)]
    pub rule_feed: RuleFeedConfig,
    #[serde(default)]
    pub yara_feed: YaraRuleFeedConfig,
    #[serde(default)]
    pub rate_limit_memory: RateLimitMemoryConfig,
    #[serde(default)]
    pub proxy_limits: ProxyLimitsConfig,
    #[serde(default)]
    pub blocklist_limits: BlocklistLimitsConfig,
    #[serde(default)]
    pub tcp: TcpDefaults,
    #[serde(default)]
    pub udp: UdpDefaults,
    #[serde(default)]
    pub tarpit: TarpitDefaults,
    #[serde(default)]
    pub persistence: super::defaults::PersistenceConfig,
    #[serde(default)]
    pub traffic_shaping: TrafficShapingConfig,
    #[serde(default)]
    pub security: MainSecurityConfig,
    #[serde(default)]
    pub static_config: Option<MainStaticConfig>,
    #[serde(default)]
    pub tunnel: TunnelConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
    #[serde(default)]
    pub serverless: ServerlessConfig,
    #[serde(default)]
    pub upgrade: Option<UpgradeConfig>,
    #[cfg(feature = "icmp-filter")]
    #[serde(default)]
    pub icmp_filter: IcmpFilterConfig,
    #[serde(default)]
    pub mimes: MimesConfig,
    #[serde(default)]
    #[cfg(feature = "dns")]
    pub dns: DnsConfig,
    #[cfg(feature = "mesh")]
    pub mesh: Option<super::MeshConfig>,
    #[serde(default)]
    pub supervisor_compat: SupervisorConfig,
    #[serde(default)]
    pub process_manager: ProcessManagerConfig,
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    #[serde(default)]
    pub honeypot_port: HoneypotPortConfig,
}

/// Compile-time capability set for fail-closed config preflight (Phase 41).
///
/// Each flag records whether the current binary was built with the
/// corresponding Cargo feature. The raw-TOML preflight rejects
/// capability-bearing sections when the feature is absent, so operators
/// cannot request a capability the binary silently ignores.
#[derive(Debug, Clone, Copy)]
pub struct CompiledCapabilities {
    pub dns: bool,
    pub mesh: bool,
    pub icmp_filter: bool,
}

impl CompiledCapabilities {
    pub fn current() -> Self {
        Self {
            dns: cfg!(feature = "dns"),
            mesh: cfg!(feature = "mesh"),
            icmp_filter: cfg!(feature = "icmp-filter"),
        }
    }
}

/// Feature-independent preflight over the raw TOML (Phase 41).
///
/// Inspects only capability-bearing keys whose silent omission is
/// security/operationally meaningful:
/// - top-level `[dns]`
/// - top-level `[mesh]`
/// - nested `[tunnel.mesh]`
/// - top-level `[icmp_filter]`
///
/// Any presence (even an inert table with only `enabled = false`) is
/// rejected when the corresponding feature is absent: the binary did not
/// understand the section, and accepting it would let operators believe
/// otherwise. Absent sections are always accepted. Comments are ignored by
/// construction (they never appear in `toml::Value`).
pub fn validate_config_capability_presence(
    raw: &toml::Value,
    compiled: CompiledCapabilities,
) -> Result<(), ConfigValidationError> {
    use super::validation::ConfigValidationError;

    let has_top = |key: &str| raw.get(key).is_some();
    let has_tunnel_mesh = raw.get("tunnel").and_then(|t| t.get("mesh")).is_some();

    if has_top("dns") && !compiled.dns {
        return Err(ConfigValidationError {
            field: "dns".to_string(),
            message: "dns: configuration is present but this binary was built without the 'dns' feature. Rebuild with `--features dns` or remove the [dns] section.".to_string(),
        });
    }
    if has_top("mesh") && !compiled.mesh {
        return Err(ConfigValidationError {
            field: "mesh".to_string(),
            message: "mesh: configuration is present but this binary was built without the 'mesh' feature. Rebuild with `--features mesh` or remove the [mesh] section.".to_string(),
        });
    }
    if has_tunnel_mesh && !compiled.mesh {
        return Err(ConfigValidationError {
            field: "tunnel.mesh".to_string(),
            message: "tunnel.mesh: configuration is present but this binary was built without the 'mesh' feature. Rebuild with `--features mesh` or remove the [tunnel.mesh] section.".to_string(),
        });
    }
    if has_top("icmp_filter") && !compiled.icmp_filter {
        return Err(ConfigValidationError {
            field: "icmp_filter".to_string(),
            message: "icmp_filter: configuration is present but this binary was built without the 'icmp-filter' feature. Rebuild with `--features icmp-filter` or remove the [icmp_filter] section.".to_string(),
        });
    }
    Ok(())
}

impl MainConfig {
    /// Parse and validate a main config from a TOML string.
    ///
    /// In-memory seam shared by [`MainConfig::from_file`] and the
    /// `config_parse_validation` fuzz target: no filesystem reads, no socket
    /// creation, no child processes. Validation follows the exact production
    /// path, including admin-token validation (which may consult the
    /// `SYNVOID_ADMIN_TOKEN` environment variable or generate an ephemeral
    /// token, exactly as file loads do). Operator side-effects that require
    /// the filesystem (mesh key/identity loading) live in `from_file` only.
    ///
    /// Order (Phase 41): raw TOML parse → capability preflight → typed
    /// deserialization → typed validation.
    pub fn from_toml_str(input: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let raw: toml::Value = toml::from_str(input)?;
        validate_config_capability_presence(&raw, CompiledCapabilities::current())?;
        let config: MainConfig = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = std::fs::read_to_string(path)?;
        let mut config = Self::from_toml_str(&content)?;

        if config.admin.token.is_empty() || config.admin.token == "changeme" {
            config.admin.token = config.admin.resolve_token();
        }

        if config.security.ipc_enforce_signing {
            if config.security.ipc_session_key_env.is_none() {
                tracing::warn!(
                    "IPC signing enforcement enabled but no session key configured. \
                    Set security.ipc_session_key_env or security.ipc_session_key in config. \
                    Generating ephemeral key (workers will not be able to reconnect after restart)."
                );
            }
        }

        // Load global node keys and node identity if mesh is configured
        #[cfg(feature = "mesh")]
        if let Some(ref mut mesh_config) = config.tunnel.mesh {
            if let Err(e) = mesh_config.load_global_node_keys() {
                tracing::warn!("Failed to load global node keys: {}", e);
            }
            if let Err(e) = mesh_config.load_node_identity() {
                tracing::warn!("Failed to load node identity: {}", e);
            }
        }

        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        self.server.validate()?;
        self.http.validate()?;
        self.tls.validate()?;
        self.threat_level.validate()?;
        self.fallback.validate()?;
        self.logging.validate()?;
        self.admin.validate()?;
        self.defaults.validate()?;
        self.tunnel.validate()?;
        // Phase 41: process/supervisor capacities are operator-reachable and
        // feed derived runtime capacities. Validate before use.
        self.process_manager.validate().map_err(|e| {
            // Prefix with the owning section when the inner validator used a
            // short field path (defense: keep exact config paths).
            if e.field.starts_with("process_manager.") {
                e
            } else {
                ConfigValidationError {
                    field: format!("process_manager.{}", e.field),
                    message: e.message,
                }
            }
        })?;
        self.supervisor.validate().map_err(|e| {
            if e.field.starts_with("supervisor") {
                e
            } else {
                ConfigValidationError {
                    field: format!("supervisor.{}", e.field),
                    message: e.message,
                }
            }
        })?;
        self.supervisor_compat.validate().map_err(|e| {
            let suffix = e
                .field
                .strip_prefix("supervisor.")
                .unwrap_or(e.field.as_str());
            ConfigValidationError {
                field: format!("supervisor_compat.{suffix}"),
                message: e.message,
            }
        })?;

        #[cfg(feature = "dns")]
        if self.dns.enabled {
            self.dns.validate()?;
        }

        #[cfg(feature = "icmp-filter")]
        if self.icmp_filter.enabled {
            self.icmp_filter
                .validate()
                .map_err(|message| ConfigValidationError {
                    field: "icmp_filter".to_string(),
                    message,
                })?;
        }

        // Mesh supervision truthfulness (Phase 41): reject
        // `restart_enabled = true` and non-default restart tuning before
        // runtime composition. Both mesh locations are validated; the
        // preflight above already rejected any mesh section when the feature
        // is absent, so typed validation only runs when the feature exists.
        #[cfg(feature = "mesh")]
        {
            if let Some(ref mesh) = self.mesh {
                mesh.validate().map_err(|e| ConfigValidationError {
                    field: format!("mesh.{}", e.field.trim_start_matches("mesh.")),
                    message: e.message,
                })?;
            }
            // `tunnel.validate()` already validates `tunnel.mesh` supervision.
        }

        Ok(())
    }

    pub fn default_config() -> Self {
        MainConfig {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                host_v6: None,
                trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            fallback: FallbackConfig {
                mode: "return_404".to_string(),
                upstream: None,
            },
            admin: AdminConfig {
                enabled: true,
                port: 8081,
                bind_address: "127.0.0.1".to_string(),
                token: String::new(),
                token_env_var: Some("SYNVOID_ADMIN_TOKEN".to_string()),
                bcrypt_cost: 12,
                cors: AdminCorsConfig::default(),
                rate_limit: AdminRateLimitConfig::default(),
                trusted_proxies: Vec::new(),
                secure_cookie: true,
            },
            logging: LoggingConfig::default(),
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
            },
            tokio: TokioConfig::default(),
            http: HttpConfig::default(),
            tls: TlsConfig::default(),
            http3: Http3Config::default(),
            threat_level: ThreatLevelConfig::default(),
            ip_feeds: IpFeedConfig::default(),
            rule_feed: RuleFeedConfig::default(),
            yara_feed: YaraRuleFeedConfig::default(),
            defaults: DefaultsConfig::default(),
            rate_limit_memory: RateLimitMemoryConfig::default(),
            proxy_limits: ProxyLimitsConfig::default(),
            blocklist_limits: BlocklistLimitsConfig::default(),
            tcp: TcpDefaults::default(),
            udp: UdpDefaults::default(),
            tarpit: TarpitDefaults::default(),
            persistence: super::defaults::PersistenceConfig::default(),
            traffic_shaping: TrafficShapingConfig::default(),
            security: MainSecurityConfig::default(),
            static_config: None,
            tunnel: TunnelConfig::default(),
            plugins: PluginConfig::default(),
            serverless: ServerlessConfig::default(),
            upgrade: None,
            #[cfg(feature = "icmp-filter")]
            icmp_filter: IcmpFilterConfig::default(),
            mimes: MimesConfig::default(),
            #[cfg(feature = "dns")]
            dns: DnsConfig::default(),
            #[cfg(feature = "mesh")]
            mesh: None,
            supervisor_compat: super::SupervisorConfig::default(),
            process_manager: super::ProcessManagerConfig::default(),
            supervisor: super::SupervisorConfig::default(),
            honeypot_port: HoneypotPortConfig::default(),
        }
    }
}

impl Default for MainConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed strong token (40 hex chars, no weak patterns) so seam tests are
    /// deterministic regardless of the surrounding environment.
    const TEST_TOKEN: &str = "7f3a9c1e5b8d2f4a6c0e9b3d7f1a5c8e0d4b6";

    fn valid_toml() -> String {
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        toml::to_string(&cfg).expect("default config must serialize")
    }

    #[test]
    fn from_toml_str_rejects_garbage_without_panicking() {
        assert!(MainConfig::from_toml_str("").is_err());
        assert!(MainConfig::from_toml_str("\x00\x01\x02{{{").is_err());
        assert!(MainConfig::from_toml_str("[unclosed").is_err());
    }

    #[test]
    fn from_toml_str_rejects_invalid_values_with_typed_error() {
        // Structurally valid TOML, but the server host is not a valid IP.
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        let mut text = toml::to_string(&cfg).expect("default config must serialize");
        text = text.replacen("0.0.0.0", "not a host !!!", 1);
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn from_toml_str_accepts_valid_config() {
        let parsed = MainConfig::from_toml_str(&valid_toml()).expect("valid TOML must parse");
        assert_eq!(parsed.server.port, 8080);
    }

    #[test]
    fn from_file_delegates_to_toml_str_seam() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("main.toml");
        let text = valid_toml();
        std::fs::write(&path, &text).unwrap();
        let via_file = MainConfig::from_file(&path).expect("from_file must succeed");
        let via_str = MainConfig::from_toml_str(&text).expect("from_toml_str must succeed");
        assert_eq!(via_file.server.port, via_str.server.port);
    }

    // ---- Phase 41: fail-closed capability preflight ----

    #[test]
    #[cfg(not(feature = "dns"))]
    fn minimal_binary_rejects_dns_section() {
        let mut text = valid_toml();
        text.push_str("\n[dns]\nenabled = true\n");
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dns"), "expected dns path, got: {msg}");
        assert!(msg.contains("without the 'dns' feature"), "got: {msg}");
    }

    #[test]
    #[cfg(not(feature = "mesh"))]
    fn minimal_binary_rejects_top_level_mesh() {
        let mut text = valid_toml();
        text.push_str("\n[mesh]\nenabled = true\n");
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mesh"), "expected mesh path, got: {msg}");
        assert!(msg.contains("without the 'mesh' feature"), "got: {msg}");
    }

    #[test]
    #[cfg(not(feature = "mesh"))]
    fn minimal_binary_rejects_tunnel_mesh() {
        let mut text = valid_toml();
        text.push_str("\n[tunnel.mesh]\nenabled = true\n");
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("tunnel.mesh"),
            "expected tunnel.mesh path, got: {msg}"
        );
    }

    #[test]
    #[cfg(not(feature = "icmp-filter"))]
    fn minimal_binary_rejects_icmp_filter_section() {
        let mut text = valid_toml();
        text.push_str("\n[icmp_filter]\nenabled = true\n");
        let err = MainConfig::from_toml_str(&text).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("icmp_filter"),
            "expected icmp_filter path, got: {msg}"
        );
        assert!(
            msg.contains("without the 'icmp-filter' feature"),
            "got: {msg}"
        );
    }

    #[test]
    #[cfg(not(feature = "mesh"))]
    fn minimal_binary_rejects_inert_disabled_mesh() {
        // Even an inert table with only `enabled = false` is rejected: the
        // binary did not understand the section.
        let mut text = valid_toml();
        text.push_str("\n[mesh]\nenabled = false\n");
        assert!(MainConfig::from_toml_str(&text).is_err());
    }

    #[test]
    fn unknown_keys_outside_capability_sections_remain_ignored() {
        // This phase deliberately does not add global deny_unknown_fields.
        // A top-level unknown key must stay ignored (not a duplicate table).
        let mut text = valid_toml();
        text.push_str("\ntypo_field_should_stay_ignored = 1\n");
        let parsed = MainConfig::from_toml_str(&text).expect("unknown keys must stay ignored");
        assert_eq!(parsed.server.port, 8080);
    }

    #[test]
    #[cfg(feature = "dns")]
    fn dns_build_accepts_valid_dns_config() {
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        cfg.dns.enabled = true;
        let text = toml::to_string(&cfg).expect("must serialize");
        let parsed = MainConfig::from_toml_str(&text).expect("valid DNS must parse");
        assert!(parsed.dns.enabled);
    }

    #[test]
    #[cfg(feature = "mesh")]
    fn mesh_build_accepts_valid_mesh_and_rejects_restart() {
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        cfg.mesh = Some(crate::MeshConfig {
            enabled: true,
            ..Default::default()
        });
        let text = toml::to_string(&cfg).expect("must serialize");
        let parsed = MainConfig::from_toml_str(&text).expect("valid mesh must parse");
        assert!(parsed.mesh.as_ref().unwrap().enabled);

        // restart_enabled = true must fail before runtime composition.
        let mut bad = MainConfig::default_config();
        bad.admin.token = TEST_TOKEN.to_string();
        bad.admin.token_env_var = None;
        let mut bad_mesh = crate::MeshConfig {
            enabled: true,
            ..Default::default()
        };
        bad_mesh.supervision.restart_enabled = true;
        bad.mesh = Some(bad_mesh);
        let bad_text = toml::to_string(&bad).expect("must serialize");
        let err = MainConfig::from_toml_str(&bad_text).unwrap_err();
        assert!(
            err.to_string().contains("restart_enabled"),
            "expected restart rejection, got: {}",
            err
        );
    }

    #[test]
    fn invalid_process_settings_fail_validation_without_panic() {
        let mut cfg = MainConfig::default_config();
        cfg.admin.token = TEST_TOKEN.to_string();
        cfg.admin.token_env_var = None;
        cfg.process_manager.min_workers = 10;
        cfg.process_manager.max_workers = 2;
        assert!(cfg.validate().is_err());

        let mut overflow = MainConfig::default_config();
        overflow.admin.token = TEST_TOKEN.to_string();
        overflow.admin.token_env_var = None;
        overflow.process_manager.unified_server_workers = usize::MAX;
        assert!(overflow.validate().is_err());

        let mut zero = MainConfig::default_config();
        zero.admin.token = TEST_TOKEN.to_string();
        zero.admin.token_env_var = None;
        zero.process_manager.unified_server_workers = 0;
        assert!(zero.validate().is_err());
    }
}
