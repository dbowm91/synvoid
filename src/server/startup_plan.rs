use std::collections::HashMap;
use std::net::SocketAddr;

use crate::config::defaults::{GlobalRateLimitConfig, IpRateLimitConfig};
use crate::config::Http3Config;
use crate::config::MainConfig;
use crate::config::TunnelConfig;
use crate::tls::config::InternalTlsConfig;
use crate::utils::parse_host_port;

/// Mostly pure validated startup state that can be produced without opening
/// sockets or spawning background tasks.
#[derive(Debug, Clone)]
pub struct UnifiedServerStartupPlan {
    pub http_listeners: Vec<crate::config::HttpListenerPlan>,
    pub admin_addr: Option<SocketAddr>,
    pub tls_enabled: bool,
    pub dns_enabled: bool,
    pub tcp_enabled: bool,
    pub udp_enabled: bool,
    pub tunnel_enabled: bool,
    pub tunnel_quic_enabled: bool,
    pub tunnel_config: Option<TunnelConfig>,
    pub http3_config: Http3Config,
    pub tls_config: InternalTlsConfig,
    pub worker_count: usize,
    pub scaled_ip_rate_limit: IpRateLimitConfig,
    pub scaled_global_rate_limit: GlobalRateLimitConfig,
}

/// Rate limit values after per-worker scaling has been applied.
#[derive(Debug, Clone)]
pub struct ScaledRateLimits {
    pub ip_per_second: u32,
    pub ip_per_minute: u32,
    pub global_per_second: u32,
    pub global_per_minute: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum UnifiedServerStartupPlanError {
    #[error("invalid HTTP bind address: {0}")]
    InvalidHttpAddress(String),
    #[error("invalid HTTPS bind address: {0}")]
    InvalidHttpsAddress(String),
    #[error("invalid HTTP/3 bind address: {0}")]
    InvalidHttp3Address(String),
    #[error("invalid admin bind address: {0}")]
    InvalidAdminAddress(String),
    #[error("listener conflict: {0}")]
    ListenerConflict(String),
    #[error("invalid feature combination: {0}")]
    InvalidFeatureCombination(String),
}

impl UnifiedServerStartupPlan {
    /// Build a validated startup plan from a config snapshot without site
    /// membership. Explicit `[[http.listeners]]` entries that require site
    /// resolution should use [`Self::from_config_snapshot_with_sites`].
    pub fn from_config_snapshot(
        main_config: &MainConfig,
        worker_count: usize,
    ) -> Result<Self, UnifiedServerStartupPlanError> {
        Self::from_config_snapshot_with_sites(main_config, &HashMap::new(), worker_count)
    }

    /// Build a validated startup plan from the main config and loaded sites.
    ///
    /// This performs listener normalization, address parsing, worker count
    /// normalization, and rate-limit scaling without opening any sockets or
    /// spawning tasks.
    pub fn from_config_snapshot_with_sites(
        main_config: &MainConfig,
        sites: &HashMap<String, crate::config::SiteConfig>,
        worker_count: usize,
    ) -> Result<Self, UnifiedServerStartupPlanError> {
        let http_listeners =
            synvoid_config::normalize_http_listeners(main_config, sites).map_err(|e| {
                match e.field.as_str() {
                    field if field.starts_with("server.") => {
                        UnifiedServerStartupPlanError::InvalidHttpAddress(format!(
                            "{}: {}",
                            e.field, e.message
                        ))
                    }
                    field if field.starts_with("http3.") => {
                        UnifiedServerStartupPlanError::InvalidHttp3Address(format!(
                            "{}: {}",
                            e.field, e.message
                        ))
                    }
                    field if field.starts_with("admin.") => {
                        UnifiedServerStartupPlanError::InvalidAdminAddress(format!(
                            "{}: {}",
                            e.field, e.message
                        ))
                    }
                    field
                        if field.starts_with("http.listeners")
                            || field.starts_with("tls.")
                            || field.starts_with("site.listeners") =>
                    {
                        UnifiedServerStartupPlanError::ListenerConflict(format!(
                            "{}: {}",
                            e.field, e.message
                        ))
                    }
                    _ => UnifiedServerStartupPlanError::InvalidFeatureCombination(format!(
                        "{}: {}",
                        e.field, e.message
                    )),
                }
            })?;

        if worker_count > 1 && http_listeners.iter().any(|listener| listener.http3) {
            return Err(UnifiedServerStartupPlanError::InvalidFeatureCombination(
                "HTTP/3 with unified_server_workers > 1 is not qualified; keep one worker or disable http3"
                    .to_string(),
            ));
        }

        let tls_config = InternalTlsConfig::from(main_config.tls.clone());

        let admin_addr = if main_config.admin.enabled {
            Some(
                parse_host_port(&main_config.admin.bind_address, main_config.admin.port).map_err(
                    |e| {
                        UnifiedServerStartupPlanError::InvalidAdminAddress(format!(
                            "bind_address={}, port={}: {}",
                            main_config.admin.bind_address, main_config.admin.port, e
                        ))
                    },
                )?,
            )
        } else {
            None
        };

        let worker_count = worker_count.max(1);
        let scaled_ip = scale_ip_rate_limit(&main_config.defaults.ratelimit.ip, worker_count);
        let scaled_global =
            scale_global_rate_limit(&main_config.defaults.ratelimit.global, worker_count);

        let http3_config = main_config.http3.clone();

        Ok(Self {
            http_listeners,
            admin_addr,
            tls_enabled: tls_config.enabled,
            #[cfg(feature = "dns")]
            dns_enabled: main_config.dns.enabled,
            #[cfg(not(feature = "dns"))]
            dns_enabled: false,
            tcp_enabled: main_config.tcp.enabled,
            udp_enabled: main_config.udp.enabled,
            tunnel_enabled: main_config.tunnel.enabled,
            tunnel_quic_enabled: main_config.tunnel.quic.enabled,
            tunnel_config: if main_config.tunnel.enabled {
                Some(main_config.tunnel.clone())
            } else {
                None
            },
            http3_config,
            tls_config,
            worker_count,
            scaled_ip_rate_limit: scaled_ip,
            scaled_global_rate_limit: scaled_global,
        })
    }
}

/// Scale an `IpRateLimitConfig` by worker count using ceiling division.
fn scale_ip_rate_limit(base: &IpRateLimitConfig, worker_count: usize) -> IpRateLimitConfig {
    if worker_count <= 1 {
        return base.clone();
    }
    IpRateLimitConfig {
        per_second: ceil_div_u32(base.per_second, worker_count),
        per_minute: ceil_div_u32(base.per_minute, worker_count),
        per_5min: ceil_div_u32(base.per_5min, worker_count),
        per_10min: ceil_div_u32(base.per_10min, worker_count),
        per_hour: ceil_div_u32(base.per_hour, worker_count),
        per_day: ceil_div_u32(base.per_day, worker_count),
        burst: base.burst.max(1),
    }
}

/// Scale a `GlobalRateLimitConfig` by worker count using ceiling division.
fn scale_global_rate_limit(
    base: &GlobalRateLimitConfig,
    worker_count: usize,
) -> GlobalRateLimitConfig {
    if worker_count <= 1 {
        return base.clone();
    }
    GlobalRateLimitConfig {
        per_second: ceil_div_u32(base.per_second, worker_count),
        per_minute: ceil_div_u32(base.per_minute, worker_count),
        per_5min: ceil_div_u32(base.per_5min, worker_count),
        max_connections: base.max_connections,
    }
}

/// Ceiling division for u32 values.
fn ceil_div_u32(numerator: u32, denominator: usize) -> u32 {
    let d = denominator as f64;
    (numerator as f64 / d).ceil() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a minimal test MainConfig with defaults suitable for unit tests.
    fn make_test_main_config() -> MainConfig {
        MainConfig::default_config()
    }

    #[test]
    fn worker_count_zero_normalizes_to_one() {
        let cfg = make_test_main_config();
        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 0).expect("plan should build");
        assert_eq!(plan.worker_count, 1);
    }

    #[test]
    fn rate_limits_scale_by_worker_count() {
        let mut cfg = make_test_main_config();
        cfg.defaults.ratelimit.ip.per_second = 100;
        cfg.defaults.ratelimit.ip.per_minute = 600;
        cfg.defaults.ratelimit.global.per_second = 500;
        cfg.defaults.ratelimit.global.per_minute = 5000;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 4).expect("plan should build");

        assert_eq!(plan.scaled_ip_rate_limit.per_second, 25);
        assert_eq!(plan.scaled_ip_rate_limit.per_minute, 150);
        assert_eq!(plan.scaled_global_rate_limit.per_second, 125);
        assert_eq!(plan.scaled_global_rate_limit.per_minute, 1250);
    }

    #[test]
    fn invalid_http_host_returns_typed_error() {
        let mut cfg = make_test_main_config();
        cfg.server.host = "not-a-valid-host".to_string();

        let err = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1)
            .expect_err("should fail on bad host");
        assert!(
            matches!(err, UnifiedServerStartupPlanError::InvalidHttpAddress(_)),
            "expected InvalidHttpAddress, got: {:?}",
            err
        );
    }

    #[test]
    fn http3_disabled_does_not_parse_http3_addr() {
        let mut cfg = make_test_main_config();
        cfg.http3.enabled = false;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1).expect("plan should build");
        assert!(plan.http_listeners.iter().all(|listener| !listener.http3));
    }

    #[test]
    fn single_worker_leaves_limits_unchanged() {
        let mut cfg = make_test_main_config();
        cfg.defaults.ratelimit.ip.per_second = 42;
        cfg.defaults.ratelimit.global.per_second = 999;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1).expect("plan should build");
        assert_eq!(plan.scaled_ip_rate_limit.per_second, 42);
        assert_eq!(plan.scaled_global_rate_limit.per_second, 999);
    }

    #[test]
    fn same_port_https_and_http_conflict() {
        let mut cfg = make_test_main_config();
        cfg.tls.enabled = true;
        cfg.tls.port = cfg.server.port;

        let err = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1)
            .expect_err("should fail on conflict");
        assert!(
            matches!(err, UnifiedServerStartupPlanError::ListenerConflict(_)),
            "expected ListenerConflict, got: {:?}",
            err
        );
    }

    #[test]
    fn tls_enabled_populates_tls_config() {
        let mut cfg = make_test_main_config();
        cfg.tls.enabled = true;
        cfg.tls.port = 8443;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1).expect("plan should build");
        assert!(plan.tls_enabled);
        let https = plan
            .http_listeners
            .iter()
            .find(|listener| listener.tls && !listener.http3)
            .expect("HTTPS listener plan");
        assert_eq!(https.addr.port(), 8443);
    }

    #[test]
    fn http3_enabled_invalid_v6_addr_returns_typed_error() {
        let mut cfg = make_test_main_config();
        cfg.tls.enabled = true;
        cfg.http3.enabled = true;
        cfg.http3.host_v6 = Some("not-a-valid-ipv6".to_string());

        let err = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1)
            .expect_err("should fail on bad HTTP/3 IPv6 host");
        assert!(
            matches!(err, UnifiedServerStartupPlanError::InvalidHttp3Address(_)),
            "expected InvalidHttp3Address, got: {:?}",
            err
        );
    }

    #[test]
    fn h3_and_https_may_share_the_same_numeric_port() {
        let mut cfg = make_test_main_config();
        cfg.tls.enabled = true;
        cfg.tls.port = 8443;
        cfg.http3.enabled = true;
        cfg.http3.port = 8443;

        let plan = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1)
            .expect("TCP HTTPS and UDP HTTP/3 may share a port");
        assert!(plan
            .http_listeners
            .iter()
            .any(|listener| listener.tls && listener.tcp && !listener.http3));
        assert!(plan
            .http_listeners
            .iter()
            .any(|listener| listener.http3 && !listener.tcp));
    }

    #[test]
    fn admin_disabled_yields_no_admin_addr() {
        let mut cfg = make_test_main_config();
        cfg.admin.enabled = false;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1).expect("plan should build");
        assert!(plan.admin_addr.is_none());
    }

    #[test]
    fn admin_enabled_parses_admin_addr() {
        let mut cfg = make_test_main_config();
        cfg.admin.enabled = true;
        cfg.admin.bind_address = "127.0.0.1".to_string();
        cfg.admin.port = 18081;

        let plan =
            UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1).expect("plan should build");
        assert_eq!(
            plan.admin_addr.map(|a| a.port()),
            Some(18081),
            "admin addr must be parsed when enabled"
        );
    }

    #[test]
    fn admin_port_conflicting_with_http_is_rejected() {
        let mut cfg = make_test_main_config();
        cfg.admin.enabled = true;
        cfg.admin.bind_address = cfg.server.host.clone();
        cfg.admin.port = cfg.server.port;

        let err = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 1)
            .expect_err("should fail on admin/HTTP conflict");
        assert!(
            matches!(err, UnifiedServerStartupPlanError::ListenerConflict(_)),
            "expected ListenerConflict, got: {:?}",
            err
        );
    }

    #[test]
    fn multi_worker_http3_is_rejected_until_qualified() {
        let mut cfg = make_test_main_config();
        cfg.tls.enabled = true;
        cfg.http3.enabled = true;
        cfg.http3.port = 8443;
        cfg.tls.port = 9443;

        let err = UnifiedServerStartupPlan::from_config_snapshot(&cfg, 2)
            .expect_err("multi-worker H3 must be rejected");
        assert!(
            matches!(
                err,
                UnifiedServerStartupPlanError::InvalidFeatureCombination(_)
            ),
            "expected InvalidFeatureCombination, got: {:?}",
            err
        );
    }
}
