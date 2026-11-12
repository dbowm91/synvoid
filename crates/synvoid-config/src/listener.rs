use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::validation::ConfigValidationError;
use crate::{MainConfig, SiteConfig};

/// Stable identity for a configured HTTP listener.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema, ToSchema,
)]
pub struct ListenerId(pub String);

impl ListenerId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ListenerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ListenerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// One explicit `[[http.listeners]]` entry.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, ToSchema)]
pub struct HttpListenerConfig {
    pub name: String,
    pub address: String,
    pub port: u16,
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub http2: bool,
    #[serde(default)]
    pub http3: bool,
    #[serde(default)]
    pub default_site: Option<String>,
    #[serde(default)]
    pub ipv6_only: bool,
}

/// Normalized, validated listener consumed by runtime composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpListenerPlan {
    pub id: ListenerId,
    /// Whether this plan owns the TCP HTTP/HTTPS socket. Legacy HTTP/3-only
    /// synthesis sets this false because its UDP endpoint is already paired
    /// with the legacy HTTPS TCP listener.
    pub tcp: bool,
    pub addr: SocketAddr,
    pub tls: bool,
    pub http2: bool,
    pub http3: bool,
    pub ipv6_only: bool,
    pub default_site: Option<String>,
    pub site_ids: Vec<String>,
}

impl HttpListenerPlan {
    pub fn name(&self) -> &str {
        self.id.as_str()
    }

    pub fn transport(&self) -> &'static str {
        match (self.tcp, self.http3) {
            (true, true) => "tcp+udp",
            (false, true) => "udp",
            _ => "tcp",
        }
    }
}

fn err(field: impl Into<String>, message: impl Into<String>) -> ConfigValidationError {
    ConfigValidationError {
        field: field.into(),
        message: message.into(),
    }
}

fn parse_ip(address: &str, field: &str) -> Result<IpAddr, ConfigValidationError> {
    let ip = address.parse::<IpAddr>().map_err(|e| {
        err(
            field,
            format!("listener address '{address}' is not a literal IP address: {e}"),
        )
    })?;
    Ok(normalize_ip(ip))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        IpAddr::V4(_) => ip,
    }
}

fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalize_ip(addr.ip()), addr.port())
}

fn addresses_conflict(a: SocketAddr, b: SocketAddr, a_v6_only: bool, b_v6_only: bool) -> bool {
    let a = normalize_addr(a);
    let b = normalize_addr(b);
    if a.port() != b.port() {
        return false;
    }
    let a_ip = a.ip();
    let b_ip = b.ip();
    if a_ip == b_ip {
        return true;
    }
    match (a_ip, b_ip) {
        // A dual-stack `[::]` claims IPv4 too; `ipv6_only` removes that claim.
        (IpAddr::V4(_), IpAddr::V6(bv6)) => bv6.is_unspecified() && !b_v6_only,
        (IpAddr::V6(av6), IpAddr::V4(_)) => av6.is_unspecified() && !a_v6_only,
        (IpAddr::V4(av4), IpAddr::V4(bv4)) => av4.is_unspecified() || bv4.is_unspecified(),
        (IpAddr::V6(av6), IpAddr::V6(bv6)) => av6.is_unspecified() || bv6.is_unspecified(),
    }
}

fn validate_listener_name(name: &str) -> Result<(), ConfigValidationError> {
    if name.trim().is_empty() {
        return Err(err("http.listeners.name", "listener name cannot be empty"));
    }
    if name.len() > 128 {
        return Err(err(
            "http.listeners.name",
            format!("listener name '{name}' is too long (max 128)"),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(err(
            "http.listeners.name",
            format!(
                "listener name '{name}' may only contain ASCII letters, digits, '-', '_' and '.'"
            ),
        ));
    }
    Ok(())
}

fn parse_listener(
    config: &HttpListenerConfig,
    main: &MainConfig,
    sites: Option<&HashMap<String, SiteConfig>>,
) -> Result<HttpListenerPlan, ConfigValidationError> {
    validate_listener_name(&config.name)?;
    let field = format!("http.listeners.{}", config.name);
    if config.port == 0 {
        return Err(err(format!("{field}.port"), "port cannot be 0"));
    }
    let ip = parse_ip(&config.address, &format!("{field}.address"))?;
    if config.ipv6_only && !ip.is_ipv6() {
        return Err(err(
            format!("{field}.ipv6_only"),
            "ipv6_only is only valid for an IPv6 listener address",
        ));
    }
    if config.http2 && !config.tls {
        return Err(err(
            format!("{field}.http2"),
            "http2 = true requires tls = true; cleartext HTTP/2 (h2c) is not supported",
        ));
    }
    if config.http3 && !config.tls {
        return Err(err(
            format!("{field}.http3"),
            "http3 = true requires tls = true",
        ));
    }
    if config.tls && !main.tls.enabled {
        return Err(err(
            format!("{field}.tls"),
            "listener requires TLS but [tls].enabled = false",
        ));
    }

    let addr = SocketAddr::new(ip, config.port);
    let (site_ids, default_site) = if let Some(sites) = sites {
        let mut site_ids = Vec::new();
        for (id, site) in sites {
            let membership = &site.site.listeners;
            if membership.is_empty() || membership.iter().any(|name| name == &config.name) {
                site_ids.push(id.clone());
            }
        }
        site_ids.sort();
        site_ids.dedup();

        if let Some(default) = &config.default_site {
            if !sites.contains_key(default) {
                return Err(err(
                    format!("{field}.default_site"),
                    format!("default_site '{default}' is not a configured site"),
                ));
            }
            if !site_ids.iter().any(|id| id == default) {
                return Err(err(
                    format!("{field}.default_site"),
                    format!(
                        "default_site '{default}' is not a member of listener '{}'",
                        config.name
                    ),
                ));
            }
        }
        if site_ids.is_empty() && config.default_site.is_none() {
            return Err(err(
                field.to_string(),
                "listener has no sites and no default_site",
            ));
        }
        (site_ids, config.default_site.clone())
    } else {
        (Vec::new(), config.default_site.clone())
    };

    Ok(HttpListenerPlan {
        id: ListenerId::new(config.name.clone()),
        tcp: true,
        addr,
        tls: config.tls,
        http2: config.http2,
        http3: config.http3,
        ipv6_only: config.ipv6_only,
        default_site,
        site_ids,
    })
}

fn parse_legacy_bind(
    host: &str,
    port: u16,
    field: &str,
) -> Result<SocketAddr, ConfigValidationError> {
    let ip = parse_ip(host, field)?;
    Ok(SocketAddr::new(ip, port))
}

fn legacy_plans(
    main: &MainConfig,
    sites: Option<&HashMap<String, SiteConfig>>,
) -> Result<Vec<HttpListenerPlan>, ConfigValidationError> {
    let site_ids = sites
        .map(|sites| {
            let mut ids: Vec<String> = sites.keys().cloned().collect();
            ids.sort();
            ids
        })
        .unwrap_or_default();

    let mut plans = Vec::new();
    let v4 = parse_legacy_bind(&main.server.host, main.server.port, "server.host")?;
    plans.push(HttpListenerPlan {
        id: ListenerId::new("default-http"),
        tcp: true,
        addr: v4,
        tls: false,
        http2: false,
        http3: false,
        ipv6_only: false,
        default_site: None,
        site_ids: site_ids.clone(),
    });
    if let Some(host_v6) = main.server.host_v6.as_deref() {
        let v6 = parse_legacy_bind(host_v6, main.server.port, "server.host_v6")?;
        if !v6.ip().is_ipv4() {
            plans.push(HttpListenerPlan {
                id: ListenerId::new("default-http-v6"),
                tcp: true,
                addr: v6,
                tls: false,
                http2: false,
                http3: false,
                ipv6_only: false,
                default_site: None,
                site_ids: site_ids.clone(),
            });
        }
    }

    if main.tls.enabled {
        let https = parse_legacy_bind(&main.server.host, main.tls.port, "tls.port")?;
        plans.push(HttpListenerPlan {
            id: ListenerId::new("default-https"),
            tcp: true,
            addr: https,
            tls: true,
            http2: true,
            http3: false,
            ipv6_only: false,
            default_site: None,
            site_ids: site_ids.clone(),
        });
        if let Some(host_v6) = main.server.host_v6.as_deref() {
            let v6 = parse_legacy_bind(host_v6, main.tls.port, "server.host_v6")?;
            if !v6.ip().is_ipv4() {
                plans.push(HttpListenerPlan {
                    id: ListenerId::new("default-https-v6"),
                    tcp: true,
                    addr: v6,
                    tls: true,
                    http2: true,
                    http3: false,
                    ipv6_only: false,
                    default_site: None,
                    site_ids: site_ids.clone(),
                });
            }
        }
    }

    if main.http3.enabled {
        if !main.tls.enabled {
            return Err(err("http3.enabled", "HTTP/3 requires [tls].enabled = true"));
        }
        let v4 = parse_legacy_bind(&main.server.host, main.http3.port, "http3.port")?;
        plans.push(HttpListenerPlan {
            id: ListenerId::new("default-http3"),
            tcp: false,
            addr: v4,
            tls: true,
            http2: false,
            http3: true,
            ipv6_only: false,
            default_site: None,
            site_ids: site_ids.clone(),
        });
        if let Some(host_v6) = main.http3.host_v6.as_deref() {
            let v6 = parse_legacy_bind(host_v6, main.http3.port, "http3.host_v6")?;
            if !v6.ip().is_ipv4() {
                plans.push(HttpListenerPlan {
                    id: ListenerId::new("default-http3-v6"),
                    tcp: false,
                    addr: v6,
                    tls: true,
                    http2: false,
                    http3: true,
                    ipv6_only: false,
                    default_site: None,
                    site_ids,
                });
            }
        }
    }

    Ok(plans)
}

fn validate_site_membership(
    main: &MainConfig,
    sites: &HashMap<String, SiteConfig>,
) -> Result<(), ConfigValidationError> {
    let names: HashSet<&str> = main
        .http
        .listeners
        .iter()
        .map(|l| l.name.as_str())
        .collect();
    let mut seen_site_ids: BTreeSet<String> = BTreeSet::new();
    for (id, site) in sites {
        if !seen_site_ids.insert(site.site_id()) {
            return Err(err(
                "site.domains",
                format!(
                    "duplicate site identity '{}' (first domain is the site id)",
                    site.site_id()
                ),
            ));
        }
        let mut seen: HashSet<&str> = HashSet::new();
        for listener in &site.site.listeners {
            if listener.trim().is_empty() {
                return Err(err(
                    "site.listeners",
                    format!("site '{id}' contains an empty listener name"),
                ));
            }
            if !seen.insert(listener.as_str()) {
                return Err(err(
                    "site.listeners",
                    format!("site '{id}' lists listener '{listener}' more than once"),
                ));
            }
            if !names.contains(listener.as_str()) {
                return Err(err(
                    "site.listeners",
                    format!("site '{id}' references unknown listener '{listener}'"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_plan_conflicts(plans: &[HttpListenerPlan]) -> Result<(), ConfigValidationError> {
    for (i, a) in plans.iter().enumerate() {
        for b in plans.iter().skip(i + 1) {
            let tcp_conflict =
                a.tcp && b.tcp && addresses_conflict(a.addr, b.addr, a.ipv6_only, b.ipv6_only);
            if tcp_conflict {
                return Err(err(
                    "http.listeners",
                    format!(
                        "listeners '{}' ({}) and '{}' ({}) claim the same TCP endpoint",
                        a.id, a.addr, b.id, b.addr
                    ),
                ));
            }
            if a.http3 && b.http3 && addresses_conflict(a.addr, b.addr, a.ipv6_only, b.ipv6_only) {
                return Err(err(
                    "http.listeners",
                    format!(
                        "HTTP/3 listeners '{}' ({}) and '{}' ({}) claim the same UDP endpoint",
                        a.id, a.addr, b.id, b.addr
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn external_tcp_addrs(main: &MainConfig) -> Vec<(String, SocketAddr)> {
    let mut out = Vec::new();
    let mut push = |label: String, host: &str, port: u16| {
        if let Ok(ip) = host.parse::<IpAddr>() {
            out.push((label, SocketAddr::new(normalize_ip(ip), port)));
        }
    };

    if main.admin.enabled {
        push(
            "admin".to_string(),
            &main.admin.bind_address,
            main.admin.port,
        );
    }
    if main.metrics.enabled {
        push(
            "metrics".to_string(),
            &main.metrics.bind_address,
            main.metrics.port,
        );
    }
    if main.tcp.enabled {
        for (protocol, config) in &main.tcp.protocols {
            for port in &config.ports {
                push(format!("tcp:{protocol}"), &main.server.host, *port);
                if let Some(host_v6) = main.server.host_v6.as_deref() {
                    push(format!("tcp:{protocol}:v6"), host_v6, *port);
                }
            }
        }
    }
    #[cfg(feature = "dns")]
    if main.dns.enabled {
        push("dns".to_string(), &main.dns.bind_address, main.dns.port);
        if main.dns.dot.enabled {
            push(
                "dns.dot".to_string(),
                &main.dns.dot.bind_address,
                main.dns.dot.port,
            );
        }
        if main.dns.doh.enabled {
            push(
                "dns.doh".to_string(),
                &main.dns.doh.bind_address,
                main.dns.doh.port,
            );
        }
    }
    #[cfg(feature = "mesh")]
    if let Some(mesh) = main.mesh.as_ref().filter(|m| m.enabled) {
        let host = mesh.bind_address.as_deref().unwrap_or(&main.server.host);
        push("mesh".to_string(), host, mesh.port);
    }
    if main.tunnel.enabled {
        if main.tunnel.vpn.enabled {
            push(
                "tunnel.vpn".to_string(),
                &main.tunnel.vpn.bind_address,
                main.tunnel.vpn.port,
            );
        }
        if main.tunnel.quic.enabled {
            push(
                "tunnel.quic".to_string(),
                &main.tunnel.quic.bind_address,
                main.tunnel.quic.port,
            );
        }
    }
    out
}

fn external_udp_addrs(main: &MainConfig) -> Vec<(String, SocketAddr)> {
    let mut out = Vec::new();
    let mut push = |label: String, host: &str, port: u16| {
        if let Ok(ip) = host.parse::<IpAddr>() {
            out.push((label, SocketAddr::new(normalize_ip(ip), port)));
        }
    };
    if main.udp.enabled {
        for (protocol, config) in &main.udp.protocols {
            for port in &config.ports {
                push(format!("udp:{protocol}"), &main.server.host, *port);
                if let Some(host_v6) = main.server.host_v6.as_deref() {
                    push(format!("udp:{protocol}:v6"), host_v6, *port);
                }
            }
        }
    }
    #[cfg(feature = "dns")]
    if main.dns.enabled {
        push("dns".to_string(), &main.dns.bind_address, main.dns.port);
        if main.dns.doq.enabled {
            push(
                "dns.doq".to_string(),
                &main.dns.doq.bind_address,
                main.dns.doq.port,
            );
        }
    }
    #[cfg(feature = "mesh")]
    if let Some(mesh) = main.mesh.as_ref().filter(|m| m.enabled) {
        let host = mesh.bind_address.as_deref().unwrap_or(&main.server.host);
        if let Some(port) = mesh.quic_port {
            push("mesh.quic".to_string(), host, port);
        }
    }
    if main.tunnel.enabled {
        if main.tunnel.vpn.enabled {
            push(
                "tunnel.vpn".to_string(),
                &main.tunnel.vpn.bind_address,
                main.tunnel.vpn.port,
            );
        }
        if main.tunnel.quic.enabled {
            push(
                "tunnel.quic".to_string(),
                &main.tunnel.quic.bind_address,
                main.tunnel.quic.port,
            );
        }
    }
    out
}

fn validate_cross_family(
    main: &MainConfig,
    plans: &[HttpListenerPlan],
) -> Result<(), ConfigValidationError> {
    let tcp = external_tcp_addrs(main);
    let udp = external_udp_addrs(main);
    for plan in plans {
        if plan.tcp {
            for (label, addr) in &tcp {
                if addresses_conflict(plan.addr, *addr, plan.ipv6_only, false) {
                    return Err(err(
                        "http.listeners",
                        format!(
                            "listener '{}' ({}) conflicts with {label} on {}",
                            plan.id, plan.addr, addr
                        ),
                    ));
                }
            }
        }
        if plan.http3 {
            for (label, addr) in &udp {
                if addresses_conflict(plan.addr, *addr, plan.ipv6_only, false) {
                    return Err(err(
                        "http.listeners",
                        format!(
                            "HTTP/3 listener '{}' ({}) conflicts with {label} on {}",
                            plan.id, plan.addr, addr
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn build_plans(
    main: &MainConfig,
    sites: Option<&HashMap<String, SiteConfig>>,
) -> Result<Vec<HttpListenerPlan>, ConfigValidationError> {
    if main.http.listeners.is_empty() {
        return legacy_plans(main, sites);
    }

    let mut names: HashSet<String> = HashSet::new();
    let mut plans = Vec::with_capacity(main.http.listeners.len());
    for config in &main.http.listeners {
        let key = config.name.to_ascii_lowercase();
        if !names.insert(key) {
            return Err(err(
                "http.listeners.name",
                format!(
                    "duplicate listener name '{}' (names are case-insensitive)",
                    config.name
                ),
            ));
        }
        plans.push(parse_listener(config, main, sites)?);
    }
    Ok(plans)
}

/// Validate listener declarations without site membership.
///
/// Called by `MainConfig::validate()`; `configtest` and runtime composition
/// call [`normalize_http_listeners`] with the loaded sites as well.
pub fn validate_listener_declarations(main: &MainConfig) -> Result<(), ConfigValidationError> {
    let plans = build_plans(main, None)?;
    validate_plan_conflicts(&plans)?;
    validate_cross_family(main, &plans)?;
    Ok(())
}

/// Normalize the canonical schema (or synthesize the legacy listeners) into
/// the single runtime listener plan.
pub fn normalize_http_listeners(
    main: &MainConfig,
    sites: &HashMap<String, SiteConfig>,
) -> Result<Vec<HttpListenerPlan>, ConfigValidationError> {
    if !main.http.listeners.is_empty() {
        validate_site_membership(main, sites)?;
    } else if let Some((id, _)) = sites
        .iter()
        .find(|(_, site)| !site.site.listeners.is_empty())
    {
        return Err(err(
            "site.listeners",
            format!(
                "site '{id}' lists listeners but [[http.listeners]] is absent; \
                 declare the process-wide listeners first"
            ),
        ));
    }
    let plans = build_plans(main, Some(sites))?;
    validate_plan_conflicts(&plans)?;
    validate_cross_family(main, &plans)?;
    Ok(plans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::UpstreamConfig;

    fn site(domain: &str, listeners: Vec<&str>) -> SiteConfig {
        let mut site = SiteConfig::default();
        site.site.domains = vec![domain.to_string()];
        site.site.listeners = listeners.into_iter().map(String::from).collect();
        site.site.upstream = UpstreamConfig::default();
        site
    }

    fn main_with(listeners: Vec<HttpListenerConfig>) -> MainConfig {
        let mut main = MainConfig::default_config();
        main.http.listeners = listeners;
        main
    }

    fn listener(name: &str, address: &str, port: u16) -> HttpListenerConfig {
        HttpListenerConfig {
            name: name.to_string(),
            address: address.to_string(),
            port,
            tls: false,
            http2: false,
            http3: false,
            default_site: None,
            ipv6_only: false,
        }
    }

    #[test]
    fn two_listeners_normalize() {
        let main = main_with(vec![
            listener("public-http", "0.0.0.0", 8080),
            listener("internal-http", "127.0.0.1", 18081),
        ]);
        let mut sites = HashMap::new();
        sites.insert("example.com".to_string(), site("example.com", vec![]));
        let plans = normalize_http_listeners(&main, &sites).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].site_ids, vec!["example.com"]);
        assert_eq!(plans[1].id.as_str(), "internal-http");
    }

    #[test]
    fn legacy_config_synthesizes_http() {
        let mut main = MainConfig::default_config();
        main.server.host = "127.0.0.1".to_string();
        main.server.port = 8080;
        main.tls.enabled = false;
        main.http3.enabled = false;
        let plans = normalize_http_listeners(&main, &HashMap::new()).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].id.as_str(), "default-http");
        assert_eq!(plans[0].addr.port(), 8080);
    }

    #[test]
    fn duplicate_name_rejected_case_insensitively() {
        let main = main_with(vec![
            listener("Public", "127.0.0.1", 8080),
            listener("public", "127.0.0.1", 8081),
        ]);
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }

    #[test]
    fn wildcard_and_concrete_conflict() {
        let main = main_with(vec![
            listener("all", "0.0.0.0", 8080),
            listener("one", "127.0.0.1", 8080),
        ]);
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }

    #[test]
    fn https_and_h3_same_port_allowed() {
        let mut main = main_with(vec![
            HttpListenerConfig {
                tls: true,
                http2: true,
                ..listener("https", "0.0.0.0", 443)
            },
            HttpListenerConfig {
                tls: true,
                http3: true,
                ..listener("h3", "127.0.0.1", 1443)
            },
        ]);
        main.tls.enabled = true;
        let mut sites = HashMap::new();
        sites.insert("example.com".to_string(), site("example.com", vec![]));
        assert!(normalize_http_listeners(&main, &sites).is_ok());
    }

    #[test]
    fn plaintext_h2_rejected() {
        let main = main_with(vec![HttpListenerConfig {
            http2: true,
            ..listener("h2c", "127.0.0.1", 8080)
        }]);
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }

    #[test]
    fn h3_without_tls_rejected() {
        let main = main_with(vec![HttpListenerConfig {
            http3: true,
            ..listener("h3", "127.0.0.1", 443)
        }]);
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }

    #[test]
    fn unknown_site_membership_rejected() {
        let mut main = main_with(vec![listener("public", "127.0.0.1", 8080)]);
        main.http.listeners[0].default_site = Some("example.com".to_string());
        let mut sites = HashMap::new();
        sites.insert(
            "example.com".to_string(),
            site("example.com", vec!["missing"]),
        );
        assert!(normalize_http_listeners(&main, &sites).is_err());
    }

    #[test]
    fn default_site_must_be_member() {
        let mut main = main_with(vec![
            listener("public", "127.0.0.1", 8080),
            listener("other", "127.0.0.1", 8081),
        ]);
        main.http.listeners[0].default_site = Some("example.com".to_string());
        let mut sites = HashMap::new();
        sites.insert(
            "example.com".to_string(),
            site("example.com", vec!["other"]),
        );
        assert!(normalize_http_listeners(&main, &sites).is_err());
    }

    #[test]
    fn listener_without_sites_rejected() {
        let main = main_with(vec![listener("public", "127.0.0.1", 8080)]);
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }

    #[test]
    fn http_and_raw_tcp_conflict() {
        let mut main = main_with(vec![listener("public", "127.0.0.1", 8080)]);
        main.tcp.enabled = true;
        main.tcp.protocols.clear();
        main.tcp.protocols.insert(
            "smtp".to_string(),
            crate::network::TcpProtocolConfig {
                ports: vec![8080],
                upstream_format: Some("127.0.0.1:25".to_string()),
                upstream_format_v6: None,
                filter_enabled: None,
                strict_mode: None,
            },
        );
        assert!(normalize_http_listeners(&main, &HashMap::new()).is_err());
    }
}
