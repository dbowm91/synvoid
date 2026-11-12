//! Composition builder for the TCP/UDP auxiliary listener pools.
//!
//! The top-level `[tcp.protocols.*]` and `[udp.protocols.*]` maps are the
//! single runtime source of truth. Each entry expands into one listener per
//! declared port and address family:
//!
//! - bind address from `[server] host` (and `host_v6` when set),
//! - expected protocol from the map key,
//! - upstream from `upstream_format` / `upstream_format_v6` with `{port}`
//!   substituted,
//! - strict protocol filtering for the declared protocol,
//! - socket options and timeouts from `[tcp]` / `[udp]`.
//!
//! Validation is fail-closed here as well as in `synvoid-config`: a malformed
//! upstream, an empty port list, a duplicate port, an unparseable bind address
//! or a port with no v4/v6 bind target refuses startup rather than producing
//! a silently empty pool.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

use synvoid_config::MainConfig;

use crate::tcp::listener::{TcpListenerConfig, TcpSocketOptions};
use crate::udp::listener::{UdpListenerConfig, UdpSocketOptions};

#[derive(Debug, thiserror::Error)]
pub enum AuxListenerConfigError {
    #[error("tcp: {0}")]
    Tcp(String),
    #[error("udp: {0}")]
    Udp(String),
}

fn render_upstream(
    protocol: &str,
    port: u16,
    template: &str,
) -> Result<String, AuxListenerConfigError> {
    let rendered = template.replace("{port}", &port.to_string());
    if rendered.contains("{port}") {
        return Err(AuxListenerConfigError::Tcp(format!(
            "protocol '{protocol}' port {port}: unresolved {{port}} placeholder in '{template}'"
        )));
    }
    Ok(rendered)
}

fn render_udp_upstream(
    protocol: &str,
    port: u16,
    template: &str,
) -> Result<String, AuxListenerConfigError> {
    let rendered = template.replace("{port}", &port.to_string());
    if rendered.contains("{port}") {
        return Err(AuxListenerConfigError::Udp(format!(
            "protocol '{protocol}' port {port}: unresolved {{port}} placeholder in '{template}'"
        )));
    }
    Ok(rendered)
}

fn parse_bind(host: &str, port: u16, section: &str) -> Result<SocketAddr, AuxListenerConfigError> {
    crate::utils::parse_host_port(host, port).map_err(|e| {
        let err = format!("{section}: bind host '{host}' port {port} is not a valid address: {e}");
        if section == "udp" {
            AuxListenerConfigError::Udp(err)
        } else {
            AuxListenerConfigError::Tcp(err)
        }
    })
}

fn bind_targets(
    main_config: &MainConfig,
    port: u16,
    section: &str,
) -> Result<Vec<SocketAddr>, AuxListenerConfigError> {
    let primary = parse_bind(&main_config.server.host, port, section)?;
    if primary.is_ipv6() {
        // `[server] host` already selected the IPv6 family; a second v6 bind
        // on the same port would conflict.
        return Ok(vec![primary]);
    }
    let mut targets = vec![primary];
    if let Some(host_v6) = main_config.server.host_v6.as_deref() {
        let v6 = parse_bind(host_v6, port, section)?;
        if v6.is_ipv6() && !targets.iter().any(|a| a.ip() == v6.ip()) {
            targets.push(v6);
        }
    }
    Ok(targets)
}

fn upstream_for(
    protocol: &str,
    port: u16,
    base: &str,
    v6: Option<&str>,
    target: SocketAddr,
    udp: bool,
) -> Result<String, AuxListenerConfigError> {
    let template = if target.is_ipv6() {
        v6.unwrap_or(base)
    } else {
        base
    };
    if udp {
        render_udp_upstream(protocol, port, template)
    } else {
        render_upstream(protocol, port, template)
    }
}

fn ensure_upstream_parses(
    section: &str,
    protocol: &str,
    port: u16,
    upstream: &str,
) -> Result<(), AuxListenerConfigError> {
    if upstream.starts_with("quictunnel:") {
        let rest = upstream
            .trim_start_matches("quictunnel://")
            .trim_start_matches("quictunnel:");
        if let Some((peer, port)) = rest.rsplit_once(':') {
            if !peer.is_empty() && port.parse::<u16>().is_ok() {
                return Ok(());
            }
        }
    } else if upstream.starts_with("unix:")
        || upstream.starts_with("http+unix:")
        || upstream.starts_with('/')
        || upstream.starts_with("./")
    {
        return Ok(());
    } else {
        let socket = if let Some(rest) = upstream
            .strip_prefix("http://")
            .or_else(|| upstream.strip_prefix("https://"))
        {
            rest.split('/').next().unwrap_or(rest)
        } else {
            upstream
        };
        if socket.parse::<SocketAddr>().is_ok() {
            return Ok(());
        }
    }

    let err = format!(
        "protocol '{protocol}' port {port}: upstream '{upstream}' is not a socket address \
         (use host:port, [v6]:port, unix:/path or quictunnel:peer:port)"
    );
    if section == "udp" {
        Err(AuxListenerConfigError::Udp(err))
    } else {
        Err(AuxListenerConfigError::Tcp(err))
    }
}

/// Expand `[tcp.protocols.*]` into listener configurations.
pub fn build_tcp_listener_configs(
    main_config: &MainConfig,
) -> Result<Vec<TcpListenerConfig>, AuxListenerConfigError> {
    if !main_config.tcp.enabled {
        return Ok(Vec::new());
    }

    main_config
        .tcp
        .validate()
        .map_err(|e| AuxListenerConfigError::Tcp(format!("{}: {}", e.field, e.message)))?;

    let socket_options = TcpSocketOptions {
        nodelay: main_config.tcp.socket.nodelay,
        send_buffer_size: main_config.tcp.socket.send_buffer_size,
        recv_buffer_size: main_config.tcp.socket.recv_buffer_size,
        reuse_port: true,
        reuse_port_ebpf: false,
        quickack: true,
        keepalive_secs: Some(60),
        keepalive_interval_secs: Some(10),
        keepalive_retries: Some(3),
    };

    let mut protocols: Vec<_> = main_config.tcp.protocols.iter().collect();
    protocols.sort_by(|a, b| a.0.cmp(b.0));

    let mut configs = Vec::new();
    let mut claimed: HashMap<(IpAddr, u16), String> = HashMap::new();

    for (protocol, entry) in protocols {
        let base_upstream = entry.upstream_format.as_deref().ok_or_else(|| {
            AuxListenerConfigError::Tcp(format!(
                "protocol '{protocol}': upstream_format is required"
            ))
        })?;
        let mut ports = entry.ports.clone();
        ports.sort_unstable();
        ports.dedup();

        for port in ports {
            if port < 1024 {
                tracing::warn!(
                    protocol = %protocol,
                    port,
                    "TCP listener uses a privileged port; binding requires root or CAP_NET_BIND_SERVICE"
                );
            }
            for target in bind_targets(main_config, port, "tcp")? {
                if let Some(existing) = claimed.insert((target.ip(), port), protocol.clone()) {
                    if existing != *protocol {
                        return Err(AuxListenerConfigError::Tcp(format!(
                            "port {port} on {} is claimed by both '{existing}' and '{protocol}'",
                            target.ip()
                        )));
                    }
                    return Err(AuxListenerConfigError::Tcp(format!(
                        "port {port} on {} is claimed twice by '{protocol}'",
                        target.ip()
                    )));
                }
                let upstream = upstream_for(
                    protocol,
                    port,
                    base_upstream,
                    entry.upstream_format_v6.as_deref(),
                    target,
                    false,
                )?;
                ensure_upstream_parses("tcp", protocol, port, &upstream)?;
                configs.push(TcpListenerConfig {
                    port,
                    bind_address: target.ip().to_string(),
                    bind_address_v6: None,
                    expected_protocol: protocol.to_string(),
                    upstream_address: upstream,
                    upstream_address_v6: None,
                    filter_enabled: entry.filter_enabled.unwrap_or(true),
                    strict_mode: entry.strict_mode.unwrap_or(true),
                    socket_options: socket_options.clone(),
                    tcp_backlog: None,
                    idle_timeout_secs: main_config.tcp.idle_timeout_secs,
                });
            }
        }
    }

    Ok(configs)
}

/// Expand `[udp.protocols.*]` into listener configurations.
pub fn build_udp_listener_configs(
    main_config: &MainConfig,
) -> Result<Vec<UdpListenerConfig>, AuxListenerConfigError> {
    if !main_config.udp.enabled {
        return Ok(Vec::new());
    }

    main_config
        .udp
        .validate()
        .map_err(|e| AuxListenerConfigError::Udp(format!("{}: {}", e.field, e.message)))?;

    let socket_options = UdpSocketOptions {
        reuse_port: true,
        recv_buffer_size: main_config.udp.socket.recv_buffer_size,
        send_buffer_size: main_config.udp.socket.send_buffer_size,
    };

    let mut protocols: Vec<_> = main_config.udp.protocols.iter().collect();
    protocols.sort_by(|a, b| a.0.cmp(b.0));

    let mut configs = Vec::new();
    let mut claimed: HashSet<(IpAddr, u16)> = HashSet::new();

    for (protocol, entry) in protocols {
        let base_upstream = entry.upstream_format.as_deref().ok_or_else(|| {
            AuxListenerConfigError::Udp(format!(
                "protocol '{protocol}': upstream_format is required"
            ))
        })?;
        let mut ports = entry.ports.clone();
        ports.sort_unstable();
        ports.dedup();

        for port in ports {
            if port < 1024 {
                tracing::warn!(
                    protocol = %protocol,
                    port,
                    "UDP listener uses a privileged port; binding requires root or CAP_NET_BIND_SERVICE"
                );
            }
            for target in bind_targets(main_config, port, "udp")? {
                if !claimed.insert((target.ip(), port)) {
                    return Err(AuxListenerConfigError::Udp(format!(
                        "port {port} on {} is claimed by more than one protocol",
                        target.ip()
                    )));
                }
                let upstream = upstream_for(
                    protocol,
                    port,
                    base_upstream,
                    entry.upstream_format_v6.as_deref(),
                    target,
                    true,
                )?;
                ensure_upstream_parses("udp", protocol, port, &upstream)?;
                configs.push(UdpListenerConfig {
                    port,
                    bind_address: target.ip().to_string(),
                    bind_address_v6: None,
                    expected_protocol: protocol.to_string(),
                    upstream_address: upstream,
                    upstream_address_v6: None,
                    filter_enabled: entry.filter_enabled.unwrap_or(true),
                    strict_mode: entry.strict_mode.unwrap_or(true),
                    max_packet_size: main_config.udp.max_packet_size,
                    rate_limit_per_ip: main_config.udp.rate_per_ip,
                    socket_options: socket_options.clone(),
                    max_flows: main_config.udp.max_flows,
                    flow_idle_timeout_secs: main_config.udp.flow_idle_timeout_secs,
                });
            }
        }
    }

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> MainConfig {
        let mut config = MainConfig::default();
        config.server.host = "127.0.0.1".to_string();
        config.server.host_v6 = Some("::1".to_string());
        config
    }

    #[test]
    fn disabled_sections_expand_to_nothing() {
        let config = base_config();
        assert!(build_tcp_listener_configs(&config).unwrap().is_empty());
        assert!(build_udp_listener_configs(&config).unwrap().is_empty());
    }

    #[test]
    fn enabled_tcp_expands_each_port_and_family() {
        let mut config = base_config();
        config.tcp.enabled = true;
        config.tcp.protocols.clear();
        config.tcp.protocols.insert(
            "echo".to_string(),
            synvoid_config::network::TcpProtocolConfig {
                ports: vec![9001],
                upstream_format: Some("127.0.0.1:{port}".to_string()),
                upstream_format_v6: Some("[::1]:{port}".to_string()),
                ..Default::default()
            },
        );

        let listeners = build_tcp_listener_configs(&config).unwrap();
        assert_eq!(listeners.len(), 2);
        assert!(listeners.iter().any(|l| l.bind_address == "127.0.0.1"));
        assert!(listeners.iter().any(|l| l.bind_address == "::1"));
        let v6 = listeners
            .iter()
            .find(|l| l.bind_address == "::1")
            .expect("v6 listener");
        assert_eq!(v6.upstream_address, "[::1]:9001");
        assert_eq!(v6.expected_protocol, "echo");
    }

    #[test]
    fn invalid_upstream_template_is_rejected_at_build_time() {
        let mut config = base_config();
        config.tcp.enabled = true;
        config.tcp.protocols.clear();
        config.tcp.protocols.insert(
            "echo".to_string(),
            synvoid_config::network::TcpProtocolConfig {
                ports: vec![9001],
                upstream_format: Some("not-an-address".to_string()),
                upstream_format_v6: None,
                ..Default::default()
            },
        );

        let err = build_tcp_listener_configs(&config).expect_err("invalid upstream must fail");
        assert!(
            err.to_string().contains("cannot produce a socket address"),
            "{err}"
        );
    }

    #[test]
    fn duplicate_udp_port_is_rejected_at_build_time() {
        let mut config = base_config();
        config.server.host_v6 = None;
        config.udp.enabled = true;
        config.udp.protocols.clear();
        for name in ["a", "b"] {
            config.udp.protocols.insert(
                name.to_string(),
                synvoid_config::network::UdpProtocolConfig {
                    ports: vec![9002],
                    upstream_format: Some("127.0.0.1:9002".to_string()),
                    upstream_format_v6: None,
                    ..Default::default()
                },
            );
        }

        let err = build_udp_listener_configs(&config).expect_err("duplicate must fail");
        assert!(err.to_string().contains("already claimed"), "{err}");
    }
}
