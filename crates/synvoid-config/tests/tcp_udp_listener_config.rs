//! Phase 02: the global `[tcp.protocols]` / `[udp.protocols]` maps are the
//! only listener source of truth, and configtest rejects definitions that
//! cannot produce a listener.

use synvoid_config::network::{TcpProtocolConfig, UdpProtocolConfig};
use synvoid_config::site::{SiteConfig, SitePortConfig, SiteTcpConfig};
use synvoid_config::MainConfig;

fn tcp_entry(ports: Vec<u16>, upstream: Option<&str>) -> TcpProtocolConfig {
    TcpProtocolConfig {
        ports,
        upstream_format: upstream.map(str::to_string),
        upstream_format_v6: None,
        ..Default::default()
    }
}

#[test]
fn enabled_tcp_with_no_protocols_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = true;
    cfg.tcp.protocols.clear();

    let err = cfg
        .validate()
        .expect_err("enabled TCP without protocols must fail");
    assert_eq!(err.field, "tcp.protocols");
    assert!(err.message.contains("no [tcp.protocols.*]"));
}

#[test]
fn enabled_udp_with_no_protocols_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.udp.enabled = true;
    cfg.udp.protocols.clear();

    let err = cfg
        .validate()
        .expect_err("enabled UDP without protocols must fail");
    assert_eq!(err.field, "udp.protocols");
}

#[test]
fn missing_upstream_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = true;
    cfg.tcp.protocols.clear();
    cfg.tcp
        .protocols
        .insert("smtp".to_string(), tcp_entry(vec![25], None));

    let err = cfg.validate().expect_err("missing upstream must fail");
    assert_eq!(err.field, "tcp.protocols.smtp.upstream_format");
}

#[test]
fn invalid_upstream_template_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = true;
    cfg.tcp.protocols.clear();
    cfg.tcp.protocols.insert(
        "smtp".to_string(),
        tcp_entry(vec![25], Some("mail.internal:{port}")),
    );

    let err = cfg.validate().expect_err("non-socket upstream must fail");
    assert_eq!(err.field, "tcp.protocols.smtp.upstream_format");
    assert!(err.message.contains("cannot produce a socket address"));
}

#[test]
fn duplicate_port_across_protocols_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = true;
    cfg.tcp.protocols.clear();
    cfg.tcp.protocols.insert(
        "smtp".to_string(),
        tcp_entry(vec![2525], Some("127.0.0.1:{port}")),
    );
    cfg.tcp.protocols.insert(
        "imap".to_string(),
        tcp_entry(vec![2525], Some("127.0.0.1:{port}")),
    );

    let err = cfg.validate().expect_err("duplicate port must fail");
    assert!(err.message.contains("already claimed"), "{}", err.message);
}

#[test]
fn duplicate_udp_port_across_protocols_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.udp.enabled = true;
    cfg.udp.protocols.clear();
    for name in ["dns", "ntp"] {
        cfg.udp.protocols.insert(
            name.to_string(),
            UdpProtocolConfig {
                ports: vec![5353],
                upstream_format: Some("127.0.0.1:5353".to_string()),
                upstream_format_v6: None,
                ..Default::default()
            },
        );
    }

    let err = cfg.validate().expect_err("duplicate UDP port must fail");
    assert!(err.message.contains("already claimed"), "{}", err.message);
}

#[test]
fn zero_port_is_rejected() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = true;
    cfg.tcp.protocols.clear();
    cfg.tcp.protocols.insert(
        "smtp".to_string(),
        tcp_entry(vec![0], Some("127.0.0.1:{port}")),
    );

    let err = cfg.validate().expect_err("port 0 must fail");
    assert!(err.message.contains("port 0"));
}

#[test]
fn disabled_sections_do_not_validate_their_definitions() {
    let mut cfg = MainConfig::default();
    cfg.tcp.enabled = false;
    cfg.tcp.protocols.clear();
    cfg.udp.enabled = false;
    cfg.udp.protocols.clear();

    cfg.validate().expect("disabled sections may be empty");
}

#[test]
fn site_level_tcp_listener_schema_is_rejected() {
    let toml = r#"
[site]
domains = ["example.com"]

[site.upstream]
default = "http://localhost:3000"

[tcp]
enabled = true

[tcp.ports.smtp]
port = 25
upstream = "mail.internal:25"
"#;

    let err = SiteConfig::from_toml_str(toml)
        .expect_err("site-level TCP listeners must be rejected, not silently ignored");
    assert!(
        err.to_string()
            .contains("site-level TCP listeners are retired"),
        "unexpected error: {err}"
    );
}

#[test]
fn retired_site_tcp_defaults_do_not_trigger_validation() {
    let cfg = SiteTcpConfig {
        ports: std::collections::HashMap::from([(
            "smtp".to_string(),
            SitePortConfig {
                port: Some(25),
                upstream: Some("mail.internal:25".to_string()),
                filter: None,
            },
        )]),
        ..SiteTcpConfig::default()
    };

    let err = cfg
        .validate_retired()
        .expect_err("non-default claim must fail");
    assert_eq!(err.field, "site.tcp");
}
