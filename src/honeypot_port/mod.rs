//! Compatibility facade for `synvoid_honeypot`.
//!
//! New code should import `synvoid_honeypot` directly. This module remains so older
//! root-crate paths continue to compile during the modularization transition.

pub use synvoid_honeypot::*;

/// Translate the persisted admin/config DTO into runtime settings while
/// retaining runtime defaults for settings the persisted DTO does not expose.
pub fn runtime_config_from_persisted(
    persisted: &synvoid_config::honeypot_port::HoneypotPortConfig,
) -> synvoid_honeypot::PortHoneypotConfig {
    let mut runtime = synvoid_honeypot::PortHoneypotConfig::default();
    runtime.enabled = persisted.enabled;
    runtime.site_scope = persisted.site_scope.clone();
    if !persisted.ports.is_empty() {
        runtime.min_port = *persisted.ports.iter().min().unwrap();
        runtime.max_port = *persisted.ports.iter().max().unwrap();
        runtime.num_honeypot_ports = persisted.ports.len();
    }
    runtime.transport_protocols = if persisted.protocols.is_empty() {
        vec!["tcp".to_string()]
    } else {
        persisted.protocols.clone()
    };
    runtime
}

#[cfg(test)]
mod tests {
    use super::runtime_config_from_persisted;
    use synvoid_config::honeypot_port::HoneypotPortConfig;

    #[test]
    fn persisted_config_defaults_and_explicit_values_translate() {
        let defaults = HoneypotPortConfig::default();
        let runtime = runtime_config_from_persisted(&defaults);
        assert!(runtime.enabled);
        assert_eq!(runtime.site_scope, "global");
        assert_eq!(runtime.min_port, 8080);
        assert_eq!(runtime.max_port, 9090);
        assert_eq!(runtime.num_honeypot_ports, 3);

        let persisted = HoneypotPortConfig {
            enabled: false,
            ports: vec![2200, 3306],
            protocols: vec!["tcp".into(), "udp".into()],
            site_scope: "edge-a".into(),
        };
        let runtime = runtime_config_from_persisted(&persisted);
        assert!(!runtime.enabled);
        assert_eq!(runtime.site_scope, "edge-a");
        assert_eq!((runtime.min_port, runtime.max_port), (2200, 3306));
        assert_eq!(runtime.num_honeypot_ports, 2);
        assert_eq!(runtime.transport_protocols, ["tcp", "udp"]);
    }
}
