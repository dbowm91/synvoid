use crate::config::site::ProxyUpstreamConfig;
use crate::filter::{BaseFilterConfig, ProtocolFilterCore};
use crate::tcp::protocol::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Drop,
    Stall,
}

impl crate::filter::FilterAction for FilterAction {
    fn is_allow(&self) -> bool {
        matches!(self, FilterAction::Allow)
    }

    fn is_drop(&self) -> bool {
        matches!(self, FilterAction::Drop)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
    pub block_unknown_ports: bool,
}

impl FilterConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }

    pub fn enable(mut self) -> Self {
        self.enabled = true;
        self
    }

    pub fn with_protocol_allowlist(mut self, protocols: Vec<String>) -> Self {
        self.protocol_allowlist = protocols;
        self
    }

    pub fn with_protocol_denylist(mut self, protocols: Vec<String>) -> Self {
        self.protocol_denylist = protocols;
        self
    }

    pub fn enable_block_unknown(self) -> Self {
        self.block_unknown_ports(true)
    }

    pub fn block_unknown_ports(mut self, block: bool) -> Self {
        self.block_unknown_ports = block;
        self
    }
}

#[derive(Clone)]
pub struct ProtocolFilter {
    core: ProtocolFilterCore<Protocol, FilterAction>,
    block_unknown_ports: bool,
}

impl ProtocolFilter {
    pub fn new(config: FilterConfig) -> Self {
        let base_config = BaseFilterConfig::new(
            config.enabled,
            config.strict_mode,
            config.protocol_allowlist,
            config.protocol_denylist,
        );
        let core = ProtocolFilterCore::new(base_config).with_strict_mode(config.strict_mode);

        Self {
            core,
            block_unknown_ports: config.block_unknown_ports,
        }
    }

    pub fn check(&self, expected_protocol: &str, detected_protocol: &Protocol) -> FilterAction {
        let result = self.core.check(
            expected_protocol,
            detected_protocol,
            FilterAction::Allow,
            FilterAction::Stall,
        );

        if result == FilterAction::Allow && *detected_protocol == Protocol::Unknown {
            return FilterAction::Allow;
        }

        result
    }

    pub fn check_upstream(
        &self,
        upstream_config: &ProxyUpstreamConfig,
        detected_protocol: &Protocol,
    ) -> FilterAction {
        if !self.core.enabled() {
            return FilterAction::Allow;
        }

        let protocol_str = detected_protocol.as_str();

        if !upstream_config.allows_protocol(protocol_str) {
            tracing::warn!(
                "Protocol {} not allowed for upstream (allowed: {:?})",
                protocol_str,
                upstream_config.allowed_protocols
            );
            return FilterAction::Drop;
        }

        if *detected_protocol == Protocol::Unknown && self.block_unknown_ports {
            return FilterAction::Stall;
        }

        FilterAction::Allow
    }

    pub fn check_with_fallback(
        &self,
        upstream_config: Option<&ProxyUpstreamConfig>,
        detected_protocol: &Protocol,
        fallback_action: FilterAction,
    ) -> FilterAction {
        if !self.core.enabled() {
            return FilterAction::Allow;
        }

        if let Some(config) = upstream_config {
            return self.check_upstream(config, detected_protocol);
        }

        if *detected_protocol == Protocol::Unknown && self.block_unknown_ports {
            return FilterAction::Stall;
        }

        fallback_action
    }

    pub fn is_enabled(&self) -> bool {
        self.core.enabled()
    }
}

impl Default for ProtocolFilter {
    fn default() -> Self {
        Self::new(FilterConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_restricts_to_http() {
        let config = ProxyUpstreamConfig::default();
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("https"));
        assert!(config.allows_protocol("websocket"));
        assert!(!config.allows_protocol("irc"));
        assert!(!config.allows_protocol("mysql"));
    }

    #[test]
    fn test_all_keyword_allows_everything() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["all".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("irc"));
        assert!(config.allows_protocol("mysql"));
        assert!(config.allows_protocol("ssh"));
    }

    #[test]
    fn test_star_keyword_allows_everything() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["*".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("irc"));
        assert!(config.allows_protocol("mysql"));
    }

    #[test]
    fn test_allows_all_protocols_method() {
        let default_config = ProxyUpstreamConfig::default();
        assert!(!default_config.allows_all_protocols());

        let all_config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["all".to_string()]),
            ..Default::default()
        };
        assert!(all_config.allows_all_protocols());

        let star_config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["*".to_string()]),
            ..Default::default()
        };
        assert!(star_config.allows_all_protocols());

        let http_config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["http".to_string()]),
            ..Default::default()
        };
        assert!(!http_config.allows_all_protocols());
    }

    #[test]
    fn test_specific_protocol_allowed() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["http".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("https"));
        assert!(!config.allows_protocol("irc"));
        assert!(!config.allows_protocol("mysql"));
    }

    #[test]
    fn test_tcp_catchall() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["tcp".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("irc"));
        assert!(config.allows_protocol("mysql"));
        assert!(!config.allows_protocol("udp"));
    }

    #[test]
    fn test_udp_category_includes_quic_and_wireguard() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["udp".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("udp"));
        assert!(config.allows_protocol("quic"));
        assert!(config.allows_protocol("wireguard"));
        assert!(config.allows_protocol("mesh_quic"));
        assert!(!config.allows_protocol("http"));
        assert!(!config.allows_protocol("irc"));
    }

    #[test]
    fn test_http_catchall() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["http".to_string()]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("https"));
        assert!(config.allows_protocol("websocket"));
        assert!(!config.allows_protocol("irc"));
    }

    #[test]
    fn test_empty_defaults_to_http() {
        let config = ProxyUpstreamConfig {
            allowed_protocols: Some(vec![]),
            ..Default::default()
        };
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("https"));
        assert!(config.allows_protocol("websocket"));
        assert!(!config.allows_protocol("irc"));
    }

    #[test]
    fn test_default_none_defaults_to_http() {
        let config = ProxyUpstreamConfig::default();
        assert!(config.allows_protocol("http"));
        assert!(config.allows_protocol("https"));
        assert!(config.allows_protocol("websocket"));
        assert!(!config.allows_protocol("irc"));
    }

    #[test]
    fn test_is_protocol_restricted() {
        let unrestricted = ProxyUpstreamConfig::default();
        assert!(!unrestricted.is_protocol_restricted());

        let restricted = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["irc".to_string()]),
            ..Default::default()
        };
        assert!(restricted.is_protocol_restricted());

        let empty = ProxyUpstreamConfig {
            allowed_protocols: Some(vec![]),
            ..Default::default()
        };
        assert!(!empty.is_protocol_restricted());
    }

    #[test]
    fn test_strict_mode_blocks_mismatch() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            strict_mode: true,
            ..Default::default()
        });

        assert_eq!(filter.check("smtp", &Protocol::Http), FilterAction::Stall);
        assert_eq!(filter.check("smtp", &Protocol::Smtp), FilterAction::Allow);
    }

    #[test]
    fn test_permissive_mode_allows_unknown() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            strict_mode: false,
            ..Default::default()
        });

        assert_eq!(filter.check("smtp", &Protocol::Http), FilterAction::Allow);
        assert_eq!(
            filter.check("smtp", &Protocol::Unknown),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_disabled_allows_all() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: false,
            strict_mode: true,
            ..Default::default()
        });

        assert_eq!(filter.check("smtp", &Protocol::Http), FilterAction::Allow);
    }

    #[test]
    fn test_upstream_restricted_drops_mismatch() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            ..Default::default()
        });

        let irc_upstream = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["irc".to_string()]),
            ..Default::default()
        };

        assert_eq!(
            filter.check_upstream(&irc_upstream, &Protocol::Irc),
            FilterAction::Allow
        );
        assert_eq!(
            filter.check_upstream(&irc_upstream, &Protocol::Http),
            FilterAction::Drop
        );
    }

    #[test]
    fn test_upstream_default_allows_http_only() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            ..Default::default()
        });

        let default_upstream = ProxyUpstreamConfig::default();

        assert_eq!(
            filter.check_upstream(&default_upstream, &Protocol::Http),
            FilterAction::Allow
        );
        assert_eq!(
            filter.check_upstream(&default_upstream, &Protocol::Irc),
            FilterAction::Drop
        );
        // Unknown is not HTTP, so it gets dropped (not allowed)
        assert_eq!(
            filter.check_upstream(&default_upstream, &Protocol::Unknown),
            FilterAction::Drop
        );
    }

    #[test]
    fn test_upstream_allows_tcp_category() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            ..Default::default()
        });

        let tcp_upstream = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["tcp".to_string()]),
            ..Default::default()
        };

        assert_eq!(
            filter.check_upstream(&tcp_upstream, &Protocol::Http),
            FilterAction::Allow
        );
        assert_eq!(
            filter.check_upstream(&tcp_upstream, &Protocol::Irc),
            FilterAction::Allow
        );
    }

    #[test]
    fn test_block_unknown_with_upstream() {
        let filter = ProtocolFilter::new(FilterConfig {
            enabled: true,
            block_unknown_ports: true,
            ..Default::default()
        });

        // Use "all" to allow any protocol, then test block_unknown_ports
        let all_protocols = ProxyUpstreamConfig {
            allowed_protocols: Some(vec!["all".to_string()]),
            ..Default::default()
        };

        assert_eq!(
            filter.check_upstream(&all_protocols, &Protocol::Http),
            FilterAction::Allow
        );
        assert_eq!(
            filter.check_upstream(&all_protocols, &Protocol::Unknown),
            FilterAction::Stall
        );
    }
}
