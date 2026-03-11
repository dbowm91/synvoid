use crate::tcp::protocol::Protocol;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    Allow,
    Drop,
    Stall,
}

#[derive(Debug, Clone)]
pub struct FilterConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub port_overrides: HashMap<u16, PortFilterConfig>,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PortFilterConfig {
    pub expected_protocol: String,
    pub action: String, // "allow", "drop", "challenge"
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_mode: true,
            port_overrides: Self::default_port_overrides(),
            protocol_allowlist: vec![],
            protocol_denylist: vec![],
        }
    }
}

impl FilterConfig {
    fn default_port_overrides() -> HashMap<u16, PortFilterConfig> {
        let mut overrides = HashMap::new();

        overrides.insert(
            25,
            PortFilterConfig {
                expected_protocol: "smtp".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            587,
            PortFilterConfig {
                expected_protocol: "smtp".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            465,
            PortFilterConfig {
                expected_protocol: "smtp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            143,
            PortFilterConfig {
                expected_protocol: "imap".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            993,
            PortFilterConfig {
                expected_protocol: "imap".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            110,
            PortFilterConfig {
                expected_protocol: "pop3".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            995,
            PortFilterConfig {
                expected_protocol: "pop3".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            3306,
            PortFilterConfig {
                expected_protocol: "mysql".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            5432,
            PortFilterConfig {
                expected_protocol: "postgres".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            6379,
            PortFilterConfig {
                expected_protocol: "redis".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            11211,
            PortFilterConfig {
                expected_protocol: "memcached".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            27017,
            PortFilterConfig {
                expected_protocol: "mongodb".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            389,
            PortFilterConfig {
                expected_protocol: "ldap".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            636,
            PortFilterConfig {
                expected_protocol: "ldap".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            3389,
            PortFilterConfig {
                expected_protocol: "rdp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            5900,
            PortFilterConfig {
                expected_protocol: "vnc".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            5222,
            PortFilterConfig {
                expected_protocol: "xmpp".to_string(),
                action: "drop".to_string(),
            },
        );
        overrides.insert(
            5269,
            PortFilterConfig {
                expected_protocol: "xmpp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            5672,
            PortFilterConfig {
                expected_protocol: "amqp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            9092,
            PortFilterConfig {
                expected_protocol: "kafka".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            554,
            PortFilterConfig {
                expected_protocol: "rtsp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            53,
            PortFilterConfig {
                expected_protocol: "dns".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            22,
            PortFilterConfig {
                expected_protocol: "ssh".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides.insert(
            21,
            PortFilterConfig {
                expected_protocol: "ftp".to_string(),
                action: "drop".to_string(),
            },
        );

        overrides
    }
}

pub struct ProtocolFilter {
    config: FilterConfig,
}

impl Clone for ProtocolFilter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

impl ProtocolFilter {
    pub fn new(config: FilterConfig) -> Self {
        Self { config }
    }

    pub fn check(&self, expected_protocol: &str, detected_protocol: &Protocol) -> FilterAction {
        if !self.config.enabled {
            return FilterAction::Allow;
        }

        if !self.config.protocol_denylist.is_empty() {
            let detected_str = detected_protocol.as_str();
            if self
                .config
                .protocol_denylist
                .iter()
                .any(|p| p.as_str() == detected_str)
            {
                return FilterAction::Stall;
            }
        }

        if !self.config.protocol_allowlist.is_empty() {
            let detected_str = detected_protocol.as_str();
            if !self
                .config
                .protocol_allowlist
                .iter()
                .any(|p| p.as_str() == detected_str)
            {
                return FilterAction::Stall;
            }
        }

        let expected = Protocol::from_str(expected_protocol);

        if expected == *detected_protocol {
            return FilterAction::Allow;
        }

        if self.config.strict_mode {
            return FilterAction::Stall;
        }

        if *detected_protocol == Protocol::Unknown {
            return FilterAction::Allow;
        }

        FilterAction::Allow
    }

    pub fn check_port(&self, port: u16, detected_protocol: &Protocol) -> FilterAction {
        if !self.config.enabled {
            return FilterAction::Allow;
        }

        if let Some(port_config) = self.config.port_overrides.get(&port) {
            let expected = Protocol::from_str(&port_config.expected_protocol);

            if expected == *detected_protocol {
                return FilterAction::Allow;
            }

            match port_config.action.as_str() {
                "drop" => return FilterAction::Stall,
                "stall" => return FilterAction::Stall,
                "allow" => return FilterAction::Allow,
                _ => {}
            }
        }

        FilterAction::Allow
    }

    pub fn with_port_override(mut self, port: u16, protocol: &str, action: &str) -> Self {
        self.config.port_overrides.insert(
            port,
            PortFilterConfig {
                expected_protocol: protocol.to_string(),
                action: action.to_string(),
            },
        );
        self
    }

    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.config.strict_mode = strict;
        self
    }

    pub fn with_allowlist(mut self, protocols: Vec<String>) -> Self {
        self.config.protocol_allowlist = protocols;
        self
    }

    pub fn with_denylist(mut self, protocols: Vec<String>) -> Self {
        self.config.protocol_denylist = protocols;
        self
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
}
