use crate::udp::protocol::UdpProtocol;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpFilterAction {
    Allow,
    Drop,
    RateLimit { rate: u32 },
    Challenge,
}

#[derive(Debug, Clone)]
pub struct UdpFilterConfig {
    pub enabled: bool,
    pub strict_mode: bool,
    pub port_overrides: HashMap<u16, UdpPortFilterConfig>,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
    pub amplification_threshold: f64,
    pub max_response_size: usize,
}

#[derive(Debug, Clone)]
pub struct UdpPortFilterConfig {
    pub expected_protocol: String,
    pub action: String,
    pub rate_limit: Option<u32>,
    pub max_packet_size: Option<usize>,
}

impl Default for UdpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_mode: true,
            port_overrides: Self::default_port_overrides(),
            protocol_allowlist: vec![],
            protocol_denylist: vec![],
            amplification_threshold: 5.0,
            max_response_size: 4096,
        }
    }
}

impl UdpFilterConfig {
    fn default_port_overrides() -> HashMap<u16, UdpPortFilterConfig> {
        let mut overrides = HashMap::new();

        overrides.insert(
            53,
            UdpPortFilterConfig {
                expected_protocol: "dns".to_string(),
                action: "rate_limit".to_string(),
                rate_limit: Some(1000),
                max_packet_size: Some(512),
            },
        );

        overrides.insert(
            67,
            UdpPortFilterConfig {
                expected_protocol: "dhcp".to_string(),
                action: "allow".to_string(),
                rate_limit: None,
                max_packet_size: Some(576),
            },
        );

        overrides.insert(
            68,
            UdpPortFilterConfig {
                expected_protocol: "dhcp".to_string(),
                action: "allow".to_string(),
                rate_limit: None,
                max_packet_size: Some(576),
            },
        );

        overrides.insert(
            123,
            UdpPortFilterConfig {
                expected_protocol: "ntp".to_string(),
                action: "rate_limit".to_string(),
                rate_limit: Some(100),
                max_packet_size: Some(128),
            },
        );

        overrides.insert(
            161,
            UdpPortFilterConfig {
                expected_protocol: "snmp".to_string(),
                action: "drop".to_string(),
                rate_limit: Some(10),
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            5353,
            UdpPortFilterConfig {
                expected_protocol: "mdns".to_string(),
                action: "rate_limit".to_string(),
                rate_limit: Some(100),
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            1900,
            UdpPortFilterConfig {
                expected_protocol: "ssdp".to_string(),
                action: "rate_limit".to_string(),
                rate_limit: Some(50),
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            5683,
            UdpPortFilterConfig {
                expected_protocol: "coap".to_string(),
                action: "allow".to_string(),
                rate_limit: Some(500),
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            3478,
            UdpPortFilterConfig {
                expected_protocol: "stun".to_string(),
                action: "allow".to_string(),
                rate_limit: Some(200),
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            51820,
            UdpPortFilterConfig {
                expected_protocol: "wireguard".to_string(),
                action: "allow".to_string(),
                rate_limit: None,
                max_packet_size: Some(1500),
            },
        );

        overrides.insert(
            443,
            UdpPortFilterConfig {
                expected_protocol: "quic".to_string(),
                action: "allow".to_string(),
                rate_limit: None,
                max_packet_size: Some(1500),
            },
        );

        overrides
    }
}

pub struct UdpProtocolFilter {
    config: UdpFilterConfig,
}

impl Clone for UdpProtocolFilter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

impl UdpProtocolFilter {
    pub fn new(config: UdpFilterConfig) -> Self {
        Self { config }
    }

    pub fn check(
        &self,
        expected_protocol: &str,
        detected_protocol: &UdpProtocol,
    ) -> UdpFilterAction {
        if !self.config.enabled {
            return UdpFilterAction::Allow;
        }

        if !self.config.protocol_denylist.is_empty() {
            let detected_str = detected_protocol.as_str();
            if self
                .config
                .protocol_denylist
                .iter()
                .any(|p| p.as_str() == detected_str)
            {
                return UdpFilterAction::Drop;
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
                return UdpFilterAction::Drop;
            }
        }

        let expected = UdpProtocol::from_str(expected_protocol);

        if expected == *detected_protocol {
            return UdpFilterAction::Allow;
        }

        if self.config.strict_mode {
            return UdpFilterAction::Drop;
        }

        if *detected_protocol == UdpProtocol::Unknown {
            return UdpFilterAction::Allow;
        }

        UdpFilterAction::Allow
    }

    pub fn check_port(&self, port: u16, detected_protocol: &UdpProtocol) -> UdpFilterAction {
        if !self.config.enabled {
            return UdpFilterAction::Allow;
        }

        if let Some(port_config) = self.config.port_overrides.get(&port) {
            let expected = UdpProtocol::from_str(&port_config.expected_protocol);

            if expected == *detected_protocol {
                if let Some(rate) = port_config.rate_limit {
                    return UdpFilterAction::RateLimit { rate };
                }
                return UdpFilterAction::Allow;
            }

            match port_config.action.as_str() {
                "drop" => return UdpFilterAction::Drop,
                "rate_limit" => {
                    if let Some(rate) = port_config.rate_limit {
                        return UdpFilterAction::RateLimit { rate };
                    }
                    return UdpFilterAction::Drop;
                }
                "allow" => return UdpFilterAction::Allow,
                _ => {}
            }
        }

        UdpFilterAction::Allow
    }

    pub fn check_amplification_risk(&self, request_size: usize, response_size: usize) -> bool {
        if request_size == 0 {
            return false;
        }

        let ratio = response_size as f64 / request_size as f64;
        ratio > self.config.amplification_threshold && response_size > self.config.max_response_size
    }

    pub fn get_rate_limit(&self, port: u16) -> Option<u32> {
        self.config
            .port_overrides
            .get(&port)
            .and_then(|c| c.rate_limit)
    }

    pub fn get_max_packet_size(&self, port: u16) -> Option<usize> {
        self.config
            .port_overrides
            .get(&port)
            .and_then(|c| c.max_packet_size)
    }

    pub fn with_port_override(
        mut self,
        port: u16,
        protocol: &str,
        action: &str,
        rate_limit: Option<u32>,
    ) -> Self {
        self.config.port_overrides.insert(
            port,
            UdpPortFilterConfig {
                expected_protocol: protocol.to_string(),
                action: action.to_string(),
                rate_limit,
                max_packet_size: None,
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

    pub fn with_amplification_threshold(mut self, threshold: f64) -> Self {
        self.config.amplification_threshold = threshold;
        self
    }
}

impl Default for UdpProtocolFilter {
    fn default() -> Self {
        Self::new(UdpFilterConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_mode_blocks_mismatch() {
        let filter = UdpProtocolFilter::new(UdpFilterConfig {
            enabled: true,
            strict_mode: true,
            ..Default::default()
        });

        assert_eq!(
            filter.check("dns", &UdpProtocol::Ntp),
            UdpFilterAction::Drop
        );
        assert_eq!(
            filter.check("dns", &UdpProtocol::Dns),
            UdpFilterAction::Allow
        );
    }

    #[test]
    fn test_permissive_mode_allows_unknown() {
        let filter = UdpProtocolFilter::new(UdpFilterConfig {
            enabled: true,
            strict_mode: false,
            ..Default::default()
        });

        assert_eq!(
            filter.check("dns", &UdpProtocol::Ntp),
            UdpFilterAction::Allow
        );
        assert_eq!(
            filter.check("dns", &UdpProtocol::Unknown),
            UdpFilterAction::Allow
        );
    }

    #[test]
    fn test_disabled_allows_all() {
        let filter = UdpProtocolFilter::new(UdpFilterConfig {
            enabled: false,
            strict_mode: true,
            ..Default::default()
        });

        assert_eq!(
            filter.check("dns", &UdpProtocol::Ntp),
            UdpFilterAction::Allow
        );
    }

    #[test]
    fn test_port_rate_limit() {
        let filter = UdpProtocolFilter::new(UdpFilterConfig {
            enabled: true,
            strict_mode: true,
            ..Default::default()
        });

        match filter.check_port(123, &UdpProtocol::Ntp) {
            UdpFilterAction::RateLimit { rate } => assert_eq!(rate, 100),
            _ => panic!("Expected rate limit"),
        }
    }

    #[test]
    fn test_amplification_detection() {
        let filter = UdpProtocolFilter::new(UdpFilterConfig {
            amplification_threshold: 5.0,
            max_response_size: 4096,
            ..Default::default()
        });

        assert!(filter.check_amplification_risk(40, 5000));
        assert!(!filter.check_amplification_risk(100, 200));
    }
}
