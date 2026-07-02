use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use synvoid_core::time::current_timestamp_secs;

use crate::parsed_query::ParsedDnsQuery;

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
                || (octets[0] == 169 && octets[1] == 254)
                || (octets[0] == 224 && octets[1] <= 239)
                || octets[0] == 0
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            segments[0] == 0xfc00
                || segments[0] == 0xfe80
                || segments[0] == 0xff00
                || (segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0
                    && segments[6] == 0
                    && segments[7] == 1)
        }
    }
}

fn extract_query_type_from_query(query: &[u8]) -> Option<u16> {
    ParsedDnsQuery::parse(query).ok().map(|p| p.qtype)
}

#[derive(Debug, Clone)]
pub struct DnsFirewallRule {
    pub id: String,
    pub rule_type: DnsFirewallRuleType,
    pub action: DnsFirewallAction,
    pub target: String,
    pub ttl: u32,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsFirewallRuleType {
    Domain,
    IpAddress,
    Subnet,
    QueryType,
    Opcode,
    ResponseCode,
    GeoLocation,
    TimeWindow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DnsFirewallAction {
    Block,
    Allow,
    Redirect { target: String },
    Sinkhole,
    RateLimit { limit: u32, window: Duration },
    LogOnly,
}

#[derive(Debug, Clone)]
pub struct DnsFirewall {
    rules: Vec<DnsFirewallRule>,
    last_cleanup: u64,
    geoip_lookup: Option<Arc<synvoid_geoip::GeoIpManager>>,
}

impl Default for DnsFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsFirewall {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            last_cleanup: 0,
            geoip_lookup: None,
        }
    }

    pub fn with_geoip(mut self, geoip: Arc<synvoid_geoip::GeoIpManager>) -> Self {
        self.geoip_lookup = Some(geoip);
        self
    }

    pub fn add_rule(&mut self, rule: DnsFirewallRule) -> Result<(), String> {
        if let Some(expires_at) = rule.expires_at {
            if expires_at < current_timestamp_secs() {
                return Err("Rule has already expired".to_string());
            }
        }

        self.rules.push(rule);
        Ok(())
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> Result<(), String> {
        self.rules.retain(|r| r.id != rule_id);
        Ok(())
    }

    pub fn evaluate_query(
        &self,
        query: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> Result<DnsFirewallDecision, String> {
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if !self.rule_matches(rule, query, client_ip, qname) {
                continue;
            }

            return Ok(DnsFirewallDecision {
                action: rule.action.clone(),
                rule_id: rule.id.clone(),
                reason: format!("Rule {} matched", rule.id),
            });
        }

        Ok(DnsFirewallDecision {
            action: DnsFirewallAction::Allow,
            rule_id: "default".to_string(),
            reason: "No matching rules, allowing query".to_string(),
        })
    }

    pub fn evaluate_response(
        &mut self,
        response: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> Result<DnsFirewallDecision, String> {
        self.cleanup_expired_rules();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if !self.response_rule_matches(rule, response, client_ip, qname) {
                continue;
            }

            return Ok(DnsFirewallDecision {
                action: rule.action.clone(),
                rule_id: rule.id.clone(),
                reason: format!("Response rule {} matched", rule.id),
            });
        }

        Ok(DnsFirewallDecision {
            action: DnsFirewallAction::Allow,
            rule_id: "default".to_string(),
            reason: "No matching response rules, allowing response".to_string(),
        })
    }

    fn rule_matches(
        &self,
        rule: &DnsFirewallRule,
        query: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> bool {
        match &rule.rule_type {
            DnsFirewallRuleType::Domain => {
                if qname.eq_ignore_ascii_case(&rule.target) {
                    return true;
                }
                if qname.ends_with(&format!(".{}", rule.target)) {
                    return true;
                }
            }
            DnsFirewallRuleType::IpAddress => {
                if let Ok(rule_ip) = rule.target.parse::<IpAddr>() {
                    if client_ip == rule_ip {
                        return true;
                    }
                }
            }
            DnsFirewallRuleType::Subnet => {
                if let Ok(cidr) = rule.target.parse::<ipnetwork::IpNetwork>() {
                    if cidr.contains(client_ip) {
                        return true;
                    }
                }
            }
            DnsFirewallRuleType::QueryType => {
                let qtype = extract_query_type_from_query(query);
                if let Some(qt) = qtype {
                    if rule.target == format!("0x{:x}", qt) {
                        return true;
                    }
                }
            }
            DnsFirewallRuleType::Opcode => {
                let opcode = (u16::from_be_bytes([query[2], query[3]]) & 0x7800) >> 11;
                if rule.target == format!("0x{:x}", opcode) {
                    return true;
                }
            }
            DnsFirewallRuleType::ResponseCode => {
                let flags = u16::from_be_bytes([query[2], query[3]]);
                let rcode = flags & 0x000F;
                if rule.target == format!("0x{:x}", rcode) {
                    return true;
                }
            }
            DnsFirewallRuleType::GeoLocation => {
                if let Ok(geo) = rule.target.parse::<GeoLocation>() {
                    if geo.contains(client_ip, self.geoip_lookup.as_ref()) {
                        return true;
                    }
                }
            }
            DnsFirewallRuleType::TimeWindow => {
                if let Ok(time_window) = rule.target.parse::<TimeWindow>() {
                    if time_window.contains(chrono::Utc::now()) {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn response_rule_matches(
        &self,
        rule: &DnsFirewallRule,
        response: &[u8],
        client_ip: IpAddr,
        qname: &str,
    ) -> bool {
        match &rule.rule_type {
            DnsFirewallRuleType::ResponseCode => {
                let flags = u16::from_be_bytes([response[2], response[3]]);
                let rcode = flags & 0x000F;
                if rule.target == format!("0x{:x}", rcode) {
                    return true;
                }
            }
            DnsFirewallRuleType::Domain => {
                if qname.eq_ignore_ascii_case(&rule.target) {
                    return true;
                }
                if qname.ends_with(&format!(".{}", rule.target)) {
                    return true;
                }
            }
            DnsFirewallRuleType::IpAddress => {
                if let Ok(rule_ip) = rule.target.parse::<IpAddr>() {
                    if client_ip == rule_ip {
                        return true;
                    }
                }
            }
            _ => return false,
        }

        false
    }

    fn cleanup_expired_rules(&mut self) {
        let now = current_timestamp_secs();
        if now - self.last_cleanup < 60 {
            return;
        }

        self.rules.retain(|r| {
            if let Some(expires_at) = r.expires_at {
                expires_at > now
            } else {
                true
            }
        });

        self.last_cleanup = now;
    }

    pub fn get_stats(&self) -> DnsFirewallStats {
        let active_rules = self.rules.len();
        let blocked_queries = 0; // Would be tracked in real implementation
        let blocked_responses = 0; // Would be tracked in real implementation

        DnsFirewallStats {
            active_rules,
            blocked_queries,
            blocked_responses,
            last_cleanup: self.last_cleanup,
        }
    }

    pub fn export_rules(&self, file_path: &str) -> Result<(), String> {
        let export_data = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "rules": self.rules.iter().map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "rule_type": format!("{:?}", r.rule_type),
                    "action": format!("{:?}", r.action),
                    "target": r.target,
                    "ttl": r.ttl,
                    "created_at": r.created_at,
                    "expires_at": r.expires_at,
                    "enabled": r.enabled,
                })
            }).collect::<Vec<_>>(),
        });

        std::fs::write(
            file_path,
            serde_json::to_string_pretty(&export_data).map_err(|e| format!("JSON error: {}", e))?,
        )
        .map_err(|e| format!("Failed to write firewall rules: {}", e))?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct DnsFirewallDecision {
    pub action: DnsFirewallAction,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct DnsFirewallStats {
    pub active_rules: usize,
    pub blocked_queries: usize,
    pub blocked_responses: usize,
    pub last_cleanup: u64,
}

#[derive(Debug, Clone)]
pub struct GeoLocation {
    pub country: String,
    pub region: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
}

impl GeoLocation {
    pub fn matches_ip(
        &self,
        ip: IpAddr,
        geoip_manager: Option<&Arc<synvoid_geoip::GeoIpManager>>,
    ) -> bool {
        if let Some(geoip) = geoip_manager {
            if let Some(country_info) = geoip.get_country_info(ip) {
                let country_match = country_info.code.to_uppercase() == self.country.to_uppercase();

                if !country_match {
                    return false;
                }

                if let Some(ref region) = self.region {
                    if let Some(ref subdivision) = country_info.subdivision {
                        if subdivision.to_uppercase() != region.to_uppercase() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                if let Some(ref city) = self.city {
                    if let Some(ref city_info) = country_info.city {
                        if city_info.to_uppercase() != city.to_uppercase() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                if let Some(asn) = self.asn {
                    if let Some(asn_info) = geoip.get_asn_info(ip) {
                        if asn_info.asn != asn {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }

                return true;
            }
        }
        false
    }

    pub fn contains(
        &self,
        ip: IpAddr,
        geoip_manager: Option<&Arc<synvoid_geoip::GeoIpManager>>,
    ) -> bool {
        self.matches_ip(ip, geoip_manager)
    }
}

#[derive(Debug, Clone)]
pub struct TimeWindow {
    pub start: chrono::DateTime<chrono::Utc>,
    pub end: chrono::DateTime<chrono::Utc>,
}

impl TimeWindow {
    pub fn contains(&self, time: chrono::DateTime<chrono::Utc>) -> bool {
        time >= self.start && time <= self.end
    }
}

impl std::str::FromStr for GeoLocation {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
        if parts.is_empty() {
            return Err("Invalid geo location format".to_string());
        }

        let asn = if parts.len() > 3 {
            parts[3].parse::<u32>().ok()
        } else {
            None
        };

        Ok(GeoLocation {
            country: parts[0].to_string(),
            region: parts.get(1).map(|s| s.to_string()),
            city: parts.get(2).map(|s| s.to_string()),
            asn,
        })
    }
}

impl std::str::FromStr for TimeWindow {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').map(|p| p.trim()).collect();
        if parts.len() != 2 {
            return Err("Invalid time window format".to_string());
        }

        let start = chrono::DateTime::parse_from_rfc3339(parts[0])
            .map_err(|e| format!("Invalid start time: {}", e))?;
        let end = chrono::DateTime::parse_from_rfc3339(parts[1])
            .map_err(|e| format!("Invalid end time: {}", e))?;

        Ok(TimeWindow {
            start: start.into(),
            end: end.into(),
        })
    }
}

pub fn create_default_firewall_rules() -> Vec<DnsFirewallRule> {
    vec![
        DnsFirewallRule {
            id: "block_internal_ips".to_string(),
            rule_type: DnsFirewallRuleType::Subnet,
            action: DnsFirewallAction::Block,
            target: "10.0.0.0/8".to_string(),
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_multicast".to_string(),
            rule_type: DnsFirewallRuleType::Subnet,
            action: DnsFirewallAction::Block,
            target: "224.0.0.0/4".to_string(),
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_reserved_domains".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "localhost".to_string(),
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_example_domains".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::Block,
            target: "example.com".to_string(),
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_zone_transfer".to_string(),
            rule_type: DnsFirewallRuleType::QueryType,
            action: DnsFirewallAction::Block,
            target: "0xfc".to_string(), // AXFR query type (252)
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "block_ixfr".to_string(),
            rule_type: DnsFirewallRuleType::QueryType,
            action: DnsFirewallAction::Block,
            target: "0xfb".to_string(), // IXFR query type (251)
            ttl: 300,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
    ]
}

pub fn create_rate_limit_rules() -> Vec<DnsFirewallRule> {
    vec![
        DnsFirewallRule {
            id: "rate_limit_per_domain".to_string(),
            rule_type: DnsFirewallRuleType::Domain,
            action: DnsFirewallAction::RateLimit {
                limit: 100,
                window: Duration::from_secs(60),
            },
            target: "*".to_string(), // All domains
            ttl: 60,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
        DnsFirewallRule {
            id: "rate_limit_per_ip".to_string(),
            rule_type: DnsFirewallRuleType::IpAddress,
            action: DnsFirewallAction::RateLimit {
                limit: 500,
                window: Duration::from_secs(60),
            },
            target: "*".to_string(), // All IPs
            ttl: 60,
            created_at: current_timestamp_secs(),
            expires_at: None,
            enabled: true,
        },
    ]
}

#[derive(Debug, Clone, PartialEq)]
pub enum RebindingCheckResult {
    Allowed,
    Blocked { reason: String },
}

pub fn check_rebinding_protection(
    qname: &str,
    resolved_ips: &[IpAddr],
    record_ttl: u32,
    config: &synvoid_config::dns::RebindingProtectionConfig,
) -> RebindingCheckResult {
    if !config.enabled {
        return RebindingCheckResult::Allowed;
    }

    if config
        .allowed_internal_domains
        .iter()
        .any(|d| qname.ends_with(d) || qname == d.trim_start_matches('.'))
    {
        return RebindingCheckResult::Allowed;
    }

    let has_internal_ip = resolved_ips.iter().any(is_private_ip);

    if has_internal_ip {
        if config.block_short_ttl_internal && record_ttl < config.min_ttl_for_internal {
            return RebindingCheckResult::Blocked {
                reason: format!(
                    "DNS rebinding protection: internal IP resolved with short TTL ({}s < {}s)",
                    record_ttl, config.min_ttl_for_internal
                ),
            };
        }

        if config.min_ttl_for_internal > 0 && record_ttl < config.min_ttl_for_internal {
            return RebindingCheckResult::Blocked {
                reason: format!(
                    "DNS rebinding protection: internal IP resolved with TTL {}s below minimum {}s",
                    record_ttl, config.min_ttl_for_internal
                ),
            };
        }
    }

    RebindingCheckResult::Allowed
}
