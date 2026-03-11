use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpzAction {
    Nxdomain,
    Nodata,
    Passthru,
    Drop,
    TcpOnly,
    Custom { ip: Option<IpAddr> },
}

impl RpzAction {
    pub fn from_string(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "nxdomain" | "NXDOMAIN" => Some(Self::Nxdomain),
            "nodata" | "NODATA" => Some(Self::Nodata),
            "passthru" | "PASSTHRU" => Some(Self::Passthru),
            "drop" | "DROP" => Some(Self::Drop),
            "tcp-only" | "TCP-ONLY" | "tcp" | "TCP" => Some(Self::TcpOnly),
            _ => None,
        }
    }

    pub fn to_response_code(&self) -> u8 {
        match self {
            Self::Nxdomain => 3,
            Self::Nodata => 0,
            Self::Passthru => 0,
            Self::Drop => 0,
            Self::TcpOnly => 0,
            Self::Custom { .. } => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpzPolicy {
    pub qname_pattern: Option<String>,
    pub ip_pattern: Option<String>,
    pub nsip_pattern: Option<String>,
    pub nsdname_pattern: Option<String>,
    pub action: RpzAction,
    pub ttl: u32,
    pub comment: Option<String>,
}

pub struct RpzZone {
    pub name: String,
    pub policies: RwLock<HashMap<String, RpzPolicy>>,
    pub enabled: bool,
}

impl RpzZone {
    pub fn new(name: String) -> Self {
        Self {
            name,
            policies: RwLock::new(HashMap::new()),
            enabled: true,
        }
    }

    pub fn add_policy(&self, qname: String, policy: RpzPolicy) {
        let mut policies = self.policies.write();
        policies.insert(qname, policy);
    }

    pub fn remove_policy(&self, qname: &str) {
        let mut policies = self.policies.write();
        policies.remove(qname);
    }

    pub fn check_qname(&self, qname: &str) -> Option<RpzAction> {
        let policies = self.policies.read();
        let qname_lower = qname.to_lowercase();

        for (pattern, policy) in policies.iter() {
            if let Some(ref qname_pattern) = policy.qname_pattern {
                let pattern_lower = qname_pattern.to_lowercase();
                if pattern_lower.starts_with('*') {
                    let suffix = &pattern_lower[1..];
                    if qname_lower.ends_with(suffix) {
                        return Some(policy.action);
                    }
                } else if qname_lower == pattern_lower {
                    return Some(policy.action);
                }
            }
        }

        None
    }

    pub fn check_ip(&self, ip: &IpAddr) -> Option<RpzAction> {
        let policies = self.policies.read();

        for (pattern, policy) in policies.iter() {
            if let Some(ref ip_pattern) = policy.ip_pattern {
                if let Ok(cidr) = ip_pattern.parse::<ipnetwork::IpNetwork>() {
                    if cidr.contains(*ip) {
                        return Some(policy.action);
                    }
                }
            }
        }

        None
    }

    pub fn get_all_policies(&self) -> Vec<(String, RpzPolicy)> {
        let policies = self.policies.read();
        policies
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn clear(&self) {
        let mut policies = self.policies.write();
        policies.clear();
    }
}

pub struct RpzManager {
    zones: RwLock<HashMap<String, Arc<RpzZone>>>,
    default_action: RpzAction,
}

impl RpzManager {
    pub fn new() -> Self {
        Self {
            zones: RwLock::new(HashMap::new()),
            default_action: RpzAction::Passthru,
        }
    }

    pub fn with_default_action(mut self, action: RpzAction) -> Self {
        self.default_action = action;
        self
    }

    pub fn add_zone(&self, zone: Arc<RpzZone>) {
        let mut zones = self.zones.write();
        zones.insert(zone.name.clone(), zone);
    }

    pub fn remove_zone(&self, name: &str) {
        let mut zones = self.zones.write();
        zones.remove(name);
    }

    pub fn check(&self, qname: &str, client_ip: Option<IpAddr>) -> RpzAction {
        let zones = self.zones.read();

        for (_name, zone) in zones.iter() {
            if !zone.enabled {
                continue;
            }

            if let Some(action) = zone.check_qname(qname) {
                if matches!(action, RpzAction::Passthru) {
                    continue;
                }
                return action;
            }

            if let Some(ip) = client_ip {
                if let Some(action) = zone.check_ip(&ip) {
                    if matches!(action, RpzAction::Passthru) {
                        continue;
                    }
                    return action;
                }
            }
        }

        self.default_action
    }

    pub fn get_zone(&self, name: &str) -> Option<Arc<RpzZone>> {
        let zones = self.zones.read();
        zones.get(name).cloned()
    }

    pub fn list_zones(&self) -> Vec<String> {
        let zones = self.zones.read();
        zones.keys().cloned().collect()
    }
}

impl Default for RpzManager {
    fn default() -> Self {
        Self::new()
    }
}
