use std::net::IpAddr;

pub struct RebindingChecker {
    min_ttl: u32,
    allowed_domains: Vec<String>,
}

impl RebindingChecker {
    pub fn new(min_ttl: u32, allowed_domains: Vec<String>) -> Self {
        Self {
            min_ttl,
            allowed_domains,
        }
    }

    pub fn is_private_ip(&self, ip: &IpAddr) -> bool {
        synvoid_core::net::is_restricted_ip(ip)
    }

    pub fn check(&self, qname: &str, ttl: u32) -> Result<(), String> {
        for domain in &self.allowed_domains {
            if qname.ends_with(domain) || qname == domain.trim_start_matches('.') {
                return Ok(());
            }
        }

        if ttl < self.min_ttl {
            return Err(format!(
                "Query {} has TTL {} below minimum {} - potential rebinding",
                qname, ttl, self.min_ttl
            ));
        }

        Ok(())
    }
}
