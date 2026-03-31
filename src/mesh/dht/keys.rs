use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum DhtKey {
    Organization(String),
    TierKey(String, String),
    MemberCertificate(String, String),
    Upstream(String),
    NodeInfo(String),
    GlobalNodeList,
    OrgNameReservation(String),
    GlobalNodePublicKey(String),
    NodeHealth(String),
    NodeLoad(String),
    VerifiedUpstream(String),
    TierClaim(String),
    UpstreamRegistrationRequest(String),
    YaraRules(String),
    YaraRuleVersion(String),
    DnsZone(String),
    DnsRecord(String, String),
    DnsDomainRegistration(String),
    AnycastNode(String),
}

impl DhtKey {
    pub fn organization(org_id: &str) -> Self {
        DhtKey::Organization(org_id.to_string())
    }

    pub fn tier_key(org_id: &str, key_id: &str) -> Self {
        DhtKey::TierKey(org_id.to_string(), key_id.to_string())
    }

    pub fn member_certificate(org_id: &str, cert_id: &str) -> Self {
        DhtKey::MemberCertificate(org_id.to_string(), cert_id.to_string())
    }

    pub fn upstream(upstream_id: &str) -> Self {
        DhtKey::Upstream(upstream_id.to_string())
    }

    pub fn node_info(node_id: &str) -> Self {
        DhtKey::NodeInfo(node_id.to_string())
    }

    pub fn global_node_list() -> Self {
        DhtKey::GlobalNodeList
    }

    pub fn org_name_reservation(org_name: &str) -> Self {
        DhtKey::OrgNameReservation(org_name.to_lowercase())
    }

    pub fn global_node_public_key(node_id: &str) -> Self {
        DhtKey::GlobalNodePublicKey(node_id.to_string())
    }

    pub fn node_health(node_id: &str) -> Self {
        DhtKey::NodeHealth(node_id.to_string())
    }

    pub fn node_load(node_id: &str) -> Self {
        DhtKey::NodeLoad(node_id.to_string())
    }

    pub fn verified_upstream(upstream_id: &str) -> Self {
        DhtKey::VerifiedUpstream(upstream_id.to_string())
    }

    pub fn tier_claim(org_id: &str) -> Self {
        DhtKey::TierClaim(org_id.to_string())
    }

    pub fn upstream_registration_request(request_id: &str) -> Self {
        DhtKey::UpstreamRegistrationRequest(request_id.to_string())
    }

    pub fn yara_rules(org_id: &str) -> Self {
        DhtKey::YaraRules(org_id.to_string())
    }

    pub fn yara_rule_version(version: &str) -> Self {
        DhtKey::YaraRuleVersion(version.to_string())
    }

    pub fn dns_zone(zone: &str) -> Self {
        DhtKey::DnsZone(zone.to_string())
    }

    pub fn dns_record(zone: &str, name: &str) -> Self {
        DhtKey::DnsRecord(zone.to_string(), name.to_string())
    }

    pub fn dns_domain_registration(domain: &str) -> Self {
        DhtKey::DnsDomainRegistration(domain.to_lowercase())
    }

    pub fn anycast_node(node_id: &str) -> Self {
        DhtKey::AnycastNode(node_id.to_string())
    }

    pub fn as_str(&self) -> String {
        match self {
            DhtKey::Organization(org_id) => format!("org:{}", org_id),
            DhtKey::TierKey(org_id, key_id) => format!("tier_key:{}:{}", org_id, key_id),
            DhtKey::MemberCertificate(org_id, cert_id) => {
                format!("member_cert:{}:{}", org_id, cert_id)
            }
            DhtKey::Upstream(upstream_id) => format!("upstream:{}", upstream_id),
            DhtKey::NodeInfo(node_id) => format!("node_info:{}", node_id),
            DhtKey::GlobalNodeList => "global_node_list".to_string(),
            DhtKey::OrgNameReservation(name) => format!("org_name_reservation:{}", name),
            DhtKey::GlobalNodePublicKey(node_id) => format!("global_node_pubkey:{}", node_id),
            DhtKey::NodeHealth(node_id) => format!("node_health:{}", node_id),
            DhtKey::NodeLoad(node_id) => format!("node_load:{}", node_id),
            DhtKey::VerifiedUpstream(upstream_id) => format!("verified_upstream:{}", upstream_id),
            DhtKey::TierClaim(org_id) => format!("tier_claim:{}", org_id),
            DhtKey::UpstreamRegistrationRequest(request_id) => {
                format!("upstream_registration_request:{}", request_id)
            }
            DhtKey::YaraRules(org_id) => format!("yara_rules:{}", org_id),
            DhtKey::YaraRuleVersion(version) => format!("yara_rule_version:{}", version),
            DhtKey::DnsZone(zone) => format!("dns_zone:{}", zone),
            DhtKey::DnsRecord(zone, name) => format!("dns_record:{}:{}", zone, name),
            DhtKey::DnsDomainRegistration(domain) => format!("dns_domain_reg:{}", domain),
            DhtKey::AnycastNode(node_id) => format!("anycast_node:{}", node_id),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();

        match parts[0] {
            "org" if parts.len() >= 2 => DhtKey::Organization(parts[1..].join(":")),
            "tier_key" if parts.len() >= 3 => {
                DhtKey::TierKey(parts[1].to_string(), parts[2].to_string())
            }
            "member_cert" if parts.len() >= 3 => {
                DhtKey::MemberCertificate(parts[1].to_string(), parts[2].to_string())
            }
            "upstream" if parts.len() >= 2 => DhtKey::Upstream(parts[1..].join(":")),
            "node_info" if parts.len() >= 2 => DhtKey::NodeInfo(parts[1..].join(":")),
            "global_node_list" => DhtKey::GlobalNodeList,
            "org_name_reservation" if parts.len() >= 2 => {
                DhtKey::OrgNameReservation(parts[1..].join(":"))
            }
            "global_node_pubkey" if parts.len() >= 2 => {
                DhtKey::GlobalNodePublicKey(parts[1..].join(":"))
            }
            "node_health" if parts.len() >= 2 => DhtKey::NodeHealth(parts[1..].join(":")),
            "node_load" if parts.len() >= 2 => DhtKey::NodeLoad(parts[1..].join(":")),
            "verified_upstream" if parts.len() >= 2 => {
                DhtKey::VerifiedUpstream(parts[1..].join(":"))
            }
            "tier_claim" if parts.len() >= 2 => DhtKey::TierClaim(parts[1..].join(":")),
            "upstream_registration_request" if parts.len() >= 2 => {
                DhtKey::UpstreamRegistrationRequest(parts[1..].join(":"))
            }
            "yara_rules" if parts.len() >= 2 => DhtKey::YaraRules(parts[1..].join(":")),
            "yara_rule_version" if parts.len() >= 2 => {
                DhtKey::YaraRuleVersion(parts[1..].join(":"))
            }
            "dns_zone" if parts.len() >= 2 => DhtKey::DnsZone(parts[1..].join(":")),
            "dns_record" if parts.len() >= 3 => {
                DhtKey::DnsRecord(parts[1].to_string(), parts[2].to_string())
            }
            "dns_domain_reg" if parts.len() >= 2 => {
                DhtKey::DnsDomainRegistration(parts[1..].join(":"))
            }
            "anycast_node" if parts.len() >= 2 => DhtKey::AnycastNode(parts[1..].join(":")),
            _ => DhtKey::NodeInfo(s.to_string()),
        }
    }

    pub fn is_privileged(&self) -> bool {
        matches!(
            self,
            DhtKey::Organization(_)
                | DhtKey::TierKey(_, _)
                | DhtKey::MemberCertificate(_, _)
                | DhtKey::GlobalNodeList
                | DhtKey::OrgNameReservation(_)
                | DhtKey::UpstreamRegistrationRequest(_)
                | DhtKey::DnsZone(_)
                | DhtKey::DnsDomainRegistration(_)
                | DhtKey::AnycastNode(_)
        )
    }

    pub fn is_public(&self) -> bool {
        matches!(
            self,
            DhtKey::Upstream(_)
                | DhtKey::NodeInfo(_)
                | DhtKey::GlobalNodePublicKey(_)
                | DhtKey::NodeHealth(_)
                | DhtKey::NodeLoad(_)
                | DhtKey::VerifiedUpstream(_)
                | DhtKey::TierClaim(_)
                | DhtKey::YaraRules(_)
                | DhtKey::YaraRuleVersion(_)
                | DhtKey::DnsZone(_)
                | DhtKey::DnsRecord(_, _)
                | DhtKey::AnycastNode(_)
        )
    }

    pub fn is_global_signature_required(&self) -> bool {
        matches!(self, DhtKey::VerifiedUpstream(_))
    }

    pub fn requires_confirmation(&self) -> bool {
        matches!(
            self,
            DhtKey::TierKey(_, _)
                | DhtKey::Organization(_)
                | DhtKey::Upstream(_)
                | DhtKey::OrgNameReservation(_)
                | DhtKey::UpstreamRegistrationRequest(_)
        )
    }

    pub fn is_self_record(&self, node_id: &str) -> bool {
        match self {
            DhtKey::NodeHealth(nid) => nid == node_id,
            DhtKey::NodeLoad(nid) => nid == node_id,
            DhtKey::NodeInfo(nid) => nid == node_id,
            _ => false,
        }
    }

    pub fn key_type(&self) -> &'static str {
        match self {
            DhtKey::Organization(_) => "organization",
            DhtKey::TierKey(_, _) => "tier_key",
            DhtKey::MemberCertificate(_, _) => "member_certificate",
            DhtKey::Upstream(_) => "upstream",
            DhtKey::NodeInfo(_) => "node_info",
            DhtKey::GlobalNodeList => "global_node_list",
            DhtKey::OrgNameReservation(_) => "org_name_reservation",
            DhtKey::GlobalNodePublicKey(_) => "global_node_public_key",
            DhtKey::NodeHealth(_) => "node_health",
            DhtKey::NodeLoad(_) => "node_load",
            DhtKey::VerifiedUpstream(_) => "verified_upstream",
            DhtKey::TierClaim(_) => "tier_claim",
            DhtKey::UpstreamRegistrationRequest(_) => "upstream_registration_request",
            DhtKey::YaraRules(_) => "yara_rules",
            DhtKey::YaraRuleVersion(_) => "yara_rule_version",
            DhtKey::DnsZone(_) => "dns_zone",
            DhtKey::DnsRecord(_, _) => "dns_record",
            DhtKey::DnsDomainRegistration(_) => "dns_domain_registration",
            DhtKey::AnycastNode(_) => "anycast_node",
        }
    }

    pub fn to_signed_record_type(&self) -> Option<crate::mesh::dht::signed::SignedRecordType> {
        use crate::mesh::dht::signed::SignedRecordType;
        match self {
            DhtKey::Organization(_) => Some(SignedRecordType::Organization),
            DhtKey::TierKey(_, _) => Some(SignedRecordType::TierKey),
            DhtKey::MemberCertificate(_, _) => Some(SignedRecordType::MemberCertificate),
            DhtKey::Upstream(_) => Some(SignedRecordType::Upstream),
            DhtKey::NodeInfo(_) => Some(SignedRecordType::NodeInfo),
            DhtKey::GlobalNodeList => Some(SignedRecordType::GlobalNodeList),
            DhtKey::OrgNameReservation(_) => Some(SignedRecordType::OrgNameReservation),
            DhtKey::GlobalNodePublicKey(_) => Some(SignedRecordType::GlobalNodePublicKey),
            DhtKey::NodeHealth(_) => Some(SignedRecordType::NodeHealth),
            DhtKey::NodeLoad(_) => Some(SignedRecordType::NodeLoad),
            DhtKey::VerifiedUpstream(_) => Some(SignedRecordType::VerifiedUpstream),
            DhtKey::TierClaim(_) => Some(SignedRecordType::TierClaim),
            DhtKey::UpstreamRegistrationRequest(_) => {
                Some(SignedRecordType::UpstreamRegistrationRequest)
            }
            DhtKey::YaraRules(_) => Some(SignedRecordType::YaraRules),
            DhtKey::YaraRuleVersion(_) => Some(SignedRecordType::YaraRuleVersion),
            DhtKey::DnsZone(_) => Some(SignedRecordType::DnsZone),
            DhtKey::DnsRecord(_, _) => Some(SignedRecordType::DnsRecord),
            DhtKey::DnsDomainRegistration(_) => Some(SignedRecordType::DnsDomainRegistration),
            DhtKey::AnycastNode(_) => Some(SignedRecordType::AnycastNode),
        }
    }

    pub fn content_hash(&self, value: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(value);
        hex::encode(hasher.finalize())
    }

    pub fn content_addressed_key(&self, value: &[u8]) -> String {
        format!("content:{}", self.content_hash(value))
    }

    pub fn is_content_addressed(&self) -> bool {
        self.as_str().starts_with("content:")
    }

    pub fn site_scope(&self) -> Option<String> {
        match self {
            DhtKey::Upstream(id) => Some(id.clone()),
            DhtKey::VerifiedUpstream(id) => Some(id.clone()),
            DhtKey::TierClaim(id) => Some(id.clone()),
            DhtKey::DnsZone(zone) => Some(zone.clone()),
            DhtKey::DnsRecord(zone, _) => Some(zone.clone()),
            DhtKey::YaraRules(site) => Some(site.clone()),
            DhtKey::YaraRuleVersion(site) => Some(site.clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_serialization() {
        let org_key = DhtKey::organization("test-org");
        assert_eq!(org_key.as_str(), "org:test-org");

        let tier_key = DhtKey::tier_key("test-org", "key-123");
        assert_eq!(tier_key.as_str(), "tier_key:test-org:key-123");

        let upstream_key = DhtKey::upstream("api.example.com");
        assert_eq!(upstream_key.as_str(), "upstream:api.example.com");
    }

    #[test]
    fn test_key_deserialization() {
        let key = DhtKey::from_str("org:test-org");
        assert_eq!(key, DhtKey::organization("test-org"));

        let key = DhtKey::from_str("tier_key:test-org:key-123");
        assert_eq!(key, DhtKey::tier_key("test-org", "key-123"));
    }

    #[test]
    fn test_key_privileges() {
        assert!(DhtKey::organization("test").is_privileged());
        assert!(DhtKey::tier_key("test", "key").is_privileged());
        assert!(DhtKey::member_certificate("test", "cert").is_privileged());

        assert!(!DhtKey::upstream("test").is_privileged());
        assert!(!DhtKey::node_info("test").is_privileged());

        assert!(DhtKey::upstream("test").is_public());
        assert!(DhtKey::node_info("test").is_public());
        assert!(!DhtKey::organization("test").is_public());
    }
}
