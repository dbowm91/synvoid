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
    OrgPublicKey(String),
    TierKey(String, String),
    MemberCertificate(String, String),
    Upstream(String),
    NodeInfo(String),
    GlobalNodeList,
    OrgNameReservation(String),
    GlobalNodePublicKey(String),
    NodeHealth(String),
    NodeLoad(String),
    GlobalNodeHeartbeat(String),
    VerifiedUpstream(String),
    TierClaim(String),

    DnsZone(String),
    DnsRecord(String, String),
    DnsDomainRegistration(String),
    AnycastNode(String),
    ThreatIndicator(String, String),
    UpstreamImageProtection(String),
    UpstreamMinification(String),
    UpstreamCompression(String),
    UpstreamProxyCachePreferences(String),
    SiteImagePoisonConfig(String),
    SiteContentVersion(String),
    TransformedContent {
        site_id: String,
        content_hash: String,
        transform_flags: String,
    },
    PoisonedImage {
        site_id: String,
        original_hash: String,
    },
    YaraRuleContent {
        content_hash: String,
    },
    YaraCompiledRuleContent {
        compiled_hash: String,
    },
    YaraRulesManifest {
        node_id: String,
    },
    YaraChunk {
        content_hash: String,
        index: u32,
    },
    YaraCompiledChunk {
        compiled_hash: String,
        index: u32,
    },
    GlobalNodeProof {
        node_id: String,
    },
    NodeCapability {
        node_id: String,
        capability: String,
    },
    OriginReachability {
        upstream_id: String,
        provider_node_id: String,
    },
    VerificationTask {
        upstream_id: String,
        provider_node_id: String,
    },
    OriginPenalty {
        upstream_id: String,
        provider_node_id: String,
    },
    UpstreamOwnershipChallenge(String),
    GenesisKeyTransition {
        sequence: u32,
        new_key_fingerprint: String,
        announced_by: String,
    },
    RevokedGlobalNode {
        node_id: String,
        revoked_at: u64,
        reason: String,
    },
    CapabilityAttestation {
        node_id: String,
        capability: String,
    },
    EdgeAttestation {
        node_id: String,
    },
    ServerlessFunction {
        function_name: String,
    },
    BehavioralFingerprint {
        fingerprint_id: String,
    },
    NodeCertBinding {
        node_id: String,
    },
    SiteScoped {
        site_id: String,
        inner_key: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAuthority {
    /// Strongly consistent global registry state. Writes must go through Raft.
    RaftGlobal,
    /// Signed feed/content published by authorized producers and cached via DHT.
    SignedFeed,
    /// Record may only be authored by the node named in the key.
    NodeSelf,
    /// Short-lived telemetry/discovery data distributed through DHT.
    EphemeralTelemetry,
    /// Content-addressed cache data. Integrity comes from the key/hash binding.
    ContentAddressedCache,
    /// Public cache/discovery data that does not define global truth.
    PublicCache,
}

impl DhtKey {
    pub fn organization(org_id: &str) -> Self {
        DhtKey::Organization(org_id.to_string())
    }

    pub fn org_public_key(org_id: &str) -> Self {
        DhtKey::OrgPublicKey(org_id.to_string())
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

    pub fn yara_compiled_rule_content(compiled_hash: &str) -> Self {
        DhtKey::YaraCompiledRuleContent {
            compiled_hash: compiled_hash.to_string(),
        }
    }

    pub fn yara_compiled_chunk(compiled_hash: &str, index: u32) -> Self {
        DhtKey::YaraCompiledChunk {
            compiled_hash: compiled_hash.to_string(),
            index,
        }
    }

    pub fn global_node_proof(node_id: &str) -> Self {
        DhtKey::GlobalNodeProof {
            node_id: node_id.to_string(),
        }
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

    pub fn global_node_heartbeat(node_id: &str) -> Self {
        DhtKey::GlobalNodeHeartbeat(node_id.to_string())
    }

    pub fn verified_upstream(upstream_id: &str) -> Self {
        DhtKey::VerifiedUpstream(upstream_id.to_string())
    }

    pub fn tier_claim(org_id: &str) -> Self {
        DhtKey::TierClaim(org_id.to_string())
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

    pub fn threat_indicator(indicator_id: &str, threat_type: &str) -> Self {
        DhtKey::ThreatIndicator(indicator_id.to_string(), threat_type.to_string())
    }

    pub fn upstream_image_protection(site_id: &str) -> Self {
        DhtKey::UpstreamImageProtection(site_id.to_string())
    }

    pub fn upstream_minification(site_id: &str) -> Self {
        DhtKey::UpstreamMinification(site_id.to_string())
    }

    pub fn upstream_compression(site_id: &str) -> Self {
        DhtKey::UpstreamCompression(site_id.to_string())
    }

    pub fn upstream_proxy_cache_preferences(site_id: &str) -> Self {
        DhtKey::UpstreamProxyCachePreferences(site_id.to_string())
    }

    pub fn site_image_poison_config(site_id: &str) -> Self {
        DhtKey::SiteImagePoisonConfig(site_id.to_string())
    }

    pub fn site_content_version(site_id: &str) -> Self {
        DhtKey::SiteContentVersion(site_id.to_string())
    }

    pub fn poisoned_image(site_id: &str, original_hash: &str) -> Self {
        DhtKey::PoisonedImage {
            site_id: site_id.to_string(),
            original_hash: original_hash.to_string(),
        }
    }

    pub fn transformed_content(site_id: &str, content_hash: &str, transform_flags: &str) -> Self {
        DhtKey::TransformedContent {
            site_id: site_id.to_string(),
            content_hash: content_hash.to_string(),
            transform_flags: transform_flags.to_string(),
        }
    }

    pub fn yara_rule_content(content_hash: &str) -> Self {
        DhtKey::YaraRuleContent {
            content_hash: content_hash.to_string(),
        }
    }

    pub fn yara_rules_manifest(node_id: &str) -> Self {
        DhtKey::YaraRulesManifest {
            node_id: node_id.to_string(),
        }
    }

    pub fn yara_chunk(content_hash: impl AsRef<str>, index: u32) -> Self {
        DhtKey::YaraChunk {
            content_hash: content_hash.as_ref().to_string(),
            index,
        }
    }

    pub fn node_capability(node_id: &str, capability: &str) -> Self {
        DhtKey::NodeCapability {
            node_id: node_id.to_string(),
            capability: capability.to_string(),
        }
    }

    pub fn origin_reachability(upstream_id: &str, provider_node_id: &str) -> Self {
        DhtKey::OriginReachability {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
        }
    }

    pub fn verification_task(upstream_id: &str, provider_node_id: &str) -> Self {
        DhtKey::VerificationTask {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
        }
    }

    pub fn origin_penalty(upstream_id: &str, provider_node_id: &str) -> Self {
        DhtKey::OriginPenalty {
            upstream_id: upstream_id.to_string(),
            provider_node_id: provider_node_id.to_string(),
        }
    }

    pub fn upstream_ownership_challenge(upstream_id: &str) -> Self {
        DhtKey::UpstreamOwnershipChallenge(upstream_id.to_string())
    }

    pub fn genesis_key_transition(sequence: u32) -> Self {
        DhtKey::GenesisKeyTransition {
            sequence,
            new_key_fingerprint: String::new(),
            announced_by: String::new(),
        }
    }

    pub fn revoked_global_node(node_id: &str) -> Self {
        DhtKey::RevokedGlobalNode {
            node_id: node_id.to_string(),
            revoked_at: 0,
            reason: String::new(),
        }
    }

    pub fn capability_attestation(node_id: &str, capability: &str) -> Self {
        DhtKey::CapabilityAttestation {
            node_id: node_id.to_string(),
            capability: capability.to_string(),
        }
    }

    pub fn edge_attestation(node_id: &str) -> Self {
        DhtKey::EdgeAttestation {
            node_id: node_id.to_string(),
        }
    }

    pub fn serverless_function(function_name: &str) -> Self {
        DhtKey::ServerlessFunction {
            function_name: function_name.to_string(),
        }
    }

    pub fn behavior_fingerprint(fingerprint_id: &str) -> Self {
        DhtKey::BehavioralFingerprint {
            fingerprint_id: fingerprint_id.to_string(),
        }
    }

    pub fn node_cert_binding(node_id: &str) -> Self {
        DhtKey::NodeCertBinding {
            node_id: node_id.to_string(),
        }
    }

    pub fn site_scoped(site_id: &str, inner: DhtKey) -> Self {
        DhtKey::SiteScoped {
            site_id: site_id.to_string(),
            inner_key: inner.as_str(),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            DhtKey::Organization(org_id) => format!("org:{}", org_id),
            DhtKey::OrgPublicKey(org_id) => format!("org_pubkey:{}", org_id),
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
            DhtKey::GlobalNodeHeartbeat(node_id) => format!("global_node_heartbeat:{}", node_id),
            DhtKey::VerifiedUpstream(upstream_id) => format!("verified_upstream:{}", upstream_id),
            DhtKey::TierClaim(org_id) => format!("tier_claim:{}", org_id),
            DhtKey::DnsZone(zone) => format!("dns_zone:{}", zone),
            DhtKey::DnsRecord(zone, name) => format!("dns_record:{}:{}", zone, name),
            DhtKey::DnsDomainRegistration(domain) => format!("dns_domain_reg:{}", domain),
            DhtKey::AnycastNode(node_id) => format!("anycast_node:{}", node_id),
            DhtKey::ThreatIndicator(indicator_id, threat_type) => {
                format!("threat_indicator:{}:{}", indicator_id, threat_type)
            }
            DhtKey::UpstreamImageProtection(site_id) => {
                format!("upstream_image_protection:{}", site_id)
            }
            DhtKey::UpstreamMinification(site_id) => {
                format!("upstream_minification:{}", site_id)
            }
            DhtKey::UpstreamCompression(site_id) => {
                format!("upstream_compression:{}", site_id)
            }
            DhtKey::UpstreamProxyCachePreferences(site_id) => {
                format!("upstream_proxy_cache_preferences:{}", site_id)
            }
            DhtKey::SiteImagePoisonConfig(site_id) => {
                format!("site_image_poison_config:{}", site_id)
            }
            DhtKey::SiteContentVersion(site_id) => {
                format!("site_content_version:{}", site_id)
            }
            DhtKey::TransformedContent {
                site_id,
                content_hash,
                transform_flags,
            } => {
                format!(
                    "transformed:{}:{}:{}",
                    site_id, content_hash, transform_flags
                )
            }
            DhtKey::PoisonedImage {
                site_id,
                original_hash,
            } => {
                format!("poisoned_image:{}:{}", site_id, original_hash)
            }
            DhtKey::YaraRuleContent { content_hash } => {
                format!("yara_rule:{}", content_hash)
            }
            DhtKey::YaraCompiledRuleContent { compiled_hash } => {
                format!("yara_compiled_rule:{}", compiled_hash)
            }
            DhtKey::YaraRulesManifest { node_id } => {
                format!("yara_rules_manifest:{}", node_id)
            }
            DhtKey::YaraChunk {
                content_hash,
                index,
            } => {
                format!("yara_chunk:{}:{}", content_hash, index)
            }
            DhtKey::YaraCompiledChunk {
                compiled_hash,
                index,
            } => {
                format!("yara_compiled_chunk:{}:{}", compiled_hash, index)
            }
            DhtKey::GlobalNodeProof { node_id } => {
                format!("global_node_proof:{}", node_id)
            }
            DhtKey::NodeCapability {
                node_id,
                capability,
            } => {
                format!("node_capability:{}:{}", node_id, capability)
            }
            DhtKey::OriginReachability {
                upstream_id,
                provider_node_id,
            } => {
                format!("origin_reachability:{}:{}", upstream_id, provider_node_id)
            }
            DhtKey::VerificationTask {
                upstream_id,
                provider_node_id,
            } => {
                format!("verification_task:{}:{}", upstream_id, provider_node_id)
            }
            DhtKey::OriginPenalty {
                upstream_id,
                provider_node_id,
            } => {
                format!("origin_penalty:{}:{}", upstream_id, provider_node_id)
            }
            DhtKey::UpstreamOwnershipChallenge(upstream_id) => {
                format!("upstream_ownership_challenge:{}", upstream_id)
            }
            DhtKey::GenesisKeyTransition {
                sequence,
                new_key_fingerprint,
                announced_by,
            } => {
                format!(
                    "genesis_key_transition:{}:{}:{}",
                    sequence, new_key_fingerprint, announced_by
                )
            }
            DhtKey::RevokedGlobalNode {
                node_id,
                revoked_at,
                reason,
            } => {
                format!("revoked_global_node:{}:{}:{}", node_id, revoked_at, reason)
            }
            DhtKey::CapabilityAttestation {
                node_id,
                capability,
            } => {
                format!("capability_attestation:{}:{}", node_id, capability)
            }
            DhtKey::EdgeAttestation { node_id } => {
                format!("edge_attestation:{}", node_id)
            }
            DhtKey::ServerlessFunction { function_name } => {
                format!("serverless_function:{}", function_name)
            }
            DhtKey::BehavioralFingerprint { fingerprint_id } => {
                format!("behavior_fingerprint:{}", fingerprint_id)
            }
            DhtKey::NodeCertBinding { node_id } => {
                format!("node_cert_binding:{}", node_id)
            }
            DhtKey::SiteScoped { site_id, inner_key } => {
                format!("site_scoped:{}:{}", site_id, inner_key)
            }
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        let parts: Vec<&str> = s.split(':').collect();

        match parts[0] {
            "org" if parts.len() >= 2 => DhtKey::Organization(parts[1..].join(":")),
            "org_pubkey" if parts.len() >= 2 => DhtKey::OrgPublicKey(parts[1..].join(":")),
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
            "global_node_heartbeat" if parts.len() >= 2 => {
                DhtKey::GlobalNodeHeartbeat(parts[1..].join(":"))
            }
            "verified_upstream" if parts.len() >= 2 => {
                DhtKey::VerifiedUpstream(parts[1..].join(":"))
            }
            "tier_claim" if parts.len() >= 2 => DhtKey::TierClaim(parts[1..].join(":")),
            "dns_zone" if parts.len() >= 2 => DhtKey::DnsZone(parts[1..].join(":")),
            "dns_record" if parts.len() >= 3 => {
                DhtKey::DnsRecord(parts[1].to_string(), parts[2].to_string())
            }
            "dns_domain_reg" if parts.len() >= 2 => {
                DhtKey::DnsDomainRegistration(parts[1..].join(":"))
            }
            "anycast_node" if parts.len() >= 2 => DhtKey::AnycastNode(parts[1..].join(":")),
            "threat_indicator" if parts.len() >= 3 => {
                DhtKey::ThreatIndicator(parts[1].to_string(), parts[2].to_string())
            }
            "upstream_image_protection" if parts.len() >= 2 => {
                DhtKey::UpstreamImageProtection(parts[1..].join(":"))
            }
            "upstream_minification" if parts.len() >= 2 => {
                DhtKey::UpstreamMinification(parts[1..].join(":"))
            }
            "upstream_compression" if parts.len() >= 2 => {
                DhtKey::UpstreamCompression(parts[1..].join(":"))
            }
            "upstream_proxy_cache_preferences" if parts.len() >= 2 => {
                DhtKey::UpstreamProxyCachePreferences(parts[1..].join(":"))
            }
            "site_image_poison_config" if parts.len() >= 2 => {
                DhtKey::SiteImagePoisonConfig(parts[1..].join(":"))
            }
            "site_content_version" if parts.len() >= 2 => {
                DhtKey::SiteContentVersion(parts[1..].join(":"))
            }
            "transformed" if parts.len() >= 4 => DhtKey::TransformedContent {
                site_id: parts[1].to_string(),
                content_hash: parts[2].to_string(),
                transform_flags: parts[3].to_string(),
            },
            "poisoned_image" if parts.len() >= 3 => DhtKey::PoisonedImage {
                site_id: parts[1].to_string(),
                original_hash: parts[2].to_string(),
            },
            "yara_rule" if parts.len() >= 2 => DhtKey::YaraRuleContent {
                content_hash: parts[1].to_string(),
            },
            "yara_compiled_rule" if parts.len() >= 2 => DhtKey::YaraCompiledRuleContent {
                compiled_hash: parts[1].to_string(),
            },
            "yara_rules_manifest" if parts.len() >= 2 => DhtKey::YaraRulesManifest {
                node_id: parts[1].to_string(),
            },
            "yara_chunk" if parts.len() >= 3 => DhtKey::YaraChunk {
                content_hash: parts[1].to_string(),
                index: parts[2].parse().unwrap_or(0),
            },
            "yara_compiled_chunk" if parts.len() >= 3 => DhtKey::YaraCompiledChunk {
                compiled_hash: parts[1].to_string(),
                index: parts[2].parse().unwrap_or(0),
            },
            "global_node_proof" if parts.len() >= 2 => DhtKey::GlobalNodeProof {
                node_id: parts[1].to_string(),
            },
            "node_capability" if parts.len() >= 3 => DhtKey::NodeCapability {
                node_id: parts[1].to_string(),
                capability: parts[2].to_string(),
            },
            "origin_reachability" if parts.len() >= 3 => DhtKey::OriginReachability {
                upstream_id: parts[1].to_string(),
                provider_node_id: parts[2].to_string(),
            },
            "verification_task" if parts.len() >= 3 => DhtKey::VerificationTask {
                upstream_id: parts[1].to_string(),
                provider_node_id: parts[2].to_string(),
            },
            "origin_penalty" if parts.len() >= 3 => DhtKey::OriginPenalty {
                upstream_id: parts[1].to_string(),
                provider_node_id: parts[2].to_string(),
            },
            "upstream_ownership_challenge" if parts.len() >= 2 => {
                DhtKey::UpstreamOwnershipChallenge(parts[1..].join(":"))
            }
            "genesis_key_transition" if parts.len() >= 4 => DhtKey::GenesisKeyTransition {
                sequence: parts[1].parse().unwrap_or(0),
                new_key_fingerprint: parts[2].to_string(),
                announced_by: parts[3].to_string(),
            },
            "revoked_global_node" if parts.len() >= 4 => DhtKey::RevokedGlobalNode {
                node_id: parts[1].to_string(),
                revoked_at: parts[2].parse().unwrap_or(0),
                reason: parts[3..].join(":"),
            },
            "capability_attestation" if parts.len() >= 3 => DhtKey::CapabilityAttestation {
                node_id: parts[1].to_string(),
                capability: parts[2].to_string(),
            },
            "edge_attestation" if parts.len() >= 2 => DhtKey::EdgeAttestation {
                node_id: parts[1].to_string(),
            },
            "serverless_function" if parts.len() >= 2 => DhtKey::ServerlessFunction {
                function_name: parts[1..].join(":"),
            },
            "behavior_fingerprint" if parts.len() >= 2 => DhtKey::BehavioralFingerprint {
                fingerprint_id: parts[1..].join(":"),
            },
            "node_cert_binding" if parts.len() >= 2 => DhtKey::NodeCertBinding {
                node_id: parts[1..].join(":"),
            },
            "site_scoped" if parts.len() >= 3 => {
                let site_id = parts[1].to_string();
                let inner_key = parts[2..].join(":");
                DhtKey::SiteScoped { site_id, inner_key }
            }
            _ => DhtKey::NodeInfo(s.to_string()),
        }
    }

    pub fn is_privileged(&self) -> bool {
        match self {
            DhtKey::SiteScoped { inner_key, .. } => DhtKey::from_str(inner_key).is_privileged(),
            _ => matches!(
                self,
                DhtKey::Organization(_)
                    | DhtKey::OrgPublicKey(_)
                    | DhtKey::TierKey(_, _)
                    | DhtKey::MemberCertificate(_, _)
                    | DhtKey::GlobalNodeList
                    | DhtKey::OrgNameReservation(_)
                    | DhtKey::DnsZone(_)
                    | DhtKey::DnsRecord(_, _)
                    | DhtKey::DnsDomainRegistration(_)
                    | DhtKey::AnycastNode(_)
            ),
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            DhtKey::SiteScoped { inner_key, .. } => DhtKey::from_str(inner_key).is_public(),
            _ => matches!(
                self,
                DhtKey::Upstream(_)
                    | DhtKey::NodeInfo(_)
                    | DhtKey::GlobalNodePublicKey(_)
                    | DhtKey::NodeHealth(_)
                    | DhtKey::NodeLoad(_)
                    | DhtKey::GlobalNodeHeartbeat(_)
                    | DhtKey::VerifiedUpstream(_)
                    | DhtKey::TierClaim(_)
                    | DhtKey::DnsZone(_)
                    | DhtKey::DnsRecord(_, _)
                    | DhtKey::AnycastNode(_)
                    | DhtKey::ThreatIndicator(_, _)
                    | DhtKey::TransformedContent { .. }
                    | DhtKey::PoisonedImage { .. }
                    | DhtKey::SiteImagePoisonConfig(_)
                    | DhtKey::SiteContentVersion(_)
                    | DhtKey::YaraRuleContent { .. }
                    | DhtKey::YaraRulesManifest { .. }
                    | DhtKey::YaraChunk { .. }
                    | DhtKey::NodeCapability { .. }
                    | DhtKey::CapabilityAttestation { .. }
                    | DhtKey::EdgeAttestation { .. }
                    | DhtKey::OriginReachability { .. }
                    | DhtKey::OriginPenalty { .. }
                    | DhtKey::UpstreamOwnershipChallenge(_)
                    | DhtKey::GenesisKeyTransition { .. }
                    | DhtKey::RevokedGlobalNode { .. }
                    | DhtKey::ServerlessFunction { .. }
                    | DhtKey::UpstreamProxyCachePreferences(_)
                    | DhtKey::OrgPublicKey(_)
                    | DhtKey::BehavioralFingerprint { .. }
                    | DhtKey::NodeCertBinding { .. }
            ),
        }
    }

    pub fn requires_confirmation(&self) -> bool {
        match self {
            DhtKey::SiteScoped { inner_key, .. } => {
                DhtKey::from_str(inner_key).requires_confirmation()
            }
            _ => matches!(
                self,
                DhtKey::TierKey(_, _)
                    | DhtKey::Organization(_)
                    | DhtKey::OrgPublicKey(_)
                    | DhtKey::Upstream(_)
                    | DhtKey::OrgNameReservation(_)
            ),
        }
    }

    pub fn authority(&self) -> RecordAuthority {
        match self {
            DhtKey::SiteScoped { inner_key, .. } => DhtKey::from_str(inner_key).authority(),
            DhtKey::Organization(_)
            | DhtKey::OrgPublicKey(_)
            | DhtKey::TierKey(_, _)
            | DhtKey::MemberCertificate(_, _)
            | DhtKey::GlobalNodeList
            | DhtKey::OrgNameReservation(_)
            | DhtKey::VerifiedUpstream(_)
            | DhtKey::TierClaim(_)
            | DhtKey::DnsDomainRegistration(_)
            | DhtKey::GenesisKeyTransition { .. }
            | DhtKey::RevokedGlobalNode { .. }
            | DhtKey::GlobalNodeProof { .. }
            | DhtKey::NodeCertBinding { .. } => RecordAuthority::RaftGlobal,

            DhtKey::NodeHealth(_)
            | DhtKey::NodeLoad(_)
            | DhtKey::GlobalNodeHeartbeat(_)
            | DhtKey::CapabilityAttestation { .. }
            | DhtKey::EdgeAttestation { .. } => RecordAuthority::NodeSelf,

            DhtKey::ThreatIndicator(_, _)
            | DhtKey::YaraRulesManifest { .. }
            | DhtKey::YaraRuleContent { .. }
            | DhtKey::YaraChunk { .. }
            | DhtKey::YaraCompiledRuleContent { .. }
            | DhtKey::YaraCompiledChunk { .. } => RecordAuthority::SignedFeed,

            DhtKey::TransformedContent { .. } | DhtKey::PoisonedImage { .. } => {
                RecordAuthority::ContentAddressedCache
            }

            DhtKey::NodeInfo(_)
            | DhtKey::GlobalNodePublicKey(_)
            | DhtKey::NodeCapability { .. }
            | DhtKey::OriginReachability { .. }
            | DhtKey::VerificationTask { .. }
            | DhtKey::OriginPenalty { .. } => RecordAuthority::EphemeralTelemetry,

            DhtKey::Upstream(_)
            | DhtKey::DnsZone(_)
            | DhtKey::DnsRecord(_, _)
            | DhtKey::AnycastNode(_)
            | DhtKey::UpstreamImageProtection(_)
            | DhtKey::UpstreamMinification(_)
            | DhtKey::UpstreamCompression(_)
            | DhtKey::UpstreamProxyCachePreferences(_)
            | DhtKey::SiteImagePoisonConfig(_)
            | DhtKey::SiteContentVersion(_)
            | DhtKey::UpstreamOwnershipChallenge(_)
            | DhtKey::ServerlessFunction { .. }
            | DhtKey::BehavioralFingerprint { .. } => RecordAuthority::PublicCache,
        }
    }

    pub fn is_raft_global(&self) -> bool {
        self.authority() == RecordAuthority::RaftGlobal
    }

    pub fn is_self_record(&self, node_id: &str) -> bool {
        match self {
            DhtKey::SiteScoped { inner_key, .. } => {
                DhtKey::from_str(inner_key).is_self_record(node_id)
            }
            DhtKey::NodeHealth(nid) => nid == node_id,
            DhtKey::NodeLoad(nid) => nid == node_id,
            DhtKey::GlobalNodeHeartbeat(nid) => nid == node_id,
            DhtKey::NodeInfo(nid) => nid == node_id,
            _ => false,
        }
    }

    pub fn key_type(&self) -> &'static str {
        match self {
            DhtKey::SiteScoped { .. } => "site_scoped",
            DhtKey::Organization(_) => "organization",
            DhtKey::OrgPublicKey(_) => "org_public_key",
            DhtKey::TierKey(_, _) => "tier_key",
            DhtKey::MemberCertificate(_, _) => "member_certificate",
            DhtKey::Upstream(_) => "upstream",
            DhtKey::NodeInfo(_) => "node_info",
            DhtKey::GlobalNodeList => "global_node_list",
            DhtKey::OrgNameReservation(_) => "org_name_reservation",
            DhtKey::GlobalNodePublicKey(_) => "global_node_pubkey",
            DhtKey::NodeHealth(_) => "node_health",
            DhtKey::NodeLoad(_) => "node_load",
            DhtKey::GlobalNodeHeartbeat(_) => "global_node_heartbeat",
            DhtKey::VerifiedUpstream(_) => "verified_upstream",
            DhtKey::TierClaim(_) => "tier_claim",
            DhtKey::DnsZone(_) => "dns_zone",
            DhtKey::DnsRecord(_, _) => "dns_record",
            DhtKey::DnsDomainRegistration(_) => "dns_domain_registration",
            DhtKey::AnycastNode(_) => "anycast_node",
            DhtKey::ThreatIndicator(_, _) => "threat_indicator",
            DhtKey::UpstreamImageProtection(_) => "upstream_image_protection",
            DhtKey::UpstreamMinification(_) => "upstream_minification",
            DhtKey::UpstreamCompression(_) => "upstream_compression",
            DhtKey::UpstreamProxyCachePreferences(_) => "upstream_proxy_cache_preferences",
            DhtKey::SiteImagePoisonConfig(_) => "site_image_poison_config",
            DhtKey::SiteContentVersion(_) => "site_content_version",
            DhtKey::TransformedContent { .. } => "transformed_content",
            DhtKey::PoisonedImage { .. } => "poisoned_image",
            DhtKey::YaraRuleContent { .. } => "yara_rule_content",
            DhtKey::YaraRulesManifest { .. } => "yara_rules_manifest",
            DhtKey::YaraChunk { .. } => "yara_chunk",
            DhtKey::NodeCapability { .. } => "node_capability",
            DhtKey::CapabilityAttestation { .. } => "capability_attestation",
            DhtKey::EdgeAttestation { .. } => "edge_attestation",
            DhtKey::OriginReachability { .. } => "origin_reachability",
            DhtKey::VerificationTask { .. } => "verification_task",
            DhtKey::OriginPenalty { .. } => "origin_penalty",
            DhtKey::UpstreamOwnershipChallenge(_) => "upstream_ownership_challenge",
            DhtKey::GenesisKeyTransition { .. } => "genesis_key_transition",
            DhtKey::RevokedGlobalNode { .. } => "revoked_global_node",
            DhtKey::ServerlessFunction { .. } => "serverless_function",
            DhtKey::BehavioralFingerprint { .. } => "behavioral_fingerprint",
            DhtKey::NodeCertBinding { .. } => "node_cert_binding",
            DhtKey::YaraCompiledRuleContent { .. } => "yara_compiled_rule_content",
            DhtKey::YaraCompiledChunk { .. } => "yara_compiled_chunk",
            DhtKey::GlobalNodeProof { .. } => "global_node_proof",
        }
    }

    pub fn to_signed_record_type(&self) -> Option<crate::dht::signed::SignedRecordType> {
        use crate::dht::signed::SignedRecordType;
        match self {
            DhtKey::SiteScoped { inner_key, .. } => {
                DhtKey::from_str(inner_key).to_signed_record_type()
            }
            DhtKey::Organization(_) => Some(SignedRecordType::Organization),
            DhtKey::OrgPublicKey(_) => Some(SignedRecordType::OrgPublicKey),
            DhtKey::TierKey(_, _) => Some(SignedRecordType::TierKey),
            DhtKey::MemberCertificate(_, _) => Some(SignedRecordType::MemberCertificate),
            DhtKey::Upstream(_) => Some(SignedRecordType::Upstream),
            DhtKey::NodeInfo(_) => Some(SignedRecordType::NodeInfo),
            DhtKey::GlobalNodeList => Some(SignedRecordType::GlobalNodeList),
            DhtKey::OrgNameReservation(_) => Some(SignedRecordType::OrgNameReservation),
            DhtKey::GlobalNodePublicKey(_) => Some(SignedRecordType::GlobalNodePublicKey),
            DhtKey::NodeHealth(_) => Some(SignedRecordType::NodeHealth),
            DhtKey::NodeLoad(_) => Some(SignedRecordType::NodeLoad),
            DhtKey::GlobalNodeHeartbeat(_) => Some(SignedRecordType::GlobalNodeHeartbeat),
            DhtKey::VerifiedUpstream(_) => Some(SignedRecordType::VerifiedUpstream),
            DhtKey::TierClaim(_) => Some(SignedRecordType::TierClaim),
            DhtKey::DnsZone(_) => Some(SignedRecordType::DnsZone),
            DhtKey::DnsRecord(_, _) => Some(SignedRecordType::DnsRecord),
            DhtKey::DnsDomainRegistration(_) => Some(SignedRecordType::DnsDomainRegistration),
            DhtKey::AnycastNode(_) => Some(SignedRecordType::AnycastNode),
            DhtKey::ThreatIndicator(_, _) => Some(SignedRecordType::ThreatIndicator),
            DhtKey::UpstreamImageProtection(_) => Some(SignedRecordType::UpstreamImageProtection),
            DhtKey::UpstreamMinification(_) => Some(SignedRecordType::UpstreamMinification),
            DhtKey::UpstreamCompression(_) => Some(SignedRecordType::UpstreamCompression),
            DhtKey::UpstreamProxyCachePreferences(_) => {
                Some(SignedRecordType::UpstreamProxyCachePreferences)
            }
            DhtKey::SiteImagePoisonConfig(_) => Some(SignedRecordType::SiteImagePoisonConfig),
            DhtKey::SiteContentVersion(_) => None,
            DhtKey::TransformedContent { .. } => None,
            DhtKey::PoisonedImage { .. } => None,
            DhtKey::YaraRuleContent { .. } => Some(SignedRecordType::YaraRuleContent),
            DhtKey::YaraCompiledRuleContent { .. } => {
                Some(SignedRecordType::YaraCompiledRuleContent)
            }
            DhtKey::YaraRulesManifest { .. } => Some(SignedRecordType::YaraRulesManifest),
            DhtKey::YaraChunk { .. } => None,
            DhtKey::YaraCompiledChunk { .. } => None,
            DhtKey::GlobalNodeProof { .. } => Some(SignedRecordType::GlobalNodeProof),
            DhtKey::NodeCapability { .. } => None,
            DhtKey::CapabilityAttestation { .. } => None,
            DhtKey::EdgeAttestation { .. } => None,
            DhtKey::OriginReachability { .. } => None,
            DhtKey::VerificationTask { .. } => None,
            DhtKey::OriginPenalty { .. } => None,
            DhtKey::UpstreamOwnershipChallenge(_) => None,
            DhtKey::GenesisKeyTransition { .. } => Some(SignedRecordType::GenesisKeyTransition),
            DhtKey::RevokedGlobalNode { .. } => Some(SignedRecordType::RevokedGlobalNode),
            DhtKey::NodeCertBinding { .. } => Some(SignedRecordType::NodeCertBinding),
            DhtKey::ServerlessFunction { .. } => None,
            DhtKey::BehavioralFingerprint { .. } => None,
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
            DhtKey::SiteScoped { site_id, .. } => Some(site_id.clone()),
            DhtKey::Upstream(id) => Some(id.clone()),
            DhtKey::VerifiedUpstream(id) => Some(id.clone()),
            DhtKey::TierClaim(id) => Some(id.clone()),
            DhtKey::DnsZone(zone) => Some(zone.clone()),
            DhtKey::DnsRecord(zone, _) => Some(zone.clone()),
            DhtKey::UpstreamImageProtection(id) => Some(id.clone()),
            DhtKey::UpstreamMinification(id) => Some(id.clone()),
            DhtKey::UpstreamCompression(id) => Some(id.clone()),
            DhtKey::UpstreamProxyCachePreferences(id) => Some(id.clone()),
            DhtKey::SiteImagePoisonConfig(id) => Some(id.clone()),
            DhtKey::TransformedContent { site_id, .. } => Some(site_id.clone()),
            DhtKey::PoisonedImage { site_id, .. } => Some(site_id.clone()),
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
    fn test_site_scoped_key() {
        let inner = DhtKey::upstream("api.example.com");
        let scoped = DhtKey::site_scoped("site1", inner.clone());
        assert_eq!(
            scoped.as_str(),
            "site_scoped:site1:upstream:api.example.com"
        );

        let parsed = DhtKey::from_str("site_scoped:site1:upstream:api.example.com");
        assert_eq!(parsed, scoped);
        assert_eq!(parsed.site_scope(), Some("site1".to_string()));
        assert!(parsed.is_public());
        assert!(!parsed.is_privileged());
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

    #[test]
    fn test_record_authority_classification() {
        assert_eq!(
            DhtKey::organization("test").authority(),
            RecordAuthority::RaftGlobal
        );
        assert_eq!(
            DhtKey::verified_upstream("example.com").authority(),
            RecordAuthority::RaftGlobal
        );
        assert_eq!(
            DhtKey::node_health("node-1").authority(),
            RecordAuthority::NodeSelf
        );
        assert_eq!(
            DhtKey::threat_indicator("indicator", "ip").authority(),
            RecordAuthority::SignedFeed
        );
        assert_eq!(
            DhtKey::transformed_content("site", "hash", "flags").authority(),
            RecordAuthority::ContentAddressedCache
        );
        assert_eq!(
            DhtKey::node_info("node-1").authority(),
            RecordAuthority::EphemeralTelemetry
        );
        assert_eq!(
            DhtKey::upstream("example.com").authority(),
            RecordAuthority::PublicCache
        );
    }
}
