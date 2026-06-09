use super::keys::{DhtKey, DhtKey::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtRecordAuthorityClass {
    SoftLocal,
    SignedByRecordOwner,
    CapabilityAttested,
    QuorumSignedGlobal,
    RaftAttestedGlobal,
    RaftOrQuorumGlobal,
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhtKeyPolicy {
    pub authority_class: DhtRecordAuthorityClass,
    pub ttl_required: bool,
    pub immutable_after_create: bool,
    pub remote_writes_allowed: bool,
    pub required_capability: Option<&'static str>,
}

pub struct DhtKeyPolicyTable;

impl DhtKeyPolicyTable {
    pub fn policy_for_key(key: &DhtKey) -> DhtKeyPolicy {
        match key {
            SiteScoped { inner_key, .. } => {
                let inner = DhtKey::from_str(inner_key);
                let mut policy = Self::policy_for_key(&inner);
                policy.remote_writes_allowed = true;
                policy
            }

            Organization(_)
            | OrgPublicKey(_)
            | TierKey(_, _)
            | MemberCertificate(_, _)
            | GlobalNodeList
            | OrgNameReservation(_)
            | VerifiedUpstream(_)
            | TierClaim(_)
            | DnsDomainRegistration(_) => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::RaftOrQuorumGlobal,
                ttl_required: false,
                immutable_after_create: false,
                remote_writes_allowed: false,
                required_capability: None,
            },

            GlobalNodeProof { .. } | NodeCertBinding { .. } | GenesisKeyTransition { .. } => {
                DhtKeyPolicy {
                    authority_class: DhtRecordAuthorityClass::RaftAttestedGlobal,
                    ttl_required: false,
                    immutable_after_create: false,
                    remote_writes_allowed: false,
                    required_capability: None,
                }
            }

            RevokedGlobalNode { .. } => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::RaftAttestedGlobal,
                ttl_required: false,
                immutable_after_create: true,
                remote_writes_allowed: false,
                required_capability: None,
            },

            DnsZone(_) => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::RaftOrQuorumGlobal,
                ttl_required: false,
                immutable_after_create: false,
                remote_writes_allowed: false,
                required_capability: None,
            },

            DnsRecord(_, _) => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::CapabilityAttested,
                ttl_required: false,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: Some("dns"),
            },

            ThreatIndicator(_, _) => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::CapabilityAttested,
                ttl_required: true,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: Some("threat_intel"),
            },

            YaraRulesManifest { .. }
            | YaraRuleContent { .. }
            | YaraCompiledRuleContent { .. }
            | YaraChunk { .. }
            | YaraCompiledChunk { .. } => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::CapabilityAttested,
                ttl_required: false,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: Some("waf"),
            },

            NodeInfo(_)
            | NodeHealth(_)
            | NodeLoad(_)
            | GlobalNodeHeartbeat(_)
            | NodeCapability { .. }
            | EdgeAttestation { .. }
            | CapabilityAttestation { .. } => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::SignedByRecordOwner,
                ttl_required: true,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: None,
            },

            GlobalNodePublicKey(_) => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::SignedByRecordOwner,
                ttl_required: true,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: None,
            },

            OriginReachability { .. } | VerificationTask { .. } | OriginPenalty { .. } => {
                DhtKeyPolicy {
                    authority_class: DhtRecordAuthorityClass::SignedByRecordOwner,
                    ttl_required: true,
                    immutable_after_create: false,
                    remote_writes_allowed: true,
                    required_capability: None,
                }
            }

            Upstream(_)
            | AnycastNode(_)
            | UpstreamImageProtection(_)
            | UpstreamMinification(_)
            | UpstreamCompression(_)
            | UpstreamProxyCachePreferences(_)
            | SiteImagePoisonConfig(_)
            | SiteContentVersion(_)
            | UpstreamOwnershipChallenge(_)
            | ServerlessFunction { .. }
            | BehavioralFingerprint { .. } => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::SoftLocal,
                ttl_required: true,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: None,
            },

            TransformedContent { .. } | PoisonedImage { .. } => DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::SoftLocal,
                ttl_required: false,
                immutable_after_create: false,
                remote_writes_allowed: true,
                required_capability: None,
            },
        }
    }

    pub fn policy_for_key_str(key_str: &str) -> DhtKeyPolicy {
        if !is_known_key_prefix(key_str) {
            return DhtKeyPolicy {
                authority_class: DhtRecordAuthorityClass::SoftLocal,
                ttl_required: true,
                immutable_after_create: false,
                remote_writes_allowed: false,
                required_capability: None,
            };
        }
        let key = DhtKey::from_str(key_str);
        Self::policy_for_key(&key)
    }
}

fn is_known_key_prefix(key_str: &str) -> bool {
    let prefix = key_str.split(':').next().unwrap_or("");
    matches!(
        prefix,
        "org"
            | "org_pubkey"
            | "tier_key"
            | "member_cert"
            | "upstream"
            | "node_info"
            | "global_node_list"
            | "org_name_reservation"
            | "global_node_pubkey"
            | "node_health"
            | "node_load"
            | "global_node_heartbeat"
            | "verified_upstream"
            | "tier_claim"
            | "dns_zone"
            | "dns_record"
            | "dns_domain_reg"
            | "anycast_node"
            | "threat_indicator"
            | "upstream_image_protection"
            | "upstream_minification"
            | "upstream_compression"
            | "upstream_proxy_cache_preferences"
            | "site_image_poison_config"
            | "site_content_version"
            | "transformed"
            | "poisoned_image"
            | "yara_rule"
            | "yara_compiled_rule"
            | "yara_rules_manifest"
            | "yara_chunk"
            | "yara_compiled_chunk"
            | "global_node_proof"
            | "node_capability"
            | "origin_reachability"
            | "verification_task"
            | "origin_penalty"
            | "upstream_ownership_challenge"
            | "genesis_key_transition"
            | "revoked_global_node"
            | "capability_attestation"
            | "edge_attestation"
            | "serverless_function"
            | "behavior_fingerprint"
            | "node_cert_binding"
            | "site_scoped"
    )
}

pub fn is_remote_write_denied(key: &DhtKey) -> bool {
    !DhtKeyPolicyTable::policy_for_key(key).remote_writes_allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_org_policy() {
        let policy = DhtKeyPolicyTable::policy_for_key(&Organization("org1".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftOrQuorumGlobal
        );
        assert!(!policy.ttl_required);
        assert!(!policy.immutable_after_create);
        assert!(!policy.remote_writes_allowed);
        assert!(policy.required_capability.is_none());
    }

    #[test]
    fn test_dns_zone_ownership() {
        let policy = DhtKeyPolicyTable::policy_for_key(&DnsZone("example.com".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftOrQuorumGlobal
        );
        assert!(!policy.ttl_required);
        assert!(!policy.immutable_after_create);
        assert!(!policy.remote_writes_allowed);
        assert!(policy.required_capability.is_none());
    }

    #[test]
    fn test_dns_record() {
        let policy =
            DhtKeyPolicyTable::policy_for_key(&DnsRecord("example.com".into(), "www".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::CapabilityAttested
        );
        assert!(!policy.ttl_required);
        assert!(policy.remote_writes_allowed);
        assert_eq!(policy.required_capability, Some("dns"));
    }

    #[test]
    fn test_yara_rules() {
        let policy = DhtKeyPolicyTable::policy_for_key(&YaraRulesManifest {
            node_id: "n1".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::CapabilityAttested
        );
        assert!(!policy.ttl_required);
        assert!(policy.remote_writes_allowed);
        assert_eq!(policy.required_capability, Some("waf"));

        let policy = DhtKeyPolicyTable::policy_for_key(&YaraRuleContent {
            content_hash: "h1".into(),
        });
        assert_eq!(policy.required_capability, Some("waf"));

        let policy = DhtKeyPolicyTable::policy_for_key(&YaraCompiledRuleContent {
            compiled_hash: "h1".into(),
        });
        assert_eq!(policy.required_capability, Some("waf"));

        let policy = DhtKeyPolicyTable::policy_for_key(&YaraChunk {
            content_hash: "h1".into(),
            index: 0,
        });
        assert_eq!(policy.required_capability, Some("waf"));

        let policy = DhtKeyPolicyTable::policy_for_key(&YaraCompiledChunk {
            compiled_hash: "h1".into(),
            index: 0,
        });
        assert_eq!(policy.required_capability, Some("waf"));
    }

    #[test]
    fn test_threat_indicator() {
        let policy =
            DhtKeyPolicyTable::policy_for_key(&ThreatIndicator("ind1".into(), "ip".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::CapabilityAttested
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
        assert_eq!(policy.required_capability, Some("threat_intel"));
    }

    #[test]
    fn test_node_info() {
        let policy = DhtKeyPolicyTable::policy_for_key(&NodeInfo("node1".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
        assert!(policy.required_capability.is_none());
    }

    #[test]
    fn test_upstream_provider_hints() {
        let policy = DhtKeyPolicyTable::policy_for_key(&Upstream("u1".into()));
        assert_eq!(policy.authority_class, DhtRecordAuthorityClass::SoftLocal);
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&UpstreamImageProtection("s1".into()));
        assert_eq!(policy.authority_class, DhtRecordAuthorityClass::SoftLocal);
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&UpstreamMinification("s1".into()));
        assert_eq!(policy.authority_class, DhtRecordAuthorityClass::SoftLocal);
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
    }

    #[test]
    fn test_revocation_immutable() {
        let policy = DhtKeyPolicyTable::policy_for_key(&RevokedGlobalNode {
            node_id: "n1".into(),
            revoked_at: 0,
            reason: "test".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftAttestedGlobal
        );
        assert!(policy.immutable_after_create);
        assert!(!policy.remote_writes_allowed);
    }

    #[test]
    fn test_authorized_global_nodes() {
        let policy = DhtKeyPolicyTable::policy_for_key(&GlobalNodeProof {
            node_id: "n1".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftAttestedGlobal
        );
        assert!(!policy.ttl_required);
        assert!(!policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&NodeCertBinding {
            node_id: "n1".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftAttestedGlobal
        );
        assert!(!policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&GenesisKeyTransition {
            sequence: 1,
            new_key_fingerprint: "fp".into(),
            announced_by: "n1".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftAttestedGlobal
        );
        assert!(!policy.remote_writes_allowed);
    }

    #[test]
    fn test_unknown_key_deny_by_default() {
        let policy = DhtKeyPolicyTable::policy_for_key_str("unknown_foo:bar:baz");
        assert_eq!(policy.authority_class, DhtRecordAuthorityClass::SoftLocal);
        assert!(policy.ttl_required);
        assert!(!policy.remote_writes_allowed);
        assert!(policy.required_capability.is_none());
    }

    #[test]
    fn test_site_scoped_delegation() {
        let inner = DhtKey::upstream("api.example.com");
        let scoped = DhtKey::site_scoped("site1", inner);
        let policy = DhtKeyPolicyTable::policy_for_key(&scoped);
        assert_eq!(policy.authority_class, DhtRecordAuthorityClass::SoftLocal);
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
    }

    #[test]
    fn test_dns_zone_remote_write_denied() {
        let key = DhtKey::DnsZone("example.com".into());
        assert!(
            is_remote_write_denied(&key),
            "DnsZone ownership must not be mutable through remote DHT capability alone"
        );
        let policy = DhtKeyPolicyTable::policy_for_key(&key);
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftOrQuorumGlobal,
            "DnsZone requires Raft or quorum attestation for writes"
        );
        assert!(
            policy.required_capability.is_none(),
            "DnsZone should not require a capability since it requires Raft/quorum proof"
        );
    }

    #[test]
    fn test_dns_record_still_allows_remote_writes() {
        let key = DhtKey::DnsRecord("example.com".into(), "www".into());
        assert!(
            !is_remote_write_denied(&key),
            "DnsRecord should still allow remote writes via capability attestation"
        );
        let policy = DhtKeyPolicyTable::policy_for_key(&key);
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::CapabilityAttested
        );
        assert_eq!(policy.required_capability, Some("dns"));
    }

    #[test]
    fn test_is_remote_write_denied() {
        assert!(is_remote_write_denied(&Organization("org1".into())));
        assert!(!is_remote_write_denied(&NodeInfo("n1".into())));
        assert!(is_remote_write_denied(&DnsZone("example.com".into())));

        let policy = DhtKeyPolicyTable::policy_for_key_str("unknown_foo:bar");
        assert!(!policy.remote_writes_allowed);
    }

    #[test]
    fn test_policy_for_key_str() {
        let policy = DhtKeyPolicyTable::policy_for_key_str("org:my-org");
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftOrQuorumGlobal
        );

        let policy = DhtKeyPolicyTable::policy_for_key_str("node_info:node-1");
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
    }

    #[test]
    fn test_content_addressed_no_ttl() {
        let policy = DhtKeyPolicyTable::policy_for_key(&TransformedContent {
            site_id: "s1".into(),
            content_hash: "h1".into(),
            transform_flags: "f1".into(),
        });
        assert!(!policy.ttl_required);
        assert!(policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&PoisonedImage {
            site_id: "s1".into(),
            original_hash: "h1".into(),
        });
        assert!(!policy.ttl_required);
        assert!(policy.remote_writes_allowed);
    }

    #[test]
    fn test_node_health_and_load() {
        let policy = DhtKeyPolicyTable::policy_for_key(&NodeHealth("n1".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&NodeLoad("n1".into()));
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
    }

    #[test]
    fn test_global_node_list_raft() {
        let policy = DhtKeyPolicyTable::policy_for_key(&GlobalNodeList);
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::RaftOrQuorumGlobal
        );
        assert!(!policy.ttl_required);
        assert!(!policy.remote_writes_allowed);
    }

    #[test]
    fn test_edge_attestation() {
        let policy = DhtKeyPolicyTable::policy_for_key(&EdgeAttestation {
            node_id: "n1".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);

        let policy = DhtKeyPolicyTable::policy_for_key(&CapabilityAttestation {
            node_id: "n1".into(),
            capability: "dns".into(),
        });
        assert_eq!(
            policy.authority_class,
            DhtRecordAuthorityClass::SignedByRecordOwner
        );
        assert!(policy.ttl_required);
        assert!(policy.remote_writes_allowed);
    }
}
