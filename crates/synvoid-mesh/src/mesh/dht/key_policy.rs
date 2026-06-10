//! DHT key authority policy — the boundary between advisory DHT records and
//! canonical trust decisions.
//!
//! **This module is a policy boundary, not canonical storage.** Advisory DHT
//! records do not become trusted because they are signed. `CanonicalTrustReader`
//! is used only for canonical trust answers (what Raft/consensus says is
//! trusted), not for advisory mechanics (what has been advertised).
//!
//! The `classify_key_authority_with_canonical_reader` function is the
//! reader-backed entry point. It preserves existing advisory classification
//! while making canonical trust questions explicit. `Unknown` canonical
//! answers are never silently treated as trust.

use super::keys::{DhtKey, DhtKey::*};
use crate::mesh::canonical::{
    CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader, CanonicalTrustReason,
};

/// Decision produced by `classify_key_authority_with_canonical_reader`.
///
/// DHT key policy is a **policy boundary**, not canonical storage. Advisory
/// DHT records do not become trusted because they are signed.
/// `CanonicalTrustReader` is used only for canonical trust answers.
/// `Unknown` canonical answers must not be silently treated as canonical trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtKeyAuthorityDecision {
    /// Pure advisory key — no canonical trust question needed.
    AcceptAdvisory,
    /// Canonical trust verified via `CanonicalTrustReader`.
    AcceptCanonical { freshness: CanonicalFreshness },
    /// Explicitly rejected (e.g. revoked signer, unauthorized global node).
    Reject { reason: DhtKeyAuthorityRejectReason },
    /// Canonical state unavailable or ambiguous — caller should defer or
    /// apply fallback policy. Never treat as trust.
    Defer { reason: DhtKeyAuthorityDeferReason },
}

/// Why a key authority decision rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtKeyAuthorityRejectReason {
    /// Signer node is revoked in canonical state.
    SignerRevoked,
    /// Signer node is not authorized as a global node in canonical state.
    SignerNotGloballyAuthorized,
    /// Threat indicator not present in canonical threat-intel state.
    ThreatIntelNotCanonical,
}

/// Why a key authority decision deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhtKeyAuthorityDeferReason {
    /// Canonical trust reader state is unavailable.
    CanonicalUnavailable,
    /// Canonical trust decision was `Unknown` (unsupported or ambiguous).
    CanonicalUnknown,
}

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

/// Classify the authority requirement for a DHT key using a canonical trust
/// reader for trust questions.
///
/// This is the **reader-backed policy entry point**. It preserves the existing
/// advisory classification from `DhtKeyPolicyTable` while making canonical
/// trust questions explicit and testable.
///
/// # Domain Distinction
///
/// - **DHT key policy** answers "what authority class does this key belong to?"
///   (advisory mechanics: TTL, namespace, local write policy, routing hints).
/// - **`CanonicalTrustReader`** answers "what does Raft/consensus say is trusted?"
///   (canonical authority: global node authorization, revocation, org key trust,
///   threat intel).
/// - **This function** composes both into an actionable decision.
///
/// # Invariants
///
/// - Advisory DHT records do not become trusted because they are signed.
/// - `Unknown` canonical answers are never silently treated as trust.
/// - Revocation is checked before global authorization (revoked wins).
/// - Pure advisory keys never touch the canonical reader.
///
/// # Arguments
///
/// * `policy` - Static key policy table (advisory mechanics).
/// * `reader` - Canonical trust reader for Raft/consensus trust answers.
/// * `key` - The DHT key being classified.
/// * `signer_node_id` - The node that signed the record (if available).
/// * `authority_hint` - Optional pre-resolved authority class override.
pub fn classify_key_authority_with_canonical_reader(
    _policy: &DhtKeyPolicyTable,
    reader: &dyn CanonicalTrustReader,
    key: &DhtKey,
    signer_node_id: Option<&str>,
    authority_hint: Option<DhtRecordAuthorityClass>,
) -> DhtKeyAuthorityDecision {
    let key_policy = DhtKeyPolicyTable::policy_for_key(key);
    let authority_class = authority_hint.unwrap_or(key_policy.authority_class);

    match authority_class {
        // Pure advisory — no canonical trust question needed.
        DhtRecordAuthorityClass::SoftLocal | DhtRecordAuthorityClass::SignedByRecordOwner => {
            DhtKeyAuthorityDecision::AcceptAdvisory
        }

        // Capability-attested keys: only ThreatIndicator has a canonical trust
        // dimension. DNS/WAF capability attestation remains advisory.
        DhtRecordAuthorityClass::CapabilityAttested => match key {
            ThreatIndicator(intel_id, _) => classify_threat_intel_authority(reader, intel_id),
            _ => DhtKeyAuthorityDecision::AcceptAdvisory,
        },

        // Raft-attested global keys: canonical trust required.
        DhtRecordAuthorityClass::RaftAttestedGlobal => {
            classify_global_required_authority(reader, signer_node_id, key)
        }

        // Raft-or-quorum global keys: canonical trust required.
        DhtRecordAuthorityClass::RaftOrQuorumGlobal => {
            classify_global_required_authority(reader, signer_node_id, key)
        }

        // Unused authority classes — fall through as advisory.
        DhtRecordAuthorityClass::QuorumSignedGlobal | DhtRecordAuthorityClass::LocalOnly => {
            DhtKeyAuthorityDecision::AcceptAdvisory
        }
    }
}

/// Authority check for keys requiring global canonical trust.
///
/// Revocation is checked **before** global authorization: a revoked signer
/// is rejected regardless of global-node status. Unavailable/unknown
/// canonical state produces `Defer`, never silent accept.
fn classify_global_required_authority(
    reader: &dyn CanonicalTrustReader,
    signer_node_id: Option<&str>,
    key: &DhtKey,
) -> DhtKeyAuthorityDecision {
    // Check revocation first — revoked wins over authorization.
    if let Some(node_id) = signer_node_id {
        match reader.node_revocation_status(node_id) {
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::Revoked,
                ..
            } => {
                return DhtKeyAuthorityDecision::Reject {
                    reason: DhtKeyAuthorityRejectReason::SignerRevoked,
                };
            }
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::CanonicalUnavailable,
                ..
            } => {
                return DhtKeyAuthorityDecision::Defer {
                    reason: DhtKeyAuthorityDeferReason::CanonicalUnavailable,
                };
            }
            CanonicalTrustDecision::Unknown { .. } => {
                return DhtKeyAuthorityDecision::Defer {
                    reason: DhtKeyAuthorityDeferReason::CanonicalUnknown,
                };
            }
            // Trusted (not revoked) or NotTrusted with other reasons —
            // continue to global authorization check.
            _ => {}
        }
    }

    // Determine the node to check for global authorization.
    let check_node = signer_node_id.or_else(|| extract_node_id_from_key(key));

    if let Some(node_id) = check_node {
        match reader.is_global_node_authorized(node_id) {
            CanonicalTrustDecision::Trusted { freshness } => {
                DhtKeyAuthorityDecision::AcceptCanonical { freshness }
            }
            CanonicalTrustDecision::NotTrusted {
                reason: CanonicalTrustReason::CanonicalUnavailable,
                ..
            } => DhtKeyAuthorityDecision::Defer {
                reason: DhtKeyAuthorityDeferReason::CanonicalUnavailable,
            },
            CanonicalTrustDecision::Unknown { .. } => DhtKeyAuthorityDecision::Defer {
                reason: DhtKeyAuthorityDeferReason::CanonicalUnknown,
            },
            CanonicalTrustDecision::NotTrusted { .. } => DhtKeyAuthorityDecision::Reject {
                reason: DhtKeyAuthorityRejectReason::SignerNotGloballyAuthorized,
            },
        }
    } else {
        // No signer or extractable node id — defer, do not silently accept.
        DhtKeyAuthorityDecision::Defer {
            reason: DhtKeyAuthorityDeferReason::CanonicalUnknown,
        }
    }
}

/// Authority check for threat-intel keys with canonical trust dimension.
fn classify_threat_intel_authority(
    reader: &dyn CanonicalTrustReader,
    intel_id: &str,
) -> DhtKeyAuthorityDecision {
    match reader.is_threat_intel_canonical(intel_id) {
        CanonicalTrustDecision::Trusted { freshness } => {
            DhtKeyAuthorityDecision::AcceptCanonical { freshness }
        }
        CanonicalTrustDecision::NotTrusted {
            reason: CanonicalTrustReason::CanonicalUnavailable,
            ..
        } => DhtKeyAuthorityDecision::Defer {
            reason: DhtKeyAuthorityDeferReason::CanonicalUnavailable,
        },
        CanonicalTrustDecision::Unknown { .. } => DhtKeyAuthorityDecision::Defer {
            reason: DhtKeyAuthorityDeferReason::CanonicalUnknown,
        },
        CanonicalTrustDecision::NotTrusted { .. } => DhtKeyAuthorityDecision::Reject {
            reason: DhtKeyAuthorityRejectReason::ThreatIntelNotCanonical,
        },
    }
}

/// Extract a node ID from key variants that embed one, for canonical
/// authorization checks when no explicit signer is available.
fn extract_node_id_from_key(key: &DhtKey) -> Option<&str> {
    match key {
        GlobalNodeProof { node_id }
        | NodeCertBinding { node_id }
        | RevokedGlobalNode { node_id, .. } => Some(node_id),
        GenesisKeyTransition { announced_by, .. } => Some(announced_by),
        _ => None,
    }
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

    // --- classify_key_authority_with_canonical_reader tests (Iteration 11) ---

    use crate::mesh::canonical::{CanonicalFreshness, StaticCanonicalTrustReader};

    fn make_reader(freshness: CanonicalFreshness) -> StaticCanonicalTrustReader {
        StaticCanonicalTrustReader::new(freshness)
    }

    #[test]
    fn test_advisory_key_does_not_require_canonical_reader() {
        // SoftLocal and SignedByRecordOwner keys return AcceptAdvisory
        // regardless of canonical reader state.
        let reader = make_reader(CanonicalFreshness::Unavailable);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &Upstream("u1".into()),
            None,
            None,
        );
        assert_eq!(d, DhtKeyAuthorityDecision::AcceptAdvisory);

        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &NodeInfo("n1".into()),
            Some("signer1"),
            None,
        );
        assert_eq!(d, DhtKeyAuthorityDecision::AcceptAdvisory);
    }

    #[test]
    fn test_global_authorized_signer_accepted() {
        // GlobalNodeProof with authorized signer returns AcceptCanonical.
        let mut reader = make_reader(CanonicalFreshness::Live);
        reader.authorized_global_nodes.insert("pk:global1".into());
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:global1"),
            None,
        );
        assert!(matches!(
            d,
            DhtKeyAuthorityDecision::AcceptCanonical {
                freshness: CanonicalFreshness::Live
            }
        ));
    }

    #[test]
    fn test_unauthorized_signer_rejected_for_global_key() {
        // GlobalNodeProof with unauthorized signer returns Reject.
        let reader = make_reader(CanonicalFreshness::Live);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:unknown"),
            None,
        );
        assert_eq!(
            d,
            DhtKeyAuthorityDecision::Reject {
                reason: DhtKeyAuthorityRejectReason::SignerNotGloballyAuthorized
            }
        );
    }

    #[test]
    fn test_revoked_signer_rejected_before_authorization() {
        // Revoked signer is rejected even if also in authorized_global_nodes.
        let mut reader = make_reader(CanonicalFreshness::Live);
        reader.authorized_global_nodes.insert("pk:bad".into());
        reader.revoked_nodes.insert("pk:bad".into());
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:bad"),
            None,
        );
        assert_eq!(
            d,
            DhtKeyAuthorityDecision::Reject {
                reason: DhtKeyAuthorityRejectReason::SignerRevoked
            }
        );
    }

    #[test]
    fn test_unavailable_canonical_state_rejects_global_key() {
        // Unavailable canonical state must NOT silently accept.
        // StaticCanonicalTrustReader returns NotPresentInCanonicalState for
        // missing nodes, which correctly maps to Reject (not AcceptAdvisory).
        // The Defer path for CanonicalUnavailable is exercised by real
        // SnapshotCanonicalTrustReader implementations, not the static test helper.
        let reader = make_reader(CanonicalFreshness::Unavailable);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:global1"),
            None,
        );
        // Not authorized => Reject (fail-closed), never AcceptAdvisory.
        assert!(matches!(
            d,
            DhtKeyAuthorityDecision::Reject {
                reason: DhtKeyAuthorityRejectReason::SignerNotGloballyAuthorized
            }
        ));
        // Explicitly verify it is NOT an accept.
        assert_ne!(d, DhtKeyAuthorityDecision::AcceptAdvisory);
    }

    #[test]
    fn test_unavailable_canonical_state_still_advisory_for_non_global() {
        // Unavailable canonical state does not affect advisory keys.
        let reader = make_reader(CanonicalFreshness::Unavailable);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &DnsRecord("example.com".into(), "www".into()),
            Some("signer1"),
            None,
        );
        assert_eq!(d, DhtKeyAuthorityDecision::AcceptAdvisory);
    }

    #[test]
    fn test_stale_canonical_state_accepted_if_present() {
        // Stale canonical state with authorized node returns AcceptCanonical.
        // Future policy may tighten this to Defer/Reject.
        let mut reader = make_reader(CanonicalFreshness::Stale { age_ms: 99999 });
        reader.authorized_global_nodes.insert("pk:global1".into());
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:global1"),
            None,
        );
        assert!(matches!(
            d,
            DhtKeyAuthorityDecision::AcceptCanonical {
                freshness: CanonicalFreshness::Stale { .. }
            }
        ));
    }

    #[test]
    fn test_unknown_canonical_decision_not_treated_as_trusted() {
        // When canonical reader returns Unknown for revocation, defer.
        // Use a custom reader that returns Unknown for revocation.
        struct UnknownRevocationReader {
            inner: StaticCanonicalTrustReader,
        }
        impl crate::mesh::canonical::CanonicalTrustReader for UnknownRevocationReader {
            fn freshness(&self) -> CanonicalFreshness {
                self.inner.freshness()
            }
            fn is_global_node_authorized(&self, node_id: &str) -> CanonicalTrustDecision {
                self.inner.is_global_node_authorized(node_id)
            }
            fn is_org_key_trusted(
                &self,
                org_id: &str,
                key_id_or_fingerprint: &str,
            ) -> CanonicalTrustDecision {
                self.inner.is_org_key_trusted(org_id, key_id_or_fingerprint)
            }
            fn is_node_revoked(&self, node_id: &str) -> CanonicalTrustDecision {
                self.inner.is_node_revoked(node_id)
            }
            fn node_revocation_status(&self, _node_id: &str) -> CanonicalTrustDecision {
                CanonicalTrustDecision::Unknown {
                    freshness: CanonicalFreshness::Live,
                    reason: CanonicalTrustReason::UnsupportedDecisionType,
                }
            }
            fn is_threat_intel_canonical(&self, intel_id: &str) -> CanonicalTrustDecision {
                self.inner.is_threat_intel_canonical(intel_id)
            }
        }

        let reader = UnknownRevocationReader {
            inner: make_reader(CanonicalFreshness::Live),
        };
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &GlobalNodeProof {
                node_id: "n1".into(),
            },
            Some("pk:global1"),
            None,
        );
        assert_eq!(
            d,
            DhtKeyAuthorityDecision::Defer {
                reason: DhtKeyAuthorityDeferReason::CanonicalUnknown
            }
        );
    }

    #[test]
    fn test_threat_intel_canonical_trusted() {
        let mut reader = make_reader(CanonicalFreshness::Live);
        reader.threat_intel_ids.insert("intel-1".into());
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &ThreatIndicator("intel-1".into(), "ip".into()),
            Some("signer1"),
            None,
        );
        assert!(matches!(
            d,
            DhtKeyAuthorityDecision::AcceptCanonical {
                freshness: CanonicalFreshness::Live
            }
        ));
    }

    #[test]
    fn test_threat_intel_not_canonical_rejected() {
        let reader = make_reader(CanonicalFreshness::Live);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &ThreatIndicator("unknown-intel".into(), "ip".into()),
            Some("signer1"),
            None,
        );
        assert_eq!(
            d,
            DhtKeyAuthorityDecision::Reject {
                reason: DhtKeyAuthorityRejectReason::ThreatIntelNotCanonical
            }
        );
    }

    #[test]
    fn test_dns_capability_remains_advisory() {
        // CapabilityAttested keys that are not ThreatIndicator remain advisory.
        let reader = make_reader(CanonicalFreshness::Unavailable);
        let d = classify_key_authority_with_canonical_reader(
            &DhtKeyPolicyTable,
            &reader,
            &DnsRecord("example.com".into(), "www".into()),
            Some("signer1"),
            None,
        );
        assert_eq!(d, DhtKeyAuthorityDecision::AcceptAdvisory);
    }

    #[test]
    fn test_extract_node_id_from_key() {
        assert!(extract_node_id_from_key(&GlobalNodeProof {
            node_id: "n1".into()
        })
        .is_some());
        assert!(extract_node_id_from_key(&NodeCertBinding {
            node_id: "n1".into()
        })
        .is_some());
        assert!(extract_node_id_from_key(&GenesisKeyTransition {
            sequence: 1,
            new_key_fingerprint: "fp".into(),
            announced_by: "n1".into(),
        })
        .is_some());
        assert!(extract_node_id_from_key(&Upstream("u1".into())).is_none());
    }
}
