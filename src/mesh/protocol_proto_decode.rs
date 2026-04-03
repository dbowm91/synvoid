use super::*;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Missing payload")]
    MissingPayload,
    #[error("Missing field: {0}")]
    MissingField(&'static str),
    #[error("Conversion error: {0}")]
    ConversionFailed(&'static str),
    #[error("Invalid value: {0}")]
    InvalidValue(&'static str),
    #[error("Invalid field: {0}")]
    InvalidField(&'static str),
}

impl TryFrom<proto::MeshMessage> for MeshMessage {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshMessage) -> Result<Self, ProtocolError> {
        let payload = pb.payload.ok_or(ProtocolError::MissingPayload)?;
        match payload {
            proto::mesh_message::Payload::Hello(h) => {
                let caps_ref = h
                    .capabilities
                    .as_ref()
                    .ok_or(ProtocolError::MissingField("capabilities"))?;
                Ok(MeshMessage::Hello {
                    version: h.version as u8,
                    node_id: h.node_id.into(),
                    role: MeshNodeRole::from_u8(h.roles as u8),
                    capabilities: caps_ref.try_into()?,
                    upstreams: h
                        .upstreams
                        .into_iter()
                        .map(|(k, v)| Ok((k, v.try_into()?)))
                        .collect::<Result<_, _>>()?,
                    auth_token: h.auth_token.map(|s| s.into()),
                    network_id: h.network_id.map(|s| s.into()),
                    global_node_key: h.global_node_key.map(|s| s.into()),
                    timestamp: h.timestamp,
                    nonce: h.nonce.map(|s| s.into()),
                    is_trusted: h.is_trusted.unwrap_or(false),
                    quic_port: h.quic_port,
                    wireguard_port: h.wireguard_port,
                    public_key: h.public_key.map(|s| s.into()),
                    pow_nonce: h.pow_nonce,
                    pow_public_key: h.pow_public_key.map(|s| s.into()),
                })
            }
            proto::mesh_message::Payload::HelloAck(h) => Ok(MeshMessage::HelloAck {
                version: h.version as u8,
                node_id: h.node_id.into(),
                role: MeshNodeRole::from_u8(h.roles as u8),
                session_id: h.session_id.into(),
                capabilities: h
                    .capabilities
                    .map(|c| c.try_into())
                    .transpose()?
                    .unwrap_or_default(),
                upstreams: h
                    .upstreams
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.try_into()?)))
                    .collect::<Result<_, _>>()?,
                auth_token: h.auth_token.map(|s| s.into()),
                network_id: h.network_id.map(|s| s.into()),
                global_node_key: h.global_node_key.map(|s| s.into()),
                timestamp: h.timestamp,
                nonce: h.nonce.map(|s| s.into()),
                is_trusted: h.is_trusted.unwrap_or(false),
                quic_port: h.quic_port,
                wireguard_port: h.wireguard_port,
                public_key: h.public_key.map(|s| s.into()),
            }),
            proto::mesh_message::Payload::SyncRequest(s) => Ok(MeshMessage::SyncRequest {
                node_id: s.node_id.into(),
            }),
            proto::mesh_message::Payload::SyncResponse(s) => Ok(MeshMessage::SyncResponse {
                nodes: s
                    .nodes
                    .into_iter()
                    .map(|n| n.try_into())
                    .collect::<Result<_, _>>()?,
                upstreams: s
                    .upstreams
                    .into_iter()
                    .map(|(k, v)| Ok((k, v.try_into()?)))
                    .collect::<Result<_, _>>()?,
                timestamp: s.timestamp,
            }),
            proto::mesh_message::Payload::RouteQuery(r) => Ok(MeshMessage::RouteQuery {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                max_hops: r.max_hops as u8,
                initiator: r.initiator.into(),
                sequence: r.sequence,
                timestamp: r.timestamp,
                nonce: r.nonce.into(),
            }),
            proto::mesh_message::Payload::RouteResponse(r) => Ok(MeshMessage::RouteResponse {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                provider_node_id: r.provider_node_id.into(),
                hops: r.hops as u8,
                ttl_secs: r.ttl_secs,
                signature: r.signature,
                sequence: r.sequence,
                timestamp: r.timestamp,
                nonce: r.nonce.into(),
                upstream_url: r.upstream_url.map(|s| s.into()),
                waf_policy: r.waf_policy.clone().map(|p| p.into()),
                priority_tier: r.priority_tier,
                tier_claim: r.tier_claim.clone().map(|tc| TierClaim {
                    tier: tc.tier,
                    key_id: tc.key_id,
                    org_id: tc.org_id,
                    mesh_id: tc.mesh_id,
                    timestamp: tc.timestamp,
                    nonce: tc.nonce,
                    signature: tc.signature,
                }),
                org_id: r.org_id.map(|s| s.into()),
                mesh_name: r.mesh_name.map(|s| s.into()),
            }),
            proto::mesh_message::Payload::RouteResponseAck(r) => {
                Ok(MeshMessage::RouteResponseAck {
                    query_id: r.query_id.into(),
                    upstream_id: r.upstream_id.into(),
                    provider_node_id: r.provider_node_id.into(),
                })
            }
            proto::mesh_message::Payload::RouteNotFound(r) => Ok(MeshMessage::RouteNotFound {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
            }),
            proto::mesh_message::Payload::RouteRejected(r) => Ok(MeshMessage::RouteRejected {
                query_id: r.query_id.into(),
                upstream_id: r.upstream_id.into(),
                reason: r.reason.into(),
                alternatives: r
                    .alternatives
                    .into_iter()
                    .map(|a| AlternativeProvider {
                        node_id: a.node_id,
                        priority_tier: a.priority_tier,
                    })
                    .collect(),
            }),
            proto::mesh_message::Payload::TierKeyAnnounce(t) => Ok(MeshMessage::TierKeyAnnounce {
                org_id: t.org_id.into(),
                key: t
                    .key
                    .map(|k| crate::mesh::organization::TierKey {
                        key_id: k.key_id,
                        tier: k.tier,
                        key: k.key,
                        valid_from: k.valid_from,
                        valid_until: k.valid_until,
                        issued_by: k.issued_by,
                        revoked: k.revoked,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    })
                    .unwrap_or_else(|| crate::mesh::organization::TierKey {
                        key_id: String::new(),
                        tier: 0,
                        key: Vec::new(),
                        valid_from: 0,
                        valid_until: 0,
                        issued_by: String::new(),
                        revoked: false,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    }),
                signature: t.signature,
            }),
            proto::mesh_message::Payload::TierKeyRevoke(t) => Ok(MeshMessage::TierKeyRevoke {
                org_id: t.org_id.into(),
                key_id: t.key_id.into(),
                signature: t.signature,
            }),
            proto::mesh_message::Payload::TierKeyQuery(t) => Ok(MeshMessage::TierKeyQuery {
                request_id: t.request_id.into(),
                org_id: t.org_id.into(),
                requested_tier: if t.requested_tier > 0 {
                    Some(t.requested_tier)
                } else {
                    None
                },
            }),
            proto::mesh_message::Payload::TierKeyQueryResponse(t) => {
                Ok(MeshMessage::TierKeyQueryResponse {
                    request_id: t.request_id.into(),
                    keys: t
                        .keys
                        .into_iter()
                        .map(|k| crate::mesh::organization::TierKey {
                            key_id: k.key_id,
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by,
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        })
                        .collect(),
                    signature: t.signature,
                })
            }
            proto::mesh_message::Payload::UnspentTierKeyAnnounce(t) => {
                Ok(MeshMessage::UnspentTierKeyAnnounce {
                    org_id: t.org_id.into(),
                    tier_keys: t
                        .tier_keys
                        .into_iter()
                        .map(|k| crate::mesh::organization::TierKey {
                            key_id: k.key_id,
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by,
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        })
                        .collect(),
                    signature: t.signature,
                    timestamp: t.timestamp,
                })
            }
            proto::mesh_message::Payload::OrgRegistrationRequest(r) => {
                Ok(MeshMessage::OrgRegistrationRequest {
                    request_id: r.request_id.into(),
                    org_name: r.org_name.into(),
                    requesting_node_id: r.requesting_node_id.into(),
                    requesting_node_pubkey: r.requesting_node_pubkey.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgRegistrationResponse(r) => {
                Ok(MeshMessage::OrgRegistrationResponse {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    org_name: r.org_name.into(),
                    approved: r.approved,
                    reason: r.reason.into(),
                    initial_tier_key: r.initial_tier_key.map(|k| {
                        crate::mesh::organization::TierKey {
                            key_id: k.key_id,
                            tier: k.tier,
                            key: k.key,
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by,
                            revoked: k.revoked,
                            revoked_at: None,
                            bound_to: None,
                            is_unspent: true,
                        }
                    }),
                    signature: r.signature,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::OrgInvitationRequest(r) => {
                Ok(MeshMessage::OrgInvitationRequest {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    inviter_node_id: r.inviter_node_id.into(),
                    invited_node_id: r.invited_node_id.into(),
                    invited_node_pubkey: if r.invited_node_pubkey.is_empty() {
                        None
                    } else {
                        Some(r.invited_node_pubkey.into())
                    },
                    invitation_token: r.invitation_token.into(),
                    expires_at: r.expires_at,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgInvitationAccept(r) => {
                Ok(MeshMessage::OrgInvitationAccept {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    invited_node_id: r.invited_node_id.into(),
                    invitation_token: r.invitation_token.into(),
                    proof_of_key: r.proof_of_key.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::OrgInvitationResponse(r) => {
                Ok(MeshMessage::OrgInvitationResponse {
                    request_id: r.request_id.into(),
                    org_id: r.org_id.into(),
                    accepted: r.accepted,
                    org_key: r.org_key.map(|k| crate::mesh::organization::TierKey {
                        key_id: k.key_id,
                        tier: k.tier,
                        key: k.key,
                        valid_from: k.valid_from,
                        valid_until: k.valid_until,
                        issued_by: k.issued_by,
                        revoked: k.revoked,
                        revoked_at: None,
                        bound_to: None,
                        is_unspent: true,
                    }),
                    reason: r.reason.into(),
                    signature: r.signature,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::GlobalNodeAnnounce(r) => {
                let action = match r.action {
                    0 => crate::mesh::protocol::GlobalNodeAction::Add,
                    1 => crate::mesh::protocol::GlobalNodeAction::Remove,
                    2 => crate::mesh::protocol::GlobalNodeAction::UpdateKeyExchange,
                    _ => crate::mesh::protocol::GlobalNodeAction::Add,
                };
                let key_exchange_endpoint = if r.key_exchange_endpoint.is_empty() {
                    None
                } else {
                    Some(r.key_exchange_endpoint.into())
                };
                Ok(MeshMessage::GlobalNodeAnnounce {
                    node_id: r.node_id.into(),
                    public_key: r.public_key.into(),
                    action,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    key_exchange_endpoint,
                })
            }
            proto::mesh_message::Payload::OrgMemberAnnounce(r) => {
                Ok(MeshMessage::OrgMemberAnnounce {
                    org_id: r.org_id.into(),
                    member_node_id: r.member_node_id.into(),
                    announced_by: r.announced_by.into(),
                    joined_at: r.joined_at,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUrlRequest(r) => {
                Ok(MeshMessage::UpstreamUrlRequest {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    url_hash: r.url_hash.into(),
                })
            }
            proto::mesh_message::Payload::UpstreamUrlResponse(r) => {
                Ok(MeshMessage::UpstreamUrlResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    upstream_url: r.upstream_url.into(),
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUrlDenied(r) => {
                Ok(MeshMessage::UpstreamUrlDenied {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                })
            }
            proto::mesh_message::Payload::UpstreamAnnounce(a) => {
                let action = AnnounceAction::from_u8(a.action as u8)
                    .map_err(|_| ProtocolError::InvalidField("invalid announce action"))?;
                Ok(MeshMessage::UpstreamAnnounce {
                    upstream_id: a.upstream_id.into(),
                    action,
                    signature: a.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamUpdate(u) => Ok(MeshMessage::UpstreamUpdate {
                upstream_id: u.upstream_id.into(),
                info: u
                    .info
                    .ok_or(ProtocolError::MissingField("info"))?
                    .try_into()
                    .map_err(|_| ProtocolError::ConversionFailed("upstream info"))?,
                signature: u.signature,
            }),
            proto::mesh_message::Payload::KeepAlive(_) => Ok(MeshMessage::KeepAlive),
            proto::mesh_message::Payload::KeepAliveAck(_) => Ok(MeshMessage::KeepAliveAck),
            proto::mesh_message::Payload::LookupRequest(r) => Ok(MeshMessage::LookupRequest {
                request_id: r.request_id.into(),
                key: r.key.into(),
                lookup_type: match r.lookup_type {
                    0 => LookupType::KeyValue,
                    1 => LookupType::Route,
                    2 => LookupType::Peer,
                    3 => LookupType::Certificate,
                    4 => LookupType::Config,
                    _ => LookupType::KeyValue,
                },
            }),
            proto::mesh_message::Payload::LookupResponse(r) => Ok(MeshMessage::LookupResponse {
                request_id: r.request_id.into(),
                key: r.key.into(),
                value: r.value,
                found: r.found,
            }),
            proto::mesh_message::Payload::LookupBatchRequest(r) => {
                Ok(MeshMessage::LookupBatchRequest {
                    request_id: r.request_id.into(),
                    keys: r.keys.into_iter().map(|s| s.into()).collect(),
                })
            }
            proto::mesh_message::Payload::LookupBatchResponse(r) => {
                Ok(MeshMessage::LookupBatchResponse {
                    request_id: r.request_id.into(),
                    results: r.results.into_iter().map(|(k, v)| (k, Some(v))).collect(),
                })
            }
            proto::mesh_message::Payload::PeerHealthCheck(r) => Ok(MeshMessage::PeerHealthCheck {
                peer_id: r.peer_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::PeerHealthResponse(r) => {
                Ok(MeshMessage::PeerHealthResponse {
                    peer_id: r.peer_id.into(),
                    status: match r.status {
                        0 => HealthStatus::Healthy,
                        1 => HealthStatus::Degraded,
                        2 => HealthStatus::Unhealthy,
                        _ => HealthStatus::Unknown,
                    },
                    latency_ms: r.latency_ms,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::PeerAnnounce(a) => {
                let caps = a
                    .capabilities
                    .ok_or(ProtocolError::MissingField("capabilities"))?;
                Ok(MeshMessage::PeerAnnounce {
                    node_id: a.node_id.into(),
                    address: a.address.into(),
                    role: MeshNodeRole::from_u8(a.role as u8),
                    capabilities: caps.try_into()?,
                    announced_at: a.announced_at,
                })
            }
            proto::mesh_message::Payload::PeerGone(r) => Ok(MeshMessage::PeerGone {
                node_id: r.node_id.into(),
                reason: r.reason.into(),
            }),
            proto::mesh_message::Payload::TopologySyncRequest(r) => {
                Ok(MeshMessage::TopologySyncRequest {
                    request_id: r.request_id.into(),
                    from_version: r.from_version,
                    prefer_delta: r.prefer_delta,
                })
            }
            proto::mesh_message::Payload::TopologySyncResponse(r) => {
                Ok(MeshMessage::TopologySyncResponse {
                    request_id: r.request_id.into(),
                    peers: r
                        .peers
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    upstreams: r
                        .upstreams
                        .into_iter()
                        .map(|(k, v)| Ok((k, v.try_into()?)))
                        .collect::<Result<_, _>>()?,
                    version: r.version,
                    is_delta: r.is_delta,
                    removed_peers: r.removed_peers.into_iter().map(|s| s.into()).collect(),
                    removed_upstreams: r.removed_upstreams.into_iter().map(|s| s.into()).collect(),
                })
            }
            proto::mesh_message::Payload::SeedListRequest(r) => Ok(MeshMessage::SeedListRequest {
                node_id: r.node_id.into(),
                request_full_mesh: r.request_full_mesh,
            }),
            proto::mesh_message::Payload::SeedListResponse(r) => {
                Ok(MeshMessage::SeedListResponse {
                    global_nodes: r
                        .global_nodes
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    edge_nodes: r
                        .edge_nodes
                        .into_iter()
                        .map(|p| p.try_into())
                        .collect::<Result<_, _>>()?,
                    version: r.version,
                    genesis_org_id: if r.genesis_org_id.is_empty() {
                        None
                    } else {
                        Some(r.genesis_org_id.into())
                    },
                })
            }
            proto::mesh_message::Payload::PeerLoadReport(r) => Ok(MeshMessage::PeerLoadReport {
                node_id: r.node_id.into(),
                active_connections: r.active_connections,
                cpu_load_percent: r.cpu_load_percent,
                memory_percent: r.memory_percent,
                requests_per_second: r.requests_per_second,
            }),
            proto::mesh_message::Payload::PeerLoadUpdate(r) => Ok(MeshMessage::PeerLoadUpdate {
                node_id: r.node_id.into(),
                load_score: r.load_score,
            }),
            proto::mesh_message::Payload::RouteUsageReport(r) => {
                Ok(MeshMessage::RouteUsageReport {
                    upstream_id: r.upstream_id.into(),
                    request_count: r.request_count,
                    bytes_transferred: r.bytes_transferred,
                })
            }
            proto::mesh_message::Payload::UpstreamBlocked(r) => Ok(MeshMessage::UpstreamBlocked {
                mesh_identifier: r.mesh_identifier.into(),
                service_id: r.service_id.into(),
                blocked_until: r.blocked_until,
                reason: r.reason.into(),
                origin_node_id: r.origin_node_id.into(),
            }),
            proto::mesh_message::Payload::BandwidthReport(r) => Ok(MeshMessage::BandwidthReport {
                upstream_id: r.upstream_id.into(),
                bytes_sent: r.bytes_sent,
                bytes_received: r.bytes_received,
                request_count: r.request_count,
                interval_secs: r.interval_secs,
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::MeshAck(r) => Ok(MeshMessage::MeshAck {
                original_message_id: r.original_message_id.into(),
                status: AckStatus::from_u8(r.status as u8),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::AuthChallenge(r) => Ok(MeshMessage::AuthChallenge {
                challenge: r.challenge.into(),
                challenge_id: r.challenge_id.into(),
                expires_at: r.expires_at,
            }),
            proto::mesh_message::Payload::AuthResponse(r) => Ok(MeshMessage::AuthResponse {
                challenge_id: r.challenge_id.into(),
                response: r.response.into(),
            }),
            proto::mesh_message::Payload::Error(e) => Ok(MeshMessage::Error {
                code: e.code as u16,
                message: e.message.into(),
            }),
            proto::mesh_message::Payload::ThreatAnnounce(t) => Ok(MeshMessage::ThreatAnnounce {
                request_id: t.request_id.into(),
                indicators: t.indicators.into_iter().map(|i| i.into()).collect(),
                highest_severity: match t.highest_severity {
                    1 => ThreatSeverity::Low,
                    2 => ThreatSeverity::Medium,
                    3 => ThreatSeverity::High,
                    4 => ThreatSeverity::Critical,
                    _ => ThreatSeverity::Unspecified,
                },
                timestamp: t.timestamp,
                source_node_id: t.source_node_id.into(),
                source_role: MeshNodeRole::from_u8(t.source_role as u8),
                source_reputation: t.source_reputation,
                signature: t.signature,
                signer_public_key: t.signer_public_key,
            }),
            proto::mesh_message::Payload::ThreatSyncRequest(t) => {
                Ok(MeshMessage::ThreatSyncRequest {
                    request_id: t.request_id.into(),
                    node_id: t.node_id.into(),
                    from_version: t.from_version,
                    prefer_delta: t.prefer_delta,
                })
            }
            proto::mesh_message::Payload::ThreatSyncResponse(t) => {
                Ok(MeshMessage::ThreatSyncResponse {
                    request_id: t.request_id.into(),
                    indicators: t.indicators.into_iter().map(|i| i.into()).collect(),
                    version: t.version,
                    is_delta: t.is_delta,
                    removed_indicators: t
                        .removed_indicators
                        .into_iter()
                        .map(|s| s.into())
                        .collect(),
                    signature: t.signature,
                    signer_public_key: t.signer_public_key,
                })
            }
            proto::mesh_message::Payload::ThreatAck(t) => Ok(MeshMessage::ThreatAcknowledgement {
                original_request_id: t.original_request_id.into(),
                node_id: t.node_id.into(),
                accepted: t.accepted,
                reason: t.reason.into(),
                timestamp: t.timestamp,
            }),
            proto::mesh_message::Payload::ReputationUpdate(r) => {
                Ok(MeshMessage::ReputationUpdate {
                    node_id: r.node_id.into(),
                    reputation_score: r.reputation_score,
                    threats_accepted: r.threats_accepted,
                    threats_rejected: r.threats_rejected,
                    false_positive_reports: r.false_positive_reports,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::YaraRuleAnnounce(r) => {
                Ok(MeshMessage::YaraRuleAnnounce {
                    request_id: r.request_id.into(),
                    version: r.version.clone(),
                    rules: r.rules.clone(),
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    source_role: MeshNodeRole::from_u8(r.source_role as u8),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleSyncRequest(r) => {
                Ok(MeshMessage::YaraRuleSyncRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    version: r.version,
                })
            }
            proto::mesh_message::Payload::YaraRuleSyncResponse(r) => {
                Ok(MeshMessage::YaraRuleSyncResponse {
                    request_id: r.request_id.into(),
                    version: r.version,
                    rules: r.rules,
                    is_full: r.is_full,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleAck(r) => {
                Ok(MeshMessage::YaraRuleAcknowledgement {
                    original_request_id: r.original_request_id.into(),
                    node_id: r.node_id.into(),
                    accepted: r.accepted,
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::YaraRuleSubmission(r) => {
                Ok(MeshMessage::YaraRuleSubmission {
                    request_id: r.request_id.into(),
                    submission_id: r.submission_id.into(),
                    node_id: r.node_id.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                    rules: r.rules.clone(),
                    description: r.description.clone(),
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::YaraRuleSubmissionResponse(r) => {
                Ok(MeshMessage::YaraRuleSubmissionResponse {
                    original_request_id: r.original_request_id.into(),
                    submission_id: r.submission_id.into(),
                    node_id: r.node_id.into(),
                    status: r.status.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::DhtRecordAnnounce(r) => {
                Ok(MeshMessage::DhtRecordAnnounce {
                    request_id: r.request_id.into(),
                    records: r.records.into_iter().map(|rec| rec.into()).collect(),
                    write_quorum: r.write_quorum,
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtRecordQuery(r) => Ok(MeshMessage::DhtRecordQuery {
                request_id: r.request_id.into(),
                key: r.key.into(),
                timestamp: r.timestamp,
                source_node_id: r.source_node_id.into(),
            }),
            proto::mesh_message::Payload::DhtRecordResponse(r) => {
                Ok(MeshMessage::DhtRecordResponse {
                    request_id: r.request_id.into(),
                    key: r.key.into(),
                    value: r.value,
                    found: r.found,
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtSyncRequest(r) => Ok(MeshMessage::DhtSyncRequest {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                from_version: r.from_version,
            }),
            proto::mesh_message::Payload::DhtSyncResponse(r) => Ok(MeshMessage::DhtSyncResponse {
                request_id: r.request_id.into(),
                records: r.records.into_iter().map(|rec| rec.into()).collect(),
                version: r.version,
                timestamp: r.timestamp,
                signature: r.signature,
                signer_public_key: r.signer_public_key,
            }),
            proto::mesh_message::Payload::DhtSnapshotRequest(r) => {
                Ok(MeshMessage::DhtSnapshotRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    from_version: r.from_version,
                })
            }
            proto::mesh_message::Payload::DhtSnapshotResponse(r) => {
                Ok(MeshMessage::DhtSnapshotResponse {
                    request_id: r.request_id.into(),
                    records: r.records.into_iter().map(|rec| rec.into()).collect(),
                    version: r.version,
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtAntiEntropyRequest(r) => {
                Ok(MeshMessage::DhtAntiEntropyRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    local_root_hash: r.local_root_hash,
                    interested_keys: r.interested_keys,
                    timestamp: r.timestamp,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtAntiEntropyResponse(r) => {
                Ok(MeshMessage::DhtAntiEntropyResponse {
                    request_id: r.request_id.into(),
                    root_hash: r.root_hash,
                    proof_keys: r.proof_keys,
                    proof_hashes: r.proof_hashes,
                    missing_records: r
                        .missing_records
                        .into_iter()
                        .map(|rec| rec.into())
                        .collect(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                    signer_public_key: r.signer_public_key,
                })
            }
            proto::mesh_message::Payload::DhtRecordPush(r) => Ok(MeshMessage::DhtRecordPush {
                request_id: r.request_id.into(),
                records: r.records.into_iter().map(|rec| rec.into()).collect(),
                hop_count: r.hop_count,
                seen_node_ids: r.seen_node_ids,
                timestamp: r.timestamp,
                signer_public_key: r.signer_public_key,
            }),
            proto::mesh_message::Payload::DhtRecordPushAck(r) => {
                Ok(MeshMessage::DhtRecordPushAck {
                    request_id: r.request_id.into(),
                    original_request_id: r.original_request_id.into(),
                    node_id: r.node_id.into(),
                    accepted: r.accepted,
                    missing_keys: r.missing_keys,
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::OriginKeyQuery(r) => Ok(MeshMessage::OriginKeyQuery {
                request_id: r.request_id.into(),
                mesh_id: r.mesh_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::OriginKeyQueryResponse(r) => {
                Ok(MeshMessage::OriginKeyQueryResponse {
                    request_id: r.request_id.into(),
                    mesh_id: r.mesh_id.into(),
                    public_key: r.public_key.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::NodeShutdown(r) => Ok(MeshMessage::NodeShutdown {
                node_id: r.node_id.into(),
                role: MeshNodeRole::from_u8(r.role as u8),
                domains: r.domains.into_iter().map(|s| s.into()).collect(),
                graceful: r.graceful,
                shutdown_at: r.shutdown_at,
                timestamp: r.timestamp,
                signature: r.signature,
            }),
            proto::mesh_message::Payload::DnsDomainRegisterRequest(r) => {
                Ok(MeshMessage::DnsDomainRegisterRequest {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    challenge_token: r.challenge_token.into(),
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainRegisterResponse(r) => {
                Ok(MeshMessage::DnsDomainRegisterResponse {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    verified: r.verified,
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainDeregisterRequest(r) => {
                Ok(MeshMessage::DnsDomainDeregisterRequest {
                    request_id: r.request_id.into(),
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    reason: r.reason.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainRegistered(r) => {
                Ok(MeshMessage::DnsDomainRegistered {
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    verified_by_global_node: r.verified_by_global_node.into(),
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    registered_at: r.registered_at,
                    expires_at: r.expires_at,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::DnsDomainDeregistered(r) => {
                Ok(MeshMessage::DnsDomainDeregistered {
                    domain: r.domain.into(),
                    origin_node_id: r.origin_node_id.into(),
                    deregistered_by_global_node: r.deregistered_by_global_node.into(),
                    reason: r.reason.into(),
                    deregistered_at: r.deregistered_at,
                    signature: r.signature,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsRegistrationRequest(_) => Err(
                ProtocolError::InvalidValue("DNS registration not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsRegistrationRequest(r) => {
                use crate::dns::messages::{
                    DnsNodeRole, DnsRegistration, DnsRegistrationWithVerificationRequest,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsRegistrationRequest {
                    request_id: req_id.clone().into(),
                    registration: DnsRegistrationWithVerificationRequest {
                        request_id: req_id,
                        registration: DnsRegistration {
                            node_id: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.node_id.clone())
                                .unwrap_or_default(),
                            domain: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.domain.clone())
                                .unwrap_or_default(),
                            ip_addresses: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.ip_addresses.clone())
                                .unwrap_or_default(),
                            geo: r.registration.as_ref().and_then(|reg| reg.geo.clone()),
                            capacity: r.registration.as_ref().map(|reg| reg.capacity).unwrap_or(0),
                            healthy: r
                                .registration
                                .as_ref()
                                .map(|reg| reg.healthy)
                                .unwrap_or(false),
                            latency_ms: r.registration.as_ref().and_then(|reg| reg.latency_ms),
                            certificate_fingerprint: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.certificate_fingerprint.clone()),
                            role: DnsNodeRole::Origin,
                            edge_node_id: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.edge_node_id.clone()),
                            edge_node_geo: r
                                .registration
                                .as_ref()
                                .and_then(|reg| reg.edge_node_geo.clone()),
                            certificate_chain: Vec::new(),
                        },
                        verify_domain_ownership: r.verify_domain_ownership,
                        timestamp: r.timestamp,
                    },
                    timestamp: r.timestamp,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsRegistrationResponse(_) => Err(
                ProtocolError::InvalidValue("DNS registration not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsRegistrationResponse(r) => {
                use crate::dns::messages::{
                    DnsRegistrationWithVerificationResponse, DomainVerificationStatus,
                    DomainVerificationType,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsRegistrationResponse {
                    request_id: req_id.clone().into(),
                    response: DnsRegistrationWithVerificationResponse {
                        request_id: req_id,
                        domain: r.domain.clone(),
                        registration_accepted: r.registration_accepted,
                        verification_status: DomainVerificationStatus::Pending,
                        verification_type: r.verification_type.map(|v| match v {
                            1 => DomainVerificationType::NsRecord,
                            _ => DomainVerificationType::TxtChallenge,
                        }),
                        challenge_token: r.challenge_token.clone(),
                        nameservers_required: Some(r.nameservers_required),
                        error_message: r.error_message.clone(),
                        global_node_id: r.global_node_id.clone(),
                        timestamp: r.timestamp,
                    },
                    timestamp: r.timestamp,
                })
            }
            #[cfg(not(feature = "dns"))]
            proto::mesh_message::Payload::DnsVerificationUpdate(_) => Err(
                ProtocolError::InvalidValue("DNS verification not available"),
            ),
            #[cfg(feature = "dns")]
            proto::mesh_message::Payload::DnsVerificationUpdate(r) => {
                use crate::dns::messages::{
                    DomainVerificationStatus, DomainVerificationStatusUpdate,
                };
                let req_id = r.request_id.clone();
                Ok(MeshMessage::DnsVerificationUpdate {
                    request_id: req_id.clone().into(),
                    update: DomainVerificationStatusUpdate {
                        request_id: req_id,
                        domain: r.domain.clone(),
                        status: DomainVerificationStatus::Pending,
                        verified_at: r.verified_at,
                        error_message: r.error_message.clone(),
                    },
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::FindNode(r) => Ok(MeshMessage::FindNode {
                request_id: r.request_id.into(),
                target_node_id: r.target_node_id,
                requester_node_id: r.requester_node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::FindNodeResponse(r) => {
                use crate::mesh::dht::routing::{GeoInfo, NodeId, PeerContact};
                Ok(MeshMessage::FindNodeResponse {
                    request_id: r.request_id.into(),
                    peers: r
                        .peers
                        .into_iter()
                        .map(|p| {
                            let node_id =
                                NodeId::from_bytes(&p.node_id).unwrap_or_else(NodeId::random);
                            let mut contact = PeerContact::new(
                                node_id,
                                p.node_id_string,
                                p.address,
                                p.port as u16,
                            );
                            if p.latitude != 0.0 || p.longitude != 0.0 {
                                contact.geo = Some(GeoInfo {
                                    country: if p.country.is_empty() {
                                        None
                                    } else {
                                        Some(p.country)
                                    },
                                    region: if p.region.is_empty() {
                                        None
                                    } else {
                                        Some(p.region)
                                    },
                                    latitude: if p.latitude == 0.0 {
                                        None
                                    } else {
                                        Some(p.latitude)
                                    },
                                    longitude: if p.longitude == 0.0 {
                                        None
                                    } else {
                                        Some(p.longitude)
                                    },
                                });
                            }
                            if p.latency_ms > 0 {
                                contact.latency_ms = Some(p.latency_ms);
                            }
                            contact.is_global = p.is_global;
                            contact.is_trusted = p.is_trusted;
                            contact
                        })
                        .collect(),
                    responder_node_id: r.responder_node_id.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::Ping(r) => Ok(MeshMessage::Ping {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::Pong(r) => Ok(MeshMessage::Pong {
                request_id: r.request_id.into(),
                node_id: r.node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::UpstreamRegistrationRequest(r) => {
                Ok(MeshMessage::UpstreamRegistrationRequest {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    upstream_url: r.upstream_url.into(),
                    org_id: r.org_id.map(|s| s.into()),
                    requesting_node_id: r.requesting_node_id.into(),
                    timestamp: r.timestamp,
                    signature: r.signature,
                })
            }
            proto::mesh_message::Payload::UpstreamRegistrationResponse(r) => {
                Ok(MeshMessage::UpstreamRegistrationResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    approved: r.approved,
                    rejection_reason: r.rejection_reason.map(|s| s.into()),
                    global_node_id: r.global_node_id.into(),
                    global_node_signature: if r.global_node_signature.is_empty() {
                        None
                    } else {
                        Some(r.global_node_signature)
                    },
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::UpstreamVerificationQuery(r) => {
                Ok(MeshMessage::UpstreamVerificationQuery {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    querying_node_id: r.querying_node_id.into(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::UpstreamVerificationResponse(r) => {
                Ok(MeshMessage::UpstreamVerificationResponse {
                    request_id: r.request_id.into(),
                    upstream_id: r.upstream_id.into(),
                    verified: r.verified,
                    global_node_id: r.global_node_id.into(),
                    global_node_signature: if r.global_node_signature.is_empty() {
                        None
                    } else {
                        Some(r.global_node_signature)
                    },
                    upstream_url: r.upstream_url.into(),
                    org_id: r.org_id.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::KeyForward(k) => Ok(MeshMessage::KeyForward {
                session_id: k.session_id.into(),
                key_id: k.key_id.into(),
                mesh_id: k.mesh_id.into(),
                client_x25519_pubkey: k.client_x25519_pubkey.into(),
                global_node_id: k.global_node_id.into(),
                nonce: k.nonce.into(),
                timestamp: k.timestamp,
            }),
            proto::mesh_message::Payload::KeySigned(k) => Ok(MeshMessage::KeySigned {
                session_id: k.session_id.into(),
                key_id: k.key_id.into(),
                mesh_id: k.mesh_id.into(),
                origin_mesh_id: k.origin_mesh_id.into(),
                origin_ed25519_pubkey: k.origin_ed25519_pubkey.into(),
                server_x25519_pubkey: k.server_x25519_pubkey.into(),
                origin_signature: k.origin_signature,
                nonce: k.nonce.into(),
                timestamp: k.timestamp,
            }),
            proto::mesh_message::Payload::NetworkPolicyUpdate(n) => {
                let policy = n.policy.unwrap_or_default();
                let blocked_nodes: Vec<crate::mesh::dht::BlockedNode> = policy
                    .blocked_nodes
                    .into_iter()
                    .map(|b| crate::mesh::dht::BlockedNode {
                        node_id: b.node_id,
                        blocked_ip: b.blocked_ip,
                        blocked_hash: b.blocked_hash,
                        reason: b.reason,
                        blocked_at: b.blocked_at,
                        blocked_by: b.blocked_by,
                        expires_at: b.expires_at,
                    })
                    .collect();
                let network_policy = crate::mesh::dht::NetworkPolicy {
                    min_reputation_for_read: policy.min_reputation_for_read,
                    min_reputation_for_write: policy.min_reputation_for_write,
                    blocked_nodes,
                    last_updated: policy.last_updated,
                    updated_by: policy.updated_by,
                    valid_from: policy.valid_from,
                    signature: policy.signature,
                };
                Ok(MeshMessage::NetworkPolicyUpdate {
                    policy: network_policy,
                    timestamp: n.timestamp,
                    source_node_id: n.source_node_id.into(),
                    signature: n.signature,
                })
            }
            proto::mesh_message::Payload::GlobalNodeBlocklistUpdate(b) => {
                let blocklist = b.blocklist.unwrap_or_default();
                let blocked_nodes: Vec<crate::mesh::dht::BlockedNode> = blocklist
                    .blocked_nodes
                    .into_iter()
                    .map(|b| crate::mesh::dht::BlockedNode {
                        node_id: b.node_id,
                        blocked_ip: b.blocked_ip,
                        blocked_hash: b.blocked_hash,
                        reason: b.reason,
                        blocked_at: b.blocked_at,
                        blocked_by: b.blocked_by,
                        expires_at: b.expires_at,
                    })
                    .collect();
                let global_blocklist = crate::mesh::dht::GlobalNodeBlocklist {
                    blocked_nodes,
                    last_updated: blocklist.last_updated,
                    updated_by: blocklist.updated_by,
                    signature: blocklist.signature,
                };
                Ok(MeshMessage::GlobalNodeBlocklistUpdate {
                    blocklist: global_blocklist,
                    timestamp: b.timestamp,
                    source_node_id: b.source_node_id.into(),
                    signature: b.signature,
                })
            }
            proto::mesh_message::Payload::AiBotListUpdate(a) => {
                let bot_list = a.bot_list.unwrap_or_default();
                let entries: Vec<crate::mesh::dht::AiBotEntry> = bot_list
                    .entries
                    .into_iter()
                    .map(|e| crate::mesh::dht::AiBotEntry {
                        pattern: e.pattern,
                        action: match e.action {
                            0 => crate::mesh::dht::BotAction::Add,
                            1 => crate::mesh::dht::BotAction::Remove,
                            _ => crate::mesh::dht::BotAction::Update,
                        },
                        source: e.source,
                        timestamp: e.timestamp,
                        expires_at: e.expires_at,
                    })
                    .collect();
                let ai_bot_list = crate::mesh::dht::GlobalAiBotList {
                    entries,
                    last_updated: bot_list.last_updated,
                    updated_by: bot_list.updated_by,
                    signature: bot_list.signature,
                };
                Ok(MeshMessage::AiBotListUpdate {
                    bot_list: ai_bot_list,
                    timestamp: a.timestamp,
                    source_node_id: a.source_node_id.into(),
                    signature: a.signature,
                })
            }
            proto::mesh_message::Payload::AnycastNodeRegistration(r) => {
                Ok(MeshMessage::AnycastNodeRegistration {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    anycast_ips: r.anycast_ips,
                    geo: r.geo.map(|s| s.into()),
                    capacity: r.capacity,
                    healthy: r.healthy,
                    dns_zones: r.dns_zones,
                    certificate_fingerprint: r.certificate_fingerprint.map(|s| s.into()),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::AnycastHealthUpdate(r) => {
                Ok(MeshMessage::AnycastHealthUpdate {
                    node_id: r.node_id.into(),
                    anycast_ips: r.anycast_ips,
                    healthy: r.healthy,
                    latency_ms: r.latency_ms,
                    load_percent: r.load_percent.map(|v| v as u8),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::ZoneSyncRequest(r) => Ok(MeshMessage::ZoneSyncRequest {
                request_id: r.request_id.into(),
                zone_origin: r.zone_origin.into(),
                serial: r.serial,
                requesting_node_id: r.requesting_node_id.into(),
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::ZoneSyncResponse(r) => {
                Ok(MeshMessage::ZoneSyncResponse {
                    request_id: r.request_id.into(),
                    zone_origin: r.zone_origin.into(),
                    records_json: r.records_json.into(),
                    serial: r.serial,
                    complete: r.complete,
                    timestamp: r.timestamp,
                    origin_signature: r.origin_signature,
                    origin_pubkey: if r.origin_pubkey.is_empty() {
                        None
                    } else {
                        Some(r.origin_pubkey)
                    },
                    previous_serial: r.previous_serial,
                    compressed: r.compressed,
                })
            }
            proto::mesh_message::Payload::ZoneSyncAck(r) => Ok(MeshMessage::ZoneSyncAck {
                request_id: r.request_id.into(),
                zone_origin: r.zone_origin.into(),
                serial: r.serial,
                timestamp: r.timestamp,
            }),
            proto::mesh_message::Payload::SiteConfigSync(r) => Ok(MeshMessage::SiteConfigSync {
                request_id: r.request_id.into(),
                site_id: r.site_id.into(),
                config_version: r.config_version,
                config_json: r.config_json.into(),
                timestamp: r.timestamp,
                source_node_id: r.source_node_id.into(),
                signature: r.signature,
                signer_public_key: r.signer_public_key.map(|s| s.into()),
            }),
            proto::mesh_message::Payload::WasmModuleAnnounce(r) => {
                Ok(MeshMessage::WasmModuleAnnounce {
                    request_id: r.request_id.into(),
                    module_name: r.module_name.into(),
                    module_type: match r.module_type {
                        0 => crate::mesh::protocol::WasmModuleType::Plugin,
                        1 => crate::mesh::protocol::WasmModuleType::Serverless,
                        _ => return Err(ProtocolError::InvalidValue("WasmModuleType")),
                    },
                    version: r.version,
                    size_bytes: r.size_bytes,
                    checksum: r.checksum.into(),
                    timestamp: r.timestamp,
                    source_node_id: r.source_node_id.into(),
                    signature: r.signature,
                    signer_public_key: r.signer_public_key.map(|s| s.into()),
                })
            }
            proto::mesh_message::Payload::WasmModuleSyncRequest(r) => {
                Ok(MeshMessage::WasmModuleSyncRequest {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    module_names: r.module_names.into_iter().map(|s| s.into()).collect(),
                    timestamp: r.timestamp,
                })
            }
            proto::mesh_message::Payload::WasmModuleSyncResponse(r) => {
                Ok(MeshMessage::WasmModuleSyncResponse {
                    request_id: r.request_id.into(),
                    node_id: r.node_id.into(),
                    modules: r
                        .modules
                        .into_iter()
                        .map(|m| {
                            Ok(crate::mesh::protocol::WasmModuleInfo {
                                module_name: m.module_name.into(),
                                module_type: match m.module_type {
                                    0 => crate::mesh::protocol::WasmModuleType::Plugin,
                                    1 => crate::mesh::protocol::WasmModuleType::Serverless,
                                    _ => return Err(ProtocolError::InvalidValue("WasmModuleType")),
                                },
                                version: m.version,
                                size_bytes: m.size_bytes,
                                checksum: m.checksum.into(),
                                data: m.data,
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    timestamp: r.timestamp,
                })
            }
        }
    }
}
