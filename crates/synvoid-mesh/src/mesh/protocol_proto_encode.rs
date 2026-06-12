use super::*;

impl From<&MeshMessage> for proto::MeshMessage {
    fn from(msg: &MeshMessage) -> Self {
        match msg {
            MeshMessage::Hello {
                version,
                node_id,
                role,
                capabilities,
                upstreams,
                auth_token,
                network_id,
                global_node_key,
                timestamp,
                nonce,
                is_trusted,
                quic_port,
                wireguard_port,
                public_key,
                pow_nonce,
                pow_public_key,
                member_certificate,
                org_public_key,
            } => proto::MeshMessage {
                message_type: 1,
                payload: Some(proto::mesh_message::Payload::Hello(proto::Hello {
                    version: *version as u32,
                    node_id: node_id.to_string(),
                    roles: role.bits() as u32,
                    capabilities: Some(capabilities.into()),
                    upstreams: upstreams
                        .iter()
                        .map(|(k, v)| (k.clone(), v.into()))
                        .collect(),
                    auth_token: auth_token.as_ref().map(|s| s.to_string()),
                    network_id: network_id.as_ref().map(|s| s.to_string()),
                    global_node_key: global_node_key.as_ref().map(|s| s.to_string()),
                    timestamp: *timestamp,
                    nonce: nonce.as_ref().map(|s| s.to_string()),
                    is_trusted: Some(*is_trusted),
                    quic_port: *quic_port,
                    wireguard_port: *wireguard_port,
                    public_key: public_key.as_ref().map(|s| s.to_string()),
                    pow_nonce: *pow_nonce,
                    pow_public_key: pow_public_key.as_ref().map(|s| s.to_string()),
                    member_certificate: member_certificate.as_ref().map(|c| {
                        proto::MemberCertificate {
                            cert_id: c.cert_id.clone(),
                            mesh_id: c.mesh_id.clone(),
                            org_id: c.org_id.clone(),
                            valid_from: c.valid_from,
                            valid_until: c.valid_until,
                            org_public_key_id: c.org_public_key_id.clone(),
                            signature: c.signature.clone(),
                        }
                    }),
                    org_public_key: org_public_key.as_ref().map(|k| proto::OrgPublicKey {
                        org_id: k.org_id.clone(),
                        key_id: k.key_id.clone(),
                        public_key: k.public_key.clone(),
                        created_at: k.created_at,
                        issued_by: k.issued_by.clone(),
                        quorum_signatures: k
                            .quorum_signatures
                            .iter()
                            .map(|s| proto::QuorumSignature {
                                signer_node_id: s.signer_node_id.clone(),
                                signer_public_key: s.signer_public_key.clone(),
                                signature: s.signature.clone(),
                                timestamp: s.timestamp,
                            })
                            .collect(),
                    }),
                })),
            },
            MeshMessage::HelloAck {
                version,
                node_id,
                role,
                session_id,
                capabilities,
                upstreams,
                auth_token,
                network_id,
                global_node_key,
                timestamp,
                nonce,
                is_trusted,
                quic_port,
                wireguard_port,
                public_key,
                member_certificate,
                org_public_key,
            } => proto::MeshMessage {
                message_type: 2,
                payload: Some(proto::mesh_message::Payload::HelloAck(proto::HelloAck {
                    version: *version as u32,
                    node_id: node_id.to_string(),
                    roles: role.bits() as u32,
                    session_id: session_id.to_string(),
                    capabilities: Some(capabilities.into()),
                    upstreams: upstreams
                        .iter()
                        .map(|(k, v)| (k.clone(), v.into()))
                        .collect(),
                    auth_token: auth_token.as_ref().map(|s| s.to_string()),
                    network_id: network_id.as_ref().map(|s| s.to_string()),
                    global_node_key: global_node_key.as_ref().map(|s| s.to_string()),
                    timestamp: *timestamp,
                    nonce: nonce.as_ref().map(|s| s.to_string()),
                    is_trusted: Some(*is_trusted),
                    quic_port: *quic_port,
                    wireguard_port: *wireguard_port,
                    public_key: public_key.as_ref().map(|s| s.to_string()),
                    member_certificate: member_certificate.as_ref().map(|c| {
                        proto::MemberCertificate {
                            cert_id: c.cert_id.clone(),
                            mesh_id: c.mesh_id.clone(),
                            org_id: c.org_id.clone(),
                            valid_from: c.valid_from,
                            valid_until: c.valid_until,
                            org_public_key_id: c.org_public_key_id.clone(),
                            signature: c.signature.clone(),
                        }
                    }),
                    org_public_key: org_public_key.as_ref().map(|k| proto::OrgPublicKey {
                        org_id: k.org_id.clone(),
                        key_id: k.key_id.clone(),
                        public_key: k.public_key.clone(),
                        created_at: k.created_at,
                        issued_by: k.issued_by.clone(),
                        quorum_signatures: k
                            .quorum_signatures
                            .iter()
                            .map(|s| proto::QuorumSignature {
                                signer_node_id: s.signer_node_id.clone(),
                                signer_public_key: s.signer_public_key.clone(),
                                signature: s.signature.clone(),
                                timestamp: s.timestamp,
                            })
                            .collect(),
                    }),
                })),
            },
            MeshMessage::SyncRequest { node_id } => proto::MeshMessage {
                message_type: 3,
                payload: Some(proto::mesh_message::Payload::SyncRequest(
                    proto::SyncRequest {
                        node_id: node_id.to_string(),
                    },
                )),
            },
            MeshMessage::SyncResponse {
                nodes,
                upstreams,
                timestamp,
            } => proto::MeshMessage {
                message_type: 4,
                payload: Some(proto::mesh_message::Payload::SyncResponse(
                    proto::SyncResponse {
                        nodes: nodes.iter().map(|n| n.into()).collect(),
                        upstreams: upstreams
                            .iter()
                            .map(|(k, v)| (k.clone(), v.into()))
                            .collect(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::RouteQuery {
                query_id,
                max_hops,
                upstream_id,
                initiator,
                sequence,
                timestamp,
                nonce,
            } => proto::MeshMessage {
                message_type: 5,
                payload: Some(proto::mesh_message::Payload::RouteQuery(
                    proto::RouteQuery {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        max_hops: *max_hops as u32,
                        initiator: initiator.to_string(),
                        sequence: *sequence,
                        timestamp: *timestamp,
                        nonce: nonce.to_string(),
                    },
                )),
            },
            MeshMessage::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                signature,
                sequence,
                timestamp,
                nonce,
                upstream_url,
                waf_policy,
                priority_tier,
                tier_claim,
                org_id,
                mesh_name,
            } => proto::MeshMessage {
                message_type: 6,
                payload: Some(proto::mesh_message::Payload::RouteResponse(
                    proto::RouteResponse {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        provider_node_id: provider_node_id.to_string(),
                        hops: *hops as u32,
                        ttl_secs: *ttl_secs,
                        signature: signature.clone(),
                        sequence: *sequence,
                        timestamp: *timestamp,
                        nonce: nonce.to_string(),
                        upstream_url: upstream_url.as_ref().map(|s| s.to_string()),
                        waf_policy: waf_policy.as_ref().map(|p| p.into()),
                        priority_tier: *priority_tier,
                        tier_claim: tier_claim.as_ref().map(|tc| proto::TierClaim {
                            tier: tc.tier,
                            key_id: tc.key_id.to_string(),
                            org_id: tc.org_id.to_string(),
                            mesh_id: tc.mesh_id.to_string(),
                            timestamp: tc.timestamp,
                            nonce: tc.nonce.to_string(),
                            signature: tc.signature.clone(),
                        }),
                        org_id: org_id.as_ref().map(|s| s.to_string()),
                        mesh_name: mesh_name.as_ref().map(|s| s.to_string()),
                    },
                )),
            },
            MeshMessage::RouteResponseAck {
                query_id,
                upstream_id,
                provider_node_id,
            } => proto::MeshMessage {
                message_type: 40,
                payload: Some(proto::mesh_message::Payload::RouteResponseAck(
                    proto::RouteResponseAck {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        provider_node_id: provider_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::RouteNotFound {
                query_id,
                upstream_id,
            } => proto::MeshMessage {
                message_type: 7,
                payload: Some(proto::mesh_message::Payload::RouteNotFound(
                    proto::RouteNotFound {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                    },
                )),
            },
            MeshMessage::RouteRejected {
                query_id,
                upstream_id,
                reason,
                alternatives,
            } => proto::MeshMessage {
                message_type: 50,
                payload: Some(proto::mesh_message::Payload::RouteRejected(
                    proto::RouteRejected {
                        query_id: query_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        reason: reason.to_string(),
                        alternatives: alternatives
                            .iter()
                            .map(|a| proto::AlternativeProvider {
                                node_id: a.node_id.to_string(),
                                priority_tier: a.priority_tier,
                            })
                            .collect(),
                    },
                )),
            },
            MeshMessage::TierKeyAnnounce {
                org_id,
                key,
                signature,
            } => proto::MeshMessage {
                message_type: 51,
                payload: Some(proto::mesh_message::Payload::TierKeyAnnounce(
                    proto::TierKeyAnnounce {
                        org_id: org_id.to_string(),
                        key: Some(proto::TierKey {
                            key_id: key.key_id.to_string(),
                            tier: key.tier,
                            key: key.key.clone(),
                            valid_from: key.valid_from,
                            valid_until: key.valid_until,
                            issued_by: key.issued_by.to_string(),
                            revoked: key.revoked,
                        }),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::TierKeyRevoke {
                org_id,
                key_id,
                signature,
            } => proto::MeshMessage {
                message_type: 52,
                payload: Some(proto::mesh_message::Payload::TierKeyRevoke(
                    proto::TierKeyRevoke {
                        org_id: org_id.to_string(),
                        key_id: key_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::TierKeyQuery {
                request_id,
                org_id,
                requested_tier,
            } => proto::MeshMessage {
                message_type: 53,
                payload: Some(proto::mesh_message::Payload::TierKeyQuery(
                    proto::TierKeyQuery {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        requested_tier: requested_tier.unwrap_or(0),
                    },
                )),
            },
            MeshMessage::TierKeyQueryResponse {
                request_id,
                keys,
                signature,
            } => proto::MeshMessage {
                message_type: 54,
                payload: Some(proto::mesh_message::Payload::TierKeyQueryResponse(
                    proto::TierKeyQueryResponse {
                        request_id: request_id.to_string(),
                        keys: keys
                            .iter()
                            .map(|k| proto::TierKey {
                                key_id: k.key_id.to_string(),
                                tier: k.tier,
                                key: k.key.clone(),
                                valid_from: k.valid_from,
                                valid_until: k.valid_until,
                                issued_by: k.issued_by.to_string(),
                                revoked: k.revoked,
                            })
                            .collect(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UnspentTierKeyAnnounce {
                org_id,
                tier_keys,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 66,
                payload: Some(proto::mesh_message::Payload::UnspentTierKeyAnnounce(
                    proto::UnspentTierKeyAnnounce {
                        org_id: org_id.to_string(),
                        tier_keys: tier_keys
                            .iter()
                            .map(|k| proto::TierKey {
                                key_id: k.key_id.to_string(),
                                tier: k.tier,
                                key: k.key.clone(),
                                valid_from: k.valid_from,
                                valid_until: k.valid_until,
                                issued_by: k.issued_by.to_string(),
                                revoked: k.revoked,
                            })
                            .collect(),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OrgRegistrationRequest {
                request_id,
                org_name,
                requesting_node_id,
                requesting_node_pubkey,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 60,
                payload: Some(proto::mesh_message::Payload::OrgRegistrationRequest(
                    proto::OrgRegistrationRequest {
                        request_id: request_id.to_string(),
                        org_name: org_name.to_string(),
                        requesting_node_id: requesting_node_id.to_string(),
                        requesting_node_pubkey: requesting_node_pubkey.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgRegistrationResponse {
                request_id,
                org_id,
                org_name,
                approved,
                reason,
                initial_tier_key,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 61,
                payload: Some(proto::mesh_message::Payload::OrgRegistrationResponse(
                    proto::OrgRegistrationResponse {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        org_name: org_name.to_string(),
                        approved: *approved,
                        reason: reason.to_string(),
                        initial_tier_key: initial_tier_key.as_ref().map(|k| proto::TierKey {
                            key_id: k.key_id.to_string(),
                            tier: k.tier,
                            key: k.key.clone(),
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.to_string(),
                            revoked: k.revoked,
                        }),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OrgInvitationRequest {
                request_id,
                org_id,
                inviter_node_id,
                invited_node_id,
                invited_node_pubkey,
                invitation_token,
                expires_at,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 62,
                payload: Some(proto::mesh_message::Payload::OrgInvitationRequest(
                    proto::OrgInvitationRequest {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        inviter_node_id: inviter_node_id.to_string(),
                        invited_node_id: invited_node_id.to_string(),
                        invited_node_pubkey: invited_node_pubkey
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        invitation_token: invitation_token.to_string(),
                        expires_at: *expires_at,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgInvitationAccept {
                request_id,
                org_id,
                invited_node_id,
                invitation_token,
                proof_of_key,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 63,
                payload: Some(proto::mesh_message::Payload::OrgInvitationAccept(
                    proto::OrgInvitationAccept {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        invited_node_id: invited_node_id.to_string(),
                        invitation_token: invitation_token.to_string(),
                        proof_of_key: proof_of_key.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgInvitationResponse {
                request_id,
                org_id,
                accepted,
                org_key,
                reason,
                signature,
                timestamp,
            } => proto::MeshMessage {
                message_type: 64,
                payload: Some(proto::mesh_message::Payload::OrgInvitationResponse(
                    proto::OrgInvitationResponse {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        accepted: *accepted,
                        org_key: org_key.as_ref().map(|k| proto::TierKey {
                            key_id: k.key_id.to_string(),
                            tier: k.tier,
                            key: k.key.clone(),
                            valid_from: k.valid_from,
                            valid_until: k.valid_until,
                            issued_by: k.issued_by.to_string(),
                            revoked: k.revoked,
                        }),
                        reason: reason.to_string(),
                        signature: signature.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::GlobalNodeAnnounce {
                node_id,
                public_key,
                action,
                timestamp,
                signature,
                key_exchange_endpoint,
                cert_chain,
            } => proto::MeshMessage {
                message_type: 66,
                payload: Some(proto::mesh_message::Payload::GlobalNodeAnnounce(
                    proto::GlobalNodeAnnounce {
                        node_id: node_id.to_string(),
                        public_key: public_key.to_string(),
                        action: *action as u32,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        key_exchange_endpoint: key_exchange_endpoint
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        cert_chain: cert_chain
                            .as_ref()
                            .and_then(|cc| serde_json::to_vec(cc).ok())
                            .unwrap_or_default(),
                    },
                )),
            },
            MeshMessage::OrgMemberAnnounce {
                org_id,
                member_node_id,
                announced_by,
                joined_at,
                signature,
            } => proto::MeshMessage {
                message_type: 65,
                payload: Some(proto::mesh_message::Payload::OrgMemberAnnounce(
                    proto::OrgMemberAnnounce {
                        org_id: org_id.to_string(),
                        member_node_id: member_node_id.to_string(),
                        announced_by: announced_by.to_string(),
                        joined_at: *joined_at,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlRequest {
                request_id,
                upstream_id,
                url_hash,
            } => proto::MeshMessage {
                message_type: 8,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlRequest(
                    proto::UpstreamUrlRequest {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        url_hash: url_hash.to_string(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlResponse {
                request_id,
                upstream_id,
                upstream_url,
                signature,
            } => proto::MeshMessage {
                message_type: 9,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlResponse(
                    proto::UpstreamUrlResponse {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        upstream_url: upstream_url.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUrlDenied {
                request_id,
                upstream_id,
            } => proto::MeshMessage {
                message_type: 10,
                payload: Some(proto::mesh_message::Payload::UpstreamUrlDenied(
                    proto::UpstreamUrlDenied {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                    },
                )),
            },
            MeshMessage::UpstreamAnnounce {
                upstream_id,
                action,
                signature,
                origin_ed25519_pubkey,
                origin_signature,
            } => proto::MeshMessage {
                message_type: 11,
                payload: Some(proto::mesh_message::Payload::UpstreamAnnounce(
                    proto::UpstreamAnnounce {
                        upstream_id: upstream_id.to_string(),
                        action: *action as u32,
                        signature: signature.clone(),
                        origin_ed25519_pubkey: origin_ed25519_pubkey.to_string(),
                        origin_signature: origin_signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamUpdate {
                upstream_id,
                info,
                signature,
            } => proto::MeshMessage {
                message_type: 12,
                payload: Some(proto::mesh_message::Payload::UpstreamUpdate(
                    proto::UpstreamUpdate {
                        upstream_id: upstream_id.to_string(),
                        info: Some(info.into()),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::KeepAlive => proto::MeshMessage {
                message_type: 13,
                payload: Some(proto::mesh_message::Payload::KeepAlive(proto::KeepAlive {})),
            },
            MeshMessage::KeepAliveAck => proto::MeshMessage {
                message_type: 14,
                payload: Some(proto::mesh_message::Payload::KeepAliveAck(
                    proto::KeepAliveAck {},
                )),
            },
            MeshMessage::LookupRequest {
                request_id,
                key,
                lookup_type,
            } => proto::MeshMessage {
                message_type: 25,
                payload: Some(proto::mesh_message::Payload::LookupRequest(
                    proto::LookupRequest {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        lookup_type: *lookup_type as u32,
                    },
                )),
            },
            MeshMessage::LookupResponse {
                request_id,
                key,
                value,
                found,
            } => proto::MeshMessage {
                message_type: 26,
                payload: Some(proto::mesh_message::Payload::LookupResponse(
                    proto::LookupResponse {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        value: value.clone(),
                        found: *found,
                    },
                )),
            },
            MeshMessage::LookupBatchRequest { request_id, keys } => proto::MeshMessage {
                message_type: 27,
                payload: Some(proto::mesh_message::Payload::LookupBatchRequest(
                    proto::LookupBatchRequest {
                        request_id: request_id.to_string(),
                        keys: keys.iter().map(|s| s.to_string()).collect(),
                    },
                )),
            },
            MeshMessage::LookupBatchResponse {
                request_id,
                results,
            } => proto::MeshMessage {
                message_type: 28,
                payload: Some(proto::mesh_message::Payload::LookupBatchResponse(
                    proto::LookupBatchResponse {
                        request_id: request_id.to_string(),
                        results: results
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone().unwrap_or_default()))
                            .collect(),
                    },
                )),
            },
            MeshMessage::PeerHealthCheck { peer_id, timestamp } => proto::MeshMessage {
                message_type: 29,
                payload: Some(proto::mesh_message::Payload::PeerHealthCheck(
                    proto::PeerHealthCheck {
                        peer_id: peer_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::PeerHealthResponse {
                peer_id,
                status,
                latency_ms,
                timestamp,
            } => proto::MeshMessage {
                message_type: 30,
                payload: Some(proto::mesh_message::Payload::PeerHealthResponse(
                    proto::PeerHealthResponse {
                        peer_id: peer_id.to_string(),
                        status: *status as u32,
                        latency_ms: *latency_ms,
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::PeerAnnounce {
                node_id,
                address,
                role,
                capabilities,
                announced_at,
            } => proto::MeshMessage {
                message_type: 31,
                payload: Some(proto::mesh_message::Payload::PeerAnnounce(
                    proto::PeerAnnounce {
                        node_id: node_id.to_string(),
                        address: address.to_string(),
                        role: role.bits() as u32,
                        capabilities: Some(capabilities.into()),
                        announced_at: *announced_at,
                    },
                )),
            },
            MeshMessage::PeerGone { node_id, reason } => proto::MeshMessage {
                message_type: 32,
                payload: Some(proto::mesh_message::Payload::PeerGone(proto::PeerGone {
                    node_id: node_id.to_string(),
                    reason: reason.to_string(),
                })),
            },
            MeshMessage::TopologySyncRequest {
                request_id,
                from_version,
                prefer_delta,
            } => proto::MeshMessage {
                message_type: 33,
                payload: Some(proto::mesh_message::Payload::TopologySyncRequest(
                    proto::TopologySyncRequest {
                        request_id: request_id.to_string(),
                        from_version: *from_version,
                        prefer_delta: *prefer_delta,
                    },
                )),
            },
            MeshMessage::TopologySyncResponse {
                request_id,
                peers,
                upstreams,
                version,
                is_delta,
                removed_peers,
                removed_upstreams,
            } => proto::MeshMessage {
                message_type: 34,
                payload: Some(proto::mesh_message::Payload::TopologySyncResponse(
                    proto::TopologySyncResponse {
                        request_id: request_id.to_string(),
                        peers: peers.iter().map(|p| p.into()).collect(),
                        upstreams: upstreams
                            .iter()
                            .map(|(k, v)| (k.clone(), v.into()))
                            .collect(),
                        version: *version,
                        is_delta: *is_delta,
                        removed_peers: removed_peers.iter().map(|s| s.to_string()).collect(),
                        removed_upstreams: removed_upstreams
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    },
                )),
            },
            MeshMessage::SeedListRequest {
                node_id,
                request_full_mesh,
            } => proto::MeshMessage {
                message_type: 35,
                payload: Some(proto::mesh_message::Payload::SeedListRequest(
                    proto::SeedListRequest {
                        node_id: node_id.to_string(),
                        request_full_mesh: *request_full_mesh,
                    },
                )),
            },
            MeshMessage::SeedListResponse {
                global_nodes,
                edge_nodes,
                version,
                genesis_org_id,
            } => proto::MeshMessage {
                message_type: 36,
                payload: Some(proto::mesh_message::Payload::SeedListResponse(
                    proto::SeedListResponse {
                        global_nodes: global_nodes.iter().map(|p| p.into()).collect(),
                        edge_nodes: edge_nodes.iter().map(|p| p.into()).collect(),
                        version: *version,
                        genesis_org_id: genesis_org_id
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                    },
                )),
            },
            MeshMessage::PeerLoadReport {
                node_id,
                active_connections,
                cpu_load_percent,
                memory_percent,
                requests_per_second,
            } => proto::MeshMessage {
                message_type: 37,
                payload: Some(proto::mesh_message::Payload::PeerLoadReport(
                    proto::PeerLoadReport {
                        node_id: node_id.to_string(),
                        active_connections: *active_connections,
                        cpu_load_percent: *cpu_load_percent,
                        memory_percent: *memory_percent,
                        requests_per_second: *requests_per_second,
                    },
                )),
            },
            MeshMessage::PeerLoadUpdate {
                node_id,
                load_score,
            } => proto::MeshMessage {
                message_type: 38,
                payload: Some(proto::mesh_message::Payload::PeerLoadUpdate(
                    proto::PeerLoadUpdate {
                        node_id: node_id.to_string(),
                        load_score: *load_score,
                    },
                )),
            },
            MeshMessage::RouteUsageReport {
                upstream_id,
                request_count,
                bytes_transferred,
            } => proto::MeshMessage {
                message_type: 39,
                payload: Some(proto::mesh_message::Payload::RouteUsageReport(
                    proto::RouteUsageReport {
                        upstream_id: upstream_id.to_string(),
                        request_count: *request_count,
                        bytes_transferred: *bytes_transferred,
                    },
                )),
            },
            MeshMessage::UpstreamBlocked {
                mesh_identifier,
                service_id,
                blocked_until,
                reason,
                origin_node_id,
            } => proto::MeshMessage {
                message_type: 70,
                payload: Some(proto::mesh_message::Payload::UpstreamBlocked(
                    proto::UpstreamBlocked {
                        mesh_identifier: mesh_identifier.to_string(),
                        service_id: service_id.to_string(),
                        blocked_until: *blocked_until,
                        reason: reason.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::PeerBlocked {
                node_id,
                blocked_until,
                reason,
                blocked_by,
                evidence_receipt,
            } => proto::MeshMessage {
                message_type: 72,
                payload: Some(proto::mesh_message::Payload::PeerBlocked(
                    proto::PeerBlocked {
                        node_id: node_id.to_string(),
                        blocked_until: *blocked_until,
                        reason: reason.to_string(),
                        blocked_by: blocked_by.to_string(),
                        evidence_receipt: evidence_receipt.as_ref().map(|er| proto::AuditReceipt {
                            reporter_node_id: er.reporter_node_id.clone(),
                            target_node_id: er.target_node_id.clone(),
                            evidence_hash: er.evidence_hash.clone(),
                            evidence_type: er.evidence_type.clone(),
                            reporter_signature: er.reporter_signature.clone(),
                            timestamp: er.timestamp,
                        }),
                    },
                )),
            },
            MeshMessage::BandwidthReport {
                upstream_id,
                bytes_sent,
                bytes_received,
                request_count,
                interval_secs,
                timestamp,
            } => proto::MeshMessage {
                message_type: 71,
                payload: Some(proto::mesh_message::Payload::BandwidthReport(
                    proto::BandwidthReport {
                        upstream_id: upstream_id.to_string(),
                        bytes_sent: *bytes_sent,
                        bytes_received: *bytes_received,
                        request_count: *request_count,
                        interval_secs: *interval_secs,
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::MeshAck {
                original_message_id,
                status,
                timestamp,
            } => proto::MeshMessage {
                message_type: 41,
                payload: Some(proto::mesh_message::Payload::MeshAck(proto::MeshAck {
                    original_message_id: original_message_id.to_string(),
                    status: *status as u32,
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::AuthChallenge {
                challenge,
                challenge_id,
                expires_at,
            } => proto::MeshMessage {
                message_type: 42,
                payload: Some(proto::mesh_message::Payload::AuthChallenge(
                    proto::AuthChallenge {
                        challenge: challenge.to_string(),
                        challenge_id: challenge_id.to_string(),
                        expires_at: *expires_at,
                    },
                )),
            },
            MeshMessage::AuthResponse {
                challenge_id,
                response,
            } => proto::MeshMessage {
                message_type: 43,
                payload: Some(proto::mesh_message::Payload::AuthResponse(
                    proto::AuthResponse {
                        challenge_id: challenge_id.to_string(),
                        response: response.to_string(),
                    },
                )),
            },
            MeshMessage::Error { code, message } => proto::MeshMessage {
                message_type: 15,
                payload: Some(proto::mesh_message::Payload::Error(proto::Error {
                    code: *code as u32,
                    message: message.to_string(),
                })),
            },
            MeshMessage::ThreatAnnounce {
                request_id,
                indicators,
                highest_severity,
                timestamp,
                source_node_id,
                source_role,
                source_reputation,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 50,
                payload: Some(proto::mesh_message::Payload::ThreatAnnounce(
                    proto::ThreatAnnounce {
                        request_id: request_id.to_string(),
                        indicators: indicators.iter().map(|i| i.into()).collect(),
                        highest_severity: (*highest_severity) as i32,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        source_role: source_role.bits() as u32,
                        source_reputation: *source_reputation,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::ThreatSyncRequest {
                request_id,
                node_id,
                from_version,
                prefer_delta,
            } => proto::MeshMessage {
                message_type: 51,
                payload: Some(proto::mesh_message::Payload::ThreatSyncRequest(
                    proto::ThreatSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                        prefer_delta: *prefer_delta,
                    },
                )),
            },
            MeshMessage::ThreatSyncResponse {
                request_id,
                indicators,
                version,
                is_delta,
                removed_indicators,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 52,
                payload: Some(proto::mesh_message::Payload::ThreatSyncResponse(
                    proto::ThreatSyncResponse {
                        request_id: request_id.to_string(),
                        indicators: indicators.iter().map(|i| i.into()).collect(),
                        version: *version,
                        is_delta: *is_delta,
                        removed_indicators: removed_indicators
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::ThreatAcknowledgement {
                original_request_id,
                node_id,
                accepted,
                reason,
                timestamp,
            } => proto::MeshMessage {
                message_type: 53,
                payload: Some(proto::mesh_message::Payload::ThreatAck(
                    proto::ThreatAcknowledgement {
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ReputationUpdate {
                node_id,
                reputation_score,
                threats_accepted,
                threats_rejected,
                false_positive_reports,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 54,
                payload: Some(proto::mesh_message::Payload::ReputationUpdate(
                    proto::ReputationUpdate {
                        node_id: node_id.to_string(),
                        reputation_score: *reputation_score,
                        threats_accepted: *threats_accepted,
                        threats_rejected: *threats_rejected,
                        false_positive_reports: *false_positive_reports,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::BehavioralFingerprintAnnounce {
                request_id,
                fingerprints,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 162,
                payload: Some(proto::mesh_message::Payload::BehavioralFingerprintAnnounce(
                    proto::BehavioralFingerprintAnnounce {
                        request_id: request_id.to_string(),
                        fingerprints: fingerprints.iter().map(|fp| fp.into()).collect(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::BehavioralFingerprintSyncRequest {
                request_id,
                node_id,
                from_version,
                prefer_delta,
            } => proto::MeshMessage {
                message_type: 163,
                payload: Some(
                    proto::mesh_message::Payload::BehavioralFingerprintSyncRequest(
                        proto::BehavioralFingerprintSyncRequest {
                            request_id: request_id.to_string(),
                            node_id: node_id.to_string(),
                            from_version: *from_version,
                            prefer_delta: *prefer_delta,
                        },
                    ),
                ),
            },
            MeshMessage::BehavioralFingerprintSyncResponse {
                request_id,
                fingerprints,
                version,
                is_delta,
                removed_fingerprint_ids,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 164,
                payload: Some(
                    proto::mesh_message::Payload::BehavioralFingerprintSyncResponse(
                        proto::BehavioralFingerprintSyncResponse {
                            request_id: request_id.to_string(),
                            fingerprints: fingerprints.iter().map(|fp| fp.into()).collect(),
                            version: *version,
                            is_delta: *is_delta,
                            removed_fingerprint_ids: removed_fingerprint_ids
                                .iter()
                                .map(|id| id.to_string())
                                .collect(),
                            signature: signature.clone(),
                            signer_public_key: signer_public_key.clone(),
                        },
                    ),
                ),
            },
            MeshMessage::YaraRuleAnnounce {
                request_id,
                version,
                rules,
                timestamp,
                source_node_id,
                source_role,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 86,
                payload: Some(proto::mesh_message::Payload::YaraRuleAnnounce(
                    proto::YaraRuleAnnounce {
                        request_id: request_id.to_string(),
                        version: version.clone(),
                        rules: rules.clone(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        source_role: source_role.bits() as u32,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraCompiledRuleAnnounce {
                request_id,
                version,
                compiled_rules,
                checksum,
                timestamp,
                source_node_id,
                source_role,
                signature,
                signer_public_key,
                source_rules,
            } => proto::MeshMessage {
                message_type: 170,
                payload: Some(proto::mesh_message::Payload::YaraCompiledRuleAnnounce(
                    proto::YaraCompiledRuleAnnounce {
                        request_id: request_id.to_string(),
                        version: version.clone(),
                        compiled_rules: compiled_rules.clone(),
                        checksum: checksum.clone(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        source_role: source_role.bits() as u32,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                        source_rules: source_rules.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSyncRequest {
                request_id,
                node_id,
                version,
            } => proto::MeshMessage {
                message_type: 87,
                payload: Some(proto::mesh_message::Payload::YaraRuleSyncRequest(
                    proto::YaraRuleSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        version: version.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSyncResponse {
                request_id,
                version,
                rules,
                is_full,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 88,
                payload: Some(proto::mesh_message::Payload::YaraRuleSyncResponse(
                    proto::YaraRuleSyncResponse {
                        request_id: request_id.to_string(),
                        version: version.clone(),
                        rules: rules.clone(),
                        is_full: *is_full,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleAcknowledgement {
                original_request_id,
                node_id,
                accepted,
                reason,
                timestamp,
            } => proto::MeshMessage {
                message_type: 89,
                payload: Some(proto::mesh_message::Payload::YaraRuleAck(
                    proto::YaraRuleAcknowledgement {
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::YaraRuleSubmission {
                request_id,
                submission_id,
                node_id,
                timestamp,
                signature,
                rules,
                description,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 90,
                payload: Some(proto::mesh_message::Payload::YaraRuleSubmission(
                    proto::YaraRuleSubmission {
                        request_id: request_id.to_string(),
                        submission_id: submission_id.to_string(),
                        node_id: node_id.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        rules: rules.clone(),
                        description: description.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::YaraRuleSubmissionResponse {
                original_request_id,
                submission_id,
                node_id,
                status,
                timestamp,
            } => proto::MeshMessage {
                message_type: 91,
                payload: Some(proto::mesh_message::Payload::YaraRuleSubmissionResponse(
                    proto::YaraRuleSubmissionResponse {
                        original_request_id: original_request_id.to_string(),
                        submission_id: submission_id.to_string(),
                        node_id: node_id.to_string(),
                        status: status.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::DhtRecordAnnounce {
                request_id,
                records,
                write_quorum,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 75,
                payload: Some(proto::mesh_message::Payload::DhtRecordAnnounce(
                    proto::DhtRecordAnnounce {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        write_quorum: *write_quorum,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordQuery {
                request_id,
                key,
                timestamp,
                source_node_id,
            } => proto::MeshMessage {
                message_type: 76,
                payload: Some(proto::mesh_message::Payload::DhtRecordQuery(
                    proto::DhtRecordQuery {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::DhtRecordResponse {
                request_id,
                key,
                value,
                found,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 77,
                payload: Some(proto::mesh_message::Payload::DhtRecordResponse(
                    proto::DhtRecordResponse {
                        request_id: request_id.to_string(),
                        key: key.to_string(),
                        value: value.clone(),
                        found: *found,
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSyncRequest {
                request_id,
                node_id,
                from_version,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 78,
                payload: Some(proto::mesh_message::Payload::DhtSyncRequest(
                    proto::DhtSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                        timestamp: *timestamp,
                        nonce: nonce.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSyncResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 79,
                payload: Some(proto::mesh_message::Payload::DhtSyncResponse(
                    proto::DhtSyncResponse {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        version: *version,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSnapshotRequest {
                request_id,
                node_id,
                from_version,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 80,
                payload: Some(proto::mesh_message::Payload::DhtSnapshotRequest(
                    proto::DhtSnapshotRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        from_version: *from_version,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtSnapshotResponse {
                request_id,
                records,
                version,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 81,
                payload: Some(proto::mesh_message::Payload::DhtSnapshotResponse(
                    proto::DhtSnapshotResponse {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        version: *version,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtAntiEntropyRequest {
                request_id,
                node_id,
                local_root_hash,
                interested_keys,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 92,
                payload: Some(proto::mesh_message::Payload::DhtAntiEntropyRequest(
                    proto::DhtAntiEntropyRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        local_root_hash: local_root_hash.clone(),
                        interested_keys: interested_keys.clone(),
                        timestamp: *timestamp,
                        signer_public_key: signer_public_key.clone(),
                        nonce: nonce.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DhtAntiEntropyResponse {
                request_id,
                root_hash,
                proof_keys,
                proof_hashes,
                missing_records,
                timestamp,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 93,
                payload: Some(proto::mesh_message::Payload::DhtAntiEntropyResponse(
                    proto::DhtAntiEntropyResponse {
                        request_id: request_id.to_string(),
                        root_hash: root_hash.clone(),
                        proof_keys: proof_keys.clone(),
                        proof_hashes: proof_hashes.clone(),
                        missing_records: missing_records.iter().map(|r| r.clone().into()).collect(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordPush {
                request_id,
                records,
                hop_count,
                seen_node_ids,
                timestamp,
                nonce,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 94,
                payload: Some(proto::mesh_message::Payload::DhtRecordPush(
                    proto::DhtRecordPush {
                        request_id: request_id.to_string(),
                        records: records.iter().map(|r| r.clone().into()).collect(),
                        hop_count: *hop_count,
                        seen_node_ids: seen_node_ids.clone(),
                        timestamp: *timestamp,
                        signer_public_key: signer_public_key.clone(),
                        nonce: nonce.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::DhtRecordPushAck {
                request_id,
                original_request_id,
                node_id,
                accepted,
                missing_keys,
                timestamp,
            } => proto::MeshMessage {
                message_type: 95,
                payload: Some(proto::mesh_message::Payload::DhtRecordPushAck(
                    proto::DhtRecordPushAck {
                        request_id: request_id.to_string(),
                        original_request_id: original_request_id.to_string(),
                        node_id: node_id.to_string(),
                        accepted: *accepted,
                        missing_keys: missing_keys.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OriginKeyQuery {
                request_id,
                mesh_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 108,
                payload: Some(proto::mesh_message::Payload::OriginKeyQuery(
                    proto::OriginKeyQuery {
                        request_id: request_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::OriginKeyQueryResponse {
                request_id,
                mesh_id,
                public_key,
                timestamp,
            } => proto::MeshMessage {
                message_type: 109,
                payload: Some(proto::mesh_message::Payload::OriginKeyQueryResponse(
                    proto::OriginKeyQueryResponse {
                        request_id: request_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        public_key: public_key.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::NodeShutdown {
                node_id,
                role,
                domains,
                graceful,
                shutdown_at,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 110,
                payload: Some(proto::mesh_message::Payload::NodeShutdown(
                    proto::NodeShutdown {
                        node_id: node_id.to_string(),
                        role: role.bits() as u32,
                        domains: domains.iter().map(|d| d.to_string()).collect(),
                        graceful: *graceful,
                        shutdown_at: *shutdown_at,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterRequest {
                request_id,
                domain,
                origin_node_id,
                challenge_token,
                geo,
                capacity,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 111,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegisterRequest(
                    proto::DnsDomainRegisterRequest {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        challenge_token: challenge_token.to_string(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegisterResponse {
                request_id,
                domain,
                origin_node_id,
                verified,
                reason,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 112,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegisterResponse(
                    proto::DnsDomainRegisterResponse {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        verified: *verified,
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregisterRequest {
                request_id,
                domain,
                origin_node_id,
                reason,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 113,
                payload: Some(proto::mesh_message::Payload::DnsDomainDeregisterRequest(
                    proto::DnsDomainDeregisterRequest {
                        request_id: request_id.to_string(),
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainRegistered {
                domain,
                origin_node_id,
                verified_by_global_node,
                geo,
                capacity,
                registered_at,
                expires_at,
                signature,
            } => proto::MeshMessage {
                message_type: 114,
                payload: Some(proto::mesh_message::Payload::DnsDomainRegistered(
                    proto::DnsDomainRegistered {
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        verified_by_global_node: verified_by_global_node.to_string(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        registered_at: *registered_at,
                        expires_at: *expires_at,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsDomainDeregistered {
                domain,
                origin_node_id,
                deregistered_by_global_node,
                reason,
                deregistered_at,
                signature,
            } => proto::MeshMessage {
                message_type: 115,
                payload: Some(proto::mesh_message::Payload::DnsDomainDeregistered(
                    proto::DnsDomainDeregistered {
                        domain: domain.to_string(),
                        origin_node_id: origin_node_id.to_string(),
                        deregistered_by_global_node: deregistered_by_global_node.to_string(),
                        reason: reason.to_string(),
                        deregistered_at: *deregistered_at,
                        signature: signature.clone(),
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsRegistrationRequest {
                request_id,
                registration,
                timestamp: _,
            } => proto::MeshMessage {
                message_type: 116,
                payload: Some(proto::mesh_message::Payload::DnsRegistrationRequest(
                    proto::DnsRegistrationRequest {
                        request_id: request_id.to_string(),
                        registration: Some(proto::DnsRegistration {
                            node_id: registration.registration.node_id.to_string(),
                            domain: registration.registration.domain.to_string(),
                            ip_addresses: registration.registration.ip_addresses.clone(),
                            geo: registration
                                .registration
                                .geo
                                .as_ref()
                                .map(|s| s.to_string()),
                            capacity: registration.registration.capacity,
                            healthy: registration.registration.healthy,
                            latency_ms: registration.registration.latency_ms,
                            certificate_fingerprint: registration
                                .registration
                                .certificate_fingerprint
                                .as_ref()
                                .map(|s| s.to_string()),
                            role: registration.registration.role as u32,
                            edge_node_id: registration
                                .registration
                                .edge_node_id
                                .as_ref()
                                .map(|s| s.to_string()),
                            edge_node_geo: registration
                                .registration
                                .edge_node_geo
                                .as_ref()
                                .map(|s| s.to_string()),
                        }),
                        verify_domain_ownership: registration.verify_domain_ownership,
                        timestamp: registration.timestamp,
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsRegistrationResponse {
                request_id,
                response,
                timestamp: _,
            } => proto::MeshMessage {
                message_type: 117,
                payload: Some(proto::mesh_message::Payload::DnsRegistrationResponse(
                    proto::DnsRegistrationResponse {
                        request_id: request_id.to_string(),
                        domain: response.domain.to_string(),
                        registration_accepted: response.registration_accepted,
                        verification_status: response.verification_status as u32,
                        verification_type: response.verification_type.map(|v| v as u32),
                        challenge_token: response.challenge_token.as_ref().map(|s| s.to_string()),
                        nameservers_required: response
                            .nameservers_required
                            .as_ref()
                            .unwrap_or(&vec![])
                            .clone(),
                        error_message: response.error_message.as_ref().map(|s| s.to_string()),
                        global_node_id: response.global_node_id.to_string(),
                        timestamp: response.timestamp,
                    },
                )),
            },
            #[cfg(feature = "dns")]
            MeshMessage::DnsVerificationUpdate {
                request_id,
                update,
                timestamp,
            } => proto::MeshMessage {
                message_type: 118,
                payload: Some(proto::mesh_message::Payload::DnsVerificationUpdate(
                    proto::DnsVerificationUpdate {
                        request_id: request_id.to_string(),
                        domain: update.domain.to_string(),
                        status: update.status as u32,
                        verified_at: update.verified_at,
                        error_message: update.error_message.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::FindNode {
                request_id,
                target_node_id,
                requester_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 102,
                payload: Some(proto::mesh_message::Payload::FindNode(proto::FindNode {
                    request_id: request_id.to_string(),
                    target_node_id: target_node_id.clone(),
                    requester_node_id: requester_node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::FindNodeResponse {
                request_id,
                peers,
                responder_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 103,
                payload: Some(proto::mesh_message::Payload::FindNodeResponse(
                    proto::FindNodeResponse {
                        request_id: request_id.to_string(),
                        peers: peers
                            .iter()
                            .map(|p| proto::PeerContact {
                                node_id: p.node_id.as_bytes().to_vec(),
                                node_id_string: p.node_id_string.clone(),
                                address: p.address.clone(),
                                port: p.port as u32,
                                country: p
                                    .geo
                                    .as_ref()
                                    .and_then(|g| g.country.clone())
                                    .unwrap_or_default(),
                                region: p
                                    .geo
                                    .as_ref()
                                    .and_then(|g| g.region.clone())
                                    .unwrap_or_default(),
                                latitude: p.geo.as_ref().and_then(|g| g.latitude).unwrap_or(0.0),
                                longitude: p.geo.as_ref().and_then(|g| g.longitude).unwrap_or(0.0),
                                latency_ms: p.latency_ms.unwrap_or(0),
                                last_seen: p.last_seen.elapsed().as_secs(),
                                is_global: p.is_global,
                                is_trusted: p.is_trusted,
                            })
                            .collect(),
                        responder_node_id: responder_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::Ping {
                request_id,
                node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 104,
                payload: Some(proto::mesh_message::Payload::Ping(proto::Ping {
                    request_id: request_id.to_string(),
                    node_id: node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::Pong {
                request_id,
                node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 105,
                payload: Some(proto::mesh_message::Payload::Pong(proto::Pong {
                    request_id: request_id.to_string(),
                    node_id: node_id.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::UpstreamVerificationQuery {
                request_id,
                upstream_id,
                querying_node_id,
                timestamp,
                provider_node_id,
            } => proto::MeshMessage {
                message_type: 98,
                payload: Some(proto::mesh_message::Payload::UpstreamVerificationQuery(
                    proto::UpstreamVerificationQuery {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        querying_node_id: querying_node_id.to_string(),
                        timestamp: *timestamp,
                        provider_node_id: provider_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::UpstreamVerificationResponse {
                request_id,
                upstream_id,
                verified,
                global_node_id,
                global_node_signature,
                upstream_url,
                org_id,
                timestamp,
                provider_node_id,
            } => proto::MeshMessage {
                message_type: 99,
                payload: Some(proto::mesh_message::Payload::UpstreamVerificationResponse(
                    proto::UpstreamVerificationResponse {
                        request_id: request_id.to_string(),
                        upstream_id: upstream_id.to_string(),
                        verified: *verified,
                        global_node_id: global_node_id.to_string(),
                        global_node_signature: global_node_signature.clone().unwrap_or_default(),
                        upstream_url: upstream_url.to_string(),
                        org_id: org_id.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                        provider_node_id: provider_node_id.to_string(),
                    },
                )),
            },
            MeshMessage::KeyForward {
                session_id,
                key_id,
                mesh_id,
                client_x25519_pubkey,
                global_node_id,
                nonce,
                timestamp,
            } => proto::MeshMessage {
                message_type: 100,
                payload: Some(proto::mesh_message::Payload::KeyForward(
                    proto::KeyForward {
                        session_id: session_id.to_string(),
                        key_id: key_id.to_string(),
                        mesh_id: mesh_id.to_string(),
                        client_x25519_pubkey: client_x25519_pubkey.to_string(),
                        global_node_id: global_node_id.to_string(),
                        nonce: nonce.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::KeySigned {
                session_id,
                key_id,
                mesh_id,
                origin_mesh_id,
                origin_ed25519_pubkey,
                server_x25519_pubkey,
                origin_signature,
                nonce,
                timestamp,
            } => proto::MeshMessage {
                message_type: 101,
                payload: Some(proto::mesh_message::Payload::KeySigned(proto::KeySigned {
                    session_id: session_id.to_string(),
                    key_id: key_id.to_string(),
                    mesh_id: mesh_id.to_string(),
                    origin_mesh_id: origin_mesh_id.to_string(),
                    origin_ed25519_pubkey: origin_ed25519_pubkey.to_string(),
                    server_x25519_pubkey: server_x25519_pubkey.to_string(),
                    origin_signature: origin_signature.clone(),
                    nonce: nonce.to_string(),
                    timestamp: *timestamp,
                })),
            },
            MeshMessage::NetworkPolicyUpdate {
                policy,
                timestamp,
                source_node_id,
                signature,
            } => proto::MeshMessage {
                message_type: 106,
                payload: Some(proto::mesh_message::Payload::NetworkPolicyUpdate(
                    proto::NetworkPolicyUpdate {
                        policy: Some(proto::NetworkPolicy {
                            min_reputation_for_read: policy.min_reputation_for_read,
                            min_reputation_for_write: policy.min_reputation_for_write,
                            blocked_nodes: policy
                                .blocked_nodes
                                .iter()
                                .map(|b| proto::BlockedNode {
                                    node_id: b.node_id.clone(),
                                    blocked_ip: b.blocked_ip.clone(),
                                    blocked_hash: b.blocked_hash.clone(),
                                    reason: b.reason.clone(),
                                    blocked_at: b.blocked_at,
                                    blocked_by: b.blocked_by.clone(),
                                    expires_at: b.expires_at,
                                    evidence_receipt: b.evidence_receipt.as_ref().map(|er| {
                                        proto::AuditReceipt {
                                            reporter_node_id: er.reporter_node_id.clone(),
                                            target_node_id: er.target_node_id.clone(),
                                            evidence_hash: er.evidence_hash.clone(),
                                            evidence_type: er.evidence_type.clone(),
                                            reporter_signature: er.reporter_signature.clone(),
                                            timestamp: er.timestamp,
                                        }
                                    }),
                                })
                                .collect(),
                            last_updated: policy.last_updated,
                            updated_by: policy.updated_by.clone(),
                            valid_from: policy.valid_from,
                            signature: policy.signature.clone(),
                        }),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::GlobalNodeBlocklistUpdate {
                blocklist,
                timestamp,
                source_node_id,
                signature,
            } => proto::MeshMessage {
                message_type: 107,
                payload: Some(proto::mesh_message::Payload::GlobalNodeBlocklistUpdate(
                    proto::GlobalNodeBlocklistUpdate {
                        blocklist: Some(proto::GlobalNodeBlocklist {
                            blocked_nodes: blocklist
                                .blocked_nodes
                                .iter()
                                .map(|b| proto::BlockedNode {
                                    node_id: b.node_id.clone(),
                                    blocked_ip: b.blocked_ip.clone(),
                                    blocked_hash: b.blocked_hash.clone(),
                                    reason: b.reason.clone(),
                                    blocked_at: b.blocked_at,
                                    blocked_by: b.blocked_by.clone(),
                                    expires_at: b.expires_at,
                                    evidence_receipt: b.evidence_receipt.as_ref().map(|er| {
                                        proto::AuditReceipt {
                                            reporter_node_id: er.reporter_node_id.clone(),
                                            target_node_id: er.target_node_id.clone(),
                                            evidence_hash: er.evidence_hash.clone(),
                                            evidence_type: er.evidence_type.clone(),
                                            reporter_signature: er.reporter_signature.clone(),
                                            timestamp: er.timestamp,
                                        }
                                    }),
                                })
                                .collect(),
                            last_updated: blocklist.last_updated,
                            updated_by: blocklist.updated_by.clone(),
                            signature: blocklist.signature.clone(),
                        }),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::AiBotListUpdate {
                bot_list,
                timestamp,
                source_node_id,
                signature,
            } => proto::MeshMessage {
                message_type: 126,
                payload: Some(proto::mesh_message::Payload::AiBotListUpdate(
                    proto::AiBotListUpdate {
                        bot_list: Some(proto::GlobalAiBotList {
                            entries: bot_list
                                .entries
                                .iter()
                                .map(|e| proto::AiBotEntry {
                                    pattern: e.pattern.clone(),
                                    action: match e.action {
                                        crate::dht::BotAction::Add => 0,
                                        crate::dht::BotAction::Remove => 1,
                                        crate::dht::BotAction::Update => 2,
                                    },
                                    source: e.source.clone(),
                                    timestamp: e.timestamp,
                                    expires_at: e.expires_at,
                                })
                                .collect(),
                            last_updated: bot_list.last_updated,
                            updated_by: bot_list.updated_by.clone(),
                            signature: bot_list.signature.clone(),
                        }),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::AnycastNodeRegistration {
                request_id,
                node_id,
                anycast_ips,
                geo,
                capacity,
                healthy,
                dns_zones,
                certificate_fingerprint,
                timestamp,
            } => proto::MeshMessage {
                message_type: 120,
                payload: Some(proto::mesh_message::Payload::AnycastNodeRegistration(
                    proto::AnycastNodeRegistration {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        anycast_ips: anycast_ips.clone(),
                        geo: geo.as_ref().map(|s| s.to_string()),
                        capacity: *capacity,
                        healthy: *healthy,
                        dns_zones: dns_zones.clone(),
                        certificate_fingerprint: certificate_fingerprint
                            .as_ref()
                            .map(|s| s.to_string()),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::AnycastHealthUpdate {
                node_id,
                anycast_ips,
                healthy,
                latency_ms,
                load_percent,
                timestamp,
            } => proto::MeshMessage {
                message_type: 121,
                payload: Some(proto::mesh_message::Payload::AnycastHealthUpdate(
                    proto::AnycastHealthUpdate {
                        node_id: node_id.to_string(),
                        anycast_ips: anycast_ips.clone(),
                        healthy: *healthy,
                        latency_ms: *latency_ms,
                        load_percent: load_percent.map(|v| v as u32),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ZoneSyncRequest {
                request_id,
                zone_origin,
                serial,
                requesting_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 122,
                payload: Some(proto::mesh_message::Payload::ZoneSyncRequest(
                    proto::ZoneSyncRequest {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        serial: *serial,
                        requesting_node_id: requesting_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ZoneSyncResponse {
                request_id,
                zone_origin,
                records_json,
                serial,
                complete,
                timestamp,
                origin_signature,
                origin_pubkey,
                previous_serial,
                compressed,
            } => proto::MeshMessage {
                message_type: 123,
                payload: Some(proto::mesh_message::Payload::ZoneSyncResponse(
                    proto::ZoneSyncResponse {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        records_json: records_json.to_string(),
                        serial: *serial,
                        complete: *complete,
                        timestamp: *timestamp,
                        origin_signature: origin_signature.clone(),
                        origin_pubkey: origin_pubkey.clone().unwrap_or_default(),
                        previous_serial: *previous_serial,
                        compressed: *compressed,
                    },
                )),
            },
            MeshMessage::ZoneSyncAck {
                request_id,
                zone_origin,
                serial,
                timestamp,
            } => proto::MeshMessage {
                message_type: 124,
                payload: Some(proto::mesh_message::Payload::ZoneSyncAck(
                    proto::ZoneSyncAck {
                        request_id: request_id.to_string(),
                        zone_origin: zone_origin.to_string(),
                        serial: *serial,
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::SiteConfigSync {
                request_id,
                site_id,
                config_version,
                config_json,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
                proxy_cache_preferences,
            } => proto::MeshMessage {
                message_type: 125,
                payload: Some(proto::mesh_message::Payload::SiteConfigSync(
                    proto::SiteConfigSync {
                        request_id: request_id.to_string(),
                        site_id: site_id.to_string(),
                        config_version: *config_version,
                        config_json: config_json.to_string(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                        proxy_cache_preferences: proxy_cache_preferences.as_ref().map(|p| {
                            proto::ProxyCachePreferences {
                                enable: p.enable,
                                inactive: p.inactive,
                                valid_status: p.valid_status.clone(),
                                methods: p.methods.clone(),
                                use_stale: p.use_stale.clone(),
                                min_uses: p.min_uses,
                                stale_while_revalidate: p.stale_while_revalidate,
                                stale_if_error: p.stale_if_error,
                            }
                        }),
                    },
                )),
            },
            MeshMessage::WasmModuleAnnounce {
                request_id,
                module_name,
                module_type,
                version,
                size_bytes,
                checksum,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 127,
                payload: Some(proto::mesh_message::Payload::WasmModuleAnnounce(
                    proto::WasmModuleAnnounce {
                        request_id: request_id.to_string(),
                        module_name: module_name.to_string(),
                        module_type: *module_type as i32,
                        version: *version,
                        size_bytes: *size_bytes,
                        checksum: checksum.to_string(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::WasmModuleSyncRequest {
                request_id,
                node_id,
                module_names,
                timestamp,
            } => proto::MeshMessage {
                message_type: 128,
                payload: Some(proto::mesh_message::Payload::WasmModuleSyncRequest(
                    proto::WasmModuleSyncRequest {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        module_names: module_names.iter().map(|s| s.to_string()).collect(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::WasmModuleSyncResponse {
                request_id,
                node_id,
                modules,
                timestamp,
            } => proto::MeshMessage {
                message_type: 129,
                payload: Some(proto::mesh_message::Payload::WasmModuleSyncResponse(
                    proto::WasmModuleSyncResponse {
                        request_id: request_id.to_string(),
                        node_id: node_id.to_string(),
                        modules: modules
                            .iter()
                            .map(|m| proto::WasmModuleInfo {
                                module_name: m.module_name.to_string(),
                                module_type: m.module_type as i32,
                                version: m.version,
                                size_bytes: m.size_bytes,
                                checksum: m.checksum.to_string(),
                                data: m.data.clone(),
                            })
                            .collect(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::SessionRotate {
                session_id,
                peer_id,
                key_version,
                peer_entropy,
                timestamp,
            } => proto::MeshMessage {
                message_type: 130,
                payload: Some(proto::mesh_message::Payload::SessionRotate(
                    proto::SessionRotate {
                        session_id: session_id.to_string(),
                        peer_id: peer_id.to_string(),
                        key_version: *key_version,
                        peer_entropy: peer_entropy.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::SessionRotateAck {
                session_id,
                peer_id,
                key_version,
                peer_entropy,
                timestamp,
            } => proto::MeshMessage {
                message_type: 131,
                payload: Some(proto::mesh_message::Payload::SessionRotateAck(
                    proto::SessionRotateAck {
                        session_id: session_id.to_string(),
                        peer_id: peer_id.to_string(),
                        key_version: *key_version,
                        peer_entropy: peer_entropy.clone(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ServerlessFunctionAnnounce(msg) => proto::MeshMessage {
                message_type: 132,
                payload: Some(proto::mesh_message::Payload::ServerlessFunctionAnnounce(
                    proto::ServerlessFunctionAnnounce {
                        function_name: msg.function_name.clone(),
                        version: msg.version,
                        checksum: msg.checksum.clone(),
                        routes: msg.routes.clone(),
                        allowed_methods: msg.allowed_methods.clone(),
                        memory_mb: msg.memory_mb.unwrap_or(0) as u32,
                        timeout_seconds: msg.timeout_seconds.unwrap_or(0) as u32,
                        priority: msg.priority,
                    },
                )),
            },
            MeshMessage::ServerlessInvokeRequest(msg) => {
                let permission_claim =
                    msg.permission_claim
                        .as_ref()
                        .map(|pc| proto::ServerlessPermissionClaim {
                            function_name: pc.function_name.clone(),
                            caller_node_id: pc.caller_node_id.clone(),
                            caller_org_id: pc.caller_org_id.clone(),
                            timestamp: pc.timestamp,
                            nonce: pc.nonce.clone(),
                            signature: pc.signature.clone(),
                        });
                proto::MeshMessage {
                    message_type: 150,
                    payload: Some(proto::mesh_message::Payload::ServerlessInvokeRequest(
                        proto::ServerlessInvokeRequest {
                            function_name: msg.function_name.clone(),
                            caller_node_id: msg.caller_node_id.clone(),
                            timestamp: msg.timestamp,
                            call_signature: msg.call_signature.clone(),
                            permission_claim,
                        },
                    )),
                }
            }
            MeshMessage::ServerlessInvokeResponse(msg) => proto::MeshMessage {
                message_type: 151,
                payload: Some(proto::mesh_message::Payload::ServerlessInvokeResponse(
                    proto::ServerlessInvokeResponse {
                        function_name: msg.function_name.clone(),
                        caller_node_id: msg.caller_node_id.clone(),
                        timestamp: msg.timestamp,
                        response_data: msg.response_data.clone(),
                        success: msg.success,
                        error_message: msg.error_message.clone(),
                        execution_time_ms: msg.execution_time_ms,
                        response_signature: msg.response_signature.clone(),
                    },
                )),
            },
            MeshMessage::UpstreamOwnershipChallenge {
                request_id,
                upstream_id,
                challenge_type,
                challenge_token,
                global_node_id,
                timestamp,
            } => {
                let challenge = match challenge_type {
                    crate::protocol::OwnershipChallengeType::Http01 {
                        token,
                        key_authorization,
                    } => {
                        proto::ownership_challenge_type::Challenge::Http01(proto::Http01Challenge {
                            token: token.clone(),
                            key_authorization: key_authorization.clone(),
                        })
                    }
                    crate::protocol::OwnershipChallengeType::Dns01 {
                        domain,
                        txt_record_name,
                        txt_record_value,
                    } => proto::ownership_challenge_type::Challenge::Dns01(proto::Dns01Challenge {
                        domain: domain.clone(),
                        txt_record_name: txt_record_name.clone(),
                        txt_record_value: txt_record_value.clone(),
                    }),
                };
                proto::MeshMessage {
                    message_type: 133,
                    payload: Some(proto::mesh_message::Payload::UpstreamOwnershipChallenge(
                        proto::UpstreamOwnershipChallenge {
                            request_id: request_id.to_string(),
                            upstream_id: upstream_id.to_string(),
                            challenge_type: Some(proto::OwnershipChallengeType {
                                challenge: Some(challenge),
                            }),
                            challenge_token: challenge_token.clone(),
                            global_node_id: global_node_id.to_string(),
                            timestamp: *timestamp,
                        },
                    )),
                }
            }
            MeshMessage::UpstreamChallengeProof {
                request_id,
                upstream_id,
                challenge_proof,
                origin_node_id,
                timestamp,
            } => {
                let proof = match challenge_proof {
                    crate::protocol::OwnershipChallengeProof::Http01 { key_authorization } => {
                        proto::ownership_challenge_proof::Proof::Http01Proof(proto::Http01Proof {
                            key_authorization: key_authorization.clone(),
                        })
                    }
                    crate::protocol::OwnershipChallengeProof::Dns01 { txt_record_value } => {
                        proto::ownership_challenge_proof::Proof::Dns01Proof(proto::Dns01Proof {
                            txt_record_value: txt_record_value.clone(),
                        })
                    }
                };
                proto::MeshMessage {
                    message_type: 134,
                    payload: Some(proto::mesh_message::Payload::UpstreamChallengeProof(
                        proto::UpstreamChallengeProof {
                            request_id: request_id.to_string(),
                            upstream_id: upstream_id.to_string(),
                            challenge_proof: Some(proto::OwnershipChallengeProof {
                                proof: Some(proof),
                            }),
                            origin_node_id: origin_node_id.to_string(),
                            timestamp: *timestamp,
                        },
                    )),
                }
            }
            MeshMessage::GenesisKeyTransition {
                sequence,
                new_key_fingerprint,
                announced_by,
                timestamp,
                genesis_signature,
            } => proto::MeshMessage {
                message_type: 135,
                payload: Some(proto::mesh_message::Payload::GenesisKeyTransition(
                    proto::GenesisKeyTransition {
                        sequence: *sequence,
                        new_key_fingerprint: new_key_fingerprint.to_string(),
                        announced_by: announced_by.to_string(),
                        timestamp: *timestamp,
                        genesis_signature: genesis_signature.clone(),
                    },
                )),
            },
            MeshMessage::RevokeGlobalNode {
                node_id,
                reason,
                timestamp,
                genesis_signature,
            } => proto::MeshMessage {
                message_type: 136,
                payload: Some(proto::mesh_message::Payload::RevokeGlobalNode(
                    proto::RevokeGlobalNode {
                        node_id: node_id.to_string(),
                        reason: reason.to_string(),
                        timestamp: *timestamp,
                        genesis_signature: genesis_signature.clone(),
                    },
                )),
            },
            MeshMessage::SiteTlsCertSync(msg) => {
                let certs = msg
                    .certs
                    .iter()
                    .map(|c| proto::SiteTlsCertEntry {
                        site_id: c.site_id.clone(),
                        cert_data: c.cert_data.clone(),
                        encrypted_key: c.encrypted_key.clone(),
                        nonce: c.nonce.clone(),
                    })
                    .collect();
                proto::MeshMessage {
                    message_type: 137,
                    payload: Some(proto::mesh_message::Payload::SiteTlsCertSync(
                        proto::SiteTlsCertSync {
                            site_id: msg.site_id.clone(),
                            node_id: msg.node_id.clone(),
                            timestamp: msg.timestamp,
                            signature: msg.signature.clone(),
                            signer_public_key: msg.signer_public_key.clone(),
                            certs,
                        },
                    )),
                }
            }
            MeshMessage::SiteTlsCertRequest(msg) => proto::MeshMessage {
                message_type: 138,
                payload: Some(proto::mesh_message::Payload::SiteTlsCertRequest(
                    proto::SiteTlsCertRequest {
                        site_id: msg.site_id.clone(),
                        node_id: msg.node_id.clone(),
                        timestamp: msg.timestamp,
                        signature: msg.signature.clone(),
                        signer_public_key: msg.signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::SiteTlsCertResponse(msg) => {
                let certs = msg
                    .certs
                    .iter()
                    .map(|c| proto::SiteTlsCertEntry {
                        site_id: c.site_id.clone(),
                        cert_data: c.cert_data.clone(),
                        encrypted_key: c.encrypted_key.clone(),
                        nonce: c.nonce.clone(),
                    })
                    .collect();
                proto::MeshMessage {
                    message_type: 139,
                    payload: Some(proto::mesh_message::Payload::SiteTlsCertResponse(
                        proto::SiteTlsCertResponse {
                            site_id: msg.site_id.clone(),
                            node_id: msg.node_id.clone(),
                            timestamp: msg.timestamp,
                            signature: msg.signature.clone(),
                            signer_public_key: msg.signer_public_key.clone(),
                            certs,
                        },
                    )),
                }
            }
            MeshMessage::OrgKeySignRequest {
                request_id,
                org_id,
                org_public_key,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 160,
                payload: Some(proto::mesh_message::Payload::OrgKeySignRequest(
                    proto::OrgKeySignRequest {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        org_public_key: Some(proto::OrgPublicKey {
                            org_id: org_public_key.org_id.clone(),
                            key_id: org_public_key.key_id.clone(),
                            public_key: org_public_key.public_key.clone(),
                            created_at: org_public_key.created_at,
                            issued_by: org_public_key.issued_by.clone(),
                            quorum_signatures: org_public_key
                                .quorum_signatures
                                .iter()
                                .map(|s| proto::QuorumSignature {
                                    signer_node_id: s.signer_node_id.clone(),
                                    signer_public_key: s.signer_public_key.clone(),
                                    signature: s.signature.clone(),
                                    timestamp: s.timestamp,
                                })
                                .collect(),
                        }),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::OrgKeySignResponse {
                request_id,
                org_id,
                signature,
                signer_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 161,
                payload: Some(proto::mesh_message::Payload::OrgKeySignResponse(
                    proto::OrgKeySignResponse {
                        request_id: request_id.to_string(),
                        org_id: org_id.to_string(),
                        signature: signature.clone(),
                        signer_node_id: signer_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::Raft {
                target_node_id,
                payload,
            } => proto::MeshMessage {
                message_type: 162,
                payload: Some(proto::mesh_message::Payload::Raft(proto::RaftMessage {
                    target_node_id: target_node_id.to_string(),
                    msg_type: payload.msg_type as i32,
                    data: payload.data.clone(),
                    request_id: payload.request_id.clone(),
                })),
            },
            MeshMessage::ConsistentReadRequest {
                request_id,
                namespace,
                key,
                requesting_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 166,
                payload: Some(proto::mesh_message::Payload::ConsistentReadRequest(
                    proto::ConsistentReadRequest {
                        request_id: request_id.to_string(),
                        namespace: namespace.as_str().to_string(),
                        key: key.to_string(),
                        requesting_node_id: requesting_node_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::ConsistentReadResponse {
                request_id,
                value,
                leader_node_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 167,
                payload: Some(proto::mesh_message::Payload::ConsistentReadResponse(
                    proto::ConsistentReadResponse {
                        request_id: request_id.to_string(),
                        value: value.clone().unwrap_or_default(),
                        leader_node_id: leader_node_id
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_default(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::NotLeader {
                request_id,
                leader_node_id,
                current_term,
            } => proto::MeshMessage {
                message_type: 168,
                payload: Some(proto::mesh_message::Payload::NotLeader(proto::NotLeader {
                    request_id: request_id.to_string(),
                    leader_node_id: leader_node_id
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    current_term: current_term.unwrap_or(0),
                })),
            },
            MeshMessage::RaftCommitNotification {
                leader_id,
                commit_index,
                namespace,
                key_id,
                timestamp,
            } => proto::MeshMessage {
                message_type: 169,
                payload: Some(proto::mesh_message::Payload::RaftCommitNotification(
                    proto::RaftCommitNotification {
                        leader_id: leader_id.to_string(),
                        commit_index: *commit_index,
                        namespace: namespace.as_str().to_string(),
                        key_id: key_id.to_string(),
                        timestamp: *timestamp,
                    },
                )),
            },
            MeshMessage::JoinRequest {
                request_id,
                public_key,
                invite_token,
                attestation_report,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 172,
                payload: Some(proto::mesh_message::Payload::JoinRequest(
                    proto::JoinRequest {
                        request_id: request_id.to_string(),
                        public_key: public_key.to_string(),
                        invite_token: invite_token.to_string(),
                        attestation_report: attestation_report.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::JoinResponse {
                request_id,
                approved,
                trust_level,
                reason,
                timestamp,
                signature,
            } => proto::MeshMessage {
                message_type: 173,
                payload: Some(proto::mesh_message::Payload::JoinResponse(
                    proto::JoinResponse {
                        request_id: request_id.to_string(),
                        approved: *approved,
                        trust_level: *trust_level as u32,
                        reason: reason.as_ref().map(|s| s.to_string()),
                        timestamp: *timestamp,
                        signature: signature.clone(),
                    },
                )),
            },
            MeshMessage::ReplicaSyncRequest {
                request_id,
                last_sync_index,
                node_id,
            } => proto::MeshMessage {
                message_type: 174,
                payload: Some(proto::mesh_message::Payload::ReplicaSyncRequest(
                    proto::ReplicaSyncRequest {
                        request_id: request_id.to_string(),
                        last_sync_index: *last_sync_index,
                        node_id: node_id.to_string(),
                    },
                )),
            },
            MeshMessage::ReplicaSyncResponse {
                request_id,
                current_index,
                snapshot_required,
                entries,
            } => proto::MeshMessage {
                message_type: 175,
                payload: Some(proto::mesh_message::Payload::ReplicaSyncResponse(
                    proto::ReplicaSyncResponse {
                        request_id: request_id.to_string(),
                        current_index: *current_index,
                        snapshot_required: *snapshot_required,
                        entries: entries
                            .iter()
                            .map(|e| proto::RaftCommitNotification {
                                leader_id: e.leader_id.to_string(),
                                commit_index: e.commit_index,
                                namespace: e.namespace.as_str().to_string(),
                                key_id: e.key_id.to_string(),
                                timestamp: e.timestamp,
                            })
                            .collect(),
                    },
                )),
            },
            MeshMessage::MeshLoadUpdate {
                request_id,
                record,
                quorum_signatures,
                timestamp,
                source_node_id,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 176,
                payload: Some(proto::mesh_message::Payload::MeshLoadUpdate(
                    proto::MeshLoadUpdate {
                        request_id: request_id.to_string(),
                        record: Some(record.clone().into()),
                        quorum_signatures: quorum_signatures
                            .iter()
                            .map(|s| proto::QuorumSignatureEntry {
                                node_id: s.node_id.clone(),
                                signature: s.signature.clone(),
                                timestamp: s.timestamp,
                            })
                            .collect(),
                        timestamp: *timestamp,
                        source_node_id: source_node_id.to_string(),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.clone(),
                    },
                )),
            },
            MeshMessage::HotThreatGossip {
                bloom_filter,
                hashes,
                timestamp,
                immediate_indicator,
            } => proto::MeshMessage {
                message_type: 177,
                payload: Some(proto::mesh_message::Payload::HotThreatGossip(
                    proto::HotThreatGossip {
                        bloom_filter: bloom_filter.clone(),
                        hashes: *hashes,
                        timestamp: *timestamp,
                        immediate_indicator: immediate_indicator.as_ref().map(|i| {
                            proto::ThreatIndicator {
                                threat_type: i.threat_type as i32,
                                indicator_value: i.indicator_value.clone(),
                                severity: i.severity as i32,
                                reason: i.reason.clone(),
                                ttl_seconds: i.ttl_seconds,
                                source_node_id: i.source_node_id.clone(),
                                timestamp: i.timestamp,
                                site_scope: i.site_scope.clone(),
                                rate_limit_requests: i.rate_limit_requests,
                                rate_limit_window_secs: i.rate_limit_window_secs,
                                suspicious_pattern: i.suspicious_pattern.clone(),
                                signature: i.signature.clone(),
                                signer_public_key: i.signer_public_key.clone(),
                            }
                        }),
                    },
                )),
            },
            MeshMessage::BlocklistEventGossip {
                event_id,
                source_node,
                timestamp,
                operation,
                target_kind,
                identifier,
                site_scope,
                reason,
                provenance_kind,
                provenance_source,
                ttl_secs,
                version,
                signature,
                signer_public_key,
            } => proto::MeshMessage {
                message_type: 178,
                payload: Some(proto::mesh_message::Payload::BlocklistEventGossip(
                    proto::BlocklistEventGossip {
                        event: Some(proto::BlocklistEventData {
                            event_id: event_id.to_string(),
                            source_node: source_node.to_string(),
                            timestamp: *timestamp,
                            operation: *operation,
                            target_kind: *target_kind,
                            identifier: identifier.to_string(),
                            site_scope: site_scope.to_string(),
                            reason: reason.as_ref().map(|r| r.to_string()),
                            provenance_kind: *provenance_kind,
                            provenance_source: provenance_source.as_ref().map(|s| s.to_string()),
                            ttl_secs: *ttl_secs,
                            version: *version,
                        }),
                        signature: signature.clone(),
                        signer_public_key: signer_public_key.as_ref().map(|k| k.to_string()),
                    },
                )),
            },
            MeshMessage::BlocklistCatchupRequest {
                requesting_node,
                since_sequence,
                since_timestamp,
                max_events,
            } => proto::MeshMessage {
                message_type: 179,
                payload: Some(proto::mesh_message::Payload::BlocklistCatchupRequest(
                    proto::BlocklistCatchupRequest {
                        requesting_node: requesting_node.to_string(),
                        since_sequence: *since_sequence,
                        since_timestamp: *since_timestamp,
                        max_events: *max_events,
                    },
                )),
            },
            MeshMessage::BlocklistCatchupResponse {
                events,
                history_complete,
                latest_sequence,
                latest_timestamp,
                snapshot_required,
            } => proto::MeshMessage {
                message_type: 180,
                payload: Some(proto::mesh_message::Payload::BlocklistCatchupResponse(
                    proto::BlocklistCatchupResponse {
                        events: events
                            .iter()
                            .map(|e| proto::BlocklistEventData {
                                event_id: e.event_id.clone(),
                                source_node: e.source_node.clone(),
                                timestamp: e.timestamp,
                                operation: e.operation,
                                target_kind: e.target_kind,
                                identifier: e.identifier.clone(),
                                site_scope: e.site_scope.clone(),
                                reason: e.reason.clone(),
                                provenance_kind: e.provenance_kind,
                                provenance_source: e.provenance_source.clone(),
                                ttl_secs: e.ttl_secs,
                                version: e.version,
                            })
                            .collect(),
                        history_complete: *history_complete,
                        latest_sequence: *latest_sequence,
                        latest_timestamp: *latest_timestamp,
                        snapshot_required: *snapshot_required,
                    },
                )),
            },
            MeshMessage::BlocklistSnapshotRequest {
                requesting_node,
                request_id,
                include_ip_blocks,
                include_mesh_id_blocks,
                include_target_state,
                site_scope,
                page_token,
                max_items,
            } => proto::MeshMessage {
                message_type: 181,
                payload: Some(proto::mesh_message::Payload::BlocklistSnapshotRequest(
                    proto::BlocklistSnapshotRequest {
                        requesting_node: requesting_node.to_string(),
                        request_id: request_id.to_string(),
                        include_ip_blocks: *include_ip_blocks,
                        include_mesh_id_blocks: *include_mesh_id_blocks,
                        include_target_state: *include_target_state,
                        site_scope: site_scope.as_ref().map(|s| s.to_string()),
                        page_token: page_token.as_ref().map(|s| s.to_string()),
                        max_items: *max_items,
                    },
                )),
            },
            MeshMessage::BlocklistSnapshotResponse {
                request_id,
                source_node,
                timestamp,
                ip_blocks,
                mesh_blocks,
                target_state_records,
                next_page_token,
                has_more,
                snapshot_complete,
                truncated_reason,
                error,
            } => proto::MeshMessage {
                message_type: 182,
                payload: Some(proto::mesh_message::Payload::BlocklistSnapshotResponse(
                    proto::BlocklistSnapshotResponse {
                        request_id: request_id.to_string(),
                        source_node: source_node.to_string(),
                        timestamp: *timestamp,
                        ip_blocks: ip_blocks
                            .iter()
                            .map(|b| proto::BlocklistSnapshotIpBlock {
                                ip: b.ip.clone(),
                                reason: b.reason.clone(),
                                blocked_at: b.blocked_at,
                                ban_expire_seconds: b.ban_expire_seconds,
                                site_scope: b.site_scope.clone(),
                                access_count: b.access_count,
                                last_access: b.last_access,
                                provenance_kind: b.provenance_kind,
                                provenance_source: b.provenance_source.clone(),
                            })
                            .collect(),
                        mesh_blocks: mesh_blocks
                            .iter()
                            .map(|b| proto::BlocklistSnapshotMeshBlock {
                                mesh_id: b.mesh_id.clone(),
                                reason: b.reason.clone(),
                                blocked_at: b.blocked_at,
                                ban_expire_seconds: b.ban_expire_seconds,
                                site_scope: b.site_scope.clone(),
                                access_count: b.access_count,
                                last_access: b.last_access,
                                provenance_kind: b.provenance_kind,
                                provenance_source: b.provenance_source.clone(),
                            })
                            .collect(),
                        target_state_records: target_state_records
                            .iter()
                            .map(|r| proto::BlocklistSnapshotTargetState {
                                target_kind: r.target_kind,
                                site_scope: r.site_scope.clone(),
                                identifier: r.identifier.clone(),
                                last_operation: r.last_operation,
                                timestamp: r.timestamp,
                                version: r.version,
                                event_id: r.event_id.clone(),
                                source_node: r.source_node.clone(),
                                provenance_kind: r.provenance_kind,
                                provenance_source: r.provenance_source.clone(),
                                recorded_at: r.recorded_at,
                                expires_at: r.expires_at,
                            })
                            .collect(),
                        next_page_token: next_page_token.as_ref().map(|s| s.to_string()),
                        has_more: *has_more,
                        snapshot_complete: *snapshot_complete,
                        truncated_reason: truncated_reason.as_ref().map(|s| s.to_string()),
                        error: error.as_ref().map(|s| s.to_string()),
                    },
                )),
            },
        }
    }
}
