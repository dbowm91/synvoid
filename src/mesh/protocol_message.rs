use super::*;

impl MeshMessage {
    pub fn generate_timestamp() -> u64 {
        crate::mesh::safe_unix_timestamp()
    }

    pub fn generate_nonce() -> ArcStr {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::fill(&mut bytes);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes).into()
    }

    pub fn message_id(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self {
            Self::RouteQuery { query_id, .. } => Some(query_id.as_str().into()),
            Self::RouteResponse { query_id, .. } => Some(query_id.as_str().into()),
            Self::LookupRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::LookupBatchRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::TopologySyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::SeedListRequest { node_id, .. } => Some(node_id.as_str().into()),
            Self::UpstreamUrlRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::PeerAnnounce { node_id, .. } => Some(node_id.as_str().into()),
            Self::ThreatAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::ThreatSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleAcknowledgement {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::YaraRuleSubmission { request_id, .. } => Some(request_id.as_str().into()),
            Self::YaraRuleSubmissionResponse {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::ThreatAcknowledgement {
                original_request_id,
                ..
            } => Some(original_request_id.as_str().into()),
            Self::DhtSnapshotRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtSnapshotResponse { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtSyncRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::UpstreamRegistrationRequest { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            Self::UpstreamRegistrationResponse { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            Self::UpstreamVerificationQuery { request_id, .. } => Some(request_id.as_str().into()),
            Self::UpstreamVerificationResponse { request_id, .. } => {
                Some(request_id.as_str().into())
            }
            #[cfg(feature = "dns")]
            Self::DnsRegistrationRequest { request_id, .. } => Some(request_id.as_str().into()),
            #[cfg(feature = "dns")]
            Self::DnsRegistrationResponse { request_id, .. } => Some(request_id.as_str().into()),
            #[cfg(feature = "dns")]
            Self::DnsVerificationUpdate { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordAnnounce { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtAntiEntropyRequest { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtAntiEntropyResponse { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordPush { request_id, .. } => Some(request_id.as_str().into()),
            Self::DhtRecordPushAck { request_id, .. } => Some(request_id.as_str().into()),
            Self::NetworkPolicyUpdate { source_node_id, .. } => {
                Some(source_node_id.as_str().into())
            }
            Self::GlobalNodeBlocklistUpdate { source_node_id, .. } => {
                Some(source_node_id.as_str().into())
            }
            Self::AiBotListUpdate { source_node_id, .. } => Some(source_node_id.as_str().into()),
            Self::SiteConfigSync { request_id, .. } => Some(request_id.as_str().into()),
            Self::UpstreamBlocked {
                mesh_identifier,
                service_id,
                origin_node_id,
                ..
            } => Some(std::borrow::Cow::Owned(format!(
                "block:{}:{}:{}",
                mesh_identifier, service_id, origin_node_id
            ))),
            _ => None,
        }
    }

    pub fn requires_reliable_delivery(&self) -> bool {
        matches!(
            self,
            Self::RouteQuery { .. }
                | Self::UpstreamAnnounce { .. }
                | Self::UpstreamUpdate { .. }
                | Self::LookupRequest { .. }
                | Self::LookupBatchRequest { .. }
                | Self::TopologySyncRequest { .. }
                | Self::SeedListRequest { .. }
                | Self::PeerAnnounce { .. }
                | Self::ThreatAnnounce { .. }
                | Self::ThreatSyncRequest { .. }
                | Self::ThreatAcknowledgement { .. }
                | Self::ReputationUpdate { .. }
                | Self::DhtSnapshotRequest { .. }
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, prost::EncodeError> {
        let pb: proto::MeshMessage = self.into();
        let mut buf = Vec::with_capacity(pb.encoded_len());
        pb.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let pb: proto::MeshMessage = proto::MeshMessage::decode(data).ok()?;
        pb.try_into().ok()
    }

    pub fn encode_with_length(&self) -> Result<Vec<u8>, String> {
        let encoded = self.encode().map_err(|e| {
            tracing::error!("Failed to encode mesh message: {}", e);
            e.to_string()
        })?;
        let len = (encoded.len() as u32).to_be_bytes().to_vec();
        Ok(len.into_iter().chain(encoded).collect())
    }

    pub fn decode_with_length(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let msg = Self::decode(&data[4..4 + len])?;
        Some((msg, 4 + len))
    }

    pub fn encode_compressed(&self) -> Result<Vec<u8>, std::io::Error> {
        let encoded = self
            .encode()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if encoded.len() < COMPRESSION_THRESHOLD {
            return Ok(encoded);
        }
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&encoded)?;
        encoder.finish()
    }

    pub fn decode_compressed(data: &[u8]) -> Option<Self> {
        if data.len() < 2 || data[0] != 0x1f || data[1] != 0x8b {
            return Self::decode(data);
        }
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decompressed).ok()?;
        Self::decode(&decompressed)
    }

    pub fn requires_signature(&self) -> bool {
        matches!(
            self,
            Self::RouteResponse { .. }
                | Self::UpstreamAnnounce { .. }
                | Self::UpstreamUpdate { .. }
                | Self::ThreatAnnounce { .. }
                | Self::ThreatSyncResponse { .. }
                | Self::ReputationUpdate { .. }
        )
    }

    pub fn get_signable_content(&self) -> Option<String> {
        match self {
            Self::RouteResponse {
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                ..
            } => Some(format!(
                "{},{},{},{},{},{}",
                query_id,
                upstream_id,
                provider_node_id,
                hops,
                ttl_secs,
                crate::mesh::safe_unix_timestamp()
            )),
            Self::UpstreamAnnounce {
                upstream_id,
                action,
                ..
            } => Some(format!("{},{:?}", upstream_id, action)),
            Self::UpstreamUpdate {
                upstream_id, info, ..
            } => Some(format!(
                "{},{},{}",
                upstream_id, info.upstream_id, info.owner_node_id
            )),
            Self::UpstreamUrlResponse {
                request_id,
                upstream_id,
                upstream_url,
                ..
            } => Some(format!("{},{},{}", request_id, upstream_id, upstream_url)),
            Self::ThreatAnnounce {
                request_id,
                source_node_id,
                highest_severity,
                ..
            } => Some(format!(
                "{},{},{:?},{}",
                request_id,
                source_node_id,
                highest_severity,
                crate::mesh::safe_unix_timestamp()
            )),
            Self::ThreatSyncResponse {
                request_id,
                version,
                indicators,
                ..
            } => Some(format!("{},{},{}", request_id, version, indicators.len())),
            Self::ReputationUpdate {
                node_id,
                reputation_score,
                ..
            } => Some(format!(
                "{},{},{}",
                node_id,
                reputation_score,
                crate::mesh::safe_unix_timestamp()
            )),
            _ => None,
        }
    }

    #[deprecated(
        since = "0.3.0",
        note = "HMAC verification no longer supported - use Ed25519 via MeshMessageSigner"
    )]
    pub fn verify_signature_with_signer(
        &self,
        _signer: &MeshMessageSigner,
    ) -> Result<(), SignatureError> {
        tracing::warn!(
            "Deprecated verify_signature_with_signer called - HMAC is no longer supported"
        );
        Err(SignatureError::VerificationFailed(
            "HMAC verification deprecated".to_string(),
        ))
    }

    #[deprecated(
        since = "0.2.0",
        note = "Use MeshMessageSigner.verify() with explicit public key"
    )]
    pub fn verify_signature(&self, expected_signer: &str) -> Result<(), SignatureError> {
        tracing::warn!(
            "Deprecated verify_signature called - signature not actually verified for {}",
            expected_signer
        );
        Err(SignatureError::VerificationFailed(
            "verify_signature is deprecated - use MeshMessageSigner.verify() with explicit public key".to_string(),
        ))
    }
}
