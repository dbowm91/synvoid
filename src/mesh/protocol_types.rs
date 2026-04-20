use super::*;

pub enum ReplayResult {
    Valid,
    ReplayDetected,
    ExpiredTimestamp,
    FutureTimestamp,
}

pub struct AuthChallenge {
    challenge: [u8; 32],
    created_at: Instant,
}

impl AuthChallenge {
    pub fn new() -> Self {
        let mut challenge = [0u8; 32];
        rand::fill(&mut challenge);
        Self {
            challenge,
            created_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(60)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.challenge
    }

    pub fn as_base64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.challenge)
    }
}

impl Default for AuthChallenge {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PendingAuthChallenge {
    challenge: String,
    expected_signer: String,
    created_at: Instant,
}

impl PendingAuthChallenge {
    pub fn new(challenge: String, expected_signer: String) -> Self {
        Self {
            challenge,
            expected_signer,
            created_at: Instant::now(),
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(60)
    }

    pub fn verify_response(&self, response: &str, signer: &MeshMessageSigner) -> bool {
        let expected = format!("{}:{}", self.challenge, self.expected_signer);
        let pk = signer.get_public_key_bytes();
        signer.verify(&expected, response.as_bytes(), &pk)
    }
}

pub const PRIORITY_TIER_FREE: u32 = 0;
pub const PRIORITY_TIER_PAID: u32 = 1;
pub const PRIORITY_TIER_PREMIUM: u32 = 2;
pub const PRIORITY_TIER_ENTERPRISE: u32 = 3;

impl From<&MeshCapabilities> for proto::MeshCapabilities {
    fn from(c: &MeshCapabilities) -> Self {
        proto::MeshCapabilities {
            can_route: c.can_route,
            can_proxy: c.can_proxy,
            can_serve_dns: c.can_serve_dns,
            is_global: c.is_global,
            waf_enabled: c.waf_enabled,
            max_hops: c.max_hops as u32,
            supported_services: c.supported_services.clone(),
            preferred_transport: c.preferred_transport.map(|t| t as u32).unwrap_or(0),
            supported_protocols: c.supported_protocols.clone(),
        }
    }
}

impl TryFrom<proto::MeshCapabilities> for MeshCapabilities {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshCapabilities) -> Result<Self, Self::Error> {
        Ok(MeshCapabilities {
            can_route: pb.can_route,
            can_proxy: pb.can_proxy,
            can_serve_dns: pb.can_serve_dns,
            is_global: pb.is_global,
            waf_enabled: pb.waf_enabled,
            max_hops: pb.max_hops as u8,
            supported_services: pb.supported_services,
            preferred_transport: match pb.preferred_transport {
                1 | 2 => Some(MeshTransportType::Quic),
                _ => None,
            },
            supported_protocols: pb.supported_protocols,
        })
    }
}

impl TryFrom<&proto::MeshCapabilities> for MeshCapabilities {
    type Error = ProtocolError;

    fn try_from(pb: &proto::MeshCapabilities) -> Result<Self, Self::Error> {
        Ok(MeshCapabilities {
            can_route: pb.can_route,
            can_proxy: pb.can_proxy,
            can_serve_dns: pb.can_serve_dns,
            is_global: pb.is_global,
            waf_enabled: pb.waf_enabled,
            max_hops: pb.max_hops as u8,
            supported_services: pb.supported_services.clone(),
            preferred_transport: match pb.preferred_transport {
                1 | 2 => Some(MeshTransportType::Quic),
                _ => None,
            },
            supported_protocols: pb.supported_protocols.clone(),
        })
    }
}

impl From<&UpstreamInfo> for proto::UpstreamInfo {
    fn from(u: &UpstreamInfo) -> Self {
        proto::UpstreamInfo {
            upstream_id: u.upstream_id.clone(),
            upstream_url: u.upstream_url.clone(),
            geo: u.geo.clone(),
            is_local: u.is_local,
            owner_node_id: u.owner_node_id.clone(),
            peered_wafs: u.peered_wafs.clone(),
            url_hash: u.url_hash.clone(),
            waf_policy: u.waf_policy.as_ref().map(|p| p.into()),
            protocol: u.protocol as i32,
        }
    }
}

impl TryFrom<proto::UpstreamInfo> for UpstreamInfo {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamInfo) -> Result<Self, Self::Error> {
        let protocol = match pb.protocol {
            0 => UpstreamProtocol::Unknown,
            1 => UpstreamProtocol::Http,
            2 => UpstreamProtocol::Https,
            3 => UpstreamProtocol::Tcp,
            4 => UpstreamProtocol::Udp,
            5 => UpstreamProtocol::Grpc,
            6 => UpstreamProtocol::Websocket,
            7 => UpstreamProtocol::Websockets,
            9 => UpstreamProtocol::Serverless,
            _ => UpstreamProtocol::Unknown,
        };

        Ok(UpstreamInfo {
            upstream_id: pb.upstream_id,
            upstream_url: pb.upstream_url,
            geo: pb.geo,
            is_local: pb.is_local,
            owner_node_id: pb.owner_node_id,
            peered_wafs: pb.peered_wafs,
            url_hash: pb.url_hash,
            waf_policy: pb.waf_policy.map(|p| p.into()),
            protocol,
        })
    }
}

impl From<&MeshPeerInfo> for proto::MeshPeerInfo {
    fn from(p: &MeshPeerInfo) -> Self {
        proto::MeshPeerInfo {
            node_id: p.node_id.clone(),
            address: p.address.clone(),
            roles: p.role.bits() as u32,
            capabilities: Some((&p.capabilities).into()),
            is_global: p.is_global,
            latency_ms: p.latency_ms,
            upstreams: p.upstreams.clone(),
            is_trusted: p.is_trusted,
            quic_port: p.quic_port,
            wireguard_port: p.wireguard_port,
            advertised_port: p.advertised_port,
            dns_serving_healthy: p.dns_serving_healthy,
        }
    }
}

impl TryFrom<proto::MeshPeerInfo> for MeshPeerInfo {
    type Error = ProtocolError;

    fn try_from(pb: proto::MeshPeerInfo) -> Result<Self, Self::Error> {
        Ok(MeshPeerInfo {
            node_id: pb.node_id,
            address: pb.address,
            role: MeshNodeRole::from_u8(pb.roles as u8),
            capabilities: pb
                .capabilities
                .ok_or(ProtocolError::MissingField("capabilities"))?
                .try_into()
                .map_err(|_| ProtocolError::ConversionFailed("capabilities"))?,
            is_global: pb.is_global,
            latency_ms: pb.latency_ms,
            upstreams: pb.upstreams,
            is_trusted: pb.is_trusted,
            quic_port: pb.quic_port,
            wireguard_port: pb.wireguard_port,
            advertised_port: pb.advertised_port,
            dns_serving_healthy: pb.dns_serving_healthy,
        })
    }
}

impl From<&UpstreamOwner> for proto::UpstreamOwner {
    fn from(u: &UpstreamOwner) -> Self {
        proto::UpstreamOwner {
            owner_node_id: u.owner_node_id.clone(),
            peered_wafs: u.peered_wafs.clone(),
        }
    }
}

impl TryFrom<proto::UpstreamOwner> for UpstreamOwner {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamOwner) -> Result<Self, Self::Error> {
        Ok(UpstreamOwner {
            owner_node_id: pb.owner_node_id,
            peered_wafs: pb.peered_wafs,
        })
    }
}

impl From<UpstreamProtocol> for proto::UpstreamProtocol {
    fn from(p: UpstreamProtocol) -> Self {
        match p {
            UpstreamProtocol::Unknown => proto::UpstreamProtocol::Unknown,
            UpstreamProtocol::Http => proto::UpstreamProtocol::Http,
            UpstreamProtocol::Https => proto::UpstreamProtocol::Https,
            UpstreamProtocol::Tcp => proto::UpstreamProtocol::Tcp,
            UpstreamProtocol::Udp => proto::UpstreamProtocol::Udp,
            UpstreamProtocol::Grpc => proto::UpstreamProtocol::Grpc,
            UpstreamProtocol::Websocket => proto::UpstreamProtocol::Websocket,
            UpstreamProtocol::Websockets => proto::UpstreamProtocol::Websockets,
            UpstreamProtocol::Serverless => proto::UpstreamProtocol::Serverless,
        }
    }
}

impl TryFrom<proto::UpstreamProtocol> for UpstreamProtocol {
    type Error = ProtocolError;

    fn try_from(pb: proto::UpstreamProtocol) -> Result<Self, Self::Error> {
        match pb {
            proto::UpstreamProtocol::Unknown => Ok(UpstreamProtocol::Unknown),
            proto::UpstreamProtocol::Http => Ok(UpstreamProtocol::Http),
            proto::UpstreamProtocol::Https => Ok(UpstreamProtocol::Https),
            proto::UpstreamProtocol::Tcp => Ok(UpstreamProtocol::Tcp),
            proto::UpstreamProtocol::Udp => Ok(UpstreamProtocol::Udp),
            proto::UpstreamProtocol::Grpc => Ok(UpstreamProtocol::Grpc),
            proto::UpstreamProtocol::Websocket => Ok(UpstreamProtocol::Websocket),
            proto::UpstreamProtocol::Websockets => Ok(UpstreamProtocol::Websockets),
            proto::UpstreamProtocol::Serverless => Ok(UpstreamProtocol::Serverless),
        }
    }
}

impl WafPolicy {
    pub fn default_for_tier(tier: u32) -> Self {
        match tier {
            PRIORITY_TIER_ENTERPRISE => WafPolicy {
                skip_rate_limit: true,
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(100000),
                    requests_per_minute: Some(5000000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_PREMIUM => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(10000),
                    requests_per_minute: Some(500000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_PAID => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(1000),
                    requests_per_minute: Some(50000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            PRIORITY_TIER_FREE => WafPolicy {
                priority_tier: tier,
                rate_limit_override: Some(RateLimitOverride {
                    requests_per_second: Some(100),
                    requests_per_minute: Some(5000),
                    ..Default::default()
                }),
                ..Default::default()
            },
            _ => WafPolicy {
                priority_tier: tier,
                ..Default::default()
            },
        }
    }
}

impl From<&WafPolicy> for proto::WafPolicy {
    fn from(p: &WafPolicy) -> Self {
        proto::WafPolicy {
            skip_rate_limit: p.skip_rate_limit,
            skip_auth_challenge: p.skip_auth_challenge,
            skip_pow_challenge: p.skip_pow_challenge,
            skip_honeypot: p.skip_honeypot,
            enabled_rules: p.enabled_rules.clone(),
            disabled_rules: p.disabled_rules.clone(),
            threat_level: p.threat_level,
            enable_bot_protection: p.enable_bot_protection,
            enable_ip_feed: p.enable_ip_feed,
            enable_threat_level: p.enable_threat_level,
            enable_traffic_shaping: p.enable_traffic_shaping,
            policy_mode: p.policy_mode.clone(),
            priority_tier: p.priority_tier,
            rate_limit_override: p
                .rate_limit_override
                .as_ref()
                .map(|r| proto::RateLimitOverride {
                    requests_per_second: r.requests_per_second,
                    requests_per_minute: r.requests_per_minute,
                    requests_per_hour: r.requests_per_hour,
                    concurrent_connections: r.concurrent_connections,
                    bandwidth_mbps: r.bandwidth_mbps,
                    burst_size: r.burst_size,
                }),
            enable_mesh_key_exchange: p.enable_mesh_key_exchange,
            enable_mesh_auditing: p.enable_mesh_auditing,
            mesh_id: p.mesh_id.clone(),
            mesh_global_node_url: p.mesh_global_node_url.clone(),
            mesh_audit_urls: p.mesh_audit_urls.clone(),
            fallback_to_regular_pow: p.fallback_to_regular_pow,
        }
    }
}

impl From<proto::WafPolicy> for WafPolicy {
    fn from(pb: proto::WafPolicy) -> Self {
        WafPolicy {
            skip_rate_limit: pb.skip_rate_limit,
            skip_auth_challenge: pb.skip_auth_challenge,
            skip_pow_challenge: pb.skip_pow_challenge,
            skip_honeypot: pb.skip_honeypot,
            enabled_rules: pb.enabled_rules,
            disabled_rules: pb.disabled_rules,
            threat_level: pb.threat_level,
            enable_bot_protection: pb.enable_bot_protection,
            enable_ip_feed: pb.enable_ip_feed,
            enable_threat_level: pb.enable_threat_level,
            enable_traffic_shaping: pb.enable_traffic_shaping,
            policy_mode: pb.policy_mode,
            priority_tier: pb.priority_tier,
            rate_limit_override: pb.rate_limit_override.map(|r| RateLimitOverride {
                requests_per_second: r.requests_per_second,
                requests_per_minute: r.requests_per_minute,
                requests_per_hour: r.requests_per_hour,
                concurrent_connections: r.concurrent_connections,
                bandwidth_mbps: r.bandwidth_mbps,
                burst_size: r.burst_size,
            }),
            enable_mesh_key_exchange: pb.enable_mesh_key_exchange,
            enable_mesh_auditing: pb.enable_mesh_auditing,
            mesh_id: pb.mesh_id,
            mesh_global_node_url: pb.mesh_global_node_url,
            mesh_audit_urls: pb.mesh_audit_urls,
            fallback_to_regular_pow: pb.fallback_to_regular_pow,
        }
    }
}

impl AnnounceAction {
    pub fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(AnnounceAction::Add),
            1 => Ok(AnnounceAction::Update),
            2 => Ok(AnnounceAction::Remove),
            _ => Err(format!("Unknown AnnounceAction value: {}", v)),
        }
    }
}

impl RouteQueryResult {
    pub fn is_expired(&self) -> bool {
        self.providers
            .iter()
            .all(|p| Instant::now().duration_since(self.discovered_at) > p.ttl)
    }

    pub fn remaining_ttl(&self) -> Duration {
        self.providers
            .iter()
            .map(|p| p.ttl)
            .min()
            .unwrap_or(Duration::ZERO)
    }

    pub fn best_provider(&self) -> Option<&ProviderInfo> {
        self.providers.iter().max_by(|a, b| {
            a.priority_tier.cmp(&b.priority_tier).then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        })
    }

    pub fn providers_sorted(&self) -> Vec<&ProviderInfo> {
        let mut providers: Vec<&ProviderInfo> = self.providers.iter().collect();
        providers.sort_by(|a, b| {
            a.priority_tier
                .cmp(&b.priority_tier)
                .reverse()
                .then_with(|| {
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        providers
    }
}

impl PendingQuery {
    pub fn is_expired(&self, timeout: Duration) -> bool {
        Instant::now().duration_since(self.created_at) > timeout
    }
}

impl MeshPeerInfo {
    pub fn new(
        node_id: String,
        address: String,
        role: MeshNodeRole,
        capabilities: MeshCapabilities,
    ) -> Self {
        Self {
            node_id,
            address,
            role,
            capabilities,
            is_global: role.is_global(),
            latency_ms: None,
            upstreams: Vec::new(),
            is_trusted: role.is_global(),
            quic_port: None,
            wireguard_port: None,
            advertised_port: None,
            dns_serving_healthy: false,
        }
    }
}

impl AckStatus {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AckStatus::Success,
            1 => AckStatus::Processing,
            2 => AckStatus::InvalidMessage,
            3 => AckStatus::Unauthorized,
            4 => AckStatus::NotFound,
            5 => AckStatus::RateLimited,
            6 => AckStatus::InternalError,
            _ => AckStatus::InternalError,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            AckStatus::Success => 0,
            AckStatus::Processing => 1,
            AckStatus::InvalidMessage => 2,
            AckStatus::Unauthorized => 3,
            AckStatus::NotFound => 4,
            AckStatus::RateLimited => 5,
            AckStatus::InternalError => 6,
        }
    }
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&ThreatIndicator> for proto::ThreatIndicator {
    fn from(i: &ThreatIndicator) -> Self {
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
            signer_public_key: i.signer_public_key.clone().unwrap_or_default(),
        }
    }
}

impl From<proto::ThreatIndicator> for ThreatIndicator {
    fn from(pb: proto::ThreatIndicator) -> Self {
        ThreatIndicator {
            threat_type: match pb.threat_type {
                1 => ThreatType::IpBlock,
                2 => ThreatType::RateLimitViolation,
                3 => ThreatType::SuspiciousActivity,
                4 => ThreatType::AsnBlock,
                _ => ThreatType::Unspecified,
            },
            indicator_value: pb.indicator_value,
            severity: match pb.severity {
                1 => ThreatSeverity::Low,
                2 => ThreatSeverity::Medium,
                3 => ThreatSeverity::High,
                4 => ThreatSeverity::Critical,
                _ => ThreatSeverity::Unspecified,
            },
            reason: pb.reason,
            ttl_seconds: pb.ttl_seconds,
            source_node_id: pb.source_node_id,
            timestamp: pb.timestamp,
            site_scope: pb.site_scope,
            rate_limit_requests: pb.rate_limit_requests,
            rate_limit_window_secs: pb.rate_limit_window_secs,
            suspicious_pattern: pb.suspicious_pattern,
            signature: pb.signature,
            signer_public_key: if pb.signer_public_key.is_empty() {
                None
            } else {
                Some(pb.signer_public_key)
            },
        }
    }
}

impl From<proto::DhtRecord> for DhtRecord {
    fn from(pb: proto::DhtRecord) -> Self {
        DhtRecord {
            key: pb.key,
            value: pb.value,
            timestamp: pb.timestamp,
            sequence_number: 0,
            ttl_seconds: pb.ttl_seconds,
            source_node_id: pb.source_node_id,
            signature: pb.signature,
            signer_public_key: if pb.signer_public_key.is_empty() {
                None
            } else {
                Some(pb.signer_public_key)
            },
            content_hash: pb.content_hash,
        }
    }
}

impl From<DhtRecord> for proto::DhtRecord {
    fn from(r: DhtRecord) -> Self {
        proto::DhtRecord {
            key: r.key,
            value: r.value,
            timestamp: r.timestamp,
            ttl_seconds: r.ttl_seconds,
            source_node_id: r.source_node_id,
            signature: r.signature,
            signer_public_key: r.signer_public_key.unwrap_or_default(),
            content_hash: r.content_hash,
        }
    }
}

impl From<ThreatSeverity> for i32 {
    fn from(s: ThreatSeverity) -> Self {
        match s {
            ThreatSeverity::Unspecified => 0,
            ThreatSeverity::Low => 1,
            ThreatSeverity::Medium => 2,
            ThreatSeverity::High => 3,
            ThreatSeverity::Critical => 4,
        }
    }
}
