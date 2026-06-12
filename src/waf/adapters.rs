use std::net::IpAddr;
use std::sync::Arc;

use synvoid_core::block_store::BlockProvenance;
use synvoid_core::request::RequestContext;
use synvoid_waf::traits::{
    BlockEntry as WafBlockEntry, BlockListStore, ChallengeService, GeoIpLookup, WafPersistence,
};

use crate::block_store::BlockStore;
use crate::challenge::ChallengeManager;
use crate::geoip::GeoIpManager;
use crate::waf::violation_tracker::ViolationTracker;

pub struct BlockStoreAdapter {
    inner: Arc<BlockStore>,
}

impl BlockStoreAdapter {
    pub fn new(inner: Arc<BlockStore>) -> Self {
        Self { inner }
    }
}

impl BlockListStore for BlockStoreAdapter {
    fn is_blocked(&self, ip: &IpAddr, scope: &str) -> Option<WafBlockEntry> {
        self.inner
            .is_blocked(ip, scope)
            .map(|e| WafBlockEntry { reason: e.reason })
    }

    fn block_ip(&self, ip: IpAddr, reason: &str, duration_secs: u64, scope: &str) {
        let _ = self.inner.block_ip(ip, reason, duration_secs, scope);
    }

    fn block_ip_with_provenance(
        &self,
        ip: IpAddr,
        reason: &str,
        duration_secs: u64,
        scope: &str,
        provenance: BlockProvenance,
    ) {
        let _ = self
            .inner
            .block_ip_with_provenance(ip, reason, duration_secs, scope, provenance);
    }
}

pub struct GeoIpAdapter {
    inner: Arc<GeoIpManager>,
}

impl GeoIpAdapter {
    pub fn new(inner: Arc<GeoIpManager>) -> Self {
        Self { inner }
    }
}

impl GeoIpLookup for GeoIpAdapter {
    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        self.inner.get_country_info(ip).map(|info| info.code)
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        self.inner.get_asn_info(ip).map(|info| info.asn)
    }
}

pub struct ChallengeServiceAdapter {
    inner: Arc<ChallengeManager>,
}

impl ChallengeServiceAdapter {
    pub fn new(inner: Arc<ChallengeManager>) -> Self {
        Self { inner }
    }
}

impl ChallengeService for ChallengeServiceAdapter {
    fn should_issue_challenge(&self, _ctx: &RequestContext) -> bool {
        self.inner.pow_enabled() || self.inner.mesh_pow_enabled() || self.inner.css_enabled()
    }

    fn build_challenge(
        &self,
        ctx: &RequestContext,
    ) -> Option<synvoid_waf::primitives::WafDecision> {
        let ip = ctx.client_ip.as_ref()?.parse::<IpAddr>().ok()?;
        let path = ctx.path.as_deref();
        let (html, session_id) = self.inner.generate_challenge_page(&ip, path);
        let challenge_type = self.inner.get_challenge_type();

        if let Some(sid) = session_id {
            Some(synvoid_waf::primitives::WafDecision::ChallengeWithCookie {
                challenge_type,
                html,
                session_cookie_name: self.inner.css_session_cookie_name(),
                session_cookie_value: sid,
                session_cookie_max_age: self.inner.css_window_secs(),
            })
        } else {
            Some(synvoid_waf::primitives::WafDecision::Challenge(
                challenge_type,
                html,
            ))
        }
    }
}

pub struct ViolationPersistenceAdapter {
    inner: Arc<ViolationTracker>,
}

impl ViolationPersistenceAdapter {
    pub fn new(inner: Arc<ViolationTracker>) -> Self {
        Self { inner }
    }
}

impl WafPersistence for ViolationPersistenceAdapter {
    fn persist_violation(&self, key: &str, reason: &str) {
        if let Ok(ip) = key.parse::<IpAddr>() {
            self.inner.record_violation(ip, reason, 3);
        } else {
            tracing::warn!("Failed to parse violation key as IP: {}", key);
        }
    }
}
