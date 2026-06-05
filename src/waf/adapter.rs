use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use http::HeaderMap;
use synvoid_core::request::{BodyScanPhase, RequestContext};
use synvoid_waf::primitives::WafDecision;
use synvoid_waf::traits::WafProcessor;

use super::WafCore;

#[derive(Debug)]
pub enum AdapterError {
    MissingClientIp,
    InvalidClientIp(std::net::AddrParseError),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterError::MissingClientIp => write!(f, "client_ip is required"),
            AdapterError::InvalidClientIp(e) => write!(f, "invalid client_ip: {e}"),
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone)]
pub struct RootWafProcessor {
    inner: Arc<WafCore>,
}

impl RootWafProcessor {
    pub fn new(core: Arc<WafCore>) -> Self {
        Self { inner: core }
    }

    pub fn core(&self) -> &WafCore {
        &self.inner
    }
}

#[async_trait]
impl WafProcessor for RootWafProcessor {
    type Error = AdapterError;

    async fn check_request(&self, ctx: &RequestContext) -> Result<WafDecision, Self::Error> {
        let ip: IpAddr = ctx
            .client_ip
            .as_deref()
            .ok_or(AdapterError::MissingClientIp)?
            .parse()
            .map_err(AdapterError::InvalidClientIp)?;

        let site_id = ctx.site_id.as_ref().map(|s| s.as_str());
        let method = ctx.method.as_deref().unwrap_or("GET");
        let path = ctx.path.as_deref().unwrap_or("/");
        let query = ctx.query.as_deref();
        let ua = ctx.user_agent.as_deref();
        let ja4_hash = ctx.tls_fingerprint.as_ref().and_then(|f| f.ja4.as_deref());

        let headers = HeaderMap::new();

        Ok(self
            .inner
            .check_request_full(
                site_id, ip, method, path, query, &headers, None, ua, ja4_hash, None, None,
            )
            .await)
    }

    async fn check_request_full(
        &self,
        ctx: &RequestContext,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> Result<WafDecision, Self::Error> {
        let ip: IpAddr = ctx
            .client_ip
            .as_deref()
            .ok_or(AdapterError::MissingClientIp)?
            .parse()
            .map_err(AdapterError::InvalidClientIp)?;

        let site_id = ctx.site_id.as_ref().map(|s| s.as_str());
        let method = ctx.method.as_deref().unwrap_or("GET");
        let path = ctx.path.as_deref().unwrap_or("/");
        let query = ctx.query.as_deref();
        let ua = ctx.user_agent.as_deref();
        let ja4_hash = ctx.tls_fingerprint.as_ref().and_then(|f| f.ja4.as_deref());

        Ok(self
            .inner
            .check_request_full(
                site_id, ip, method, path, query, headers, body, ua, ja4_hash, None, None,
            )
            .await)
    }

    async fn check_body_chunk(
        &self,
        _ctx: &RequestContext,
        chunk: &[u8],
        _phase: BodyScanPhase,
    ) -> Result<Option<WafDecision>, Self::Error> {
        let (_continue, decision) = self.inner.check_request_body(chunk);
        Ok(decision)
    }
}
