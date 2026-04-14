use super::types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};
use crate::upstream::pool::UpstreamPool;
use crate::waf::WafCore;
use std::sync::Arc;

pub trait ProtocolHandler: Send + Sync {
    fn protocol_type(&self) -> ProtocolType;

    fn name(&self) -> &'static str;

    fn detect(&self, data: &[u8]) -> bool;

    fn parse_request(&self, data: &[u8]) -> Result<ProtocolRequest, ProtocolError>;

    fn build_request_for_upstream(&self, request: &ProtocolRequest) -> Vec<u8>;

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse, ProtocolError>;

    fn apply_waf(&self, request: &mut ProtocolRequest, waf: &Arc<WafCore>) -> WafAction;

    fn select_upstream(
        &self,
        request: &ProtocolRequest,
        pool: &UpstreamPool,
    ) -> Option<crate::upstream::pool::Backend>;

    fn metrics(&self) -> ProtocolMetrics;

    fn set_waf(&mut self, waf: Arc<WafCore>);

    fn set_upstream_pool(&mut self, pool: Arc<UpstreamPool>);
}

#[derive(Debug, Clone, Default)]
pub enum WafAction {
    #[default]
    Allow,
    Block,
    Challenge,
    Stall,
    TarPit,
    LogOnly,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid framing: {0}")]
    Framing(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Upstream error: {0}")]
    Upstream(String),

    #[error("WAF blocked: {0}")]
    WafBlocked(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}
