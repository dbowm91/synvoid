use super::types::{ProtocolMetrics, ProtocolRequest, ProtocolResponse, ProtocolType};
use std::sync::Arc;
use synvoid_upstream::UpstreamPool;

pub trait WafCoreBackend: Send + Sync + 'static {}

pub trait ProtocolHandler: Send + Sync {
    fn protocol_type(&self) -> ProtocolType;

    fn name(&self) -> &'static str;

    fn detect(&self, data: &[u8]) -> bool;

    fn parse_request(&self, data: &[u8]) -> Result<ProtocolRequest, ProtocolError>;

    fn build_request_for_upstream(&self, request: &ProtocolRequest) -> Vec<u8>;

    fn parse_response(&self, data: &[u8]) -> Result<ProtocolResponse, ProtocolError>;

    fn apply_waf(&self, request: &mut ProtocolRequest, waf: &Arc<dyn WafCoreBackend>) -> WafAction;

    fn select_upstream(
        &self,
        request: &ProtocolRequest,
        pool: &UpstreamPool,
    ) -> Option<synvoid_upstream::Backend>;

    fn metrics(&self) -> ProtocolMetrics;

    fn set_waf(&mut self, waf: Arc<dyn WafCoreBackend>);

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

impl WafAction {
    /// Transport-local action projected onto the canonical enforcement
    /// classification (`synvoid_core::enforcement::EnforcementClass`).
    ///
    /// This mapping is exhaustive over `WafAction`: adding a variant here
    /// without updating the match is a compile error, so this adapter cannot
    /// silently diverge from the canonical contract. See
    /// `architecture/enforcement_decision_contract.md`.
    pub const fn class(&self) -> synvoid_core::enforcement::EnforcementClass {
        use synvoid_core::enforcement::EnforcementClass;
        match self {
            Self::Allow => EnforcementClass::Allow,
            Self::Block => EnforcementClass::Block,
            Self::Challenge => EnforcementClass::Challenge,
            Self::Stall => EnforcementClass::Stall,
            Self::TarPit => EnforcementClass::Tarpit,
            Self::LogOnly => EnforcementClass::Observe,
        }
    }

    /// Project a canonical class back onto the transport-local action.
    ///
    /// Fail-closed degradation: the protocol layer cannot express silent
    /// `Drop` (it always produces a framed response or closes with a status),
    /// so canonical `Drop` degrades to `Block`. Both deny the request; the
    /// degradation is covered by [`WafAction`] mapping tests.
    pub const fn from_class(class: synvoid_core::enforcement::EnforcementClass) -> Self {
        use synvoid_core::enforcement::EnforcementClass;
        match class {
            EnforcementClass::Allow => Self::Allow,
            EnforcementClass::Observe => Self::LogOnly,
            EnforcementClass::Challenge => Self::Challenge,
            EnforcementClass::Stall => Self::Stall,
            EnforcementClass::Tarpit => Self::TarPit,
            EnforcementClass::Block | EnforcementClass::Drop => Self::Block,
        }
    }
}

impl From<WafAction> for synvoid_core::enforcement::EnforcementClass {
    fn from(action: WafAction) -> Self {
        action.class()
    }
}

impl From<synvoid_core::enforcement::EnforcementClass> for WafAction {
    fn from(class: synvoid_core::enforcement::EnforcementClass) -> Self {
        Self::from_class(class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_core::enforcement::EnforcementClass;

    #[test]
    fn waf_action_class_mapping_is_exhaustive() {
        assert_eq!(WafAction::Allow.class(), EnforcementClass::Allow);
        assert_eq!(WafAction::Block.class(), EnforcementClass::Block);
        assert_eq!(WafAction::Challenge.class(), EnforcementClass::Challenge);
        assert_eq!(WafAction::Stall.class(), EnforcementClass::Stall);
        assert_eq!(WafAction::TarPit.class(), EnforcementClass::Tarpit);
        assert_eq!(WafAction::LogOnly.class(), EnforcementClass::Observe);
    }

    #[test]
    fn from_class_covers_every_canonical_class() {
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Allow),
            WafAction::Allow
        ));
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Observe),
            WafAction::LogOnly
        ));
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Challenge),
            WafAction::Challenge
        ));
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Stall),
            WafAction::Stall
        ));
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Tarpit),
            WafAction::TarPit
        ));
        assert!(matches!(
            WafAction::from_class(EnforcementClass::Block),
            WafAction::Block
        ));
    }

    #[test]
    fn drop_degrades_to_block_fail_closed() {
        // The protocol layer cannot silently drop; canonical Drop must still
        // deny, so it degrades to Block (never to Allow/LogOnly).
        let degraded = WafAction::from_class(EnforcementClass::Drop);
        assert!(matches!(degraded, WafAction::Block));
        assert_eq!(degraded.class(), EnforcementClass::Block);
        assert!(degraded.class().is_terminal());
    }

    #[test]
    fn round_trip_preserves_all_expressible_classes() {
        for class in [
            EnforcementClass::Allow,
            EnforcementClass::Observe,
            EnforcementClass::Challenge,
            EnforcementClass::Stall,
            EnforcementClass::Tarpit,
            EnforcementClass::Block,
        ] {
            assert_eq!(WafAction::from_class(class).class(), class);
        }
    }
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
