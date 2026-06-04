use serde::{Deserialize, Serialize};

/// A WAF verdict representing the outcome of request analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafVerdict {
    /// Request is clean, allow it through.
    Pass,
    /// Request should be blocked.
    Block,
    /// Request triggered a challenge (CAPTCHA, PoW, etc.).
    Challenge,
    /// Request should be logged but allowed.
    Log,
    /// Request triggered rate limiting.
    RateLimit,
}

impl WafVerdict {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block | Self::Challenge | Self::RateLimit)
    }
}
