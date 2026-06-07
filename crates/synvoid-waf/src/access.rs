//! Narrow trait covering WafCore capabilities needed by HTTP/3 and future
//! HTTP server movement, but not already covered by [`WafProcessor`](crate::traits::WafProcessor).

use std::sync::Arc;

use crate::traffic_shaper::ConnectionLimiter;

/// Access to WAF infrastructure that HTTP/3 and HTTP server dispatch code needs
/// but which [`WafProcessor`](crate::traits::WafProcessor) does not cover.
///
/// This trait is intentionally narrow (3 methods). It covers:
/// - Connection limiting (rate-limiting new connections)
/// - Bandwidth limit checks (monthly bandwidth caps)
/// - Streaming WAF scanner access (body-scanning for chunked uploads)
///
/// The streaming scanner type is an associated type because different crates
/// (root `synvoid` and `synvoid-waf`) have their own `StreamingWafCore`
/// implementations wrapping different `AttackDetector` types.
///
/// Methods like `check_request_full`, `generate_tarpit_response`, and
/// `stream_tarpit` are already covered by traits in `synvoid-http`
/// (`Http3RequestWaf`, `BufferedRequestWaf`) and do not belong here.
pub trait WafAccess: Send + Sync + 'static {
    /// The concrete streaming WAF scanner type produced by this implementation.
    type StreamingScanner: Send + Sync + 'static;

    /// Returns the connection limiter, if configured.
    ///
    /// Callers use this to enforce per-IP and global connection rate limits
    /// before accepting a new HTTP/3 or HTTP/2 connection.
    fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>>;

    /// Returns `true` if the site has exceeded its monthly bandwidth limit.
    fn is_over_bandwidth_limit(&self) -> bool;

    /// Returns a streaming WAF scanner for body/chunk inspection, if attack
    /// detection is enabled.
    fn streaming(&self) -> Option<Self::StreamingScanner>;
}
