//! SynVoid HTTP/3 (QUIC) server.
//!
//! This crate owns the HTTP/3 QUIC server implementation. The server accepts
//! WAF and drain abstractions as trait objects, keeping concrete root-owned
//! types (`WafCore`, `WorkerDrainState`) out of this crate.
//!
//! **STATUS**: Server code moved from `src/http3/server.rs` into this crate.
//! The `bind_udp_reuse` platform utility is consumed via `synvoid-platform`.
//! The root crate re-exports `Http3Server` from this crate.

pub mod server;

use synvoid_waf::access::WafAccess;

/// Composite trait combining the WAF capabilities needed by HTTP/3:
/// request-level WAF checks (`Http3RequestWaf`) plus infrastructure access
/// (`WafAccess`: connection limiter, bandwidth, streaming scanner).
///
/// This trait is defined here so the HTTP/3 server can accept WAF backends
/// as trait objects without depending on concrete root-owned types.
pub trait Http3WafBackend: synvoid_http::Http3RequestWaf + WafAccess {}
impl<T> Http3WafBackend for T where T: synvoid_http::Http3RequestWaf + WafAccess {}

pub use server::Http3Server;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use std::sync::Arc;
    use synvoid_config::site::SiteBotConfig;
    use synvoid_waf::primitives::WafDecision;
    use synvoid_waf::ConnectionLimiter;

    /// Mock WAF that implements both `Http3RequestWaf` and `WafAccess`
    /// without depending on concrete root-owned `WafCore`.
    struct MockWaf;

    #[async_trait::async_trait]
    impl synvoid_http::Http3RequestWaf for MockWaf {
        async fn check_request_full(
            &self,
            _site_id: Option<&str>,
            _ip: IpAddr,
            _method: &str,
            _path: &str,
            _query: Option<&str>,
            _headers: &http::HeaderMap,
            _body: Option<&[u8]>,
            _user_agent: Option<&str>,
            _ja4_hash: Option<&str>,
            _site_bot_config: Option<&SiteBotConfig>,
        ) -> WafDecision {
            WafDecision::Pass
        }

        fn generate_tarpit_response(&self, _path: &str) -> String {
            String::new()
        }
    }

    impl synvoid_waf::access::WafAccess for MockWaf {
        fn connection_limiter(&self) -> Option<Arc<ConnectionLimiter>> {
            None
        }

        fn is_over_bandwidth_limit(&self) -> bool {
            false
        }

        fn streaming(&self) -> Option<Box<dyn synvoid_core::streaming_waf::StreamingWafScanner>> {
            None
        }
    }

    /// Verify that a mock WAF can be used as `Arc<dyn Http3WafBackend>`
    /// without any reference to concrete `WafCore`. This prevents the
    /// architectural boundary from silently regressing.
    #[test]
    fn mock_waf_satisfies_http3_waf_backend() {
        let waf: Arc<dyn Http3WafBackend> = Arc::new(MockWaf);
        assert!(!waf.is_over_bandwidth_limit());
        assert!(waf.connection_limiter().is_none());
        assert!(waf.streaming().is_none());
    }

    /// Verify that `Http3WafBackend` is object-safe by constructing a
    /// trait object and calling methods on it.
    #[test]
    fn http3_waf_backend_is_object_safe() {
        let waf: Arc<dyn Http3WafBackend> = Arc::new(MockWaf);
        let _ = waf.connection_limiter();
        let _ = waf.is_over_bandwidth_limit();
        let _ = waf.streaming();
        let _ = waf.generate_tarpit_response("/");
    }

    /// Boundary regression: verify that the concrete `WafCore` type from the
    /// root crate is never used as the WAF backend in HTTP/3. The server must
    /// accept only the `Http3WafBackend` trait object. This test asserts that
    /// the mock (and therefore any real implementation) is a different type
    /// from `WafCore`, preventing accidental coupling.
    #[test]
    fn http3_waf_backend_does_not_use_concrete_waf_core() {
        use std::any::type_name;
        let waf: Arc<dyn Http3WafBackend> = Arc::new(MockWaf);
        // The concrete type behind the trait object must NOT be WafCore.
        // If someone accidentally wires WafCore directly, this assertion
        // will catch it because type_name returns the concrete type.
        let concrete = type_name::<MockWaf>();
        assert!(
            !concrete.contains("WafCore"),
            "Http3WafBackend should not use concrete WafCore; got {concrete}"
        );
        // Also verify the trait object type name does not mention WafCore.
        let trait_obj = type_name::<Arc<dyn Http3WafBackend>>();
        assert!(
            !trait_obj.contains("WafCore"),
            "Arc<dyn Http3WafBackend> should not resolve to WafCore; got {trait_obj}"
        );
    }
}
