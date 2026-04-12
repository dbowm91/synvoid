use std::sync::Arc;

#[derive(Clone)]
pub struct TlsContext {
    pub ja4_hash: Option<String>,
    pub protocol: &'static str,
}

impl TlsContext {
    pub fn plaintext() -> Self {
        Self {
            ja4_hash: None,
            protocol: "http",
        }
    }

    pub fn with_ja4(ja4_hash: Option<String>) -> Self {
        Self {
            ja4_hash,
            protocol: "https",
        }
    }
}

impl Default for TlsContext {
    fn default() -> Self {
        Self::plaintext()
    }
}

pub trait ConnectionMeta: Send + Sync {
    fn request_drop(&self);
    fn should_drop(&self) -> bool;
    fn get_ja4(&self) -> Option<String>;
    fn supports_websocket(&self) -> bool {
        true
    }
    fn protocol(&self) -> &'static str {
        if self.get_ja4().is_some() {
            "https"
        } else {
            "http"
        }
    }
    fn tls_context(&self) -> TlsContext {
        if let Some(ja4) = self.get_ja4() {
            TlsContext::with_ja4(Some(ja4))
        } else {
            TlsContext::plaintext()
        }
    }
}

pub struct UnifiedHandlerConfig {
    pub supports_websocket: bool,
    pub supports_internal_endpoints: bool,
}

impl Default for UnifiedHandlerConfig {
    fn default() -> Self {
        Self {
            supports_websocket: true,
            supports_internal_endpoints: true,
        }
    }
}

impl UnifiedHandlerConfig {
    pub fn https_mode() -> Self {
        Self {
            supports_websocket: false,
            supports_internal_endpoints: false,
        }
    }
}

impl ConnectionMeta for crate::http::server::HttpConnection {
    fn request_drop(&self) {
        crate::http::server::HttpConnection::request_drop(self)
    }
    fn should_drop(&self) -> bool {
        crate::http::server::HttpConnection::should_drop(self)
    }
    fn get_ja4(&self) -> Option<String> {
        None
    }
}

impl ConnectionMeta for crate::tls::server::HttpsConnection {
    fn request_drop(&self) {
        crate::tls::server::HttpsConnection::request_drop(self)
    }
    fn should_drop(&self) -> bool {
        crate::tls::server::HttpsConnection::should_drop(self)
    }
    fn get_ja4(&self) -> Option<String> {
        crate::tls::server::HttpsConnection::get_ja4(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_context_plaintext() {
        let ctx = TlsContext::plaintext();
        assert!(ctx.ja4_hash.is_none());
        assert_eq!(ctx.protocol, "http");
    }

    #[test]
    fn test_tls_context_with_ja4() {
        let ctx = TlsContext::with_ja4(Some("test_ja4_hash".to_string()));
        assert!(ctx.ja4_hash.is_some());
        assert_eq!(ctx.protocol, "https");
    }

    #[test]
    fn test_tls_context_default_plaintext() {
        let ctx = TlsContext::default();
        assert!(ctx.ja4_hash.is_none());
        assert_eq!(ctx.protocol, "http");
    }
}
