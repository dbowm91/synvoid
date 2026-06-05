use crate::ids::{RequestId, SiteId};

/// TLS fingerprint data derived from the client hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFingerprint {
    pub ja3: Option<String>,
    pub ja4: Option<String>,
}

/// Phase of body scanning for streaming WAF evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyScanPhase {
    /// Only headers have been received.
    HeadersOnly,
    /// Body is being received in streaming chunks.
    StreamingChunk,
    /// Full body has been collected.
    CompleteBody,
}

/// Lightweight request metadata that can cross crate boundaries
/// without depending on hyper or other HTTP types.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: RequestId,
    pub site_id: Option<SiteId>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub tls_fingerprint: Option<TlsFingerprint>,
}

impl RequestContext {
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            site_id: None,
            client_ip: None,
            method: None,
            uri: None,
            path: None,
            query: None,
            host: None,
            user_agent: None,
            content_type: None,
            content_length: None,
            tls_fingerprint: None,
        }
    }
}
