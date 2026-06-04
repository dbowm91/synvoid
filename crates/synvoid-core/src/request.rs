use crate::ids::{RequestId, SiteId};

/// Lightweight request metadata that can cross crate boundaries
/// without depending on hyper or other HTTP types.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: RequestId,
    pub site_id: Option<SiteId>,
    pub client_ip: Option<String>,
    pub method: Option<String>,
    pub uri: Option<String>,
}

impl RequestContext {
    pub fn new(request_id: RequestId) -> Self {
        Self {
            request_id,
            site_id: None,
            client_ip: None,
            method: None,
            uri: None,
        }
    }
}
