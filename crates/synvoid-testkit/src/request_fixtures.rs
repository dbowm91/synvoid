use synvoid_core::ids::{RequestId, SiteId};
use synvoid_core::request::RequestContext;

/// Creates a test RequestContext with a random ID.
pub fn test_request_context() -> RequestContext {
    RequestContext::new(RequestId::new(format!("test-{}", uuid_simple())))
}

/// Creates a test RequestContext with a specific site.
pub fn test_request_context_with_site(site_id: &str) -> RequestContext {
    let mut ctx = test_request_context();
    ctx.site_id = Some(SiteId::new(site_id));
    ctx
}

/// Simple deterministic ID generator for tests (no uuid dependency needed).
fn uuid_simple() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
