use synvoid_core::ids::{RequestId, SiteId};
use synvoid_core::request::RequestContext;

/// Creates a [`RequestContext`] with a unique auto-incrementing ID.
///
/// The ID format is `"test-{N}"` where N is a monotonically increasing
/// counter, ensuring uniqueness within a single test process without
/// requiring the `uuid` crate.
pub fn test_request_context() -> RequestContext {
    RequestContext::new(RequestId::new(format!("test-{}", uuid_simple())))
}

/// Creates a [`RequestContext`] bound to the given `site_id`.
///
/// Equivalent to [`test_request_context`] but additionally sets the
/// `site_id` field, which is needed when testing site-scoped logic.
pub fn test_request_context_with_site(site_id: &str) -> RequestContext {
    let mut ctx = test_request_context();
    ctx.site_id = Some(SiteId::new(site_id));
    ctx
}

/// Monotonically increasing counter used to generate unique request IDs
/// in tests without an external UUID dependency.
fn uuid_simple() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
