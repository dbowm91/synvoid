use std::future::Future;
use std::pin::Pin;

/// Callback trait for GeoIP database health notifications.
pub trait GeoIpNotificationHandler: Send + Sync + 'static {
    fn send_stale_notification(
        &self,
        edition_id: &str,
        days_since_update: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>>;
}

/// No-op implementation for tests and when alerting is disabled.
pub struct NoopNotificationHandler;

impl GeoIpNotificationHandler for NoopNotificationHandler {
    fn send_stale_notification(
        &self,
        _: &str,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'static>> {
        Box::pin(async { Ok(()) })
    }
}
