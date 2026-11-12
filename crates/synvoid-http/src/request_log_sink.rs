//! Request-log sink: the narrow seam through which request-path code hands a
//! request-log record to the control plane without naming it.
//!
//! The data plane (`synvoid-http`, `src/waf`, `src/proxy`) must never import
//! `AdminState`, `ProcessManager`, or any other control-plane concrete type
//! (request-path capability boundary). It depends on this trait only; a
//! composition root (`src/server/`) implements it for `AdminState` and hands
//! the handle down through the neutral pipeline contexts.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

/// One request-log record. Borrowed: the caller formats nothing, the sink
/// owns what it keeps.
pub struct RequestLogRecord<'a> {
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub latency_ms: u64,
    pub site_id: &'a str,
    pub user_agent: Option<&'a str>,
    pub is_internal: bool,
}

/// Implemented once, in a composition root, for the admin `AdminState`.
/// Called after the `[logging.verbose_request_logging]` category and
/// per-second rate-limit gates have passed.
pub trait RequestLogSink: Send + Sync + 'static {
    fn emit(&self, record: RequestLogRecord<'_>);
}

/// Sink for tests and for call sites that have no control plane.
pub struct NoopRequestLogSink;

impl RequestLogSink for NoopRequestLogSink {
    fn emit(&self, _record: RequestLogRecord<'_>) {}
}

/// Set-once handle threaded from the composition root down to the request
/// path. Resolved per request (`get().cloned()`) so a control plane that
/// starts after the listeners still receives records on already-accepted
/// keep-alive connections.
pub type RequestLogSinkHandle = Arc<OnceLock<Arc<dyn RequestLogSink>>>;

pub fn empty_sink_handle() -> RequestLogSinkHandle {
    Arc::new(OnceLock::new())
}

#[cfg(test)]
mod request_log_sink_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSink(AtomicUsize);

    impl RequestLogSink for CountingSink {
        fn emit(&self, _record: RequestLogRecord<'_>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record<'a>() -> RequestLogRecord<'a> {
        RequestLogRecord {
            client_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            method: "GET",
            path: "/",
            status: 200,
            latency_ms: 3,
            site_id: "blog",
            user_agent: None,
            is_internal: false,
        }
    }

    #[test]
    fn unset_handle_resolves_to_none() {
        let handle = empty_sink_handle();
        assert!(handle.get().is_none());
    }

    #[test]
    fn set_handle_emits() {
        let handle = empty_sink_handle();
        let sink: Arc<dyn RequestLogSink> = Arc::new(CountingSink(AtomicUsize::new(0)));
        assert!(
            handle.set(sink.clone()).is_ok(),
            "set-once handle accepts the first set"
        );
        sink.emit(record());
        assert!(handle.get().is_some());
    }

    #[test]
    fn noop_sink_discards() {
        NoopRequestLogSink.emit(record());
    }
}
