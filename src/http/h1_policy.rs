//! Root-local Hyper H1 builder policy (Phase 70).
//!
//! Both the plaintext accept loop (`super::server::accept_loop`) and the
//! TLS accept path (`crate::tls::server`) serve HTTP/1.1 through
//! `hyper::server::conn::http1::Builder`. This module owns the single
//! transport-independent mapping from [`HttpConfig`] to that builder so the
//! two transports cannot drift apart again.
//!
//! Scope is deliberately narrow: header-read timeout, header count, and
//! parser-buffer ceiling only. H2 flow-control/body limits, keep-alive idle
//! policy, and pipeline depth are owned elsewhere (Phase 71 matrix).
//!
//! Hyper timer requirement (verified against the resolved `hyper 1.10.1`
//! source in `src/server/conn/http1.rs` + `src/common/time.rs`):
//! `Builder::header_read_timeout` stores `Dur::Configured`, and
//! `serve_connection` calls `Time::check`, which **panics** when a timeout
//! is configured without a `Timer`. The plaintext path previously called
//! `.header_read_timeout(..)` with `Time::Empty`, so every connection would
//! panic at `serve_connection` time instead of enforcing the timeout. Both
//! H1 paths must therefore set an explicit Tokio timer adapter. The
//! canonical adapter already in the dependency graph is
//! `hyper_util::rt::TokioTimer` (root depends on `hyper-util` with the
//! `tokio` feature for `TokioExecutor`/`TokioIo`).

use std::time::Duration;

use synvoid_config::http::HttpConfig;

/// Protocol label advertised by the plaintext accept loop.
///
/// The plaintext driver constructs only `hyper::server::conn::http1::Builder`
/// (no cleartext H2/h2c), so the startup log must say exactly this. The TLS
/// listener keeps its own `(HTTP/1.1 + HTTP/2)` claim because ALPN routing
/// actually serves both.
///
/// Public so integration parity tests (`tests/http_h1_parser_parity.rs`) can
/// pin the label without duplicating it.
pub const PLAINTEXT_PROTOCOL_LABEL: &str = "HTTP/1.1";

/// Format the plaintext startup line from a bound address.
pub fn plaintext_startup_message(addr: &std::net::SocketAddr) -> String {
    format!("HTTP server listening on {addr} ({PLAINTEXT_PROTOCOL_LABEL}) [SO_REUSEPORT]")
}

/// Apply the transport-independent H1 parser controls to a Hyper H1 builder.
///
/// Sets, from [`HttpConfig`]:
/// - `header_read_timeout` (+ explicit `TokioTimer` so the timeout is active),
/// - `max_headers`,
/// - `max_buf_size` (parser-buffer ceiling, *not* a request-body limit).
///
/// H2 limits are intentionally untouched here.
///
/// Public so the parser-parity integration tests exercise the exact
/// production mapping rather than a copy of it.
pub fn configure_h1_builder(
    builder: &mut hyper::server::conn::http1::Builder,
    config: &HttpConfig,
) {
    builder.timer(hyper_util::rt::TokioTimer::new());
    builder.header_read_timeout(Duration::from_secs(config.header_read_timeout_secs));
    builder.max_headers(config.max_headers);
    builder.max_buf_size(config.max_request_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_label_is_h1_only() {
        assert_eq!(PLAINTEXT_PROTOCOL_LABEL, "HTTP/1.1");
        assert!(!PLAINTEXT_PROTOCOL_LABEL.contains("HTTP/2"));
    }

    #[test]
    fn startup_message_advertises_only_h1() {
        let addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let msg = plaintext_startup_message(&addr);
        assert!(msg.contains("HTTP/1.1"));
        assert!(!msg.contains("HTTP/2"));
    }

    #[test]
    fn helper_sets_timer_so_configured_timeout_does_not_panic() {
        // Regression for the Phase 70 timer finding: configuring a header
        // timeout without a timer makes `serve_connection` panic. The helper
        // must set the timer, so building a connection with a configured
        // timeout must not panic.
        let config = HttpConfig {
            header_read_timeout_secs: 10,
            max_headers: 32,
            max_request_size: 16384,
            ..HttpConfig::default()
        };
        let mut builder = hyper::server::conn::http1::Builder::new();
        configure_h1_builder(&mut builder, &config);
        let svc = hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
            Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                bytes::Bytes::from_static(b"ok"),
            )))
        });
        let (client, _server) = tokio::io::duplex(8192);
        // Must not panic (the pre-Phase-70 plaintext builder without a timer
        // panicked here once `header_read_timeout` was configured).
        let _conn = builder.serve_connection(hyper_util::rt::TokioIo::new(client), svc);
    }
}
