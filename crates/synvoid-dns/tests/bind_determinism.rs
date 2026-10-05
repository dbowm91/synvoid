//! Bind determinism evidence (Phase 131).
//!
//! Phase 130 finding F-3 recorded that the DNS conformance lane was
//! intermittently red because of a TOCTOU race in `free_port()`: it released
//! the port before `DnsServer::start` bound it, so a concurrently starting test
//! could claim the same port.
//!
//! `DnsServer::start` binds the authoritative UDP *and* TCP sockets itself, so
//! a held reservation cannot protect the port. The remediation removes the
//! assumption instead: `support::start_bound_dns_server` proposes a port, lets
//! the server perform the real bind, and takes a new port only when the bind
//! actually lost a race.
//!
//! These tests pin the three properties that design depends on. If any of them
//! regresses, the remediation silently degrades back into a flake:
//!
//! 1. the returned port is the port the server really listens on;
//! 2. a bind conflict is distinguished from every other startup failure, so a
//!    real error is never retried away;
//! 3. the error prefixes the discrimination keys on still exist in the source.
//!
//! A fourth test exercises ten consecutive binds in one process, and the
//! repeated-run matrix for the suites themselves is recorded in the Phase 131
//! closeout.

mod support;

use std::time::Duration;

use support::runtime_config::{is_bind_conflict, BIND_TCP_PREFIX, BIND_UDP_PREFIX};

/// The port the helper reports must be the port the server is listening on.
///
/// This is the property the old helper could not guarantee: it returned a
/// *predicted* port, so a test could dial a port the server never got.
#[tokio::test]
async fn reported_port_is_the_port_the_server_listens_on() {
    let bound = support::start_bound_dns_server(|_| {}).await;

    assert_ne!(bound.port, 0, "a bound server must hold a real port");
    assert!(
        bound.port > 1024,
        "ephemeral port expected, got {}",
        bound.port
    );

    let connect = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", bound.port)).await;
    assert!(
        connect.is_ok(),
        "server must be listening on the reported port {}: {:?}",
        bound.port,
        connect.err()
    );
}

/// A lost bind race is recognized, and nothing else is.
///
/// Both `AddrInUse` shapes count: a UDP bind that lost, and a UDP bind that
/// succeeded while the TCP bind on the same port lost.
#[test]
fn bind_conflict_discrimination_matches_only_addr_in_use_binds() {
    let udp_conflict = format!("{BIND_UDP_PREFIX} Address already in use (os error 98)");
    let tcp_conflict = format!("{BIND_TCP_PREFIX} Address already in use (os error 48)");
    assert!(is_bind_conflict(&udp_conflict), "UDP AddrInUse must retry");
    assert!(is_bind_conflict(&tcp_conflict), "TCP AddrInUse must retry");

    // Real startup errors that are not port conflicts: retrying these would
    // mask a genuine failure behind eight doomed attempts.
    let zero_port = "Invalid authoritative bind address: port cannot be zero".to_string();
    let anycast =
        "Anycast requires mesh feature (not available in extracted dns crate)".to_string();
    let bind_denied = format!("{BIND_UDP_PREFIX} Permission denied (os error 13)");
    let bind_other = format!("{BIND_UDP_PREFIX} Address not available (os error 99)");

    assert!(!is_bind_conflict(&zero_port), "zero port must not retry");
    assert!(
        !is_bind_conflict(&anycast),
        "anycast rejection must not retry"
    );
    assert!(!is_bind_conflict(&bind_denied), "EACCES must not retry");
    assert!(
        !is_bind_conflict(&bind_other),
        "EADDRNOTAVAIL must not retry"
    );

    // A non-bind error that merely mentions the address-in-use text.
    let unrelated =
        "recursive upstream 127.0.0.1:5353 reported a stale cache entry in use".to_string();
    assert!(
        !is_bind_conflict(&unrelated),
        "only the two bind prefixes may classify a conflict"
    );
}

/// The prefixes the discrimination keys on must still exist in the source.
///
/// Without this, renaming either `map_err` prefix in `startup.rs` would turn
/// every conflict into a non-retryable error, and the suites would go back to
/// being intermittently red with a much more confusing failure.
#[test]
fn startup_source_still_contains_the_bind_error_prefixes() {
    let source = std::fs::read_to_string("src/server/startup.rs")
        .expect("startup.rs is readable from the package root");

    assert!(
        source.contains(BIND_UDP_PREFIX),
        "startup.rs must still format the UDP bind error as {BIND_UDP_PREFIX:?}"
    );
    assert!(
        source.contains(BIND_TCP_PREFIX),
        "startup.rs must still format the TCP bind error as {BIND_TCP_PREFIX:?}"
    );
}

/// Ten consecutive binds in one process all succeed and all report a port the
/// server actually holds.
#[tokio::test]
async fn repeated_binds_are_deterministic() {
    for attempt in 0..10 {
        let bound = support::start_bound_dns_server(|_| {}).await;

        let connect = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", bound.port)).await;
        assert!(
            connect.is_ok(),
            "attempt {attempt}: reported port {} is not served",
            bound.port
        );

        // Let the listener fully release before the next attempt.
        drop(bound);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A non-bind startup failure propagates instead of being retried away.
///
/// `#[should_panic]` on the exact reason proves the helper did not swallow a
/// real error behind its retry loop.
#[tokio::test]
#[should_panic(expected = "DNS server start failed")]
async fn a_non_bind_startup_error_is_not_retried() {
    let _ = support::start_bound_dns_server(|runtime| {
        runtime.authoritative.anycast =
            synvoid_dns::runtime_config::AnycastRuntimeConfig { enabled: true };
    })
    .await;
}
