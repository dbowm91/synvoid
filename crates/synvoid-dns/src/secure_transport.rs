//! DNS-owned capabilities that the encrypted-transport stack needs from a
//! provider (Phase 134).
//!
//! Phase 133 proved the `synvoid-tls` seam is exactly two provider types with
//! one method each, and narrower than the Phase 130 record claimed: DNS holds
//! a `CertResolver` only to obtain a built rustls `ServerConfig`, and an
//! `AcmeDnsChallenge` only to read a pending TXT value. Neither provider's
//! state, configuration, or types need to cross the boundary.
//!
//! The traits below are therefore DNS-owned and name no `synvoid-tls` type.
//! They are implemented in a composition root over the concrete providers, and
//! `synvoid-dns` no longer depends on `synvoid-tls` at all.
//!
//! ## Why the error type is `String`
//!
//! The call sites already flatten a provider error into
//! `"Failed to build TLS config: {e}"`, and the DNS listeners surface that
//! text to the operator at startup. Returning `String` keeps the existing
//! messages byte for byte, which is what the Phase 133 evidence suites pin.
//! Widening this to a typed error is a separate change, not an inversion.

use std::sync::Arc;

/// Supplies a rustls server configuration for the encrypted DNS listeners.
///
/// The returned `ServerConfig` is a rustls type, not a SynVoid type, and is
/// exactly what `tokio_rustls::TlsAcceptor::from` and
/// `quinn::crypto::rustls::QuicServerConfig::try_from` consume.
///
/// ## Contract the implementer must preserve
///
/// The implementation is expected to be cheap to clone and to share its
/// certificate state behind an `Arc`, because a reload must be visible through
/// an **already-built** `ServerConfig` rather than requiring a rebuild. Phase
/// 133 proved that is how `CertResolver` behaves, and
/// `a_reload_is_visible_through_an_already_built_server_config` pins it. An
/// implementation that caches a snapshot per call would silently break
/// certificate reload for DoT, DoH, and DoQ.
///
/// Implementations own certificate material end to end. Private keys are read,
/// validated, and loaded inside the provider and never appear in DNS.
pub trait SecureTransportConfig: Send + Sync {
    /// Build a server configuration, or fail with an operator-readable message.
    fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String>;
}

/// Reads a pending ACME DNS-01 challenge value (RFC 8555 §8.4).
///
/// `None` means "no challenge is pending for this domain", which is the normal
/// answer for the overwhelming majority of queries. Callers must not treat it
/// as an error.
pub trait AcmeTxtChallenges: Send + Sync {
    /// The TXT value to serve for `_acme-challenge.{domain}`, if one is pending.
    fn txt_value(&self, domain: &str) -> Option<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both traits are object safe and usable as `Arc<dyn Trait>`, which is the
    /// shape every call site uses. If either stopped being dyn compatible this
    /// would fail to compile here rather than at every field.
    #[test]
    fn both_capabilities_are_usable_as_trait_objects() {
        let transport: Arc<dyn SecureTransportConfig> = Arc::new(Unbuildable);
        let acme: Arc<dyn AcmeTxtChallenges> = Arc::new(Empty);

        assert!(transport.server_config().is_err());
        assert_eq!(acme.txt_value("example.com"), None);
    }

    struct Unbuildable;

    impl SecureTransportConfig for Unbuildable {
        fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
            Err("no certificates configured".to_string())
        }
    }

    struct Empty;

    impl AcmeTxtChallenges for Empty {
        fn txt_value(&self, _domain: &str) -> Option<String> {
            None
        }
    }
}
