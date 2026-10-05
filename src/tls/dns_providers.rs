//! Composition-owned adapters implementing the DNS encrypted-transport
//! capabilities over the concrete `synvoid-tls` providers (Phase 134).
//!
//! `synvoid-dns` declares `SecureTransportConfig` and `AcmeTxtChallenges` and
//! knows nothing about certificates. This module is where the two meet: it is
//! the only place in the tree that knows a `CertResolver` produces a
//! `rustls::ServerConfig` and that an `AcmeDnsChallenge` holds a TXT value.
//!
//! Both adapters are thin and hold an `Arc` to the provider, so cloning one is
//! cheap and the certificate state stays shared. That matters: Phase 133 proved
//! a certificate reload is visible through an already-built `ServerConfig`
//! precisely because the provider's state is interior-mutable behind the
//! `Arc`. Building a fresh snapshot per call would break reload.

use std::sync::Arc;

use synvoid_dns::secure_transport::{AcmeTxtChallenges, SecureTransportConfig};

/// Adapts a `CertResolver` to the DNS-owned `SecureTransportConfig`.
///
/// The error mapping is the whole point of this adapter: DNS wants a `String`
/// so the listeners can keep reporting
/// `"Failed to build TLS config: {e}"` verbatim, and the provider's own text
/// has to survive that trip. Wrapping it here, once, is what lets the DNS side
/// stay a pass-through.
#[derive(Clone)]
pub struct CertResolverTransport {
    resolver: Arc<synvoid_tls::CertResolver>,
}

impl CertResolverTransport {
    pub fn new(resolver: Arc<synvoid_tls::CertResolver>) -> Self {
        Self { resolver }
    }

    /// The wrapped provider, for the root's own TLS server which still needs
    /// the concrete type.
    pub fn resolver(&self) -> &Arc<synvoid_tls::CertResolver> {
        &self.resolver
    }
}

impl SecureTransportConfig for CertResolverTransport {
    fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        self.resolver
            .build_server_config()
            .map_err(|e| e.to_string())
    }
}

/// Adapts an `AcmeDnsChallenge` to the DNS-owned `AcmeTxtChallenges`.
#[derive(Clone)]
pub struct AcmeChallengeLookup {
    challenges: Arc<synvoid_tls::AcmeDnsChallenge>,
}

impl AcmeChallengeLookup {
    pub fn new(challenges: Arc<synvoid_tls::AcmeDnsChallenge>) -> Self {
        Self { challenges }
    }

    /// The wrapped provider, for root code that still needs the concrete type.
    pub fn challenges(&self) -> &Arc<synvoid_tls::AcmeDnsChallenge> {
        &self.challenges
    }
}

impl AcmeTxtChallenges for AcmeChallengeLookup {
    fn txt_value(&self, domain: &str) -> Option<String> {
        self.challenges.get_txt_value(domain)
    }
}

/// Wrap a provider handle for the DNS encrypted-transport stack.
///
/// A `None` resolver stays `None`: the DNS listeners report
/// "No TLS certificate resolver available", and a disabled TLS section must not
/// be turned into a provider that fails for a different reason.
pub fn as_transport(
    resolver: Option<Arc<synvoid_tls::CertResolver>>,
) -> Option<Arc<dyn SecureTransportConfig>> {
    resolver.map(|resolver| {
        Arc::new(CertResolverTransport::new(resolver)) as Arc<dyn SecureTransportConfig>
    })
}

/// Wrap pending ACME DNS-01 challenges for the DNS query path.
///
/// Takes the provider directly rather than an `Option`: the only caller already
/// established that a challenge set exists, and `with_acme_dns_challenges` takes
/// a bare `Arc`. Absence is expressed at the call site by not calling this.
pub fn as_acme_challenges(
    challenges: Arc<synvoid_tls::AcmeDnsChallenge>,
) -> Arc<dyn AcmeTxtChallenges> {
    Arc::new(AcmeChallengeLookup::new(challenges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_tls::{InternalClientAuthConfig, InternalTlsConfig};

    fn unconfigured() -> Arc<synvoid_tls::CertResolver> {
        // No certificate or key path: `build_server_config` still succeeds,
        // because the resolver is installed as the cert resolver and only
        // discovers the emptiness when a client offers an SNI.
        Arc::new(synvoid_tls::CertResolver::new(InternalTlsConfig {
            enabled: true,
            prefer_post_quantum: false,
            tls_1_3_only: true,
            ocsp_stapling_enabled: false,
            ..Default::default()
        }))
    }

    #[test]
    fn an_absent_provider_stays_absent() {
        // The DNS listeners distinguish "TLS disabled" from "TLS misconfigured"
        // by this `None`, so the adapter must not invent a failing provider.
        assert!(as_transport(None).is_none());
    }

    #[test]
    fn a_configured_provider_is_wrapped_without_changing_the_outcome() {
        let transport = as_transport(Some(unconfigured())).expect("wrapped");
        assert!(
            transport.server_config().is_ok(),
            "the adapter must reproduce the provider's own outcome"
        );
    }

    #[test]
    fn a_provider_error_survives_as_its_own_text() {
        let resolver = Arc::new(synvoid_tls::CertResolver::new(InternalTlsConfig {
            enabled: true,
            client_auth: InternalClientAuthConfig {
                enabled: true,
                ca_cert_path: None,
            },
            prefer_post_quantum: false,
            tls_1_3_only: true,
            ocsp_stapling_enabled: false,
            ..Default::default()
        }));
        let transport = as_transport(Some(resolver)).expect("wrapped");

        let message = transport
            .server_config()
            .expect_err("client auth without a CA must fail");
        assert_eq!(
            message, "CA certificate path not configured for client authentication",
            "the provider's text must reach the DNS listeners unchanged"
        );
    }

    #[test]
    fn the_acme_adapter_reports_no_pending_challenge() {
        let challenges = Arc::new(synvoid_tls::AcmeDnsChallenge::new());
        let lookup = as_acme_challenges(challenges);
        assert_eq!(lookup.txt_value("example.com"), None);
    }

    #[test]
    fn the_acme_adapter_forwards_a_prepared_challenge() {
        let challenges = Arc::new(synvoid_tls::AcmeDnsChallenge::new());
        let expected = challenges.prepare_challenge("example.com", "key-authorization");
        let lookup = as_acme_challenges(Arc::clone(&challenges));

        assert_eq!(lookup.txt_value("example.com"), Some(expected));
        assert_eq!(lookup.txt_value("other.test"), None);
    }
}
