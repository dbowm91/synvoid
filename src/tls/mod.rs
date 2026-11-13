//! Transitional compatibility surface for `synvoid_tls`.
//!
//! Core TLS/ACME implementation lives in the `synvoid_tls` crate. This root
//! module still exposes a local `server` submodule (`HttpsServer`) that depends
//! on root HTTP infrastructure. See `architecture/root_module_ledger.md` before
//! adding new implementation here.

pub mod server;

// Composition-owned adapters bridging `synvoid-tls` providers to the
// DNS-owned encrypted-transport capabilities (Phase 134).
#[cfg(feature = "dns")]
pub mod dns_providers;

// Re-export from extracted crate for backwards compatibility
pub use synvoid_tls::acme;
#[cfg(feature = "dns")]
pub use synvoid_tls::acme_dns;
pub use synvoid_tls::cert_resolver;
pub use synvoid_tls::config;
pub use synvoid_tls::sni_peek;

pub use server::HttpsServer;
#[cfg(feature = "dns")]
pub use synvoid_tls::AcmeDnsChallenge;
pub use synvoid_tls::AcmeManager;
pub use synvoid_tls::CertResolver;
pub use synvoid_tls::InternalTlsConfig as ServerTlsConfig;

/// Select the process-wide rustls crypto provider.
///
/// Several rustls builders (including `WebPkiClientVerifier::builder`) resolve
/// the process default and panic when the crate feature set cannot pick one.
/// Call this once at process start, before any consumer builds a TLS config.
pub fn install_process_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}
