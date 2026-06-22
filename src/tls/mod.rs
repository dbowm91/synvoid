//! Transitional compatibility surface for `synvoid_tls`.
//!
//! Core TLS/ACME implementation lives in the `synvoid_tls` crate. This root
//! module still exposes a local `server` submodule (`HttpsServer`) that depends
//! on root HTTP infrastructure. See `architecture/root_module_ledger.md` before
//! adding new implementation here.

pub mod server;

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
