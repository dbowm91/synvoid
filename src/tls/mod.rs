pub mod server;

// Re-export from extracted crate for backwards compatibility
pub use synvoid_tls::config;
pub use synvoid_tls::cert_resolver;
pub use synvoid_tls::acme;
pub use synvoid_tls::sni_peek;
#[cfg(feature = "dns")]
pub use synvoid_tls::acme_dns;

#[cfg(feature = "dns")]
pub use synvoid_tls::AcmeDnsChallenge;
pub use synvoid_tls::CertResolver;
pub use synvoid_tls::InternalTlsConfig as ServerTlsConfig;
pub use synvoid_tls::AcmeManager;
pub use server::HttpsServer;
