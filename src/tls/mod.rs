//! TLS configuration and HTTPS server.
//!
//! Provides TLS config parsing, ACME certificate management, certificate
//! resolution (supporting multiple domains), and the HTTPS listener
//! implementation. Re-exports [`ServerTlsConfig`], [`CertResolver`], and
//! [`HttpsServer`] for convenience.

pub mod acme;
pub mod cert_resolver;
pub mod config;
pub mod server;

pub use cert_resolver::CertResolver;
pub use config::InternalTlsConfig as ServerTlsConfig;
pub use server::HttpsServer;
