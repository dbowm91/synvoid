//! TLS certificate management, ACME protocol, and SNI handling.

pub mod acme;
#[cfg(feature = "dns")]
pub mod acme_dns;
pub mod cert_resolver;
pub mod config;
pub mod sni_peek;

pub use acme::{AcmeError, AcmeManager};
#[cfg(feature = "dns")]
pub use acme_dns::AcmeDnsChallenge;
pub use cert_resolver::{load_cert_from_pem, watch_for_cert_changes, CertResolver};
pub use config::{
    InternalAcmeChallengeType, InternalAcmeConfig, InternalClientAuthConfig, InternalTlsConfig,
};
pub use sni_peek::{compute_ja4, extract_sni, ClientHelloInfo, SniError, SniPeekResult};
