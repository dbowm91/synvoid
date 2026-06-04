//! TLS certificate management, ACME protocol, and SNI handling.

pub mod config;
pub mod cert_resolver;
pub mod acme;
#[cfg(feature = "dns")]
pub mod acme_dns;
pub mod sni_peek;

pub use config::{InternalAcmeConfig, InternalAcmeChallengeType, InternalClientAuthConfig, InternalTlsConfig};
pub use cert_resolver::{CertResolver, load_cert_from_pem, watch_for_cert_changes};
pub use acme::{AcmeManager, AcmeError};
#[cfg(feature = "dns")]
pub use acme_dns::AcmeDnsChallenge;
pub use sni_peek::{extract_sni, compute_ja4, SniError, SniPeekResult, ClientHelloInfo};
