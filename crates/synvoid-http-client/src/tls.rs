//! TLS configuration and certificate handling for upstream HTTP clients.
//!
//! Handles UpstreamTlsConfig, native/webpki root loading, custom CA, skip-verify
//! with HostnameSkippingVerifier, and rustls ClientConfig construction.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::DigitallySignedStruct;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct UpstreamTlsConfig {
    pub verify: bool,
    pub ca_cert_path: Option<String>,
    pub server_name: Option<String>,
    pub skip_verify: bool,
    pub skip_verify_reason: Option<String>,
    pub allow_plaintext: bool,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            ca_cert_path: None,
            server_name: None,
            skip_verify: false,
            skip_verify_reason: None,
            allow_plaintext: false,
        }
    }
}

pub fn upstream_tls_from_site_config(
    config: &synvoid_config::site::UpstreamTlsConfig,
) -> Option<UpstreamTlsConfig> {
    let enabled = config.enabled.unwrap_or(true);
    if !enabled {
        return None;
    }
    let skip_verify = config.skip_verify.unwrap_or(false);
    if skip_verify {
        let reason = config
            .skip_verify_reason
            .as_deref()
            .unwrap_or("none provided");
        tracing::warn!(
            reason,
            "Upstream TLS: skip_verify is ENABLED \u{2014} hostname verification is BYPASSED but chain validation still occurs. Configure skip_verify_reason to document why this is needed."
        );
    }
    Some(UpstreamTlsConfig {
        verify: !skip_verify,
        ca_cert_path: config.ca_cert.clone(),
        server_name: None,
        skip_verify,
        skip_verify_reason: config.skip_verify_reason.clone(),
        allow_plaintext: false,
    })
}

#[derive(Hash, PartialEq, Eq, Clone)]
pub(crate) struct UpstreamTlsConfigHashable {
    pub(crate) verify: bool,
    pub(crate) ca_cert_path: Option<String>,
    pub(crate) server_name: Option<String>,
    pub(crate) skip_verify: bool,
    pub(crate) allow_plaintext: bool,
}

impl From<&UpstreamTlsConfig> for UpstreamTlsConfigHashable {
    fn from(cfg: &UpstreamTlsConfig) -> Self {
        Self {
            verify: cfg.verify,
            ca_cert_path: cfg.ca_cert_path.clone(),
            server_name: cfg.server_name.clone(),
            skip_verify: cfg.skip_verify,
            allow_plaintext: cfg.allow_plaintext,
        }
    }
}

pub(crate) fn load_ca_certs_from_path(
    path: &str,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use rustls_pki_types::pem::PemObject;
    let pem_data = std::fs::read(path)
        .with_context(|| format!("Failed to read CA certificate file: {}", path))?;
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_slice_iter(&pem_data)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse PEM certificates")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path);
    }
    Ok(certs)
}

pub(crate) fn build_tls_config(
    ca_cert_path: Option<&str>,
    skip_verify: bool,
    skip_verify_reason: Option<&str>,
) -> rustls::ClientConfig {
    use rustls::crypto::aws_lc_rs;

    let provider = Arc::new(aws_lc_rs::default_provider());

    // Log crypto provider capabilities at first build
    static PROVIDER_LOGGED: std::sync::Once = std::sync::Once::new();
    PROVIDER_LOGGED.call_once(|| {
        tracing::info!(
            "HTTP client TLS initialized with aws-lc-rs provider (TLS 1.3, \
             PQ support: {})",
            if cfg!(feature = "post-quantum") {
                "enabled"
            } else {
                "not available"
            }
        );
    });

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("failed to set TLS protocol versions");

    if skip_verify {
        let reason = skip_verify_reason.unwrap_or("not specified");
        tracing::warn!(
            reason,
            "TLS hostname verification BYPASSED for upstream — chain validation still occurs. Connection is secure against eavesdropping but NOT against impersonation."
        );

        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            let _ = root_store.add(cert);
        }
        if root_store.is_empty() {
            tracing::warn!("No native root certificates available, falling back to webpki roots");
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        if !native_certs.errors.is_empty() {
            tracing::warn!(
                "Some native root certificates failed to load: {} errors",
                native_certs.errors.len()
            );
        }

        if let Some(ca_path) = ca_cert_path {
            match load_ca_certs_from_path(ca_path) {
                Ok(certs) => {
                    let added = certs.len();
                    for cert in certs {
                        let _ = root_store.add(cert);
                    }
                    tracing::info!("Loaded {} custom CA certificate(s) from {}", added, ca_path);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load custom CA certificates from {}: {}",
                        ca_path,
                        e
                    );
                }
            }
        }

        let inner = WebPkiServerVerifier::builder(Arc::new(root_store))
            .build()
            .expect("failed to build WebPkiServerVerifier");
        let verifier_reason = skip_verify_reason.unwrap_or("not specified");
        let verifier = HostnameSkippingVerifier::new(inner, verifier_reason.to_string());

        let mut config = builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        return config;
    }

    // Try native roots, fall back to webpki
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }
    if root_store.is_empty() {
        tracing::warn!("No native root certificates available, falling back to webpki roots");
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if !native_certs.errors.is_empty() {
        tracing::warn!(
            "Some native root certificates failed to load: {} errors",
            native_certs.errors.len()
        );
    }

    // Load custom CA certificates from file
    if let Some(ca_path) = ca_cert_path {
        match load_ca_certs_from_path(ca_path) {
            Ok(certs) => {
                let added = certs.len();
                for cert in certs {
                    let _ = root_store.add(cert);
                }
                tracing::info!("Loaded {} custom CA certificate(s) from {}", added, ca_path);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load custom CA certificates from {}: {}",
                    ca_path,
                    e
                );
            }
        }
    }

    let mut config = builder
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}

#[derive(Debug)]
pub(crate) struct HostnameSkippingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    skip_reason: String,
}

impl HostnameSkippingVerifier {
    pub(crate) fn new(inner: Arc<WebPkiServerVerifier>, reason: String) -> Self {
        Self {
            inner,
            skip_reason: reason,
        }
    }
}

impl ServerCertVerifier for HostnameSkippingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(scv) => Ok(scv),
            Err(rustls::Error::InvalidCertificate(cert_error)) => {
                if let rustls::CertificateError::NotValidForName = cert_error {
                    tracing::warn!(
                        reason = %self.skip_reason,
                        "Skipping hostname verification for upstream connection"
                    );
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(cert_error))
                }
            }
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_tls_config_default_preserves_defaults() {
        let cfg = UpstreamTlsConfig::default();
        assert_eq!(cfg.verify, true);
        assert_eq!(cfg.skip_verify, false);
        assert_eq!(cfg.allow_plaintext, false);
        assert!(cfg.ca_cert_path.is_none());
        assert!(cfg.server_name.is_none());
        assert!(cfg.skip_verify_reason.is_none());
    }

    #[test]
    fn upstream_tls_from_site_config_returns_none_when_disabled() {
        let site_cfg = synvoid_config::site::UpstreamTlsConfig {
            enabled: Some(false),
            ..Default::default()
        };
        assert!(upstream_tls_from_site_config(&site_cfg).is_none());
    }

    #[test]
    fn upstream_tls_from_site_config_maps_skip_verify_and_reason() {
        let site_cfg = synvoid_config::site::UpstreamTlsConfig {
            enabled: Some(true),
            skip_verify: Some(true),
            skip_verify_reason: Some("test reason".to_string()),
            ..Default::default()
        };
        let cfg = upstream_tls_from_site_config(&site_cfg).unwrap();
        assert_eq!(cfg.skip_verify, true);
        assert_eq!(cfg.verify, false);
        assert_eq!(cfg.skip_verify_reason.as_deref(), Some("test reason"));
        assert!(cfg.ca_cert_path.is_none());
        assert!(cfg.server_name.is_none());
        assert!(!cfg.allow_plaintext);
    }

    #[test]
    fn build_tls_config_default_does_not_panic() {
        // Ensure a CryptoProvider is installed for rustls 0.23+ (aws-lc-rs) before
        // constructing ClientConfig in tests. Safe to call multiple times.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let _ = build_tls_config(None, false, None);
    }

    #[test]
    fn build_tls_config_skip_verify_does_not_panic() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let _ = build_tls_config(None, true, Some("test"));
    }

    #[test]
    fn build_tls_config_invalid_ca_path_does_not_panic() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let _ = build_tls_config(Some("/nonexistent/invalid-ca.pem"), false, None);
    }
}
