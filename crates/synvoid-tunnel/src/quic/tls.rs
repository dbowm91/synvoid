#![allow(unused_variables, dead_code, unused_mut)]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::{self, PemObject};

use quinn::{ClientConfig, ServerConfig};

use synvoid_config::TunnelQuicConfig;

#[derive(Debug, Clone)]
pub struct QuicTlsConfig {
    pub server_cert_path: Option<PathBuf>,
    pub server_key_path: Option<PathBuf>,
    pub client_ca_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
    pub server_ca_path: Option<PathBuf>,
    pub require_client_cert: bool,
    pub verify_server: bool,
    pub auto_generate_certs: bool,
    pub cert_domain: Option<String>,
}

impl QuicTlsConfig {
    pub fn from_config(config: &TunnelQuicConfig) -> Self {
        Self {
            server_cert_path: config.cert_path.as_ref().map(PathBuf::from),
            server_key_path: config.key_path.as_ref().map(PathBuf::from),
            client_ca_path: config.client_ca.as_ref().map(PathBuf::from),
            client_cert_path: config.client.client_cert_path.as_ref().map(PathBuf::from),
            client_key_path: config.client.client_key_path.as_ref().map(PathBuf::from),
            server_ca_path: config.client.server_ca.as_ref().map(PathBuf::from),
            require_client_cert: config.server.require_client_cert,
            verify_server: config.client.verify_server,
            auto_generate_certs: config.auto_generate_certs,
            cert_domain: config.cert_domain.clone(),
        }
    }

    pub fn has_server_certs(&self) -> bool {
        self.server_cert_path.is_some() && self.server_key_path.is_some()
    }

    pub fn has_client_certs(&self) -> bool {
        self.client_cert_path.is_some() && self.client_key_path.is_some()
    }

    pub fn has_client_ca(&self) -> bool {
        self.client_ca_path.is_some()
    }

    pub fn has_server_ca(&self) -> bool {
        self.server_ca_path.is_some()
    }

    pub fn ensure_certs(&mut self) -> Result<(), QuicTlsError> {
        if self.auto_generate_certs && !self.has_server_certs() {
            tracing::warn!(
                "SECURITY WARNING: Auto-generating self-signed certificates. \
                This is insecure for production use and should only be used in development/testing. \
                Configure proper TLS certificates via cert_path and key_path for production."
            );

            let domain = self.cert_domain.as_deref().unwrap_or("synvoid-tunnel");
            let cert_dir = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("certs");

            std::fs::create_dir_all(&cert_dir)
                .map_err(|e| QuicTlsError::IoError(cert_dir.display().to_string(), e))?;

            let (cert_path, key_path) = generate_self_signed_cert(domain, &cert_dir)?;

            self.server_cert_path = Some(cert_path);
            self.server_key_path = Some(key_path);

            tracing::info!("Auto-generated self-signed certificate for {}", domain);
        }
        Ok(())
    }

    pub fn build_server_config(&self) -> Result<ServerConfig, QuicTlsError> {
        let cert_path = self
            .server_cert_path
            .as_ref()
            .ok_or(QuicTlsError::MissingServerCert)?;
        let key_path = self
            .server_key_path
            .as_ref()
            .ok_or(QuicTlsError::MissingServerKey)?;

        let certs = load_certs(cert_path)?;
        let key = load_private_key(key_path)?;

        // `require_client_cert` used to only log a warning: no client
        // verifier was installed, so the server accepted any peer while the
        // logs claimed mutual TLS. Install a real verifier, and fail closed
        // when the CA needed to check peers was not configured.
        let server_config = if self.require_client_cert {
            let ca_path = self.client_ca_path.as_ref().ok_or_else(|| {
                QuicTlsError::ConfigError(
                    "require_client_cert = true needs client_ca to verify peer certificates"
                        .to_string(),
                )
            })?;
            let roots = load_roots(ca_path)?;
            // Use the explicit provider: `WebPkiClientVerifier::builder`
            // resolves the process-default provider and panics when the crate
            // feature set cannot pick one, which killed the worker at startup.
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;
            let tls = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;
            let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;
            ServerConfig::with_crypto(Arc::new(quic))
        } else {
            ServerConfig::with_single_cert(certs, key)
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?
        };

        if self.require_client_cert {
            tracing::info!(
                "QUIC mTLS enforced: peer certificates are verified against {:?}",
                self.client_ca_path
            );
        } else {
            tracing::info!(
                "QUIC server TLS configured without client certificate requirement. \
                 Any client can connect (subject to auth_token validation)."
            );
        }

        Ok(server_config)
    }

    pub fn build_client_config(
        &self,
        server_name: Option<&str>,
    ) -> Result<ClientConfig, QuicTlsError> {
        self.build_client_config_with_transport(server_name, None)
    }

    pub fn build_client_config_with_transport(
        &self,
        server_name: Option<&str>,
        transport_config: Option<Arc<quinn::TransportConfig>>,
    ) -> Result<ClientConfig, QuicTlsError> {
        if !self.verify_server {
            if let Some(name) = server_name {
                tracing::warn!(
                    "TLS server verification DISABLED for {}. This is insecure!",
                    name
                );
            }
            return Err(QuicTlsError::ConfigError(
                "Server certificate verification must be enabled in current quinn version. \
                 Set verify_server: true in config."
                    .to_string(),
            ));
        }

        // A configured `server_ca` is the trust anchor. Using the platform
        // verifier unconditionally made a private CA (and therefore mesh,
        // whose peers are issued by the operator's CA) impossible to trust.
        let mut client_config = match self.server_ca_path.as_ref() {
            Some(ca_path) => {
                let roots = load_roots(ca_path)?;
                let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let builder = rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?
                    .with_root_certificates(roots);

                // The peer may require mutual TLS; present this node's
                // certificate. Quinn's platform-verifier convenience
                // constructor cannot carry client auth, which is why the CA
                // path builds the rustls config explicitly.
                let tls = match (
                    self.client_cert_path.as_ref(),
                    self.client_key_path.as_ref(),
                ) {
                    (Some(cert_path), Some(key_path)) => {
                        let certs = load_certs(cert_path)?;
                        let key = load_private_key(key_path)?;
                        builder
                            .with_client_auth_cert(certs, key)
                            .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?
                    }
                    _ => builder.with_no_client_auth(),
                };

                let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                    .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;
                ClientConfig::new(Arc::new(quic_tls))
            }
            None => ClientConfig::try_with_platform_verifier()
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?,
        };

        if let Some(transport) = transport_config {
            client_config.transport_config(transport);
        }

        if let Some(name) = server_name {
            tracing::debug!(
                "QUIC client connecting with server_name: {} (verification enabled)",
                name
            );
        }

        Ok(client_config)
    }

    pub fn server_cert_path(&self) -> Option<&PathBuf> {
        self.server_cert_path.as_ref()
    }
}

fn load_roots(path: &PathBuf) -> Result<rustls::RootCertStore, QuicTlsError> {
    let certs = load_certs(path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(QuicTlsError::NoCertificates(path.display().to_string()));
    }
    Ok(roots)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>, QuicTlsError> {
    let file =
        File::open(path).map_err(|e| QuicTlsError::IoError(path.display().to_string(), e))?;
    let mut reader = BufReader::new(file);

    let mut certs = Vec::new();
    while let Ok(Some((kind, der))) = pem::from_buf(&mut reader) {
        if kind == pem::SectionKind::Certificate {
            certs.push(CertificateDer::from(der));
        }
    }

    if certs.is_empty() {
        return Err(QuicTlsError::NoCertificates(path.display().to_string()));
    }

    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>, QuicTlsError> {
    let file =
        File::open(path).map_err(|e| QuicTlsError::IoError(path.display().to_string(), e))?;
    let mut reader = BufReader::new(file);

    while let Some((kind, der)) =
        pem::from_buf(&mut reader).map_err(|e| QuicTlsError::ParseError(e.to_string()))?
    {
        if kind == pem::SectionKind::PrivateKey
            || kind == pem::SectionKind::EcPrivateKey
            || kind == pem::SectionKind::RsaPrivateKey
        {
            if let Some(key) = PrivateKeyDer::from_pem(kind, der) {
                return Ok(key);
            }
        }
    }

    Err(QuicTlsError::NoPrivateKey(path.display().to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum QuicTlsError {
    #[error("Missing server certificate path")]
    MissingServerCert,
    #[error("Missing server key path")]
    MissingServerKey,
    #[error("Missing client CA path (required when require_client_cert is true)")]
    MissingClientCa,
    #[error("IO error reading {0}: {1}")]
    IoError(String, std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("No certificates found in {0}")]
    NoCertificates(String),
    #[error("No private key found in {0}")]
    NoPrivateKey(String),
    #[error("TLS config error: {0}")]
    ConfigError(String),
}

pub fn generate_self_signed_cert(
    cn: &str,
    output_dir: &PathBuf,
) -> Result<(PathBuf, PathBuf), QuicTlsError> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec![cn.to_string()];
    let certified_key = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;

    let cert_path = output_dir.join(format!("{}.crt", cn.replace(['*', '.'], "_")));
    let key_path = output_dir.join(format!("{}.key", cn.replace(['*', '.'], "_")));

    std::fs::write(&cert_path, certified_key.cert.pem())
        .map_err(|e| QuicTlsError::IoError(cert_path.display().to_string(), e))?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut key_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|e| QuicTlsError::IoError(key_path.display().to_string(), e))?;
        key_file
            .write_all(certified_key.key_pair.serialize_pem().as_bytes())
            .map_err(|e| QuicTlsError::IoError(key_path.display().to_string(), e))?;
        key_file
            .sync_all()
            .map_err(|e| QuicTlsError::IoError(key_path.display().to_string(), e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, certified_key.key_pair.serialize_pem())
            .map_err(|e| QuicTlsError::IoError(key_path.display().to_string(), e))?;
        let _ = synvoid_platform::fs::set_file_permissions(&key_path, false);
    }

    tracing::info!(
        "Generated self-signed certificate for {} in {:?}",
        cn,
        output_dir
    );

    Ok((cert_path, key_path))
}

pub fn generate_client_cert(
    _client_id: &str,
    _ca_cert_path: &PathBuf,
    _ca_key_path: &PathBuf,
    _output_dir: &PathBuf,
) -> Result<(PathBuf, PathBuf), QuicTlsError> {
    Err(QuicTlsError::ConfigError(
        "Client certificate signing requires CA - use external tools".to_string(),
    ))
}
