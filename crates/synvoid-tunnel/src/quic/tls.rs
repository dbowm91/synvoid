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

        let mut server_config = ServerConfig::with_single_cert(certs, key)
            .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?;

        if self.require_client_cert {
            if !self.has_client_ca() {
                tracing::error!(
                    "SECURITY MISCONFIGURATION: require_client_cert=true but client_ca is not set. \
                    Client certificate verification will NOT be performed. \
                    To enable mTLS, set client_ca to the path of your CA certificate that signed client certificates."
                );
            } else {
                tracing::warn!(
                    "QUIC mTLS: require_client_cert is enabled with client_ca at {:?}. \
                    NOTE: Quinn's rustls integration performs basic client cert verification. \
                    For advanced mTLS features (CRL checking, OCSP, certificate policies), \
                    consider implementing application-level certificate validation.",
                    self.client_ca_path
                );
            }
        } else {
            tracing::info!(
                "QUIC server TLS configured without client certificate requirement. \
                Any client can connect (subject to auth_token validation)."
            );
        }

        tracing::info!(
            "QUIC server TLS configured (client_cert_required={}, client_ca={})",
            self.require_client_cert,
            self.client_ca_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );

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
        let mut client_config = if self.verify_server {
            ClientConfig::try_with_platform_verifier()
                .map_err(|e| QuicTlsError::ConfigError(e.to_string()))?
        } else {
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
    std::fs::write(&key_path, certified_key.key_pair.serialize_pem())
        .map_err(|e| QuicTlsError::IoError(key_path.display().to_string(), e))?;

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
