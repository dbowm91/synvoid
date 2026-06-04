use metrics::counter;
use notify::Watcher;
use parking_lot::RwLock;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::version::{TLS12, TLS13};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::SupportedProtocolVersion;
use rustls_pki_types::pem::{self, PemObject};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::config::InternalTlsConfig;

#[derive(Clone)]
pub struct CertResolver {
    certs: Arc<RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
    default_cert: Arc<RwLock<Option<Arc<rustls::sign::CertifiedKey>>>>,
    config: InternalTlsConfig,
    reload_tx: broadcast::Sender<()>,
}

impl std::fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertResolver")
            .field("config", &self.config)
            .finish()
    }
}

impl CertResolver {
    pub fn new(config: InternalTlsConfig) -> Self {
        let (reload_tx, _) = broadcast::channel(16);
        Self {
            certs: Arc::new(RwLock::new(HashMap::new())),
            default_cert: Arc::new(RwLock::new(None)),
            config,
            reload_tx,
        }
    }

    pub fn reload_tx(&self) -> broadcast::Sender<()> {
        self.reload_tx.clone()
    }

    pub fn load_certificates(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cert_path = match &self.config.cert_path {
            Some(p) => p,
            None => return Err("No certificate path configured".into()),
        };

        let key_path = match &self.config.key_path {
            Some(p) => p,
            None => return Err("No key path configured".into()),
        };

        let certs = load_certs(cert_path)?;
        if certs.is_empty() {
            return Err("No certificates found in file".into());
        }

        let key = load_private_key(key_path)?;

        // Validate minimum key strength for security
        self.validate_key_strength(&key)?;

        let provider = default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key.clone_key())
            .map_err(|e| format!("Failed to load private key: {}", e))?;

        let ocsp_response = if self.config.ocsp_stapling_enabled {
            if let Some(ocsp_path) = &self.config.ocsp_response_path {
                match load_ocsp_response(ocsp_path) {
                    Ok(resp) => {
                        tracing::info!("OCSP stapling enabled with response from {:?}", ocsp_path);
                        Some(resp)
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load OCSP response: {}, OCSP stapling disabled",
                            e
                        );
                        None
                    }
                }
            } else {
                tracing::warn!("OCSP stapling enabled but no response path configured");
                None
            }
        } else {
            None
        };

        let certified_key = rustls::sign::CertifiedKey {
            cert: certs,
            key: signing_key,
            ocsp: ocsp_response,
        };

        self.validate_certified_key(&certified_key)?;

        *self.default_cert.write() = Some(Arc::new(certified_key.clone()));

        if let Some(watch_dir) = &self.config.watch_dir {
            if let Err(e) = self.load_certs_from_dir(watch_dir) {
                tracing::warn!("Failed to load certificates from watch directory: {}", e);
            }
        }

        if self.reload_tx.send(()).is_err() {
            counter!("synvoid.tls.reload_events_dropped").increment(1);
            tracing::warn!("Failed to notify TLS reload - receiver dropped");
        }
        Ok(())
    }

    fn validate_certified_key(
        &self,
        certified_key: &rustls::sign::CertifiedKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if certified_key.cert.is_empty() {
            return Err("Certificate chain is empty".into());
        }

        let cert_der = &certified_key.cert[0];
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| format!("Failed to parse certificate: {:?}", e))?;

        let now = std::time::SystemTime::now();
        let not_before =
            std::time::SystemTime::from(cert.tbs_certificate.validity.not_before.to_datetime());
        let not_after =
            std::time::SystemTime::from(cert.tbs_certificate.validity.not_after.to_datetime());

        if now < not_before {
            return Err(format!(
                "Certificate is not yet valid (valid from: {:?})",
                not_before
            )
            .into());
        }

        if now > not_after {
            return Err(format!("Certificate has expired (expired at: {:?})", not_after).into());
        }

        tracing::debug!(
            "Certificate validated: subject={:?}, valid_until={:?}",
            cert.tbs_certificate.subject,
            not_after
        );

        Ok(())
    }

    fn validate_key_strength(
        &self,
        key: &PrivateKeyDer<'_>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::PublicKeyParts;

        match key {
            PrivateKeyDer::Pkcs1(pkcs1) => {
                let der = pkcs1.secret_pkcs1_der();
                let mod_len = der.len();
                let rough_bits = mod_len.saturating_sub(10).saturating_mul(8);
                if rough_bits < 2048 {
                    return Err(
                        format!("RSA key too weak: ~{} bits (minimum 2048)", rough_bits).into(),
                    );
                }
                if rough_bits < 3072 {
                    tracing::warn!("RSA key uses ~{} bits (3072+ recommended)", rough_bits);
                } else {
                    tracing::debug!("RSA key validated: ~{} bits", rough_bits);
                }
            }
            PrivateKeyDer::Sec1(_sec1) => {
                tracing::debug!("SEC1 key validated (EC keys are >= 160 bits, inherently strong)");
            }
            PrivateKeyDer::Pkcs8(pkcs8) => {
                let der = pkcs8.secret_pkcs8_der();
                if let Ok(rsa_key) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
                    let bits = rsa_key.n().bits();
                    if bits < 2048 {
                        return Err(
                            format!("RSA key too weak: {} bits (minimum 2048)", bits).into()
                        );
                    }
                    if bits < 3072 {
                        tracing::warn!("RSA key uses {} bits (3072+ recommended)", bits);
                    } else {
                        tracing::debug!("RSA PKCS#8 key validated: {} bits", bits);
                    }
                } else {
                    tracing::debug!("Non-RSA PKCS#8 key validated (Ed25519/EC)");
                }
            }
            _ => {
                tracing::debug!("Unknown key type, skipping strength validation");
            }
        }
        Ok(())
    }

    fn load_certs_from_dir(
        &self,
        dir: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "pem").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    if let Some(domain) = stem.to_str() {
                        if let Ok(certs) = load_certs(&path) {
                            let key_path = path.with_extension("key");
                            if key_path.exists() {
                                if let Ok(key) = load_private_key(&key_path) {
                                    if let Err(e) = self.validate_key_strength(&key) {
                                        tracing::warn!(
                                            "Certificate for domain '{}' rejected: {}",
                                            domain,
                                            e
                                        );
                                        continue;
                                    }
                                    let provider = default_provider();
                                    if let Ok(signing_key) =
                                        provider.key_provider.load_private_key(key)
                                    {
                                        let certified_key =
                                            rustls::sign::CertifiedKey::new(certs, signing_key);
                                        self.certs
                                            .write()
                                            .insert(domain.to_string(), Arc::new(certified_key));
                                        tracing::info!("Loaded certificate for domain: {}", domain);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn build_server_config(
        &self,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let provider = default_provider();

        if self.config.prefer_post_quantum {
            tracing::debug!("TLS: post-quantum hybrid key exchange enabled (TLS 1.3)");
            counter!("synvoid.tls.post_quantum").increment(1);
        }

        let versions: &[&SupportedProtocolVersion] = if self.config.tls_1_3_only {
            tracing::info!("TLS: enforcing TLS 1.3 only (secure mode)");
            counter!("synvoid.tls.config").increment(1);
            &[&TLS13]
        } else if self.config.enable_tls_12_fallback {
            tracing::info!("TLS: allowing TLS 1.2 and TLS 1.3 (fallback enabled)");
            counter!("synvoid.tls.config", "mode" => "fallback_enabled").increment(1);
            tracing::warn!(
                "TLS 1.2 enabled with fallback. CBC cipher suites are vulnerable to BEAST attacks. \
                For secure environments, use tls_1_3_only = true or configure custom cipher suites."
            );
            &[&TLS13, &TLS12]
        } else {
            tracing::warn!(
                "TLS: allowing TLS 1.2 and TLS 1.3 (backward compatibility mode). \
                CBC cipher suites (TLS 1.2) are vulnerable to BEAST attacks. \
                For production, set tls_1_3_only = true to enforce TLS 1.3 only."
            );
            counter!("synvoid.tls.config", "mode" => "backward_compat").increment(1);
            &[&TLS13, &TLS12]
        };

        // Configure client authentication (mTLS) if enabled
        if self.config.client_auth.enabled {
            if let Some(ref ca_cert_path) = self.config.client_auth.ca_cert_path {
                let ca_certs = load_ca_certs(ca_cert_path)?;
                if !ca_certs.is_empty() {
                    // For proper mTLS, use the CA certs to verify clients
                    let verifier = rustls::server::WebPkiClientVerifier::builder(
                        std::sync::Arc::new(ca_certs),
                    )
                    .build()
                    .map_err(|e| format!("Failed to build client cert verifier: {}", e))?;

                    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
                        .with_protocol_versions(versions)
                        .map_err(|e| format!("Failed to set protocol versions: {}", e))?
                        .with_client_cert_verifier(verifier)
                        .with_cert_resolver(Arc::new(self.clone()));

                    tracing::info!("mTLS enabled with CA certificate: {:?}", ca_cert_path);
                    return Ok(Arc::new(server_config));
                } else {
                    return Err("No CA certificates found for client authentication".into());
                }
            } else {
                return Err("CA certificate path not configured for client authentication".into());
            }
        }

        // Default: no client authentication (server-only TLS)
        let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(versions)
            .map_err(|e| format!("Failed to set protocol versions: {}", e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(self.clone()));

        Ok(Arc::new(server_config))
    }
}

impl rustls::server::ResolvesServerCert for CertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(sni) = client_hello.server_name() {
            let certs = self.certs.read();

            if let Some(cert) = certs.get(sni) {
                return Some(cert.clone());
            }

            if let Some(dot_pos) = sni.find('.') {
                let wildcard_key = format!("*.{}", &sni[dot_pos + 1..]);
                if let Some(cert) = certs.get(&wildcard_key) {
                    return Some(cert.clone());
                }
            }
        }

        self.default_cert.read().as_ref().cloned()
    }
}

fn load_certs(
    path: &PathBuf,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut certs = Vec::new();
    while let Ok(Some((kind, der))) = pem::from_buf(&mut reader) {
        if kind == pem::SectionKind::Certificate {
            certs.push(CertificateDer::from(der));
        }
    }

    if certs.is_empty() {
        return Err("No certificates found in file".into());
    }

    Ok(certs)
}

fn load_private_key(
    path: &PathBuf,
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    while let Some((kind, der)) = pem::from_buf(&mut reader)? {
        if kind == pem::SectionKind::PrivateKey
            || kind == pem::SectionKind::EcPrivateKey
            || kind == pem::SectionKind::RsaPrivateKey
        {
            if let Some(key) = PrivateKeyDer::from_pem(kind, der) {
                return Ok(key);
            }
        }
    }

    Err("No private key found in file".into())
}

fn load_ca_certs(path: &Path) -> Result<RootCertStore, Box<dyn std::error::Error + Send + Sync>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    let mut certs = Vec::new();
    while let Ok(Some((kind, der))) = pem::from_buf(&mut reader) {
        if kind == pem::SectionKind::Certificate {
            certs.push(CertificateDer::from(der));
        }
    }

    if certs.is_empty() {
        return Err("No CA certificates found in file".into());
    }

    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| format!("Failed to add CA certificate: {}", e))?;
    }

    Ok(store)
}

pub fn load_cert_from_pem(
    pem_data: &[u8],
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(pem_data);

    let mut certs = Vec::new();
    while let Ok(Some((kind, der))) = pem::from_buf(&mut reader) {
        if kind == pem::SectionKind::Certificate {
            certs.push(CertificateDer::from(der));
        }
    }

    if certs.is_empty() {
        return Err("No certificates found in PEM data".into());
    }

    Ok(certs)
}

fn load_ocsp_response(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    const MAX_OCSP_SIZE: usize = 256 * 1024; // 256KB max

    let ocsp_data = std::fs::read(path)?;

    if ocsp_data.is_empty() {
        return Err("OCSP response file is empty".into());
    }

    if ocsp_data.len() > MAX_OCSP_SIZE {
        return Err(format!(
            "OCSP response exceeds maximum size of {} bytes",
            MAX_OCSP_SIZE
        )
        .into());
    }

    tracing::debug!("Loaded OCSP response: {} bytes", ocsp_data.len());

    Ok(ocsp_data)
}

pub fn watch_for_cert_changes(
    resolver: Arc<CertResolver>,
    watch_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);

        let mut watcher =
            match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if res.is_ok() {
                    let _ = tx.blocking_send(());
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

        if let Err(e) = watcher.watch(watch_dir.as_path(), notify::RecursiveMode::Recursive) {
            tracing::error!("Failed to watch certificate directory: {}", e);
            return;
        }

        tracing::info!("Watching for certificate changes in {:?}", watch_dir);

        loop {
            let mut needs_reload = tokio::select! {
                Some(_) = rx.recv() => true,
                _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {
                    tracing::debug!("Certificate watcher heartbeat");
                    false
                }
            };

            while needs_reload {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                while rx.try_recv().is_ok() {}
                tracing::info!("Certificate change detected, reloading...");
                match resolver.load_certificates() {
                    Err(e) => {
                        tracing::error!("Failed to reload certificates: {}", e);
                    }
                    _ => {
                        tracing::info!("Certificates reloaded successfully");
                    }
                }
                needs_reload = rx.try_recv().is_ok();
            }
        }
    })
}
