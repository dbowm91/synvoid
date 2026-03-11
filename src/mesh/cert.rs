#![allow(unused_variables, unused_mut)]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, Verifier};
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{ClientConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::{self, PemObject};
use subtle::ConstantTimeEq;

use crate::mesh::config::MeshConfig;

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

    loop {
        match pem::from_buf(&mut reader)? {
            Some((kind, der)) => {
                if kind == pem::SectionKind::PrivateKey
                    || kind == pem::SectionKind::EcPrivateKey
                    || kind == pem::SectionKind::RsaPrivateKey
                    || kind == pem::SectionKind::PrivateKey
                    || kind == pem::SectionKind::EcPrivateKey
                    || kind == pem::SectionKind::RsaPrivateKey
                {
                    if let Some(key) = PrivateKeyDer::from_pem(kind, der) {
                        return Ok(key);
                    }
                }
            }
            None => break,
        }
    }

    Err("No private key found in file".into())
}

type HmacSha256 = Hmac<sha2::Sha256>;
type HmacSha3_256 = Hmac<sha3::Sha3_256>;

#[cfg(feature = "audit")]
use chrono::Utc;

#[cfg(feature = "verify-pq")]
pub fn verify_post_quantum_tls() {
    use rustls::crypto::CryptoProvider;

    let provider = match CryptoProvider::get_default() {
        Some(p) => p,
        None => {
            tracing::error!("[PQ-VERIFY] No default crypto provider found!");
            return;
        }
    };

    let group_count = provider.kx_groups.len();
    tracing::info!(
        "[PQ-VERIFY] TLS crypto provider has {} key exchange groups available",
        group_count
    );

    let mut pq_available = false;
    let mut has_x25519 = false;

    for (idx, group) in provider.kx_groups.iter().enumerate() {
        let group_name = format!("{:?}", group);
        let is_pq = group_name.contains("MLKEM")
            || group_name.contains("mlkem")
            || group_name.contains("Kyber")
            || group_name.contains("kyber");
        let is_x25519 = group_name.contains("X25519") || group_name.contains("x25519");

        if is_pq {
            pq_available = true;
            tracing::info!("[PQ-VERIFY] [{}] POST-QUANTUM KEX: {}", idx, group_name);
        } else if is_x25519 {
            has_x25519 = true;
            tracing::info!("[PQ-VERIFY] [{}] Classical KEX: {}", idx, group_name);
        } else {
            tracing::debug!("[PQ-VERIFY] [{}] KEX: {}", idx, group_name);
        }
    }

    if pq_available {
        tracing::info!(
            "[PQ-VERIFY] POST-QUANTUM TLS IS ACTIVE - Mesh connections will use hybrid KEX"
        );
    } else {
        tracing::warn!(
            "[PQ-VERIFY] POST-QUANTUM NOT AVAILABLE - Using classical cryptography only"
        );
    }

    if !has_x25519 && !pq_available {
        tracing::error!("[PQ-VERIFY] CRITICAL: No X25519 or PQ KEX groups found!");
    }
}

#[derive(Debug, Clone)]
pub struct MeshCertManager {
    node_id: String,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    auto_generate: bool,
    is_global: bool,
    verified_nodes: Arc<RwLock<std::collections::HashSet<String>>>,
    global_node_public_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    trusted_ca_certs: Arc<RwLock<std::collections::HashMap<String, CertificateDer<'static>>>>,
    node_private_key: Arc<RwLock<Option<PrivateKeyDer<'static>>>>,
    cert_rotation_interval: Arc<RwLock<Option<std::time::Duration>>>,
    cert_expiration_monitor: Arc<RwLock<Option<std::time::Instant>>>,
    certificate_revocation_list: Arc<RwLock<std::collections::HashSet<String>>>,
}

impl MeshCertManager {
    pub fn new(config: &MeshConfig) -> Self {
        let is_global = config.role.is_global();
        let cert_rotation_interval = config
            .tls
            .cert_rotation_interval_secs
            .map(|secs| std::time::Duration::from_secs(secs));
        let cert_expiration_monitor = if config.tls.auto_monitor_expiration {
            Some(std::time::Instant::now())
        } else {
            None
        };

        Self {
            node_id: config.node_id(),
            cert_path: config.tls.cert_path.as_ref().map(PathBuf::from),
            key_path: config.tls.key_path.as_ref().map(PathBuf::from),
            ca_path: config.tls.ca_path.as_ref().map(PathBuf::from),
            auto_generate: config.tls.auto_generate_certs && !is_global,
            is_global,
            verified_nodes: Arc::new(RwLock::new(std::collections::HashSet::new())),
            global_node_public_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            trusted_ca_certs: Arc::new(RwLock::new(std::collections::HashMap::new())),
            node_private_key: Arc::new(RwLock::new(None)),
            cert_rotation_interval: Arc::new(RwLock::new(cert_rotation_interval)),
            cert_expiration_monitor: Arc::new(RwLock::new(cert_expiration_monitor)),
            certificate_revocation_list: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[cfg(feature = "verify-pq")]
    pub fn verify_post_quantum(&self) {
        verify_post_quantum_tls();
    }

    #[cfg(not(feature = "verify-pq"))]
    pub fn verify_post_quantum(&self) {
        // No-op when verify-pq feature is not enabled
    }

    pub fn ensure_certs(&mut self) -> Result<(), MeshCertError> {
        if self.auto_generate && !self.has_certs() {
            let cert_dir = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("certs")
                .join("mesh");

            std::fs::create_dir_all(&cert_dir)
                .map_err(|e| MeshCertError::IoError(cert_dir.display().to_string(), e))?;

            let (cert_path, key_path) =
                generate_mesh_cert(&self.node_id, &cert_dir, self.is_global)?;

            self.cert_path = Some(cert_path);
            self.key_path = Some(key_path);

            tracing::info!("Auto-generated mesh certificate for node {}", self.node_id);
        }

        if let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) {
            let key = load_private_key(key_path)
                .map_err(|e| MeshCertError::ConfigError(e.to_string()))?;
            *self.node_private_key.write() = Some(key);
        }

        if let Some(ref ca_path) = self.ca_path {
            self.load_ca_certificate(ca_path)?;
        }

        Ok(())
    }

    fn load_ca_certificate(&self, ca_path: &PathBuf) -> Result<(), MeshCertError> {
        let certs = load_certs(ca_path).map_err(|e| MeshCertError::ConfigError(e.to_string()))?;
        let mut trusted = self.trusted_ca_certs.write();
        for cert in &certs {
            if let Some(issuer) = extract_issuer_name(cert) {
                trusted.insert(issuer, cert.clone());
            }
        }
        tracing::info!(
            "Loaded {} CA certificates from {}",
            trusted.len(),
            ca_path.display()
        );
        Ok(())
    }

    pub fn add_trusted_global_cert(&self, node_id: &str, cert_der: CertificateDer<'static>) {
        let mut trusted = self.trusted_ca_certs.write();
        trusted.insert(node_id.to_string(), cert_der.clone());
        tracing::debug!("Added trusted global node certificate: {}", node_id);
    }

    pub fn has_certs(&self) -> bool {
        self.cert_path.is_some() && self.key_path.is_some()
    }

    pub fn has_ca(&self) -> bool {
        self.ca_path.is_some()
    }

    pub fn build_server_config(&self) -> Result<ServerConfig, MeshCertError> {
        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            return Err(MeshCertError::MissingCert);
        };

        let cert_file = File::open(cert_path)
            .map_err(|e| MeshCertError::IoError(cert_path.display().to_string(), e))?;
        let key_file = File::open(key_path)
            .map_err(|e| MeshCertError::IoError(key_path.display().to_string(), e))?;

        let cert_reader = &mut BufReader::new(cert_file);
        let key_reader = &mut BufReader::new(key_file);

        let mut cert_chain = Vec::new();
        while let Ok(Some((kind, der))) = pem::from_buf(cert_reader) {
            if kind == pem::SectionKind::Certificate {
                cert_chain.push(CertificateDer::from(der));
            }
        }

        let key_pem = pem::from_buf(key_reader)
            .map_err(|e| MeshCertError::ParseError(format!("{:?}", e)))?
            .ok_or_else(|| MeshCertError::NoPrivateKey(key_path.display().to_string()))?;

        let private_key = PrivateKeyDer::from_pem(key_pem.0, key_pem.1)
            .ok_or_else(|| MeshCertError::NoPrivateKey(key_path.display().to_string()))?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to build server config: {}", e))
            })?;

        let quic_server_config = QuicServerConfig::try_from(std::sync::Arc::new(server_config))
            .map_err(|e| {
                MeshCertError::ConfigError(format!(
                    "Failed to convert to QUIC server config: {}",
                    e
                ))
            })?;

        // Quinn 0.11 with rustls automatically supports 0-RTT when the server accepts it
        // No explicit configuration needed - 0-RTT is enabled by default
        let quic_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_config));

        Ok(quic_config)
    }

    pub fn build_client_config(&self, peer_node_id: &str) -> Result<ClientConfig, MeshCertError> {
        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            let client_config = ClientConfig::try_with_platform_verifier().map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to create client config: {}", e))
            })?;
            // Quinn 0.11 with rustls automatically supports 0-RTT when available
            tracing::debug!(
                "Mesh TLS client configured (no client cert) for node {}",
                self.node_id
            );
            return Ok(client_config);
        };

        let cert_file = File::open(cert_path)
            .map_err(|e| MeshCertError::IoError(cert_path.display().to_string(), e))?;
        let key_file = File::open(key_path)
            .map_err(|e| MeshCertError::IoError(key_path.display().to_string(), e))?;

        let cert_reader = &mut BufReader::new(cert_file);
        let key_reader = &mut BufReader::new(key_file);

        let mut cert_chain = Vec::new();
        while let Ok(Some((kind, der))) = pem::from_buf(cert_reader) {
            if kind == pem::SectionKind::Certificate {
                cert_chain.push(CertificateDer::from(der));
            }
        }

        let key_pem = pem::from_buf(key_reader)
            .map_err(|e| MeshCertError::ParseError(format!("{:?}", e)))?
            .ok_or_else(|| MeshCertError::NoPrivateKey(key_path.display().to_string()))?;

        let private_key = PrivateKeyDer::from_pem(key_pem.0, key_pem.1)
            .ok_or_else(|| MeshCertError::NoPrivateKey(key_path.display().to_string()))?;

        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates({
                let mut root_store = rustls::RootCertStore::empty();
                if let Some(ref ca_path) = self.ca_path {
                    if let Ok(ca_file) = File::open(ca_path) {
                        let mut ca_reader = BufReader::new(ca_file);
                        let mut ca_certs = Vec::new();
                        while let Ok(Some((kind, der))) = pem::from_buf(&mut ca_reader) {
                            if kind == pem::SectionKind::Certificate {
                                ca_certs.push(CertificateDer::from(der));
                            }
                        }
                        for ca_cert in ca_certs {
                            root_store.add(ca_cert).ok();
                        }
                    }
                }
                root_store
            })
            .with_no_client_auth();

        let quic_client_config = QuicClientConfig::try_from(std::sync::Arc::new(client_config))
            .map_err(|e| {
                MeshCertError::ConfigError(format!(
                    "Failed to convert to QUIC client config: {}",
                    e
                ))
            })?;

        // Quinn 0.11 with rustls automatically supports 0-RTT when available
        let quic_config = quinn::ClientConfig::new(std::sync::Arc::new(quic_client_config));

        Ok(quic_config)
    }

    pub fn register_global_node(&self, node_id: &str, public_key: Vec<u8>) {
        let mut keys = self.global_node_public_keys.write();
        keys.insert(node_id.to_string(), public_key);
        tracing::info!("Registered global node: {}", node_id);
    }

    pub fn is_verified(&self, node_id: &str) -> bool {
        let verified = self.verified_nodes.read();
        verified.contains(node_id)
    }

    pub fn mark_verified(&self, node_id: &str) {
        let mut verified = self.verified_nodes.write();
        verified.insert(node_id.to_string());
        tracing::debug!("Node {} marked as verified", node_id);
    }

    pub fn get_global_node_key(&self, node_id: &str) -> Option<Vec<u8>> {
        let keys = self.global_node_public_keys.read();
        keys.get(node_id).cloned()
    }

    pub fn add_seed_public_key(&self, node_id: &str, public_key: Option<String>) {
        if let Some(key) = public_key {
            if let Ok(key_bytes) = base64::engine::general_purpose::STANDARD.decode(&key) {
                let mut keys = self.global_node_public_keys.write();
                keys.insert(node_id.to_string(), key_bytes);
                tracing::debug!("Added seed public key for {}", node_id);
            }
        }
    }

    pub fn should_rotate_cert(&self) -> bool {
        if let Some(interval) = *self.cert_rotation_interval.read() {
            if let Some(last_check) = *self.cert_expiration_monitor.read() {
                return last_check.elapsed() >= interval;
            }
        }
        false
    }

    pub fn rotate_certificates(&mut self) -> Result<(), MeshCertError> {
        if !self.auto_generate {
            return Err(MeshCertError::ConfigError(
                "Auto certificate rotation is disabled".to_string(),
            ));
        }

        let cert_dir = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("certs")
            .join("mesh");

        std::fs::create_dir_all(&cert_dir)
            .map_err(|e| MeshCertError::IoError(cert_dir.display().to_string(), e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let rotated_node_id = format!("{}-{:x}", self.node_id, timestamp);

        let (cert_path, key_path) =
            generate_mesh_cert(&rotated_node_id, &cert_dir, self.is_global)?;

        if let Some(ref old_cert) = self.cert_path {
            let rotated = old_cert.with_extension("rotated");
            std::fs::rename(old_cert, &rotated).ok();
        }
        if let Some(ref old_key) = self.key_path {
            let rotated = old_key.with_extension("rotated");
            std::fs::rename(old_key, &rotated).ok();
        }

        self.cert_path = Some(cert_path);
        self.key_path = Some(key_path);

        if let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) {
            let key = load_private_key(key_path)
                .map_err(|e| MeshCertError::ConfigError(e.to_string()))?;
            *self.node_private_key.write() = Some(key);
        }

        *self.cert_expiration_monitor.write() = Some(std::time::Instant::now());

        tracing::info!("Successfully rotated certificate for node {}", self.node_id);

        #[cfg(feature = "audit")]
        {
            crate::audit::log_event(crate::audit::AuditEvent {
                timestamp: chrono::Utc::now(),
                event_type: "CERTIFICATE_ROTATED".to_string(),
                node_id: self.node_id.clone(),
                details: format!("Certificate rotated for node {}", self.node_id),
                severity: crate::audit::AuditSeverity::Info,
            });
        }

        Ok(())
    }

    pub fn revoke_certificate(&self, node_id: &str) -> Result<(), MeshCertError> {
        let mut crl = self.certificate_revocation_list.write();
        crl.insert(node_id.to_string());

        tracing::warn!("Certificate revoked for node: {}", node_id);

        #[cfg(feature = "audit")]
        {
            crate::audit::log_event(crate::audit::AuditEvent {
                timestamp: chrono::Utc::now(),
                event_type: "CERTIFICATE_REVOKED".to_string(),
                node_id: self.node_id.clone(),
                details: format!("Certificate revoked for node: {}", node_id),
                severity: crate::audit::AuditSeverity::Warning,
            });
        }

        Ok(())
    }

    pub fn is_certificate_revoked(&self, node_id: &str) -> bool {
        let crl = self.certificate_revocation_list.read();
        crl.contains(node_id)
    }

    pub fn load_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError> {
        let content = std::fs::read_to_string(crl_path)
            .map_err(|e| MeshCertError::IoError(crl_path.display().to_string(), e))?;

        let mut crl = self.certificate_revocation_list.write();
        let mut count = 0;

        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                crl.insert(trimmed.to_string());
                count += 1;
            }
        }

        tracing::info!(
            "Loaded {} entries into CRL from {}",
            count,
            crl_path.display()
        );
        Ok(count)
    }

    pub fn export_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError> {
        let crl = self.certificate_revocation_list.read();
        let mut content = String::new();
        content.push_str("# Certificate Revocation List\n");
        content.push_str(&format!("# Generated: {}\n", chrono::Utc::now()));
        content.push_str("# Revoked node IDs:\n");

        for node_id in crl.iter() {
            content.push_str(node_id);
            content.push('\n');
        }

        std::fs::write(crl_path, content)
            .map_err(|e| MeshCertError::IoError(crl_path.display().to_string(), e))?;

        tracing::info!(
            "Exported CRL with {} entries to {}",
            crl.len(),
            crl_path.display()
        );
        Ok(crl.len())
    }

    pub fn verify_peer_certificate(
        &self,
        peer_node_id: &str,
        cert_der: &[u8],
    ) -> Result<bool, MeshCertError> {
        if self.is_certificate_revoked(peer_node_id) {
            tracing::warn!("Peer {} certificate is revoked", peer_node_id);
            return Ok(false);
        }

        let trusted = self.trusted_ca_certs.read();
        if trusted.is_empty() {
            tracing::debug!(
                "No CA certificates configured, accepting peer {} certificate",
                peer_node_id
            );
            return Ok(true);
        }

        use x509_parser::prelude::*;

        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| MeshCertError::ParseError(e.to_string()))?;

        for (_, trusted_cert) in trusted.iter() {
            let trusted_der = trusted_cert.as_ref();
            if let Ok((_, trusted_x509)) = X509Certificate::from_der(trusted_der) {
                if cert.subject().to_string() == trusted_x509.subject().to_string() {
                    tracing::debug!(
                        "Peer {} certificate issuer matches trusted CA",
                        peer_node_id
                    );
                    return Ok(true);
                }
            }
        }

        tracing::warn!("Peer {} certificate verification failed", peer_node_id);
        Ok(false)
    }

    pub fn add_peer_public_key(&self, peer_node_id: &str, public_key: Vec<u8>) {
        let mut keys = self.global_node_public_keys.write();
        keys.insert(peer_node_id.to_string(), public_key);
    }
}

fn generate_mesh_cert(
    node_id: &str,
    output_dir: &PathBuf,
    is_global: bool,
) -> Result<(PathBuf, PathBuf), MeshCertError> {
    use rcgen::generate_simple_self_signed;

    let subject_alt_names = vec![node_id.to_string(), format!("{}.mesh", node_id)];
    let certified_key = generate_simple_self_signed(subject_alt_names)
        .map_err(|e| MeshCertError::ConfigError(e.to_string()))?;

    let cert_path = output_dir.join(format!("{}.crt", node_id.replace([':', '-', '.'], "_")));
    let key_path = output_dir.join(format!("{}.key", node_id.replace([':', '-', '.'], "_")));

    std::fs::write(&cert_path, certified_key.cert.pem())
        .map_err(|e| MeshCertError::IoError(cert_path.display().to_string(), e))?;
    std::fs::write(&key_path, certified_key.key_pair.serialize_pem())
        .map_err(|e| MeshCertError::IoError(key_path.display().to_string(), e))?;

    tracing::info!(
        "Generated {} certificate for {} in {:?}",
        if is_global { "global (CA)" } else { "node" },
        node_id,
        output_dir
    );

    Ok((cert_path, key_path))
}

fn extract_issuer_name(cert: &CertificateDer<'_>) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, x509) = X509Certificate::from_der(cert).ok()?;
    let subject = x509.subject();
    for rdn in subject.iter() {
        for attr in rdn.iter() {
            if let Ok(value) = attr.as_str() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn extract_public_key_from_cert(cert_der: &[u8]) -> Option<Vec<u8>> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    let public_key = cert.public_key();
    Some(public_key.raw.to_vec())
}

pub fn sign_message(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha3_256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_signature(data: &[u8], signature: &[u8], key: &[u8]) -> bool {
    let expected = sign_message(data, key);
    if expected.len() != signature.len() {
        return false;
    }
    expected.as_slice().ct_eq(signature).into()
}

pub fn sign_hmac(data: &str, key: &[u8]) -> Vec<u8> {
    sign_message(data.as_bytes(), key)
}

pub fn verify_hmac(data: &str, signature: &[u8], key: &[u8]) -> bool {
    verify_signature(data.as_bytes(), signature, key)
}

pub fn sign_ed25519(data: &str, private_key: &[u8]) -> Option<Vec<u8>> {
    if private_key.len() != 32 {
        return None;
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(private_key);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
    let signature = signing_key.sign(data.as_bytes());
    Some(signature.to_bytes().to_vec())
}

pub fn verify_ed25519(data: &str, signature: &[u8], public_key: &[u8]) -> bool {
    if signature.len() != 64 || public_key.len() != 32 {
        return false;
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature);
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(public_key);

    match ed25519_dalek::VerifyingKey::from_bytes(&pk_array) {
        Ok(pk) => pk
            .verify(
                data.as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&sig_array),
            )
            .is_ok(),
        Err(_) => false,
    }
}

pub fn get_ed25519_public_key(private_key: &[u8]) -> Option<Vec<u8>> {
    if private_key.len() != 32 {
        return None;
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(private_key);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();
    Some(verifying_key.as_bytes().to_vec())
}

#[derive(Debug, thiserror::Error)]
pub enum MeshCertError {
    #[error("Missing certificate")]
    MissingCert,
    #[error("Missing private key")]
    MissingKey,
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
    #[error("Certificate rotation failed: {0}")]
    RotationFailed(String),
    #[error("Certificate revoked: {0}")]
    CertificateRevoked(String),
    #[error("Certificate expired")]
    CertificateExpired,
    #[error("Certificate not yet valid")]
    CertificateNotYetValid,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CertificateStatus {
    Valid,
    ExpiringSoon { days_remaining: u32 },
    Expired,
    NotYetValid,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub node_id: String,
    pub cert_path: PathBuf,
    pub not_before: std::time::SystemTime,
    pub not_after: std::time::SystemTime,
}

impl CertificateInfo {
    pub fn is_expired(&self) -> bool {
        std::time::SystemTime::now() > self.not_after
    }

    pub fn days_until_expiry(&self) -> Option<i64> {
        std::time::SystemTime::now()
            .duration_since(self.not_after)
            .ok()
            .map(|d| -(d.as_secs() as i64 / 86400))
    }
}
