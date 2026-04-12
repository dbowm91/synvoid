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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::mesh::config::MeshConfig;

#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizingPrivateKeyDer(PrivateKeyDer<'static>);

impl std::ops::Deref for ZeroizingPrivateKeyDer {
    type Target = PrivateKeyDer<'static>;
    fn deref(&self) -> &Self::Target {
        &self.0
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

type HmacSha3_256 = Hmac<sha3::Sha3_256>;

struct PinnedFingerprint {
    fingerprint: String,
    pinned_at: std::time::Instant,
}

const MAX_TOOF_FINGERPRINT_AGE_DAYS: u64 = 90;
const MAX_TOOF_FINGERPRINT_AGE_SECS: u64 = 90 * 24 * 60 * 60;

#[cfg(feature = "audit")]
use chrono::Utc;

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

#[derive(Clone)]
pub struct MeshCertManager {
    node_id: String,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    ca_path: Option<PathBuf>,
    auto_generate: bool,
    is_global: bool,
    ca_mode: bool,
    enforce_mutual_tls: bool,
    quic_enable_0rtt: bool,
    strict_certificate_validation: bool,
    ca_key_pair: Arc<RwLock<Option<rcgen::KeyPair>>>,
    ca_certificate: Arc<RwLock<Option<rcgen::Certificate>>>,
    ca_cert_der: Arc<RwLock<Option<CertificateDer<'static>>>>,
    verified_nodes: Arc<RwLock<std::collections::HashSet<String>>>,
    global_node_public_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    trusted_ca_certs: Arc<RwLock<std::collections::HashMap<String, CertificateDer<'static>>>>,
    node_private_key: Arc<RwLock<Option<ZeroizingPrivateKeyDer>>>,
    cert_rotation_interval: Arc<RwLock<Option<std::time::Duration>>>,
    cert_expiration_monitor: Arc<RwLock<Option<std::time::Instant>>>,
    certificate_revocation_list: Arc<RwLock<std::collections::HashSet<String>>>,
    crl_entries: Arc<RwLock<std::collections::HashMap<String, CrlEntry>>>,
    seed_tofu_fingerprints: Arc<RwLock<std::collections::HashMap<String, PinnedFingerprint>>>,
    tofu_enabled: Arc<RwLock<bool>>,
}

impl std::fmt::Debug for MeshCertManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshCertManager")
            .field("node_id", &self.node_id)
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("ca_path", &self.ca_path)
            .field("auto_generate", &self.auto_generate)
            .field("is_global", &self.is_global)
            .field("ca_mode", &self.ca_mode)
            .field("verified_nodes", &self.verified_nodes)
            .field("global_node_public_keys", &self.global_node_public_keys)
            .field("trusted_ca_certs", &self.trusted_ca_certs)
            .field(
                "certificate_revocation_list",
                &self.certificate_revocation_list,
            )
            .finish_non_exhaustive()
    }
}

impl MeshCertManager {
    pub fn new(config: &MeshConfig) -> Self {
        let is_global = config.role.is_global();
        let ca_mode = config.tls.ca_mode;
        let cert_rotation_interval = config
            .tls
            .cert_rotation_interval_secs
            .map(std::time::Duration::from_secs);
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
            ca_mode,
            enforce_mutual_tls: config.tls.enforce_mutual_tls,
            quic_enable_0rtt: config.tls.quic_enable_0rtt,
            strict_certificate_validation: config.tls.strict_certificate_validation,
            ca_key_pair: Arc::new(RwLock::new(None)),
            ca_certificate: Arc::new(RwLock::new(None)),
            ca_cert_der: Arc::new(RwLock::new(None)),
            verified_nodes: Arc::new(RwLock::new(std::collections::HashSet::new())),
            global_node_public_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            trusted_ca_certs: Arc::new(RwLock::new(std::collections::HashMap::new())),
            node_private_key: Arc::new(RwLock::new(None)),
            cert_rotation_interval: Arc::new(RwLock::new(cert_rotation_interval)),
            cert_expiration_monitor: Arc::new(RwLock::new(cert_expiration_monitor)),
            certificate_revocation_list: Arc::new(RwLock::new(std::collections::HashSet::new())),
            crl_entries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            seed_tofu_fingerprints: Arc::new(RwLock::new(std::collections::HashMap::new())),
            tofu_enabled: Arc::new(RwLock::new(true)),
        }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn verify_post_quantum(&self) {
        verify_post_quantum_tls();
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
            *self.node_private_key.write() = Some(ZeroizingPrivateKeyDer(key));
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

    fn load_cert_chain_and_key(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), MeshCertError> {
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

        Ok((cert_chain, private_key))
    }

    pub fn build_server_config(
        &self,
        enforce_mutual_tls: bool,
    ) -> Result<ServerConfig, MeshCertError> {
        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            return Err(MeshCertError::MissingCert);
        };

        let (cert_chain, private_key) = Self::load_cert_chain_and_key(cert_path, key_path)?;

        let mut server_config = if enforce_mutual_tls {
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
            let client_cert_verifier =
                rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(root_store))
                    .build()
                    .map_err(|e| {
                        MeshCertError::ConfigError(format!(
                            "Failed to build client verifier: {}",
                            e
                        ))
                    })?;

            rustls::ServerConfig::builder()
                .with_client_cert_verifier(client_cert_verifier)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| {
                    MeshCertError::ConfigError(format!("Failed to build server config: {}", e))
                })?
        } else {
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| {
                    MeshCertError::ConfigError(format!("Failed to build server config: {}", e))
                })?
        };

        if !self.quic_enable_0rtt {
            server_config.max_early_data_size = 0;
        }

        let quic_server_config = QuicServerConfig::try_from(std::sync::Arc::new(server_config))
            .map_err(|e| {
                MeshCertError::ConfigError(format!(
                    "Failed to convert to QUIC server config: {}",
                    e
                ))
            })?;

        let quic_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(quic_server_config));

        if !self.quic_enable_0rtt {
            tracing::info!("QUIC 0-RTT disabled");
        } else {
            tracing::warn!("QUIC 0-RTT enabled - warning: 0-RTT is susceptible to replay attacks");
        }

        Ok(quic_config)
    }

    pub fn build_client_config(&self, peer_node_id: &str) -> Result<ClientConfig, MeshCertError> {
        let enforce_mutual_tls = self.enforce_mutual_tls;

        if !enforce_mutual_tls {
            let client_config = ClientConfig::try_with_platform_verifier().map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to create client config: {}", e))
            })?;
            tracing::debug!(
                "Mesh TLS client configured (no client cert, mTLS not enforced) for node {}",
                self.node_id
            );
            return Ok(client_config);
        }

        let (Some(cert_path), Some(key_path)) = (&self.cert_path, &self.key_path) else {
            if enforce_mutual_tls {
                tracing::warn!(
                    "mTLS enforced but no client cert configured for node {}",
                    self.node_id
                );
            }
            let client_config = ClientConfig::try_with_platform_verifier().map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to create client config: {}", e))
            })?;
            return Ok(client_config);
        };

        let (cert_chain, private_key) = Self::load_cert_chain_and_key(cert_path, key_path)?;

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
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to configure client cert: {}", e))
            })?;

        tracing::info!(
            "Mesh TLS client configured with client cert for node {}",
            self.node_id
        );

        let quic_client_config = QuicClientConfig::try_from(std::sync::Arc::new(client_config))
            .map_err(|e| {
                MeshCertError::ConfigError(format!(
                    "Failed to convert to QUIC client config: {}",
                    e
                ))
            })?;

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

    pub fn set_tofu_enabled(&self, enabled: bool) {
        *self.tofu_enabled.write() = enabled;
    }

    pub fn is_tofu_enabled(&self) -> bool {
        *self.tofu_enabled.read()
    }

    pub fn compute_cert_fingerprint(cert_der: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let hash = hasher.finalize();
        base64::engine::general_purpose::STANDARD.encode(hash)
    }

    pub fn pin_seed_fingerprint(&self, seed_address: &str, fingerprint: &str) {
        let mut fingerprints = self.seed_tofu_fingerprints.write();
        let old = fingerprints.insert(
            seed_address.to_string(),
            PinnedFingerprint {
                fingerprint: fingerprint.to_string(),
                pinned_at: std::time::Instant::now(),
            },
        );
        if old.is_none() {
            tracing::info!("TOFU: Pinned new fingerprint for seed {}", seed_address);
        } else {
            tracing::debug!("TOFU: Updated fingerprint for seed {}", seed_address);
        }
    }

    pub fn verify_seed_fingerprint(
        &self,
        seed_address: &str,
        fingerprint: &str,
    ) -> Result<(), String> {
        let mut fingerprints = self.seed_tofu_fingerprints.write();
        match fingerprints.entry(seed_address.to_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => {
                let pinned = entry.get();
                if pinned.fingerprint == fingerprint {
                    if pinned.pinned_at.elapsed().as_secs() > MAX_TOOF_FINGERPRINT_AGE_SECS {
                        entry.remove();
                        return Err(format!(
                            "TOFU: Fingerprint expired for seed {} (older than {} days)",
                            seed_address, MAX_TOOF_FINGERPRINT_AGE_DAYS
                        ));
                    }
                    Ok(())
                } else {
                    Err(format!(
                        "TOFU: Fingerprint mismatch for seed {}. Expected: {}, Got: {}",
                        seed_address, pinned.fingerprint, fingerprint
                    ))
                }
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                tracing::warn!(
                    "CRITICAL SECURITY: First connection to seed {} - fingerprint accepted without verification. \
                    An active attacker could intercept this connection. Configure pinned_cert_fingerprint \
                    in your mesh seed configuration for production deployments.",
                    seed_address
                );
                entry.insert(PinnedFingerprint {
                    fingerprint: fingerprint.to_string(),
                    pinned_at: std::time::Instant::now(),
                });
                Ok(())
            }
        }
    }

    pub fn get_pinned_fingerprints(&self) -> std::collections::HashMap<String, String> {
        self.seed_tofu_fingerprints
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.fingerprint.clone()))
            .collect()
    }

    pub fn cleanup_expired_tofu_fingerprints(&self) -> usize {
        let mut fingerprints = self.seed_tofu_fingerprints.write();
        let before = fingerprints.len();
        fingerprints
            .retain(|_, v| v.pinned_at.elapsed().as_secs() <= MAX_TOOF_FINGERPRINT_AGE_SECS);
        let after = fingerprints.len();
        let removed = before.saturating_sub(after);
        if removed > 0 {
            tracing::info!("TOFU: Cleaned up {} expired fingerprints", removed);
        }
        removed
    }

    pub fn remove_pinned_fingerprint(&self, seed_address: &str) -> Option<String> {
        let mut fingerprints = self.seed_tofu_fingerprints.write();
        let removed = fingerprints.remove(seed_address);
        if removed.is_some() {
            tracing::info!("TOFU: Removed pinned fingerprint for seed {}", seed_address);
        }
        removed.map(|p| p.fingerprint)
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

        let timestamp = crate::utils::safe_unix_duration().as_nanos();
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
            *self.node_private_key.write() = Some(ZeroizingPrivateKeyDer(key));
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
        intermediate_certs: Option<&[CertificateDer<'static>]>,
    ) -> Result<bool, MeshCertError> {
        if self.is_certificate_revoked(peer_node_id) {
            tracing::warn!("Peer {} certificate is revoked", peer_node_id);
            return Ok(false);
        }

        let trusted = self.trusted_ca_certs.read();
        if trusted.is_empty() {
            if self.strict_certificate_validation {
                tracing::warn!(
                    "CRITICAL SECURITY: No CA certificates configured but strict_certificate_validation=true. \
                    Rejecting peer {} certificate. Configure ca_path in mesh.tls or set strict_certificate_validation=false",
                    peer_node_id
                );
                return Err(MeshCertError::ConfigError(
                    "No CA certificates configured with strict validation enabled".to_string(),
                ));
            }
            tracing::warn!(
                "SECURITY WARNING: No CA certificates configured, accepting peer {} certificate without validation",
                peer_node_id
            );
            return Ok(true);
        }

        use rustls::client::danger::ServerCertVerifier;
        use rustls::client::WebPkiServerVerifier;
        use rustls::RootCertStore;
        use std::time::SystemTime;

        let mut root_store = RootCertStore::empty();
        for (_, trusted_cert) in trusted.iter() {
            root_store
                .add(trusted_cert.clone())
                .map_err(|e| MeshCertError::ConfigError(format!("Failed to add CA: {}", e)))?;
        }

        let verifier = WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
            .build()
            .map_err(|e| MeshCertError::ConfigError(format!("Failed to build verifier: {}", e)))?;

        let cert = CertificateDer::from(cert_der);
        let intermediates = intermediate_certs.unwrap_or(&[]);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| MeshCertError::ConfigError(format!("System time error: {}", e)))?
            .as_secs() as i64;

        let server_name = rustls_pki_types::ServerName::try_from(peer_node_id.to_string())
            .map_err(|e| MeshCertError::ConfigError(format!("Invalid server name: {}", e)))?;

        match verifier.verify_server_cert(
            &cert,
            intermediates,
            &server_name,
            &[],
            rustls_pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                now as u64,
            )),
        ) {
            Ok(_) => {
                tracing::debug!(
                    "Peer {} certificate verified successfully ({} intermediate certs)",
                    peer_node_id,
                    intermediates.len()
                );
                Ok(true)
            }
            Err(e) => {
                tracing::warn!(
                    "Peer {} certificate verification failed: {}",
                    peer_node_id,
                    e
                );
                Ok(false)
            }
        }
    }

    pub fn add_peer_public_key(&self, peer_node_id: &str, public_key: Vec<u8>) {
        let mut keys = self.global_node_public_keys.write();
        keys.insert(peer_node_id.to_string(), public_key);
    }

    pub fn ca_mode(&self) -> bool {
        self.ca_mode
    }

    pub fn generate_ca_certificate(&self) -> Result<(), MeshCertError> {
        if !self.ca_mode {
            return Err(MeshCertError::ConfigError(
                "CA mode is not enabled".to_string(),
            ));
        }

        let mut params = rcgen::CertificateParams::new(vec![format!("{}.ca.mesh", self.node_id)])
            .map_err(|e| {
            MeshCertError::ConfigError(format!("Failed to create CA params: {}", e))
        })?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("MaluWAF CA - {}", self.node_id),
        );
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "MaluWAF");

        let key_pair = rcgen::KeyPair::generate().map_err(|e| {
            MeshCertError::ConfigError(format!("Failed to generate CA key pair: {}", e))
        })?;

        let cert = params.self_signed(&key_pair).map_err(|e| {
            MeshCertError::ConfigError(format!("Failed to self-sign CA cert: {}", e))
        })?;

        let cert_der = CertificateDer::from(cert.der().to_vec());

        *self.ca_key_pair.write() = Some(key_pair);
        *self.ca_certificate.write() = Some(cert);
        *self.ca_cert_der.write() = Some(cert_der.clone());

        let mut trusted = self.trusted_ca_certs.write();
        trusted.insert(self.node_id.clone(), cert_der);

        tracing::info!(
            "Generated CA certificate for node {} (CA mode)",
            self.node_id
        );

        Ok(())
    }

    pub fn get_ca_certificate(&self) -> Option<CertificateDer<'static>> {
        self.ca_cert_der.read().clone()
    }

    pub fn sign_certificate(
        &self,
        subject_node_id: &str,
        subject_alt_names: Vec<String>,
    ) -> Result<(Vec<u8>, Vec<u8>), MeshCertError> {
        let ca_key_pair = self.ca_key_pair.read();
        let ca_certificate = self.ca_certificate.read();

        let (ca_key, ca_cert) = match (ca_key_pair.as_ref(), ca_certificate.as_ref()) {
            (Some(k), Some(c)) => (k, c),
            _ => {
                return Err(MeshCertError::ConfigError(
                    "CA certificate not generated. Call generate_ca_certificate() first."
                        .to_string(),
                ))
            }
        };

        let mut sans = vec![subject_node_id.to_string()];
        sans.extend(subject_alt_names);

        let mut params = rcgen::CertificateParams::new(sans).map_err(|e| {
            MeshCertError::ConfigError(format!("Failed to create cert params: {}", e))
        })?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, subject_node_id);

        let subject_key_pair = rcgen::KeyPair::generate().map_err(|e| {
            MeshCertError::ConfigError(format!("Failed to generate key pair: {}", e))
        })?;

        let cert = params
            .signed_by(&subject_key_pair, ca_cert, ca_key)
            .map_err(|e| {
                MeshCertError::ConfigError(format!("Failed to sign certificate: {}", e))
            })?;

        Ok((cert.der().to_vec(), subject_key_pair.serialize_der()))
    }

    pub fn generate_crl(&self) -> Result<Vec<CrlEntry>, MeshCertError> {
        let entries = self.crl_entries.read();
        Ok(entries.values().cloned().collect())
    }

    pub fn revoke_certificate_with_reason(
        &self,
        node_id: &str,
        reason: CrlReason,
    ) -> Result<(), MeshCertError> {
        {
            let mut crl = self.certificate_revocation_list.write();
            crl.insert(node_id.to_string());
        }

        {
            let mut entries = self.crl_entries.write();
            entries.insert(
                node_id.to_string(),
                CrlEntry {
                    serial_number: node_id.to_string(),
                    revocation_time: crate::utils::safe_unix_duration().as_secs(),
                    reason,
                },
            );
        }

        tracing::warn!(
            "Certificate revoked for node: {} (reason: {:?})",
            node_id,
            reason
        );

        #[cfg(feature = "audit")]
        {
            crate::audit::log_event(crate::audit::AuditEvent {
                timestamp: chrono::Utc::now(),
                event_type: "CERTIFICATE_REVOKED".to_string(),
                node_id: self.node_id.clone(),
                details: format!(
                    "Certificate revoked for node: {} (reason: {:?})",
                    node_id, reason
                ),
                severity: crate::audit::AuditSeverity::Warning,
            });
        }

        Ok(())
    }

    pub fn export_structured_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError> {
        let entries = self.crl_entries.read();
        let crl_data = serde_json::json!({
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "issuer_node_id": self.node_id,
            "entries": entries.values().collect::<Vec<_>>(),
        });

        let content = serde_json::to_string_pretty(&crl_data)
            .map_err(|e| MeshCertError::ParseError(format!("CRL serialization failed: {}", e)))?;

        std::fs::write(crl_path, content)
            .map_err(|e| MeshCertError::IoError(crl_path.display().to_string(), e))?;

        tracing::info!(
            "Exported structured CRL with {} entries to {}",
            entries.len(),
            crl_path.display()
        );
        Ok(entries.len())
    }

    pub fn load_structured_crl(&self, crl_path: &PathBuf) -> Result<usize, MeshCertError> {
        let content = std::fs::read_to_string(crl_path)
            .map_err(|e| MeshCertError::IoError(crl_path.display().to_string(), e))?;

        let crl_data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| MeshCertError::ParseError(format!("CRL parse error: {}", e)))?;

        let entries_value = crl_data
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| MeshCertError::ParseError("Missing entries array in CRL".to_string()))?;

        let mut crl = self.certificate_revocation_list.write();
        let mut crl_entries = self.crl_entries.write();
        let mut count = 0;

        for entry_value in entries_value {
            if let Ok(entry) = serde_json::from_value::<CrlEntry>(entry_value.clone()) {
                crl.insert(entry.serial_number.clone());
                crl_entries.insert(entry.serial_number.clone(), entry);
                count += 1;
            }
        }

        tracing::info!(
            "Loaded {} structured CRL entries from {}",
            count,
            crl_path.display()
        );
        Ok(count)
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

pub fn sign_message(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac =
        HmacSha3_256::new_from_slice(key).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_signature(data: &[u8], signature: &[u8], key: &[u8]) -> bool {
    let expected = match sign_message(data, key) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    if expected.len() != signature.len() {
        return false;
    }
    expected.as_slice().ct_eq(signature).into()
}

pub fn sign_hmac(data: &str, key: &[u8]) -> Result<Vec<u8>, String> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrlReason {
    #[default]
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlEntry {
    pub serial_number: String,
    pub revocation_time: u64,
    pub reason: CrlReason,
}
