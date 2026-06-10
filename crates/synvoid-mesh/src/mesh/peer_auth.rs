use crate::mesh::canonical::{
    CanonicalFreshness, CanonicalTrustDecision, CanonicalTrustReader, CanonicalTrustReason,
};
use base64::Engine;
use dashmap::DashMap;
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RevocationInfo {
    pub revoked_at: u64,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PersistedRevocationList {
    pub version: u32,
    pub revoked_nodes: std::collections::HashMap<String, RevocationInfo>,
    pub saved_at: u64,
}

pub struct GlobalNodeRevocationList {
    revoked_nodes: Arc<DashMap<String, RevocationInfo>>,
    persistence_path: Option<PathBuf>,
}

impl GlobalNodeRevocationList {
    pub fn new() -> Self {
        Self {
            revoked_nodes: Arc::new(DashMap::new()),
            persistence_path: None,
        }
    }

    pub fn new_with_persistence(persistence_path: PathBuf) -> Self {
        let list = Self {
            revoked_nodes: Arc::new(DashMap::new()),
            persistence_path: Some(persistence_path),
        };
        list.load();
        list
    }

    pub fn add_revoked_node(&self, node_id: &str, reason: &str) {
        let info = RevocationInfo {
            revoked_at: synvoid_utils::current_timestamp(),
            reason: reason.to_string(),
        };
        self.revoked_nodes.insert(node_id.to_string(), info);
        self.save();
    }

    pub fn is_node_revoked(&self, node_id: &str) -> Option<RevocationInfo> {
        self.revoked_nodes
            .get(node_id)
            .map(|entry| entry.value().clone())
    }

    pub fn remove_revoked_node(&self, node_id: &str) {
        self.revoked_nodes.remove(node_id);
        self.save();
    }

    pub fn get_all_revoked(&self) -> Vec<(String, RevocationInfo)> {
        self.revoked_nodes
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    fn save(&self) {
        let Some(ref path) = self.persistence_path else {
            return;
        };

        let data: std::collections::HashMap<String, RevocationInfo> = self
            .revoked_nodes
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        let persisted = PersistedRevocationList {
            version: 1,
            revoked_nodes: data,
            saved_at: synvoid_utils::current_timestamp(),
        };

        if let Ok(bytes) = synvoid_utils::serialization::serialize(&persisted) {
            let _ = std::fs::write(path, bytes);
        }
    }

    fn load(&self) {
        let Some(ref path) = self.persistence_path else {
            return;
        };

        if !path.exists() {
            return;
        }

        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(persisted) =
                synvoid_utils::serialization::deserialize::<PersistedRevocationList>(&bytes)
            {
                for (node_id, info) in persisted.revoked_nodes {
                    self.revoked_nodes.insert(node_id, info);
                }
                tracing::info!(
                    "Loaded {} revoked nodes from persistence",
                    self.revoked_nodes.len()
                );
            }
        }
    }
}

impl Default for GlobalNodeRevocationList {
    fn default() -> Self {
        Self::new()
    }
}

use crate::organization::{MemberCertificate, OrgPublicKey};
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RaftAttestation {
    pub leader_id: String,
    pub commit_index: u64,
    pub namespace: crate::raft::Namespace,
    pub key_id: String,
    pub timestamp: u64,
    #[serde(default)]
    pub value_hash: Option<Vec<u8>>,
}

impl RaftAttestation {
    /// Compute SHA-256 hash of canonical value bytes for binding to attestation.
    pub fn compute_value_hash(value: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.finalize().to_vec()
    }
}

pub fn raft_attestation_from_dht_record(value: &[u8]) -> Option<RaftAttestation> {
    synvoid_utils::serialization::deserialize(value).ok()
}

pub const RAFT_ATTESTATION_PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedRaftAttestation {
    pub attestation: RaftAttestation,
    pub signer_node_id: String,
    pub signer_public_key: String,
    pub signature: Vec<u8>,
    pub protocol_version: u32,
}

impl SignedRaftAttestation {
    pub fn signable_content(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}", self.attestation.namespace).as_bytes());
        hasher.update(b"\0");
        hasher.update(self.attestation.key_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.attestation.leader_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(self.attestation.commit_index.to_le_bytes());
        hasher.update(b"\0");
        hasher.update(self.attestation.timestamp.to_le_bytes());
        hasher.update(b"\0");
        hasher.update(self.protocol_version.to_le_bytes());
        hasher.update(b"\0");
        if let Some(ref value_hash) = self.attestation.value_hash {
            hasher.update(value_hash);
        }
        hasher.finalize().to_vec()
    }

    pub fn verify_signature(&self) -> bool {
        let Ok(pk_bytes) =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&self.signer_public_key)
        else {
            return false;
        };
        let Ok(pk_array) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
            return false;
        };
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&pk_array) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&self.signable_content(), &signature)
            .is_ok()
    }

    pub fn from_attestation(
        attestation: RaftAttestation,
        signer_node_id: String,
        signer_keypair: &ed25519_dalek::SigningKey,
        value_hash: Option<Vec<u8>>,
    ) -> Self {
        let mut att = attestation;
        att.value_hash = value_hash;
        let mut sa = Self {
            attestation: att,
            signer_node_id,
            signer_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signer_keypair.verifying_key().as_bytes()),
            signature: Vec::new(),
            protocol_version: RAFT_ATTESTATION_PROTOCOL_VERSION,
        };
        let sig = signer_keypair.sign(&sa.signable_content());
        sa.signature = sig.to_bytes().to_vec();
        sa
    }
}

pub fn validate_member_certificate(
    cert: &MemberCertificate,
    org_pub_key: &OrgPublicKey,
    authorized_global_pubkeys: &[String],
    peer_node_id: &str,
) -> Result<(), String> {
    // 1. Verify cert belongs to this node
    if cert.mesh_id != peer_node_id {
        return Err("Certificate does not belong to this node".to_string());
    }

    // 2. Verify cert is valid for current time
    if !cert.is_valid() {
        return Err("Certificate is expired or not yet valid".to_string());
    }

    // 3. Verify cert matches org_pub_key
    if cert.org_id != org_pub_key.org_id || cert.org_public_key_id != org_pub_key.key_id {
        return Err("Certificate does not match providing organization key".to_string());
    }

    // 4. Verify cert signature with org_pub_key
    if !cert.verify_with_public_key(&org_pub_key.public_key) {
        return Err("Invalid certificate signature".to_string());
    }

    // 5. Verify org_pub_key quorum signatures OR Raft attestation
    // Raft-committed keys bypass quorum signature requirement since
    // Raft commit itself proves majority consensus
    if org_pub_key.quorum_signatures.is_empty() {
        return Err(
            "Organization key has no quorum signatures and is not Raft-attested".to_string(),
        );
    }

    let mut global_keys_map: HashMap<String, String> = HashMap::new();
    for pubkey in authorized_global_pubkeys {
        global_keys_map.insert(pubkey.clone(), pubkey.clone());
    }

    let total_signers = authorized_global_pubkeys.len();
    if !org_pub_key.verify_quorum(&global_keys_map, total_signers) {
        return Err(
            "Organization key lacks sufficient quorum signatures from global nodes".to_string(),
        );
    }

    Ok(())
}

pub fn validate_member_certificate_with_raft_attestation(
    cert: &MemberCertificate,
    org_pub_key: &OrgPublicKey,
    authorized_global_pubkeys: &[String],
    peer_node_id: &str,
    raft_attestation: Option<&SignedRaftAttestation>,
    allow_v1_raft_attestations: bool,
) -> Result<(), String> {
    // 1. Verify cert belongs to this node
    if cert.mesh_id != peer_node_id {
        return Err("Certificate does not belong to this node".to_string());
    }

    // 2. Verify cert is valid for current time
    if !cert.is_valid() {
        return Err("Certificate is expired or not yet valid".to_string());
    }

    // 3. Verify cert matches org_pub_key
    if cert.org_id != org_pub_key.org_id || cert.org_public_key_id != org_pub_key.key_id {
        return Err("Certificate does not match providing organization key".to_string());
    }

    // 4. Verify cert signature with org_pub_key
    if !cert.verify_with_public_key(&org_pub_key.public_key) {
        return Err("Invalid certificate signature".to_string());
    }

    // 5. Verify trust via EITHER quorum signatures OR cryptographically signed Raft attestation
    let has_quorum = !org_pub_key.quorum_signatures.is_empty() && {
        let mut global_keys_map: HashMap<String, String> = HashMap::new();
        for pubkey in authorized_global_pubkeys {
            global_keys_map.insert(pubkey.clone(), pubkey.clone());
        }
        let total_signers = authorized_global_pubkeys.len();
        org_pub_key.verify_quorum(&global_keys_map, total_signers)
    };

    let has_raft_attestation = raft_attestation
        .map(|att| {
            // Verify signature against signer's public key
            if !att.verify_signature() {
                return false;
            }

            // Verify signer is an authorized Global Node
            let signer_authorized = authorized_global_pubkeys
                .iter()
                .any(|k| k == &att.signer_public_key);
            if !signer_authorized {
                return false;
            }

            // Verify attestation fields match org_pub_key
            if att.attestation.namespace != crate::raft::Namespace::Org
                || att.attestation.key_id != org_pub_key.key_id
                || att.attestation.timestamp == 0
                || att.attestation.commit_index == 0
            {
                return false;
            }

            // V2+ attestations must have a value_hash bound to the actual record
            if att.protocol_version >= 2 {
                if let Some(ref attested_value_hash) = att.attestation.value_hash {
                    let actual_value_hash = RaftAttestation::compute_value_hash(
                        &org_pub_key.get_signable_data().as_bytes(),
                    );
                    if attested_value_hash != &actual_value_hash {
                        return false;
                    }
                }
                // If protocol_version >= 2 but no value_hash, reject (must bind to value)
                else {
                    return false;
                }
            }
            // V1 attestations: reject unless allow_v1_raft_attestations is enabled
            else if !allow_v1_raft_attestations {
                return false;
            }

            true
        })
        .unwrap_or(false);

    if !has_quorum && !has_raft_attestation {
        return Err(
            "Organization key lacks both quorum signatures and valid signed Raft attestation"
                .to_string(),
        );
    }

    Ok(())
}

pub fn validate_peer_role(
    role: &crate::config::MeshNodeRole,
    authorized_global_pubkeys: &[String],
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    peer_signature: Option<&str>,
    timestamp: u64,
    max_age_secs: u64,
    revoked_nodes: Option<&GlobalNodeRevocationList>,
    global_node_attestation_key: Option<&str>,
    global_node_attestation_sig: Option<&str>,
    pow_nonce: Option<u64>,
    pow_public_key: Option<&str>,
    member_certificate: Option<&MemberCertificate>,
    org_public_key: Option<&OrgPublicKey>,
    raft_attestation: Option<&SignedRaftAttestation>,
    allow_v1_raft_attestations: bool,
) -> Result<(), String> {
    // Try Organization Trust Chain first if available for Edge nodes
    if role.is_edge() {
        if let (Some(cert), Some(org_key)) = (member_certificate, org_public_key) {
            // Prefer value-bound Raft attestation path when attestation is available
            if raft_attestation.is_some() {
                // When an attestation is explicitly provided, use it exclusively.
                // Reject if the attestation is invalid rather than falling through.
                return validate_member_certificate_with_raft_attestation(
                    cert,
                    org_key,
                    authorized_global_pubkeys,
                    peer_node_id,
                    raft_attestation,
                    allow_v1_raft_attestations,
                );
            } else if let Ok(()) =
                validate_member_certificate(cert, org_key, authorized_global_pubkeys, peer_node_id)
            {
                return Ok(());
            }
        }
    }

    if role.is_global() && role.is_edge() {
        let mut errors = Vec::new();

        if pow_nonce.is_none() || pow_public_key.is_none() {
            errors.push("GLOBAL_EDGE role requires PoW (nonce and public key)".to_string());
        } else if let Err(e) =
            validate_edge_node_pow(peer_node_id, peer_public_key, pow_nonce, pow_public_key)
        {
            errors.push(format!("PoW validation failed: {}", e));
        }

        if peer_signature.is_none() {
            errors.push("GLOBAL_EDGE role requires Ed25519 signature".to_string());
        } else if let Err(e) = validate_global_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            authorized_global_pubkeys,
        ) {
            errors.push(format!("Signature validation failed: {}", e));
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        return Ok(());
    }

    if role.is_global() && !role.is_origin() {
        return validate_global_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            authorized_global_pubkeys,
        );
    }

    if role.is_edge() && !role.is_global() && role.is_origin() {
        let mut errors = Vec::new();

        if let Err(e) = validate_edge_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            pow_nonce,
            pow_public_key,
            false,
        ) {
            errors.push(format!("Edge validation failed: {}", e));
        }

        if let Err(e) = validate_origin_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            global_node_attestation_key,
            global_node_attestation_sig,
            authorized_global_pubkeys,
        ) {
            errors.push(format!("Origin validation failed: {}", e));
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        return Ok(());
    }

    if role.is_edge() {
        let is_global_or_trusted = role.is_global();
        return validate_edge_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            pow_nonce,
            pow_public_key,
            is_global_or_trusted,
        );
    }

    if role.is_origin() {
        return validate_origin_node(
            peer_node_id,
            peer_public_key,
            peer_signature,
            timestamp,
            max_age_secs,
            revoked_nodes,
            global_node_attestation_key,
            global_node_attestation_sig,
            authorized_global_pubkeys,
        );
    }

    Err(format!("Unknown node role: {}", role.bits()))
}

/// Staged helper for canonical revocation and global-node authorization checks.
///
/// This is a narrow, reader-backed seam (using `&dyn CanonicalTrustReader`) for the
/// subset of peer role validation that depends on canonical (Raft) state:
/// - Revocation status for *all* roles (fails closed on explicit `Revoked`).
/// - Global-node authorization only for roles where `role.is_global() && !role.is_origin()`
///   (i.e. pure `GLOBAL` and `GLOBAL_EDGE`; composites carrying the `ORIGIN` bit such as
///   `GLOBAL_ORIGIN` are exempt from the authorization list check in *this* helper because
///   their origin claim is attested separately by a real authorized global node).
///
/// It does **not**:
/// - Verify signatures, certificates, PoW, timestamps, origin attestations, or Raft value-hash binding.
/// - Replace `validate_peer_role(...)` (the full identity + policy entry point that owns
///   signature/PoW/attestation validation).
/// - Perform any I/O, network, or DHT lookups (implementations are snapshot-oriented and synchronous).
///
/// Freshness (`CanonicalFreshness`) is always observed from the reader and included in
/// error messages, but does not yet drive acceptance/rejection decisions here. Existing
/// policy is lenient (`AuthorityFreshnessConfig` governs per-record grace/hard limits);
/// future policy may tighten using the freshness value. `Unavailable` revocation preserves
/// legacy permissive "no list present" skip behavior. `Unavailable` (or `Unknown`) global
/// authorization fails closed for global non-origin roles.
///
/// `Trusted` from `node_revocation_status` only means "no revocation record in canonical
/// (Raft) state" — it is **not** equivalent to "the node is fully trusted or authorized".
/// Callers must combine with global auth, org keys, and higher policy.
///
/// This helper is intentionally low-churn/staged (Iteration 10 test hardening) before
/// broader consumer migration (e.g. `dht/key_policy.rs`). Production call sites to
/// `validate_peer_role` and the legacy revocation-list / authorized-key paths remain
/// untouched.
///
/// Prefer depending on `&dyn CanonicalTrustReader` (or `Box<dyn ...>`) when a policy
/// or peer-auth consumer needs canonical answers, rather than importing Raft internals.
///
/// See `CanonicalTrustReader` (and `StaticCanonicalTrustReader` / `SnapshotCanonicalTrustReader`)
/// for the seam contract, decision/freshness/reason types, and revocation-vs-authorization
/// semantics.
pub fn validate_peer_canonical_status(
    reader: &dyn CanonicalTrustReader,
    peer_node_id: &str,
    role: &crate::config::MeshNodeRole,
) -> Result<(), String> {
    let freshness: CanonicalFreshness = reader.freshness();
    // Freshness is observed via reader.freshness() and included in error messages,
    // but does not affect acceptance decisions in this pass. Existing policy is
    // lenient; AuthorityFreshnessConfig governs per-record tolerance. Future
    // policy can tighten using the freshness value.
    let rev_status = reader.node_revocation_status(peer_node_id);
    if let CanonicalTrustDecision::NotTrusted {
        reason: CanonicalTrustReason::Revoked,
        ..
    } = rev_status
    {
        let role_prefix = if role.is_global() {
            "Global"
        } else if role.is_edge() {
            "Edge"
        } else if role.is_origin() {
            "Origin"
        } else {
            "Peer"
        };
        return Err(format!(
            "{} node {} is revoked in canonical state (freshness: {:?})",
            role_prefix, peer_node_id, freshness
        ));
    }
    // Unknown/Unavailable for revocation treated as allow (preserve old "no list" skip)
    if role.is_global() && !role.is_origin() {
        let auth_status = reader.is_global_node_authorized(peer_node_id);
        if !matches!(auth_status, CanonicalTrustDecision::Trusted { .. }) {
            return Err(format!(
                "Global node {} is not authorized in canonical state (freshness: {:?})",
                peer_node_id, freshness
            ));
        }
    }
    Ok(())
}

fn validate_edge_node(
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    peer_signature: Option<&str>,
    timestamp: u64,
    max_age_secs: u64,
    revoked_nodes: Option<&GlobalNodeRevocationList>,
    pow_nonce: Option<u64>,
    pow_public_key: Option<&str>,
    is_global_or_trusted: bool,
) -> Result<(), String> {
    if let Some(revocation_list) = revoked_nodes {
        if let Some(revocation_info) = revocation_list.is_node_revoked(peer_node_id) {
            return Err(format!(
                "Edge node {} has been revoked: {} (at {})",
                peer_node_id, revocation_info.reason, revocation_info.revoked_at
            ));
        }
    }

    let mut pow_verified = false;

    if !is_global_or_trusted {
        let (nonce, pow_key) = match (pow_nonce, pow_public_key) {
            (Some(nonce), Some(pk)) => (nonce, pk),
            (None, None) => {
                return Err(format!(
                    "Edge node {} did not provide PoW nonce and public key - PoW is required",
                    peer_node_id
                ))
            }
            (None, Some(_)) => {
                return Err(format!(
                    "Edge node {} provided PoW public key but not nonce",
                    peer_node_id
                ))
            }
            (Some(_), None) => {
                return Err(format!(
                    "Edge node {} provided PoW nonce but not public key",
                    peer_node_id
                ))
            }
        };
        validate_edge_node_pow(peer_node_id, peer_public_key, Some(nonce), Some(pow_key))?;
        pow_verified = true;
    } else if pow_nonce.is_some() && pow_public_key.is_some() {
        validate_edge_node_pow(peer_node_id, peer_public_key, pow_nonce, pow_public_key)?;
        pow_verified = true;
    }

    if pow_verified {
        return Ok(());
    }

    let pubkey = peer_public_key.ok_or_else(|| {
        format!(
            "Edge node {} did not provide Ed25519 public key for authentication",
            peer_node_id
        )
    })?;

    let signature = peer_signature.ok_or_else(|| {
        format!(
            "Edge node {} did not provide Ed25519 signature for authentication",
            peer_node_id
        )
    })?;

    validate_timestamp(peer_node_id, timestamp, max_age_secs)?;

    let challenge = format!("edge:{}:{}", peer_node_id, timestamp);
    verify_signature(pubkey, &challenge, signature, peer_node_id, "Edge node")
}

pub fn validate_edge_node_with_attestation(
    peer_node_id: &str,
    record_store: &parking_lot::RwLock<Option<Arc<crate::dht::RecordStoreManager>>>,
    authorized_global_pubkeys: &[String],
    revoked_nodes: Option<&HashSet<String>>,
) -> Result<(), String> {
    let edge_key = format!("edge_attestation:{}", peer_node_id);
    let guard = record_store.read();
    let store = guard.as_ref().ok_or("Record store not initialized")?;
    let record = store.get_record(&edge_key).ok_or_else(|| {
        format!(
            "Edge node {} has no attestation - must be attested by a global node first",
            peer_node_id
        )
    })?;

    let attestation = crate::dht::edge_attestation::EdgeAttestation::deserialize(&record.value)
        .ok_or_else(|| format!("Edge node {} has invalid attestation format", peer_node_id))?;

    if attestation.is_expired() {
        return Err(format!(
            "Edge node {} attestation expired at {}",
            peer_node_id, attestation.expires_at
        ));
    }

    let signable_content = attestation.signable_content();
    let attestation_pubkey_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&attestation.signer_public_key)
        .map_err(|e| format!("Invalid attestation signer public key: {}", e))?;

    let signature_valid = crate::cert::verify_ed25519(
        &signable_content,
        &attestation.signature,
        &attestation_pubkey_bytes,
    );

    if !signature_valid {
        return Err(format!(
            "Edge node {} has invalid attestation signature",
            peer_node_id
        ));
    }

    if let Some(revoked) = revoked_nodes {
        if revoked.contains(&attestation.signer_public_key) {
            return Err(format!(
                "Edge node {} attestation signed by revoked global node",
                peer_node_id
            ));
        }
    }

    let mut key_verified = false;
    for global_pubkey in authorized_global_pubkeys {
        if let Ok(pk_bytes) = base64::engine::general_purpose::STANDARD.decode(global_pubkey) {
            if pk_bytes == attestation_pubkey_bytes {
                key_verified = true;
                break;
            }
        }
    }

    if !key_verified {
        return Err(format!(
            "Edge node {} attestation signed by unknown global node",
            peer_node_id
        ));
    }

    tracing::debug!(
        "Edge node {} attestation validated successfully",
        peer_node_id
    );
    Ok(())
}

pub fn validate_edge_node_pow(
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    pow_nonce: Option<u64>,
    pow_public_key: Option<&str>,
) -> Result<(), String> {
    let pubkey = peer_public_key.ok_or_else(|| {
        format!(
            "Edge node {} did not provide public key for PoW validation",
            peer_node_id
        )
    })?;

    let nonce =
        pow_nonce.ok_or_else(|| format!("Edge node {} did not provide PoW nonce", peer_node_id))?;

    let pow_key = pow_public_key
        .ok_or_else(|| format!("Edge node {} did not provide PoW public key", peer_node_id))?;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let pk_bytes = URL_SAFE_NO_PAD.decode(pubkey).map_err(|e| {
        format!(
            "Edge node {} has invalid public key encoding: {}",
            peer_node_id, e
        )
    })?;

    let pow_pk_bytes = URL_SAFE_NO_PAD.decode(pow_key).map_err(|e| {
        format!(
            "Edge node {} has invalid PoW public key encoding: {}",
            peer_node_id, e
        )
    })?;

    if pk_bytes.len() != 32 {
        return Err(format!(
            "Edge node {} public key has invalid length: {} (expected 32)",
            peer_node_id,
            pk_bytes.len()
        ));
    }

    if pow_pk_bytes.len() != 32 {
        return Err(format!(
            "Edge node {} PoW public key has invalid length: {} (expected 32)",
            peer_node_id,
            pow_pk_bytes.len()
        ));
    }

    if pk_bytes != pow_pk_bytes {
        return Err(format!(
            "Edge node {} PoW public key does not match identity public key",
            peer_node_id
        ));
    }

    let node_id = crate::dht::routing::node_id::NodeId::from_public_key(&pow_pk_bytes);
    if !node_id.verify_pow(&pow_pk_bytes, nonce) {
        return Err(format!(
            "Edge node {} PoW verification failed",
            peer_node_id
        ));
    }

    tracing::debug!(
        "Edge node {} PoW validated successfully (nonce: {})",
        peer_node_id,
        nonce
    );

    Ok(())
}

fn validate_origin_node(
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    peer_signature: Option<&str>,
    timestamp: u64,
    max_age_secs: u64,
    revoked_nodes: Option<&GlobalNodeRevocationList>,
    global_node_attestation_key: Option<&str>,
    global_node_attestation_sig: Option<&str>,
    authorized_global_pubkeys: &[String],
) -> Result<(), String> {
    if let Some(revocation_list) = revoked_nodes {
        if let Some(revocation_info) = revocation_list.is_node_revoked(peer_node_id) {
            return Err(format!(
                "Origin node {} has been revoked: {} (at {})",
                peer_node_id, revocation_info.reason, revocation_info.revoked_at
            ));
        }
    }

    let pubkey = peer_public_key.ok_or_else(|| {
        format!(
            "Origin node {} did not provide Ed25519 public key for authentication",
            peer_node_id
        )
    })?;

    let signature = peer_signature.ok_or_else(|| {
        format!(
            "Origin node {} did not provide Ed25519 signature for authentication",
            peer_node_id
        )
    })?;

    validate_timestamp(peer_node_id, timestamp, max_age_secs)?;

    let challenge = format!("origin:{}:{}", peer_node_id, timestamp);

    verify_signature(pubkey, &challenge, signature, peer_node_id, "Origin node")?;

    let attestation_key = global_node_attestation_key.ok_or_else(|| {
        format!(
            "Origin node {} did not provide global node attestation key",
            peer_node_id
        )
    })?;

    let attestation_sig = global_node_attestation_sig.ok_or_else(|| {
        format!(
            "Origin node {} did not provide global node attestation signature",
            peer_node_id
        )
    })?;

    if authorized_global_pubkeys.is_empty() {
        return Err("No authorized global node keys configured for origin attestation".to_string());
    }

    if !authorized_global_pubkeys
        .iter()
        .any(|k| k == attestation_key)
    {
        return Err(format!(
            "Origin node {} global node attestation key not in authorized list",
            peer_node_id
        ));
    }

    verify_signature(
        attestation_key,
        &challenge,
        attestation_sig,
        peer_node_id,
        "Origin node global attestation",
    )
}

fn validate_global_node(
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    peer_signature: Option<&str>,
    timestamp: u64,
    max_age_secs: u64,
    revoked_nodes: Option<&GlobalNodeRevocationList>,
    authorized_global_pubkeys: &[String],
) -> Result<(), String> {
    if let Some(revocation_list) = revoked_nodes {
        if let Some(revocation_info) = revocation_list.is_node_revoked(peer_node_id) {
            return Err(format!(
                "Global node {} has been revoked: {} (at {})",
                peer_node_id, revocation_info.reason, revocation_info.revoked_at
            ));
        }
    }

    let pubkey = peer_public_key.ok_or_else(|| {
        format!(
            "Global node {} did not provide Ed25519 public key for authentication",
            peer_node_id
        )
    })?;

    let signature = peer_signature.ok_or_else(|| {
        format!(
            "Global node {} did not provide Ed25519 signature for authentication",
            peer_node_id
        )
    })?;

    validate_timestamp(peer_node_id, timestamp, max_age_secs)?;

    if authorized_global_pubkeys.is_empty() {
        return Err(format!(
            "Global node {} authentication failed: no authorized global node public keys configured",
            peer_node_id
        ));
    }

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let pk_bytes = URL_SAFE_NO_PAD.decode(pubkey).map_err(|e| {
        format!(
            "Global node {} has invalid public key encoding: {}",
            peer_node_id, e
        )
    })?;

    if pk_bytes.len() != 32 {
        return Err(format!(
            "Global node {} public key has invalid length: {} (expected 32)",
            peer_node_id,
            pk_bytes.len()
        ));
    }

    let pk_base64 = URL_SAFE_NO_PAD.encode(&pk_bytes);
    if !authorized_global_pubkeys.iter().any(|k| k == &pk_base64) {
        return Err(format!(
            "Global node {} public key not in authorized list",
            peer_node_id
        ));
    }

    let challenge = format!("{}:{}", peer_node_id, timestamp);
    verify_signature(pubkey, &challenge, signature, peer_node_id, "Global node")
}

fn validate_timestamp(peer_node_id: &str, timestamp: u64, max_age_secs: u64) -> Result<(), String> {
    let now = synvoid_utils::current_timestamp();
    if now.saturating_sub(timestamp) > max_age_secs {
        return Err(format!(
            "Node {} authentication expired: timestamp {} is older than {} seconds",
            peer_node_id, timestamp, max_age_secs
        ));
    }
    if timestamp > now.saturating_add(60) {
        return Err(format!(
            "Node {} authentication has future timestamp: {} (now: {})",
            peer_node_id, timestamp, now
        ));
    }
    Ok(())
}

fn verify_signature(
    pubkey: &str,
    challenge: &str,
    signature: &str,
    peer_node_id: &str,
    node_type: &str,
) -> Result<(), String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    let sig_bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|e| {
        format!(
            "{} {} has invalid signature encoding: {}",
            node_type, peer_node_id, e
        )
    })?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "{} {} signature has invalid length: {} (expected 64)",
            node_type,
            peer_node_id,
            sig_bytes.len()
        ));
    }

    let pk_bytes = URL_SAFE_NO_PAD.decode(pubkey).map_err(|e| {
        format!(
            "{} {} has invalid public key encoding: {}",
            node_type, peer_node_id, e
        )
    })?;

    if pk_bytes.len() != 32 {
        return Err(format!(
            "{} {} public key has invalid length: {} (expected 32)",
            node_type,
            peer_node_id,
            pk_bytes.len()
        ));
    }

    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        format!(
            "{} {} has invalid Ed25519 public key: {}",
            node_type, peer_node_id, e
        )
    })?;

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);

    verifying_key
        .verify(
            challenge.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&sig_array),
        )
        .map_err(|e| {
            format!(
                "{} {} Ed25519 signature verification failed: {}",
                node_type, peer_node_id, e
            )
        })?;

    Ok(())
}

pub fn generate_global_node_auth(
    node_id: &str,
    secret_key: &[u8; 32],
) -> Result<(String, u64), String> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let timestamp = synvoid_utils::current_timestamp();
    let challenge = format!("{}:{}", node_id, timestamp);
    let signature = signing_key.sign(challenge.as_bytes());
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    Ok((URL_SAFE_NO_PAD.encode(signature.to_bytes()), timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    fn generate_test_keypair() -> ([u8; 32], String) {
        use ed25519_dalek::SigningKey;
        let secret = [0x01; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
        (secret, public)
    }

    fn generate_different_keypair(seed: u8) -> ([u8; 32], String) {
        use ed25519_dalek::SigningKey;
        let mut secret = [0u8; 32];
        secret[0] = seed;
        let signing_key = SigningKey::from_bytes(&secret);
        let public = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());
        (secret, public)
    }

    #[test]
    fn test_non_global_passes() {
        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[],
            "test-node",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("did not provide PoW nonce and public key - PoW is required"));
    }

    #[test]
    fn test_edge_node_with_valid_signature_passes() {
        use crate::dht::routing::node_id::NodeId;
        let (secret, public) = generate_test_keypair();
        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("test-node:{}", timestamp);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            Some(pow_nonce),
            Some(&public),
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_signature_passes() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) =
            generate_global_node_auth("test-global-node", &secret).unwrap();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-global-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_revoked_node_fails() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) =
            generate_global_node_auth("test-global-node", &secret).unwrap();

        let revocation_list = GlobalNodeRevocationList::new();
        revocation_list.add_revoked_node("test-global-node", "Compromised key");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-global-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            Some(&revocation_list),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has been revoked"));
    }

    #[test]
    fn test_missing_public_key_fails() {
        let (_, public) = generate_test_keypair();
        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public],
            "test-node",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_signature_fails() {
        let (_, public) = generate_test_keypair();
        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[],
            "test-node",
            Some(&public),
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_timestamp_fails() {
        let (secret, public) = generate_test_keypair();
        let old_timestamp = synvoid_utils::current_timestamp() - 600;
        let challenge = format!("test-node:{}", old_timestamp);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&signature),
            old_timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unauthorized_public_key_fails() {
        let (_, public_a) = generate_test_keypair();
        let (secret_b, public_b) = generate_different_keypair(0x02);
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret_b).unwrap();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public_a],
            "test-node",
            Some(&public_b),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_authorized_list_rejects_all() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret).unwrap();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[],
            "test-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("no authorized global node public keys configured"));
    }

    #[test]
    fn test_invalid_signature_fails() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret).unwrap();
        let corrupted_sig = format!("{}corrupted", signature);

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&corrupted_sig),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_origin_node_with_valid_signature_and_attestation_passes() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x03);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature =
            URL_SAFE_NO_PAD.encode(global_signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::ORIGIN,
            &[global_public.clone()],
            "origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            Some(&global_public),
            Some(&attestation_signature),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok(), "Origin validation failed: {:?}", result);
    }

    #[test]
    fn test_origin_node_missing_attestation_key_fails() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (_, global_public) = generate_different_keypair(0x03);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::ORIGIN,
            &[global_public.clone()],
            "origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("did not provide global node attestation key"));
    }

    #[test]
    fn test_origin_node_attestation_key_not_authorized_fails() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x03);
        let (_, unauthorized_global) = generate_different_keypair(0x04);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature =
            URL_SAFE_NO_PAD.encode(global_signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::ORIGIN,
            &[unauthorized_global],
            "origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            Some(&global_public),
            Some(&attestation_signature),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("global node attestation key not in authorized list"));
    }

    #[test]
    fn test_origin_node_revoked_fails() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x03);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature =
            URL_SAFE_NO_PAD.encode(global_signing_key.sign(challenge.as_bytes()).to_bytes());

        let revocation_list = GlobalNodeRevocationList::new();
        revocation_list.add_revoked_node("origin-node", "Security breach");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::ORIGIN,
            &[global_public.clone()],
            "origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            Some(&revocation_list),
            Some(&global_public),
            Some(&attestation_signature),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has been revoked"));
    }

    #[test]
    fn test_edge_node_with_valid_pow_passes() {
        use crate::dht::routing::node_id::NodeId;

        let (_, public) = generate_test_keypair();

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_edge_node_pow(
            "edge-pow-node",
            Some(&public),
            Some(pow_nonce),
            Some(&public),
        );
        assert!(result.is_ok(), "PoW validation failed: {:?}", result);
    }

    #[test]
    fn test_edge_node_pow_key_mismatch_fails() {
        use crate::dht::routing::node_id::NodeId;
        let (_, public) = generate_test_keypair();
        let (_, different_public) = generate_different_keypair(0x05);

        let pow_pk_bytes = URL_SAFE_NO_PAD
            .decode(&different_public)
            .expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_edge_node_pow(
            "edge-pow-node",
            Some(&public),
            Some(pow_nonce),
            Some(&different_public),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("PoW public key does not match identity public key"));
    }

    #[test]
    fn test_edge_node_pow_invalid_nonce_fails() {
        use crate::dht::routing::node_id::NodeId;
        let (_, public) = generate_test_keypair();

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let _ = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let invalid_nonce = u64::MAX;

        let result = validate_edge_node_pow(
            "edge-pow-node",
            Some(&public),
            Some(invalid_nonce),
            Some(&public),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("PoW verification failed"));
    }

    #[test]
    fn test_edge_node_pow_missing_nonce_fails() {
        let (_, public) = generate_test_keypair();

        let result = validate_edge_node_pow("edge-pow-node", Some(&public), None, Some(&public));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("did not provide PoW nonce"));
    }

    #[test]
    fn test_edge_node_pow_missing_pow_key_fails() {
        use crate::dht::routing::node_id::NodeId;
        let (_, public) = generate_test_keypair();

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_edge_node_pow("edge-pow-node", Some(&public), Some(pow_nonce), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("did not provide PoW public key"));
    }

    #[test]
    fn test_edge_node_with_pow_bypasses_signature() {
        use crate::dht::routing::node_id::NodeId;

        let (_, public) = generate_test_keypair();

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[],
            "edge-pow-node",
            Some(&public),
            None,
            0,
            300,
            None,
            None,
            None,
            Some(pow_nonce),
            Some(&public),
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok(), "PoW validation failed: {:?}", result);
    }

    #[test]
    fn test_composite_role_global_edge_passes_global_validation() {
        use crate::dht::routing::node_id::NodeId;
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) = generate_global_node_auth("composite-node", &secret).unwrap();

        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
            &[public.clone()],
            "composite-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            Some(pow_nonce),
            Some(&public),
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_composite_role_global_origin_passes_origin_validation() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x07);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:composite-origin:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature =
            URL_SAFE_NO_PAD.encode(global_signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_ORIGIN,
            &[global_public.clone()],
            "composite-origin",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            Some(&global_public),
            Some(&attestation_signature),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_future_timestamp_fails() {
        let (secret, public) = generate_test_keypair();
        let future_timestamp = synvoid_utils::current_timestamp() + 120;
        let challenge = format!("test-node:{}", future_timestamp);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&signature),
            future_timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future timestamp"));
    }

    #[test]
    fn test_invalid_public_key_encoding_fails() {
        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &["invalid_base64_key".to_string()],
            "test-node",
            Some("invalid_base64_key"),
            Some("some_signature"),
            synvoid_utils::current_timestamp(),
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid public key encoding"));
    }

    #[test]
    fn test_revocation_list_check_for_edge_node() {
        let revocation_list = GlobalNodeRevocationList::new();
        revocation_list.add_revoked_node("revoked-edge", "Compromised");

        let (_, public) = generate_test_keypair();
        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("edge:revoked-edge:{}", timestamp);
        let (secret, _) = generate_test_keypair();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[],
            "revoked-edge",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            Some(&revocation_list),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has been revoked"));
    }

    #[test]
    fn test_revocation_list_check_for_global_node() {
        let revocation_list = GlobalNodeRevocationList::new();
        revocation_list.add_revoked_node("revoked-global", "Key compromise");

        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) = generate_global_node_auth("revoked-global", &secret).unwrap();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "revoked-global",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            Some(&revocation_list),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("has been revoked"));
    }

    #[test]
    fn test_empty_authorized_pubkeys_for_origin_attestation_fails() {
        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x08);

        let timestamp = synvoid_utils::current_timestamp();
        let challenge = format!("origin:origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature =
            URL_SAFE_NO_PAD.encode(origin_signing_key.sign(challenge.as_bytes()).to_bytes());

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature =
            URL_SAFE_NO_PAD.encode(global_signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::ORIGIN,
            &[],
            "origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            Some(&global_public),
            Some(&attestation_signature),
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("No authorized global node keys configured"));
    }

    #[test]
    fn test_generate_and_validate_global_node_auth_roundtrip() {
        let (secret, public) = generate_test_keypair();
        let node_id = "test-auth-node";

        let (signature, timestamp) = generate_global_node_auth(node_id, &secret).unwrap();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            node_id,
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_edge_origin_composite_passes() {
        use crate::dht::routing::node_id::NodeId;

        let (origin_secret, origin_public) = generate_test_keypair();
        let (global_secret, global_public) = generate_different_keypair(0x09);

        let timestamp = synvoid_utils::current_timestamp();
        let origin_challenge = format!("origin:edge-origin-node:{}", timestamp);

        let origin_signing_key = ed25519_dalek::SigningKey::from_bytes(&origin_secret);
        let origin_signature = URL_SAFE_NO_PAD.encode(
            origin_signing_key
                .sign(origin_challenge.as_bytes())
                .to_bytes(),
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation_signature = URL_SAFE_NO_PAD.encode(
            global_signing_key
                .sign(origin_challenge.as_bytes())
                .to_bytes(),
        );

        let pow_pk_bytes = URL_SAFE_NO_PAD
            .decode(&origin_public)
            .expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE_ORIGIN,
            &[global_public.clone()],
            "edge-origin-node",
            Some(&origin_public),
            Some(&origin_signature),
            timestamp,
            300,
            None,
            Some(&global_public),
            Some(&attestation_signature),
            Some(pow_nonce),
            Some(&origin_public),
            None,
            None,
            None,
            false,
        );
        assert!(
            result.is_ok(),
            "EDGE_ORIGIN validation failed: {:?}",
            result
        );
    }

    #[test]
    fn test_global_edge_requires_pow_and_signature() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) =
            generate_global_node_auth("global-edge-node", &secret).unwrap();
        use crate::dht::routing::node_id::NodeId;
        let pow_pk_bytes = URL_SAFE_NO_PAD.decode(&public).expect("valid base64");
        let pow_nonce = NodeId::find_pow_nonce(&pow_pk_bytes).expect("pow nonce found");

        let result_with_pow_only = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
            &[public.clone()],
            "global-edge-node",
            Some(&public),
            None,
            timestamp,
            300,
            None,
            None,
            None,
            Some(pow_nonce),
            Some(&public),
            None,
            None,
            None,
            false,
        );
        assert!(result_with_pow_only.is_err(), "Should require signature");
        let err_pow = result_with_pow_only.unwrap_err();
        assert!(
            err_pow.contains("GLOBAL_EDGE role requires Ed25519 signature"),
            "Error: {}",
            err_pow
        );

        let result_with_signature_only = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
            &[public.clone()],
            "global-edge-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert!(result_with_signature_only.is_err(), "Should require PoW");
        let err_sig = result_with_signature_only.unwrap_err();
        assert!(
            err_sig.contains("GLOBAL_EDGE role requires PoW"),
            "Error: {}",
            err_sig
        );

        let result_with_both = validate_peer_role(
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
            &[public.clone()],
            "global-edge-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
            None,
            None,
            None,
            Some(pow_nonce),
            Some(&public),
            None,
            None,
            None,
            false,
        );
        assert!(
            result_with_both.is_ok(),
            "Should pass with both: {:?}",
            result_with_both
        );
    }

    #[test]
    fn test_signed_raft_attestation_rejects_unsigned() {
        let (org_secret, org_public_b64) = generate_test_keypair();
        let org_secret_bytes = URL_SAFE_NO_PAD.decode(&org_public_b64).unwrap();
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: org_secret_bytes.clone(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let authorized_global_pubkeys = vec![org_public_b64.clone()];

        // No attestation at all - should fail (no quorum sigs either)
        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            None,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("lacks both quorum signatures and valid signed Raft attestation"));
    }

    #[test]
    fn test_signed_raft_attestation_from_authorized_global_accepted() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let value_hash =
            RaftAttestation::compute_value_hash(&org_pub_key.get_signable_data().as_bytes());

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(value_hash.clone()),
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(value_hash),
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_ok(),
            "Valid signed attestation should be accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_signed_raft_attestation_from_unauthorized_key_rejected() {
        let (unauth_secret, _unauth_public_b64) = generate_different_keypair(0x20);
        let (_global_secret, global_public_b64) = generate_different_keypair(0x21);

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        // Sign with an unauthorized key
        let unauth_signing_key = ed25519_dalek::SigningKey::from_bytes(&unauth_secret);
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "unauthorized-node".to_string(),
            &unauth_signing_key,
            None,
        );

        // Only the global key is authorized, not the signing key
        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Unauthorized signer should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_wrong_namespace_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Wrong namespace: Intel instead of Org
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Intel,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Wrong namespace should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_wrong_key_id_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Wrong key_id
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "wrong-key-id".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Wrong key_id should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_tampered_signature_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let mut signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        // Tamper with the signature
        if let Some(first_byte) = signed_att.signature.first_mut() {
            *first_byte ^= 0xff;
        }

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Tampered signature should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_zero_timestamp_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Zero timestamp - should be rejected
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: 0,
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Zero timestamp should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_zero_commit_index_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Zero commit_index - should be rejected
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 0,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(result.is_err(), "Zero commit_index should be rejected");
    }

    #[test]
    fn test_signed_raft_attestation_from_revoked_node_accepted_at_attestation_level() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let value_hash =
            RaftAttestation::compute_value_hash(&org_pub_key.get_signable_data().as_bytes());

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(value_hash.clone()),
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(value_hash),
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_ok(),
            "Attestation from revoked global node is accepted at attestation validation level \
             (revocation is checked separately in validate_peer_role, not in attestation validation)"
        );
    }

    #[test]
    fn test_signed_raft_attestation_wrong_key_id_for_org_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Attestation for a different org key (value hash mismatch scenario)
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "wrong-org-key-id".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "Attestation for wrong key_id should be rejected (value hash mismatch)"
        );
    }

    #[test]
    fn test_signed_raft_attestation_empty_signer_public_key_rejected() {
        let (global_secret, _global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let mut signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        // Replace the signer public key with empty
        signed_att.signer_public_key = String::new();

        let authorized_global_pubkeys = vec!["some-authorized-key".to_string()];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "Attestation with empty signer_public_key should be rejected"
        );
    }

    #[test]
    fn test_v2_attestation_with_matching_value_hash_accepted() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);
        let expected_value_hash =
            RaftAttestation::compute_value_hash(&org_pub_key.get_signable_data().as_bytes());

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(expected_value_hash.clone()),
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(expected_value_hash),
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_ok(),
            "V2 attestation with matching value hash should be accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_v2_attestation_with_wrong_value_hash_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Wrong value hash (doesn't match the actual record)
        let wrong_value_hash = vec![0xff; 32];

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(wrong_value_hash.clone()),
        };

        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(wrong_value_hash),
        );

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "V2 attestation with wrong value hash should be rejected"
        );
    }

    #[test]
    fn test_v2_attestation_without_value_hash_rejected() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // V2 attestation without value_hash - should be rejected
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let mut signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            None,
        );

        // Force protocol version to 2 (simulating a v2 attestation missing value_hash)
        signed_att.protocol_version = 2;

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "V2 attestation without value_hash should be rejected"
        );
    }

    #[test]
    fn test_v1_attestation_backward_compat_accepted() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        // Build the v1 attestation manually so the signature matches protocol_version=1
        let mut signed_att = SignedRaftAttestation {
            attestation,
            signer_node_id: "global-node-1".to_string(),
            signer_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(global_signing_key.verifying_key().as_bytes()),
            signature: Vec::new(),
            protocol_version: 1,
        };
        let sig = global_signing_key.sign(&signed_att.signable_content());
        signed_att.signature = sig.to_bytes().to_vec();

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            true, // allow_v1_raft_attestations=true for backward compat test
        );
        assert!(
            result.is_ok(),
            "V1 attestation should be accepted when allow_v1_raft_attestations=true: {:?}",
            result
        );
    }

    #[test]
    fn test_compute_value_hash_deterministic() {
        let data = b"test data for hashing";
        let hash1 = RaftAttestation::compute_value_hash(data);
        let hash2 = RaftAttestation::compute_value_hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 output
    }

    #[test]
    fn test_compute_value_hash_different_inputs() {
        let hash1 = RaftAttestation::compute_value_hash(b"input-a");
        let hash2 = RaftAttestation::compute_value_hash(b"input-b");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_v1_attestation_rejected_by_default() {
        let (global_secret, global_public_b64) = generate_test_keypair();

        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);

        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );

        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: "org-key-1".to_string(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };

        let mut signed_att = SignedRaftAttestation {
            attestation,
            signer_node_id: "global-node-1".to_string(),
            signer_public_key: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(global_signing_key.verifying_key().as_bytes()),
            signature: Vec::new(),
            protocol_version: 1,
        };
        let sig = global_signing_key.sign(&signed_att.signable_content());
        signed_att.signature = sig.to_bytes().to_vec();

        let authorized_global_pubkeys = vec![global_public_b64];

        let result = validate_member_certificate_with_raft_attestation(
            &cert,
            &org_pub_key,
            &authorized_global_pubkeys,
            "peer-1",
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "V1 attestation should be rejected when allow_v1_raft_attestations=false: {:?}",
            result
        );
    }

    // --- validate_peer_role Raft attestation integration tests ---

    fn setup_edge_org_test() -> (
        crate::organization::OrgKey,
        crate::organization::OrgPublicKey,
        crate::organization::MemberCertificate,
        [u8; 32],
        String,
    ) {
        let (global_secret, global_public_b64) = generate_test_keypair();
        let (org_secret, _org_public_b64) = generate_different_keypair(0x10);
        let org_key = crate::organization::OrgKey {
            key_id: "org-key-1".to_string(),
            private_key: org_secret.to_vec(),
            public_key: ed25519_dalek::SigningKey::from_bytes(&org_secret)
                .verifying_key()
                .as_bytes()
                .to_vec(),
            created_at: synvoid_utils::current_timestamp(),
            issued_by: None,
        };
        let org_pub_key = crate::organization::OrgPublicKey::new("test-org".to_string(), &org_key);
        let cert = crate::organization::MemberCertificate::new(
            "peer-1".to_string(),
            "test-org".to_string(),
            &org_key,
            30,
        );
        (org_key, org_pub_key, cert, global_secret, global_public_b64)
    }

    fn make_v2_raft_attestation(
        global_secret: &[u8; 32],
        org_pub_key: &crate::organization::OrgPublicKey,
    ) -> SignedRaftAttestation {
        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(global_secret);
        let value_hash =
            RaftAttestation::compute_value_hash(&org_pub_key.get_signable_data().as_bytes());
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: org_pub_key.key_id.clone(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(value_hash.clone()),
        };
        SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(value_hash),
        )
    }

    #[test]
    fn test_validate_peer_role_edge_with_raft_attestation_passes() {
        let (_org_key, org_pub_key, cert, global_secret, global_public_b64) = setup_edge_org_test();
        let signed_att = make_v2_raft_attestation(&global_secret, &org_pub_key);

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[global_public_b64],
            "peer-1",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            Some(&org_pub_key),
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_ok(),
            "EDGE with valid V2 Raft attestation should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_role_edge_without_attestation_falls_back_to_quorum() {
        let (_org_key, org_pub_key, cert, _global_secret, global_public_b64) =
            setup_edge_org_test();

        // No attestation and no quorum sigs -> should fail
        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[global_public_b64],
            "peer-1",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            Some(&org_pub_key),
            None,
            false,
        );
        assert!(
            result.is_err(),
            "EDGE without attestation and without quorum sigs should fail: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_role_edge_wrong_value_hash_rejected() {
        let (_org_key, org_pub_key, cert, global_secret, global_public_b64) = setup_edge_org_test();
        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // Create attestation with wrong value hash
        let wrong_value_hash = RaftAttestation::compute_value_hash(b"wrong-value");
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: org_pub_key.key_id.clone(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: Some(wrong_value_hash.clone()),
        };
        let signed_att = SignedRaftAttestation::from_attestation(
            attestation,
            "global-node-1".to_string(),
            &global_signing_key,
            Some(wrong_value_hash),
        );

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[global_public_b64],
            "peer-1",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            Some(&org_pub_key),
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "EDGE with wrong value hash should be rejected: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_role_edge_v1_attestation_rejected_by_default() {
        let (_org_key, org_pub_key, cert, global_secret, global_public_b64) = setup_edge_org_test();
        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // V1 attestation: no value_hash, protocol_version=1
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: org_pub_key.key_id.clone(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };
        let mut signed_att = SignedRaftAttestation {
            attestation,
            signer_node_id: "global-node-1".to_string(),
            signer_public_key: URL_SAFE_NO_PAD
                .encode(global_signing_key.verifying_key().as_bytes()),
            signature: Vec::new(),
            protocol_version: 1,
        };
        let sig = global_signing_key.sign(&signed_att.signable_content());
        signed_att.signature = sig.to_bytes().to_vec();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[global_public_b64],
            "peer-1",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            Some(&org_pub_key),
            Some(&signed_att),
            false,
        );
        assert!(
            result.is_err(),
            "EDGE with V1 attestation should be rejected when allow_v1=false: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_role_edge_v1_attestation_accepted_when_allowed() {
        let (_org_key, org_pub_key, cert, global_secret, global_public_b64) = setup_edge_org_test();
        let global_signing_key = ed25519_dalek::SigningKey::from_bytes(&global_secret);

        // V1 attestation: no value_hash, protocol_version=1
        let attestation = RaftAttestation {
            leader_id: "leader-1".to_string(),
            commit_index: 42,
            namespace: crate::raft::Namespace::Org,
            key_id: org_pub_key.key_id.clone(),
            timestamp: synvoid_utils::current_timestamp(),
            value_hash: None,
        };
        let mut signed_att = SignedRaftAttestation {
            attestation,
            signer_node_id: "global-node-1".to_string(),
            signer_public_key: URL_SAFE_NO_PAD
                .encode(global_signing_key.verifying_key().as_bytes()),
            signature: Vec::new(),
            protocol_version: 1,
        };
        let sig = global_signing_key.sign(&signed_att.signable_content());
        signed_att.signature = sig.to_bytes().to_vec();

        let result = validate_peer_role(
            &crate::config::MeshNodeRole::EDGE,
            &[global_public_b64],
            "peer-1",
            None,
            None,
            0,
            300,
            None,
            None,
            None,
            None,
            None,
            Some(&cert),
            Some(&org_pub_key),
            Some(&signed_att),
            true,
        );
        assert!(
            result.is_ok(),
            "EDGE with V1 attestation should pass when allow_v1=true: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_canonical_status_authorized_global_not_revoked_ok() {
        let mut r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        r.authorized_global_nodes.insert("global1".to_string());
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "global1",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(result.is_ok(), "expected ok, got {:?}", result);
    }

    #[test]
    fn test_validate_peer_canonical_status_authorized_global_edge_passes() {
        // GLOBAL_EDGE is_global() && !is_origin() so it requires canonical global auth in this helper.
        let mut r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        r.authorized_global_nodes.insert("ge1".to_string());
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "ge1",
            &crate::config::MeshNodeRole::GLOBAL_EDGE,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_peer_canonical_status_unauthorized_global_rejected() {
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "global-bad",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not authorized"));
        assert!(err.contains("Global node"));
    }

    #[test]
    fn test_validate_peer_canonical_status_revoked_rejected_any_role() {
        let mut r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        r.revoked_nodes.insert("evil1".to_string());
        // Cover pure + composites to make GLOBAL/GLOBAL_EDGE/GLOBAL_ORIGIN revocation behavior explicit.
        for role in [
            crate::config::MeshNodeRole::EDGE,
            crate::config::MeshNodeRole::GLOBAL,
            crate::config::MeshNodeRole::ORIGIN,
            crate::config::MeshNodeRole::GLOBAL_EDGE,
            crate::config::MeshNodeRole::GLOBAL_ORIGIN,
            crate::config::MeshNodeRole::EDGE_ORIGIN,
        ] {
            let result = crate::peer_auth::validate_peer_canonical_status(&r, "evil1", &role);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(err.contains("revoked"));
            assert!(err.contains("canonical state"));
        }
    }

    #[test]
    fn test_validate_peer_canonical_status_unavailable_allows_revocation_part() {
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Unavailable);
        let result_edge = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "some-edge",
            &crate::config::MeshNodeRole::EDGE,
        );
        assert!(result_edge.is_ok());
        let result_global = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "some-global",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(result_global.is_err());
        assert!(result_global.unwrap_err().contains("not authorized"));
    }

    #[test]
    fn test_validate_peer_canonical_status_stale_explicit() {
        let mut r_stale_trusted =
            crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Stale {
                age_ms: 999,
            });
        r_stale_trusted
            .authorized_global_nodes
            .insert("g1".to_string());
        let res_trusted_stale = crate::peer_auth::validate_peer_canonical_status(
            &r_stale_trusted,
            "g1",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(res_trusted_stale.is_ok());
        // NOTE: freshness is observed and reported but acceptance is still permissive here.
        // Future policy may tighten stale global auth checks using AuthorityFreshnessConfig.
        let mut r_stale_not =
            crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Stale {
                age_ms: 1234,
            });
        let res_not_stale = crate::peer_auth::validate_peer_canonical_status(
            &r_stale_not,
            "g2",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(res_not_stale.is_err());
        let err = res_not_stale.unwrap_err();
        assert!(err.contains("not authorized"));
        assert!(err.contains("Stale"));
    }

    #[test]
    fn test_validate_peer_canonical_status_revoked_global_fails_even_if_authorized() {
        // Proves revocation is checked first and fails before global auth success can matter.
        let mut r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        r.authorized_global_nodes.insert("evil-global".to_string());
        r.revoked_nodes.insert("evil-global".to_string());
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "evil-global",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("revoked in canonical state"));
        assert!(!err.contains("not authorized")); // revoked path short-circuits
    }

    #[test]
    fn test_validate_peer_canonical_status_non_revoked_edge_passes_without_global_auth() {
        // Edge (non-global) requires no entry in authorized_global_nodes for this helper.
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "plain-edge",
            &crate::config::MeshNodeRole::EDGE,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_peer_canonical_status_global_origin_exempt_from_global_auth_list_in_this_helper(
    ) {
        // GLOBAL_ORIGIN carries is_global() but also is_origin(), so the guard
        // `role.is_global() && !role.is_origin()` intentionally skips the canonical
        // global authorization list check in *this* helper.
        //
        // Rationale (consistent with legacy validate_peer_role + role bitmask design):
        // - A GLOBAL_ORIGIN is a global (consensus participant) that also hosts origins.
        // - Its *global* authority is expressed via Raft membership (AuthorizedGlobalNodes)
        //   and origin claims are attested by a *separate* real authorized global node.
        // - Origins (incl. composites) cannot self-attest global membership.
        // - Therefore this helper does not require the ID in authorized_global_nodes
        //   for GLOBAL_ORIGIN (or EDGE_ORIGIN etc.); the origin side is validated
        //   via attestation path elsewhere.
        //
        // This test makes the exemption explicit and matches plan intent.
        // If policy ever changes to require global auth for *any* is_global() role,
        // update the guard + this test name/behavior + rustdoc together.
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        // deliberately no authorized_global entry for this ID
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "global-that-is-also-origin",
            &crate::config::MeshNodeRole::GLOBAL_ORIGIN,
        );
        assert!(
            result.is_ok(),
            "GLOBAL_ORIGIN should be exempt from canonical global-auth list in this helper: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_peer_canonical_status_unavailable_global_auth_fails_closed() {
        // Unavailable global auth must fail closed for global non-origin roles.
        // Error must include both "not authorized" text and the freshness.
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Unavailable);
        let result = crate::peer_auth::validate_peer_canonical_status(
            &r,
            "missing-global",
            &crate::config::MeshNodeRole::GLOBAL,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("not authorized in canonical state"));
        assert!(err.contains("Unavailable"));
    }

    fn _validate_peer_canonical_accepts_dyn(r: &dyn crate::CanonicalTrustReader) {
        let _ = crate::peer_auth::validate_peer_canonical_status(
            r,
            "n",
            &crate::config::MeshNodeRole::EDGE,
        );
    }

    #[test]
    fn test_low_risk_consumer_peer_auth_uses_dyn_trait() {
        let r = crate::StaticCanonicalTrustReader::new(crate::CanonicalFreshness::Live);
        _validate_peer_canonical_accepts_dyn(&r);
        let b: Box<dyn crate::CanonicalTrustReader> = Box::new(r);
        _validate_peer_canonical_accepts_dyn(&*b);
    }
}
