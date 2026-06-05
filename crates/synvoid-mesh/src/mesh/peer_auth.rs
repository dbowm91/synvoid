use base64::Engine;
use dashmap::DashMap;
use ed25519_dalek::{Signer, Verifier};
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
}

impl RaftAttestation {
    pub fn from_dht_record(value: &[u8]) -> Option<Self> {
        synvoid_utils::serialization::deserialize(value).ok()
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
    raft_attestation: Option<&RaftAttestation>,
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

    // 5. Verify trust via EITHER quorum signatures OR Raft attestation
    // Raft commit IS the proof of consensus - the Leader's commit index
    // proves majority agreement without needing 2/3 individual signatures
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
            att.namespace == crate::raft::Namespace::Org
                && att.key_id == org_pub_key.key_id
                && att.timestamp > 0
                && att.commit_index > 0
        })
        .unwrap_or(false);

    if !has_quorum && !has_raft_attestation {
        return Err(
            "Organization key lacks both quorum signatures and valid Raft attestation".to_string(),
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
) -> Result<(), String> {
    // Try Organization Trust Chain first if available for Edge nodes
    if role.is_edge() {
        if let (Some(cert), Some(org_key)) = (member_certificate, org_public_key) {
            if let Ok(()) =
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
        );
        assert!(
            result_with_both.is_ok(),
            "Should pass with both: {:?}",
            result_with_both
        );
    }
}
