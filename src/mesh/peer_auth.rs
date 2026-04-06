/// Ed25519 challenge-response authentication for mesh peers claiming global role.
///
/// Replaces the previous shared secret approach with cryptographic verification:
/// - Global nodes sign a challenge with their Ed25519 private key
/// - Verifying nodes check the signature against a list of authorized public keys
/// - The challenge includes the peer's node_id and a timestamp to prevent replay
use ed25519_dalek::{Signer, Verifier};

/// Verifies that a peer claiming a global role has a valid Ed25519 signature.
///
/// The signature is over the format: `{node_id}:{timestamp}`
/// This prevents replay attacks since timestamps are validated.
///
/// # Arguments
/// * `role` - The role claimed by the peer
/// * `authorized_global_pubkeys` - List of authorized global node public keys (base64 URL-safe no-pad)
/// * `peer_node_id` - The node ID claimed by the peer
/// * `peer_public_key` - The Ed25519 public key of the peer (base64 URL-safe no-pad)
/// * `peer_signature` - The signature over the challenge data (base64 URL-safe no-pad)
/// * `timestamp` - The timestamp included in the challenge
/// * `max_age_secs` - Maximum allowed age of the challenge (default: 300 seconds)
///
/// # Returns
/// * `Ok(())` if the peer is not claiming global, or if signature verification succeeds
/// * `Err(String)` with a descriptive message if verification fails
pub fn validate_peer_role(
    role: &crate::mesh::config::MeshNodeRole,
    authorized_global_pubkeys: &[String],
    peer_node_id: &str,
    peer_public_key: Option<&str>,
    peer_signature: Option<&str>,
    timestamp: u64,
    max_age_secs: u64,
) -> Result<(), String> {
    if !role.is_global() {
        return Ok(());
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

    // Validate timestamp to prevent replay attacks
    let now = crate::utils::current_timestamp();
    if now.saturating_sub(timestamp) > max_age_secs {
        return Err(format!(
            "Global node {} authentication expired: timestamp {} is older than {} seconds",
            peer_node_id, timestamp, max_age_secs
        ));
    }
    if timestamp > now.saturating_add(60) {
        return Err(format!(
            "Global node {} authentication has future timestamp: {} (now: {})",
            peer_node_id, timestamp, now
        ));
    }

    // Verify the public key is in the authorized list
    if authorized_global_pubkeys.is_empty() {
        return Err(format!(
            "Global node {} authentication failed: no authorized global node public keys configured",
            peer_node_id
        ));
    }

    // Decode public key
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

    // Check decoded pubkey is in authorized list
    let pk_base64 = URL_SAFE_NO_PAD.encode(&pk_bytes);
    if !authorized_global_pubkeys.iter().any(|k| k == &pk_base64) {
        return Err(format!(
            "Global node {} public key not in authorized list",
            peer_node_id
        ));
    }

    // Decode signature
    let sig_bytes = URL_SAFE_NO_PAD.decode(signature).map_err(|e| {
        format!(
            "Global node {} has invalid signature encoding: {}",
            peer_node_id, e
        )
    })?;

    if sig_bytes.len() != 64 {
        return Err(format!(
            "Global node {} signature has invalid length: {} (expected 64)",
            peer_node_id,
            sig_bytes.len()
        ));
    }

    // Build challenge message and verify signature
    let challenge = format!("{}:{}", peer_node_id, timestamp);
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_array).map_err(|e| {
        format!(
            "Global node {} has invalid Ed25519 public key: {}",
            peer_node_id, e
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
                "Global node {} Ed25519 signature verification failed: {}",
                peer_node_id, e
            )
        })?;

    Ok(())
}

/// Generates an Ed25519 signature for global node authentication.
///
/// Signs the format: `{node_id}:{timestamp}` using the provided secret key.
///
/// # Arguments
/// * `node_id` - This node's ID
/// * `secret_key` - Ed25519 secret key bytes (32 bytes)
///
/// # Returns
/// * `(signature, timestamp)` - Base64-encoded signature and the timestamp used
pub fn generate_global_node_auth(
    node_id: &str,
    secret_key: &[u8; 32],
) -> Result<(String, u64), String> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
    let timestamp = crate::utils::current_timestamp();
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
            &crate::mesh::config::MeshNodeRole::EDGE,
            &[],
            "test-node",
            None,
            None,
            0,
            300,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_valid_signature_passes() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) =
            generate_global_node_auth("test-global-node", &secret).unwrap();

        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-global-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_missing_public_key_fails() {
        let (_, public) = generate_test_keypair();
        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[public],
            "test-node",
            None,
            None,
            0,
            300,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_signature_fails() {
        let (_, public) = generate_test_keypair();
        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[],
            "test-node",
            Some(&public),
            None,
            0,
            300,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_timestamp_fails() {
        let (secret, public) = generate_test_keypair();
        let old_timestamp = crate::utils::current_timestamp() - 600;
        let challenge = format!("test-node:{}", old_timestamp);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let signature = URL_SAFE_NO_PAD.encode(signing_key.sign(challenge.as_bytes()).to_bytes());

        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&signature),
            old_timestamp,
            300,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_unauthorized_public_key_fails() {
        let (_, public_a) = generate_test_keypair();
        let (secret_b, public_b) = generate_different_keypair(0x02);
        // Sign with secret_b, but authorized list has public_a
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret_b).unwrap();

        // Node presents public_b but authorized list has public_a
        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[public_a],
            "test-node",
            Some(&public_b),
            Some(&signature),
            timestamp,
            300,
        );
        // Should fail because public_b != public_a
        assert!(
            result.is_err(),
            "Expected error for unauthorized key, got: {:?}",
            result
        );
    }

    #[test]
    fn test_empty_authorized_list_rejects_all() {
        let (secret, public) = generate_test_keypair();
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret).unwrap();

        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[],
            "test-node",
            Some(&public),
            Some(&signature),
            timestamp,
            300,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("no authorized global node public keys configured"));
    }

    #[test]
    fn test_invalid_signature_fails() {
        let (secret, public) = generate_test_keypair();
        // Sign with same secret (valid), but then corrupt the signature
        let (signature, timestamp) = generate_global_node_auth("test-node", &secret).unwrap();
        let corrupted_sig = format!("{}corrupted", signature);

        let result = validate_peer_role(
            &crate::mesh::config::MeshNodeRole::GLOBAL,
            &[public.clone()],
            "test-node",
            Some(&public),
            Some(&corrupted_sig),
            timestamp,
            300,
        );
        assert!(
            result.is_err(),
            "Expected error for invalid signature encoding, got: {:?}",
            result
        );
    }
}
