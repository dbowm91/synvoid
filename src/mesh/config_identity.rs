use super::*;

impl GlobalNodeConfig {
    pub fn is_invite_token_valid(&self, token: &str) -> bool {
        self.invite_tokens.iter().any(|t| t == token)
    }

    pub fn load_keys(&mut self) -> Result<(), String> {
        use base64::Engine;

        // Load X25519 key
        if let Some(ref b64) = self.x25519_private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 X25519 key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("X25519 key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.x25519_private_key = Some(key);

            // Derive public key
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(key);
            let public = PublicKey::from(&secret);
            self.x25519_public_key_base64 = Some(URL_SAFE_NO_PAD.encode(public.as_bytes()));
        }

        // Load Ed25519 key
        if let Some(ref b64) = self.ed25519_private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 Ed25519 key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("Ed25519 key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.ed25519_private_key = Some(key);

            // Derive public key
            use ed25519_dalek::SigningKey;
            let signing_key = SigningKey::from_bytes(&key);
            self.ed25519_public_key_base64 =
                Some(URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()));
        }

        // Load ML-KEM-768 key - if private key is provided, derive public key
        if let Some(ref b64) = self.ml_kem_private_key_base64 {
            use pqc::MlKem768;
            let sk = MlKem768::secret_key_from_base64(b64)
                .map_err(|e| format!("Invalid base64 ML-KEM key: {}", e))?;

            let pk = sk
                .public_key()
                .map_err(|e| format!("Failed to derive public key: {}", e))?;
            self.ml_kem_public_key_base64 = Some(pk.to_base64());
        }

        // Auto-generate ML-KEM-768 key if not configured (for post-quantum security)
        if self.ml_kem_private_key_base64.is_none() {
            tracing::info!("Auto-generating ML-KEM-768 keypair for post-quantum key exchange");
            match self.generate_ml_kem_keypair() {
                Ok((pk, _)) => {
                    tracing::debug!(
                        "Generated ML-KEM public key: {}...",
                        &pk[..32.min(pk.len())]
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to auto-generate ML-KEM key: {}", e);
                }
            }
        }

        // Load ML-DSA-44 key - if private key is provided, derive public key
        if let Some(ref b64) = self.ml_dsa_private_key_base64 {
            let sk = pqc::SigningKey::from_base64(b64)
                .map_err(|e| format!("Invalid base64 ML-DSA key: {}", e))?;

            let vk = sk.verifying_key();
            self.ml_dsa_public_key_base64 = Some(vk.to_base64());
        }

        Ok(())
    }

    /// Generate new ML-KEM-768 keypair for post-quantum key exchange
    pub fn generate_ml_kem_keypair(&mut self) -> Result<(String, String), String> {
        use pqc::MlKem768;
        let (pk, sk) = MlKem768::generate_keypair()
            .map_err(|e| format!("Failed to generate ML-KEM keypair: {}", e))?;

        self.ml_kem_public_key_base64 = Some(pk.to_base64());
        self.ml_kem_private_key_base64 = Some(sk.to_base64());

        Ok((pk.to_base64(), sk.to_base64()))
    }

    /// Generate new ML-DSA-44 keypair for post-quantum signatures
    pub fn generate_ml_dsa_keypair(&mut self) -> Result<(String, String), String> {
        use pqc::MlDsa44;
        let (vk, sk) = MlDsa44::generate_keypair()
            .map_err(|e| format!("Failed to generate ML-DSA keypair: {}", e))?;

        self.ml_dsa_public_key_base64 = Some(vk.to_base64());
        self.ml_dsa_private_key_base64 = Some(sk.to_base64());

        Ok((vk.to_base64(), sk.to_base64()))
    }
}

impl GenesisKeyConfig {
    pub fn generate() -> Self {
        use rand::{RngCore, SeedableRng};
        let mut key = [0u8; 32];
        let mut rng = rand::rngs::StdRng::from_os_rng();
        rng.fill_bytes(&mut key);
        let public_key = Self::derive_public_key(&key);

        Self {
            private_key_base64: None,
            private_key: Some(key),
            public_key,
            is_first_node: true,
            previous_genesis_key_base64: None,
            rotation_sequence: 0,
            authorized_genesis_keys: Vec::new(),
        }
    }

    pub fn load(&mut self) -> Result<(), String> {
        if let Some(ref b64) = self.private_key_base64 {
            let key_bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| format!("Invalid base64 genesis key: {}", e))?;

            if key_bytes.len() != 32 {
                return Err("Genesis key must be 32 bytes".to_string());
            }

            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            self.private_key = Some(key);
            self.public_key = Self::derive_public_key(&key);
        }
        Ok(())
    }

    pub(crate) fn derive_public_key(key: &[u8; 32]) -> Option<String> {
        crate::mesh::cert::get_ed25519_public_key(key)
            .map(|pk| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pk))
    }

    pub fn get_public_key(&self) -> Option<String> {
        self.public_key.clone()
    }

    pub fn sign(&self, data: &str) -> Option<Vec<u8>> {
        self.private_key
            .as_ref()
            .and_then(|key| crate::mesh::cert::sign_ed25519(data, key))
    }

    pub fn sign_with_rotation(&self, data: &str) -> Option<Vec<u8>> {
        self.private_key.as_ref().and_then(|key| {
            let signable = format!("{}:{}", data, self.rotation_sequence);
            crate::mesh::cert::sign_ed25519(&signable, key)
        })
    }

    pub fn verify(&self, data: &str, signature: &[u8]) -> bool {
        if let Some(ref key) = self.private_key {
            if let Some(pk) = crate::mesh::cert::get_ed25519_public_key(key) {
                crate::mesh::cert::verify_ed25519(data, signature, &pk)
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn verify_with_rotation(&self, data: &str, signature: &[u8], sequence: u32) -> bool {
        if sequence != self.rotation_sequence {
            return false;
        }
        if let Some(ref key) = self.private_key {
            if let Some(pk) = crate::mesh::cert::get_ed25519_public_key(key) {
                let signable = format!("{}:{}", data, sequence);
                crate::mesh::cert::verify_ed25519(&signable, signature, &pk)
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn is_key_rotated(&self) -> bool {
        self.previous_genesis_key_base64.is_some() || self.rotation_sequence > 0
    }

    pub fn verify_previous_key(&self, data: &str, signature: &[u8]) -> bool {
        if let Some(ref prev_key_b64) = self.previous_genesis_key_base64 {
            if let Ok(key_bytes) =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(prev_key_b64)
            {
                if key_bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);
                    if let Some(pk) = crate::mesh::cert::get_ed25519_public_key(&key) {
                        return crate::mesh::cert::verify_ed25519(data, signature, &pk);
                    }
                }
            }
        }
        false
    }

    pub fn is_genesis_key_authorized(&self, genesis_public_key: &str) -> bool {
        if self.authorized_genesis_keys.is_empty() {
            tracing::warn!(
                "No authorized genesis keys configured - rejecting genesis key authentication. \
                This is a security risk if the system expects authorized keys."
            );
            return false;
        }
        self.authorized_genesis_keys
            .iter()
            .any(|k| k == genesis_public_key)
    }

    pub fn authorize_genesis_key(&mut self, public_key: String) {
        if !self.authorized_genesis_keys.contains(&public_key) {
            self.authorized_genesis_keys.push(public_key);
        }
    }

    pub fn revoke_genesis_key(&mut self, public_key: &str) {
        self.authorized_genesis_keys.retain(|k| k != public_key);
    }
}

impl NodeIdentityConfig {
    pub fn genesis_org_id(&self) -> String {
        self.genesis_org_id
            .clone()
            .unwrap_or_else(|| ADMIN_ORG_ID.to_string())
    }

    pub fn derive_signing_key_from_genesis(
        &mut self,
        genesis_key: &[u8; 32],
        public_key: &[u8],
    ) -> Result<(), String> {
        use hkdf::Hkdf;
        use sha2::Sha256;

        const INFO: &[u8] = b"synvoid-global-node-signing-key";

        let hk = Hkdf::<Sha256>::new(Some(genesis_key), INFO);
        let mut okm = [0u8; 32];

        hk.expand(public_key, &mut okm)
            .map_err(|e| format!("HKDF expand failed: {}", e))?;

        self.private_key = Some(okm.to_vec());
        self.public_key = Some(derive_node_id_hash(&okm));
        self.node_id = Some(derive_node_id(&okm));

        if let Some(ref path) = self.private_key_path {
            if let Some(ref key) = self.private_key {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                #[cfg(unix)]
                {
                    use std::io::Write;
                    use std::os::unix::fs::PermissionsExt;
                    let temp_path = std::path::Path::new(path).with_extension("tmp");
                    let mut file = std::fs::File::create(&temp_path)
                        .map_err(|e| format!("Failed to create temp signing key file: {}", e))?;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    file.set_permissions(perms)
                        .map_err(|e| format!("Failed to set permissions on temp file: {}", e))?;
                    file.write_all(key)
                        .map_err(|e| format!("Failed to write signing key: {}", e))?;
                    drop(file);
                    std::fs::rename(&temp_path, path)
                        .map_err(|e| format!("Failed to rename temp signing key file: {}", e))?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(path, key)
                        .map_err(|e| format!("Failed to write signing key: {}", e))?;
                }
            }
        }

        tracing::info!(
            "Derived signing key from genesis key. Node ID: {:?}",
            self.node_id
        );

        Ok(())
    }

    pub fn load_or_generate(&mut self) -> Result<(), String> {
        self.load_or_generate_with_passphrase(None)
    }

    pub fn load_or_generate_with_passphrase(
        &mut self,
        passphrase: Option<&str>,
    ) -> Result<(), String> {
        if let Some(ref proof) = self.minting_proof {
            self.node_id = Some(proof.node_id.clone());
            self.public_key = Some(proof.node_public_key.clone());
        }

        if let Some(ref path) = self.private_key_path {
            if std::path::Path::new(path).exists() {
                let key_data = std::fs::read(path)
                    .map_err(|e| format!("Failed to read signing key: {}", e))?;

                if key_data.len() == 32 + 12 + 16 {
                    let decrypted = self.decrypt_key(&key_data, passphrase)?;
                    let pubkey = derive_node_id_hash(&decrypted);
                    let node_id = derive_node_id(&decrypted);

                    if let Some(ref proof) = self.minting_proof {
                        if pubkey != proof.node_public_key {
                            return Err("Private key mismatch with minting proof public key".to_string());
                        }
                    }

                    self.private_key = Some(decrypted);
                    self.public_key = Some(pubkey);
                    self.node_id = Some(node_id);
                    return Ok(());
                } else if key_data.len() == 32 {
                    let pubkey = derive_node_id_hash(&key_data);
                    let node_id = derive_node_id(&key_data);

                    if let Some(ref proof) = self.minting_proof {
                        if pubkey != proof.node_public_key {
                            return Err("Private key mismatch with minting proof public key".to_string());
                        }
                    }

                    self.private_key = Some(key_data.clone());
                    self.public_key = Some(pubkey);
                    self.node_id = Some(node_id);
                    return Ok(());
                } else {
                    return Err("Invalid signing key file format".to_string());
                }
            }
        }

        if self.minting_proof.is_some() {
            return Err("Pre-minted identity configured but private key file not found".to_string());
        }

        let mut key = [0u8; 32];
        use rand::TryRngCore;
        let mut rng = rand::rngs::OsRng;
        rng.try_fill_bytes(&mut key).expect("RNG failure");
        self.private_key = Some(key.to_vec());
        self.public_key = Some(derive_node_id_hash(&key));
        self.node_id = Some(derive_node_id(&key));

        if let Some(ref path) = self.private_key_path {
            if let Some(ref key) = self.private_key {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let encrypted = self.encrypt_key(key, passphrase)?;
                std::fs::write(path, encrypted)
                    .map_err(|e| format!("Failed to write signing key: {}", e))?;
            }
        }

        Ok(())
    }

    pub(crate) fn derive_encryption_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), salt, 100_000)
    }

    pub(crate) fn encrypt_key(
        &self,
        plaintext: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };
                use rand::RngCore;

                let mut salt = [0u8; 16];
                rand::rng().fill_bytes(&mut salt);

                let key = Self::derive_encryption_key(pass, &salt);
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| format!("Cipher init failed: {}", e))?;

                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| format!("Encryption failed: {}", e))?;

                let mut result = Vec::with_capacity(12 + 16 + ciphertext.len());
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&salt);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            _ => Ok(plaintext.to_vec()),
        }
    }

    pub(crate) fn decrypt_key(
        &self,
        ciphertext: &[u8],
        passphrase: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };

                if ciphertext.len() < 12 + 16 + 16 {
                    return Err("Ciphertext too short".to_string());
                }

                let nonce = Nonce::from_slice(&ciphertext[..12]);
                let salt = &ciphertext[12..28];
                let ciphertext_only = &ciphertext[28..];

                let key = Self::derive_encryption_key(pass, salt);
                let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

                cipher
                    .decrypt(nonce, ciphertext_only)
                    .map_err(|e| format!("Decryption failed: {}", e))
            }
            _ => Ok(ciphertext.to_vec()),
        }
    }

    pub fn public_key_hex(&self) -> Option<String> {
        self.public_key.as_ref().map(hex::encode)
    }

    pub fn node_id(&self) -> Option<&String> {
        self.node_id.as_ref()
    }

    pub fn router_id(&self) -> Option<&String> {
        self.router_id.as_ref()
    }
}
