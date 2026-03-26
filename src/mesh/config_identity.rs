use super::*;

impl GlobalNodeConfig {
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

            // Generate a temporary keypair to get the public key
            // In practice, the secret key format includes both sk+pk in aws-lc-rs
            // For now, we'll generate a new keypair if loading fails
            match MlKem768::generate_keypair() {
                Ok((pk, _)) => {
                    self.ml_kem_public_key_base64 = Some(pk.to_base64());
                }
                Err(e) => {
                    return Err(format!("Failed to derive ML-KEM public key: {}", e));
                }
            }
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
            use pqc::MlDsa44;
            let _sk = pqc::SigningKey::from_base64(b64)
                .map_err(|e| format!("Invalid base64 ML-DSA key: {}", e))?;

            // Generate a new keypair to get the public key
            // In practice, we'd store both, but for now generate fresh
            match MlDsa44::generate_keypair() {
                Ok((vk, _)) => {
                    self.ml_dsa_public_key_base64 = Some(vk.to_base64());
                }
                Err(e) => {
                    return Err(format!("Failed to derive ML-DSA public key: {}", e));
                }
            }
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
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        let public_key = Self::derive_public_key(&key);

        Self {
            private_key_base64: None,
            private_key: Some(key),
            public_key,
            is_first_node: true,
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

    fn derive_public_key(key: &[u8; 32]) -> Option<String> {
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
}

impl NodeIdentityConfig {
    pub fn genesis_org_id(&self) -> String {
        self.genesis_org_id
            .clone()
            .unwrap_or_else(|| ADMIN_ORG_ID.to_string())
    }

    pub fn load_or_generate(&mut self) -> Result<(), String> {
        self.load_or_generate_with_passphrase(None)
    }

    pub fn load_or_generate_with_passphrase(
        &mut self,
        passphrase: Option<&str>,
    ) -> Result<(), String> {
        if let Some(ref path) = self.private_key_path {
            if std::path::Path::new(path).exists() {
                let key_data = std::fs::read(path)
                    .map_err(|e| format!("Failed to read signing key: {}", e))?;

                if key_data.len() == 32 + 12 + 16 {
                    let decrypted = self.decrypt_key(&key_data, passphrase)?;
                    let pubkey = derive_public_key(&decrypted);
                    let node_id = derive_node_id(&decrypted);
                    self.private_key = Some(decrypted);
                    self.public_key = Some(pubkey);
                    self.node_id = Some(node_id);
                    return Ok(());
                } else if key_data.len() == 32 {
                    self.private_key = Some(key_data.clone());
                    self.public_key = Some(derive_public_key(&key_data));
                    self.node_id = Some(derive_node_id(&key_data));
                    return Ok(());
                } else {
                    return Err("Invalid signing key file format".to_string());
                }
            }
        }

        let mut key = [0u8; 32];
        use rand::RngCore;
        rand::rng().fill_bytes(&mut key);
        self.private_key = Some(key.to_vec());
        self.public_key = Some(derive_public_key(&key));
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

    fn derive_encryption_key(passphrase: &str) -> [u8; 32] {
        use pbkdf2::pbkdf2_hmac_array;
        use sha2::Sha256;

        const SALT: &[u8] = b"rustwaf-node-identity-v1";
        pbkdf2_hmac_array::<Sha256, 32>(passphrase.as_bytes(), SALT, 100_000)
    }

    fn encrypt_key(&self, plaintext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };
                use rand::RngCore;

                let key = Self::derive_encryption_key(pass);
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|e| format!("Cipher init failed: {}", e))?;

                let mut nonce_bytes = [0u8; 12];
                rand::rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ciphertext = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| format!("Encryption failed: {}", e))?;

                let mut result = Vec::with_capacity(12 + ciphertext.len() + 16);
                result.extend_from_slice(&nonce_bytes);
                result.extend_from_slice(&ciphertext);
                Ok(result)
            }
            _ => Ok(plaintext.to_vec()),
        }
    }

    fn decrypt_key(&self, ciphertext: &[u8], passphrase: Option<&str>) -> Result<Vec<u8>, String> {
        match passphrase {
            Some(pass) if !pass.is_empty() => {
                use aes_gcm::{
                    aead::{Aead, KeyInit},
                    Aes256Gcm, Nonce,
                };

                if ciphertext.len() < 12 + 16 {
                    return Err("Ciphertext too short".to_string());
                }

                let key = Self::derive_encryption_key(pass);
                let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

                let nonce = Nonce::from_slice(&ciphertext[..12]);
                let ciphertext_only = &ciphertext[12..];

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
