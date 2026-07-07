// DNSSEC key management: key generation, storage, rollover, CDS/CDNSKEY generation

use std::path::PathBuf;
use std::result::Result;

use ed25519_dalek::SigningKey;

use super::dnssec::{
    calculate_key_tag, Algorithm, CryptoRngAdapter, DnsSecKeyStatus, KeyInfo, KeyRotationConfig,
    KeyRotationResult, KeyType, RolloverState, ZoneSigningKey,
};

pub struct DnsSecKeyManager {
    pub key_path: PathBuf,
    pub key_signing_key: Option<ZoneSigningKey>,
    pub zone_signing_key: Option<ZoneSigningKey>,
    pub standby_ksk: Option<ZoneSigningKey>,
    pub standby_zsk: Option<ZoneSigningKey>,
    pub rollover_state: RolloverState,
}

impl DnsSecKeyManager {
    pub fn new(key_path: PathBuf) -> Self {
        Self {
            key_path,
            key_signing_key: None,
            zone_signing_key: None,
            standby_ksk: None,
            standby_zsk: None,
            rollover_state: RolloverState::default(),
        }
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        std::fs::create_dir_all(&self.key_path)
            .map_err(|e| format!("Failed to create DNSSEC key directory: {}", e))?;

        let ksk_path = self.key_path.join("ksk");
        let zsk_path = self.key_path.join("zsk");
        std::fs::create_dir_all(&ksk_path)
            .map_err(|e| format!("Failed to create KSK key directory: {}", e))?;
        std::fs::create_dir_all(&zsk_path)
            .map_err(|e| format!("Failed to create ZSK key directory: {}", e))?;

        tracing::info!("DNSSEC key directory initialized at {:?}", self.key_path);

        Ok(())
    }

    pub fn load_keys_from_disk(&mut self) -> Result<(), String> {
        for (key_type, is_standby) in [
            (KeyType::KSK, false),
            (KeyType::ZSK, false),
            (KeyType::KSK, true),
            (KeyType::ZSK, true),
        ] {
            let dir_name = match (key_type, is_standby) {
                (KeyType::KSK, false) => "ksk",
                (KeyType::ZSK, false) => "zsk",
                (KeyType::KSK, true) => "ksk",
                (KeyType::ZSK, true) => "zsk",
            };
            let key_dir = self.key_path.join(dir_name);
            if !key_dir.exists() {
                continue;
            }

            let entries = std::fs::read_dir(&key_dir)
                .map_err(|e| format!("Failed to read key directory: {}", e))?;

            let mut best_key: Option<ZoneSigningKey> = None;

            for entry in entries {
                let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
                let path = entry.path();
                if !path.is_file() || path.extension().map(|e| e != "key").unwrap_or(true) {
                    continue;
                }

                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read key file: {}", e))?;
                let meta: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| format!("Invalid key metadata: {}", e))?;

                let meta_standby = meta
                    .get("standby")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if meta_standby != is_standby {
                    continue;
                }

                let created_at = meta.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0);
                let expires_at = meta
                    .get("expires_at")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(u64::MAX);
                let now = synvoid_core::time::current_timestamp_secs();
                if expires_at < now {
                    continue;
                }

                let algo_byte = meta.get("algorithm").and_then(|v| v.as_u64()).unwrap_or(15) as u8;
                let algorithm = Algorithm::from_u8(algo_byte).unwrap_or(Algorithm::Ed25519);
                let key_tag = meta.get("key_tag").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let flags = meta.get("flags").and_then(|v| v.as_u64()).unwrap_or(257) as u16;
                let key_size = meta
                    .get("key_size")
                    .and_then(|v| v.as_u64())
                    .map(|v| v as u32);
                let key_id_str = meta
                    .get("key_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(dir_name);

                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let pub_file = key_dir.join(format!("{}.pub", stem));
                let priv_file = key_dir.join(format!("{}.priv", stem));

                if !pub_file.exists() || !priv_file.exists() {
                    continue;
                }

                let public_key = std::fs::read(&pub_file)
                    .map_err(|e| format!("Failed to read public key: {}", e))?;
                let private_key = std::fs::read(&priv_file)
                    .map_err(|e| format!("Failed to read private key: {}", e))?;

                let zone_key = ZoneSigningKey {
                    key_id: key_id_str.to_string(),
                    algorithm,
                    key_type,
                    created_at,
                    expires_at,
                    public_key,
                    private_key,
                    key_tag,
                    flags,
                    key_size,
                };

                match &best_key {
                    Some(existing) => {
                        if created_at > existing.created_at {
                            best_key = Some(zone_key);
                        }
                    }
                    None => best_key = Some(zone_key),
                }
            }

            if let Some(key) = best_key {
                let is_ksk = key_type == KeyType::KSK;
                if is_standby {
                    if is_ksk {
                        self.standby_ksk = Some(key.clone());
                    } else {
                        self.standby_zsk = Some(key.clone());
                    }
                } else if is_ksk {
                    self.key_signing_key = Some(key.clone());
                } else {
                    self.zone_signing_key = Some(key.clone());
                }
                tracing::info!(
                    "Loaded {}{} key from disk (tag: {})",
                    if is_standby { "standby " } else { "" },
                    if is_ksk { "KSK" } else { "ZSK" },
                    key.key_tag,
                );
            }
        }

        Ok(())
    }

    pub fn get_signing_keys(&self) -> Vec<&ZoneSigningKey> {
        let mut keys = Vec::new();

        if let Some(ref zsk) = self.zone_signing_key {
            keys.push(zsk);
        }

        if self.rollover_state.zsk_in_rollover {
            if let Some(ref standby_zsk) = self.standby_zsk {
                keys.push(standby_zsk);
            }
        }

        keys
    }

    pub fn get_all_dnskeys(&self) -> Vec<&ZoneSigningKey> {
        let mut keys = Vec::new();

        if let Some(ref ksk) = self.key_signing_key {
            keys.push(ksk);
        }

        if self.rollover_state.ksk_in_rollover {
            if let Some(ref standby_ksk) = self.standby_ksk {
                keys.push(standby_ksk);
            }
        }

        if let Some(ref zsk) = self.zone_signing_key {
            keys.push(zsk);
        }

        if self.rollover_state.zsk_in_rollover {
            if let Some(ref standby_zsk) = self.standby_zsk {
                keys.push(standby_zsk);
            }
        }

        keys
    }

    /// Generate CDS record data for a KSK
    ///
    /// RFC 5011 specifies that CDS records are used by the parent zone
    /// to automatically update DS records. CDS contains:
    /// - Key tag (2 bytes)
    /// - Algorithm (1 byte)
    /// - Digest type (1 byte)
    /// - Digest (variable)
    ///
    /// Currently supports SHA-256 digest (type 2)
    pub fn generate_cds_record(&self, key: &ZoneSigningKey) -> Result<Vec<u8>, String> {
        if key.key_type != KeyType::KSK {
            return Err("CDS records can only be generated for KSK keys".to_string());
        }

        let key_tag = key.key_tag.to_be_bytes();
        let algorithm = key.algorithm.to_u8();
        let digest_type = 2; // SHA-256

        // Calculate SHA-256 hash of the DNSKEY record
        // DNSKEY RDATA: [2 bytes flags][1 byte protocol][1 byte algorithm][public key]
        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&key.flags.to_be_bytes());
        dnskey_rdata.push(3); // Protocol (always 3 for DNSSEC)
        dnskey_rdata.push(key.algorithm.to_u8());
        dnskey_rdata.extend_from_slice(&key.public_key);

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&dnskey_rdata);
        let digest = hasher.finalize();

        // Build CDS RDATA: key tag + algorithm + digest type + digest
        let mut cds = Vec::new();
        cds.extend_from_slice(&key_tag);
        cds.push(algorithm);
        cds.push(digest_type);
        cds.extend_from_slice(&digest);

        Ok(cds)
    }

    /// Generate CDNSKEY record data for a KSK
    ///
    /// RFC 5011 specifies that CDNSKEY records are used by the parent zone
    /// to automatically update DNSKEY records. CDNSKEY is the same as DNSKEY
    /// but with the CD (Check Disabled) flag set.
    pub fn generate_cdnskey_record(&self, key: &ZoneSigningKey) -> Result<Vec<u8>, String> {
        if key.key_type != KeyType::KSK {
            return Err("CDNSKEY records can only be generated for KSK keys".to_string());
        }

        // CDNSKEY has the same wire format as DNSKEY
        // The CD flag is in the DNS message header, not in the key flags
        // DNSKEY RDATA: [2 bytes flags][1 byte protocol][1 byte algorithm][public key]
        let mut cdnskey = Vec::new();

        cdnskey.extend_from_slice(&key.flags.to_be_bytes());

        cdnskey.push(3); // Protocol (always 3 for DNSSEC)
        cdnskey.push(key.algorithm.to_u8());
        cdnskey.extend_from_slice(&key.public_key);

        Ok(cdnskey)
    }

    /// Generate all CDS records for all active and standby KSKs
    ///
    /// Returns a vector of (key_tag, algorithm, digest_type, digest) tuples
    #[allow(clippy::type_complexity)]
    pub fn get_all_cds_records(&self) -> Vec<Result<(u16, u8, u8, Vec<u8>), String>> {
        let mut results = Vec::new();

        if let Some(ref ksk) = self.key_signing_key {
            if let Ok(cds) = self.generate_cds_record(ksk) {
                // Extract components from CDS RDATA
                let key_tag = u16::from_be_bytes([cds[0], cds[1]]);
                let algorithm = cds[2];
                let digest_type = cds[3];
                let digest = cds[4..].to_vec();
                results.push(Ok((key_tag, algorithm, digest_type, digest)));
            }
        }

        if let Some(ref standby_ksk) = self.standby_ksk {
            if let Ok(cds) = self.generate_cds_record(standby_ksk) {
                let key_tag = u16::from_be_bytes([cds[0], cds[1]]);
                let algorithm = cds[2];
                let digest_type = cds[3];
                let digest = cds[4..].to_vec();
                results.push(Ok((key_tag, algorithm, digest_type, digest)));
            }
        }

        results
    }

    /// Generate all CDNSKEY records for all active and standby KSKs
    pub fn get_all_cdnskey_records(&self) -> Vec<Result<Vec<u8>, String>> {
        let mut results = Vec::new();

        if let Some(ref ksk) = self.key_signing_key {
            results.push(self.generate_cdnskey_record(ksk));
        }

        if let Some(ref standby_ksk) = self.standby_ksk {
            results.push(self.generate_cdnskey_record(standby_ksk));
        }

        results
    }

    fn generate_key_internal(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        _rsa_key_size: u32,
        validity_days: u32,
        is_standby: bool,
    ) -> Result<(), String> {
        let now = synvoid_core::time::current_timestamp_secs();
        let expires_at = now + (validity_days as u64 * 86400);

        let (public_key, private_key, key_tag, flags, key_size) = match algorithm {
            Algorithm::Ed25519 => {
                let bytes = super::crypto_rng::random_bytes(32)
                    .map_err(|e| format!("Crypto RNG failed for DNSSEC key generation: {}", e))?;
                let signing_key = SigningKey::from_bytes(
                    bytes
                        .as_slice()
                        .try_into()
                        .expect("random_bytes(32) always returns 32 bytes"),
                );
                let public = signing_key.verifying_key().to_bytes().to_vec();
                let private = signing_key.to_bytes().to_vec();
                let flags = if key_type == KeyType::KSK { 257 } else { 256 };
                let key_tag = calculate_key_tag(flags, 3, Algorithm::Ed25519.to_u8(), &public);
                let key_size = None;
                (public, private, key_tag, flags, key_size)
            }
            Algorithm::RSA => {
                use rsa::traits::PublicKeyParts;

                let bits = if _rsa_key_size == 0 {
                    2048_usize
                } else {
                    let requested_bits = _rsa_key_size as usize;
                    if requested_bits == 1024 {
                        tracing::warn!("RSA 1024 is insecure, auto-upgrading to 2048");
                        2048
                    } else {
                        requested_bits
                    }
                };
                if !matches!(bits, 2048 | 4096) {
                    return Err(format!(
                        "Unsupported RSA key size {}. Use 2048 or 4096.",
                        bits
                    ));
                }

                let private_key = rsa::RsaPrivateKey::new(&mut CryptoRngAdapter, bits)
                    .map_err(|e| format!("RSA key generation failed: {}", e))?;
                let public_key_rsa = private_key.to_public_key();

                let e_bytes = public_key_rsa.e().to_bytes_be();
                let n_bytes = public_key_rsa.n().to_bytes_be();

                let mut public_dnskey = Vec::new();
                if e_bytes.len() > 255 {
                    public_dnskey.push(0);
                    public_dnskey.push((e_bytes.len() >> 8) as u8);
                    public_dnskey.push((e_bytes.len() & 0xFF) as u8);
                } else {
                    public_dnskey.push(e_bytes.len() as u8);
                }
                public_dnskey.extend_from_slice(&e_bytes);
                public_dnskey.extend_from_slice(&n_bytes);

                let private_der = {
                    use rsa::pkcs8::EncodePrivateKey;
                    let der = private_key
                        .to_pkcs8_der()
                        .map_err(|e| format!("RSA private key DER encoding failed: {}", e))?;
                    der.as_bytes().to_vec()
                };

                let flags = if key_type == KeyType::KSK { 257 } else { 256 };
                let key_tag = calculate_key_tag(flags, 3, Algorithm::RSA.to_u8(), &public_dnskey);
                (
                    public_dnskey,
                    private_der,
                    key_tag,
                    flags,
                    Some(bits as u32),
                )
            }
        };

        let key_id = match (key_type, is_standby) {
            (KeyType::KSK, false) => "ksk",
            (KeyType::ZSK, false) => "zsk",
            (KeyType::KSK, true) => "ksk-standby",
            (KeyType::ZSK, true) => "zsk-standby",
        };

        let key_name = if is_standby {
            format!("{}-{}", key_id, now)
        } else {
            format!("dnssec-{}-{}", key_id, now)
        };
        let key_dir = self.key_path.join(key_id);
        std::fs::create_dir_all(&key_dir)
            .map_err(|e| format!("Failed to create key directory: {}", e))?;

        let key_file = key_dir.join(format!("{}.key", key_name));
        let mut meta = serde_json::json!({
            "key_id": key_id,
            "algorithm": algorithm.to_u8(),
            "key_type": key_type as u8,
            "created_at": now,
            "expires_at": expires_at,
            "key_tag": key_tag,
            "flags": flags,
            "key_size": key_size,
        });
        if is_standby {
            meta["standby"] = serde_json::Value::Bool(true);
        }

        std::fs::write(
            &key_file,
            serde_json::to_string_pretty(&meta).map_err(|e| format!("JSON error: {}", e))?,
        )
        .map_err(|e| format!("Failed to write key metadata: {}", e))?;

        let pub_file = key_dir.join(format!("{}.pub", key_name));
        std::fs::write(&pub_file, &public_key)
            .map_err(|e| format!("Failed to write public key: {}", e))?;

        let priv_file = key_dir.join(format!("{}.priv", key_name));
        std::fs::write(&priv_file, &private_key)
            .map_err(|e| format!("Failed to write private key: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_file, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set private key permissions: {}", e))?;
        }

        let zone_key = ZoneSigningKey {
            key_id: key_id.to_string(),
            algorithm,
            key_type,
            created_at: now,
            expires_at,
            public_key,
            private_key,
            key_tag,
            flags,
            key_size,
        };

        if is_standby {
            match key_type {
                KeyType::KSK => self.standby_ksk = Some(zone_key),
                KeyType::ZSK => self.standby_zsk = Some(zone_key),
            }
        } else {
            match key_type {
                KeyType::KSK => self.key_signing_key = Some(zone_key),
                KeyType::ZSK => self.zone_signing_key = Some(zone_key),
            }
        }

        tracing::info!(
            "Generated {}{} {} key: {}",
            if is_standby { "standby " } else { "" },
            algorithm.dns_algorithm_name(),
            key_id,
            key_name
        );

        Ok(())
    }

    pub fn generate_key(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        rsa_key_size: u32,
        validity_days: u32,
    ) -> Result<(), String> {
        self.generate_key_internal(algorithm, key_type, rsa_key_size, validity_days, false)
    }

    pub fn generate_standby_key(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        rsa_key_size: u32,
        validity_days: u32,
    ) -> Result<(), String> {
        self.generate_key_internal(algorithm, key_type, rsa_key_size, validity_days, true)
    }

    pub fn start_key_rollover(&mut self, key_type: KeyType) -> Result<(), String> {
        let now = synvoid_core::time::current_timestamp_secs();

        match key_type {
            KeyType::KSK => {
                if self.standby_ksk.is_some() {
                    return Err("Standby KSK already exists".to_string());
                }
                let algorithm = self
                    .key_signing_key
                    .as_ref()
                    .map(|k| k.algorithm)
                    .unwrap_or(Algorithm::Ed25519);
                let key_size = self
                    .key_signing_key
                    .as_ref()
                    .and_then(|k| k.key_size)
                    .unwrap_or(2048);

                self.generate_standby_key(algorithm, KeyType::KSK, key_size, 365)?;
                self.rollover_state.ksk_in_rollover = true;
                self.rollover_state.ksk_rollover_started = Some(now);
                self.rollover_state.publish_dnssec = true;

                tracing::info!("Started KSK rollover");
            }
            KeyType::ZSK => {
                if self.standby_zsk.is_some() {
                    return Err("Standby ZSK already exists".to_string());
                }
                let algorithm = self
                    .zone_signing_key
                    .as_ref()
                    .map(|k| k.algorithm)
                    .unwrap_or(Algorithm::Ed25519);
                let key_size = self
                    .zone_signing_key
                    .as_ref()
                    .and_then(|k| k.key_size)
                    .unwrap_or(2048);

                self.generate_standby_key(algorithm, KeyType::ZSK, key_size, 90)?;
                self.rollover_state.zsk_in_rollover = true;
                self.rollover_state.zsk_rollover_started = Some(now);
                self.rollover_state.publish_dnssec = true;

                tracing::info!("Started ZSK rollover");
            }
        }

        Ok(())
    }

    pub fn complete_key_rollover(&mut self, key_type: KeyType) -> Result<(), String> {
        match key_type {
            KeyType::KSK => {
                if !self.rollover_state.ksk_in_rollover {
                    return Err("KSK not in rollover".to_string());
                }

                if let Some(standby_ksk) = self.standby_ksk.take() {
                    self.key_signing_key = Some(standby_ksk);
                }

                self.rollover_state.ksk_in_rollover = false;
                self.rollover_state.ksk_rollover_started = None;

                tracing::info!("Completed KSK rollover");
            }
            KeyType::ZSK => {
                if !self.rollover_state.zsk_in_rollover {
                    return Err("ZSK not in rollover".to_string());
                }

                if let Some(standby_zsk) = self.standby_zsk.take() {
                    self.zone_signing_key = Some(standby_zsk);
                }

                self.rollover_state.zsk_in_rollover = false;
                self.rollover_state.zsk_rollover_started = None;

                tracing::info!("Completed ZSK rollover");
            }
        }

        Ok(())
    }

    pub fn get_rollover_status(&self) -> serde_json::Value {
        serde_json::json!({
            "ksk_in_rollover": self.rollover_state.ksk_in_rollover,
            "zsk_in_rollover": self.rollover_state.zsk_in_rollover,
            "ksk_rollover_started": self.rollover_state.ksk_rollover_started,
            "zsk_rollover_started": self.rollover_state.zsk_rollover_started,
            "publish_dnssec": self.rollover_state.publish_dnssec,
        })
    }

    pub fn check_key_rotation(&mut self, config: KeyRotationConfig) -> Result<(), String> {
        let now = synvoid_core::time::current_timestamp_secs();

        if let Some(ksk) = &self.key_signing_key {
            let age = now - ksk.created_at;
            let age_days = age / 86400;
            let rollover_threshold = (config.ksk_rollover_days as u64 * 86400)
                - (config.grace_period_days as u64 * 86400);

            if age_days >= (config.ksk_rollover_days as u64).saturating_sub(7) {
                tracing::warn!(
                    "KSK key expiring soon: {} days old (rotation due in {} days)",
                    age_days,
                    config.ksk_rollover_days.saturating_sub(age_days as u32)
                );
            }

            if age > rollover_threshold {
                tracing::info!("KSK key rotation needed (age: {} days)", age_days);
                self.rotate_ksk(config)?;
            }
        }

        if let Some(zsk) = &self.zone_signing_key {
            let age = now - zsk.created_at;
            let age_days = age / 86400;
            let rollover_threshold = (config.zsk_rollover_days as u64 * 86400)
                - (config.grace_period_days as u64 * 86400);

            if age_days >= (config.zsk_rollover_days as u64).saturating_sub(7) {
                tracing::warn!(
                    "ZSK key expiring soon: {} days old (rotation due in {} days)",
                    age_days,
                    config.zsk_rollover_days.saturating_sub(age_days as u32)
                );
            }

            if age > rollover_threshold {
                tracing::info!("ZSK key rotation needed (age: {} days)", age_days);
                self.rotate_zsk(config)?;
            }
        }

        Ok(())
    }

    pub fn rotate_ksk(&mut self, config: KeyRotationConfig) -> Result<(), String> {
        if self.key_signing_key.is_none() {
            return Err("No KSK key to rotate".to_string());
        }

        let ksk = self
            .key_signing_key
            .as_ref()
            .expect("checked is_some above");
        let algorithm = ksk.algorithm;
        let key_size = ksk.key_size.unwrap_or(2048);

        self.generate_key(
            algorithm,
            KeyType::KSK,
            key_size,
            config.key_expiration_days,
        )?;

        Ok(())
    }

    pub fn rotate_zsk(&mut self, config: KeyRotationConfig) -> Result<(), String> {
        if self.zone_signing_key.is_none() {
            return Err("No ZSK key to rotate".to_string());
        }

        let zsk = self
            .zone_signing_key
            .as_ref()
            .expect("checked is_some above");
        let algorithm = zsk.algorithm;
        let key_size = zsk.key_size.unwrap_or(2048);

        self.generate_key(
            algorithm,
            KeyType::ZSK,
            key_size,
            config.key_expiration_days,
        )?;

        Ok(())
    }

    pub fn get_active_keys(&self) -> Result<Vec<ZoneSigningKey>, String> {
        let mut keys = Vec::new();

        if let Some(ksk) = &self.key_signing_key {
            keys.push(ksk.clone());
        }

        if let Some(zsk) = &self.zone_signing_key {
            keys.push(zsk.clone());
        }

        if keys.is_empty() {
            return Err("No active DNSSEC keys found".to_string());
        }

        Ok(keys)
    }

    pub fn get_active_ksk(&self) -> Result<&ZoneSigningKey, String> {
        self.key_signing_key
            .as_ref()
            .ok_or("No active KSK found".to_string())
    }

    pub fn get_active_zsk(&self) -> Result<&ZoneSigningKey, String> {
        self.zone_signing_key
            .as_ref()
            .ok_or("No active ZSK found".to_string())
    }

    pub fn check_and_rotate(
        &mut self,
        config: KeyRotationConfig,
    ) -> Result<KeyRotationResult, String> {
        let mut result = KeyRotationResult::default();

        let now = synvoid_core::time::current_timestamp_secs();

        // Clone key data to avoid borrow checker issues
        let ksk_needs_rotation = self.key_signing_key.as_ref().map(|ksk| {
            let age_days = (now - ksk.created_at) / 86400;
            let rollover_threshold = config.ksk_rollover_days - config.grace_period_days;
            (age_days >= rollover_threshold as u64, age_days)
        });

        if let Some((needs_rotation, age_days)) = ksk_needs_rotation {
            result.ksk_age_days = Some(age_days);

            if needs_rotation {
                tracing::info!(
                    "KSK key rotation needed (age: {} days, threshold: {} days)",
                    age_days,
                    config.ksk_rollover_days - config.grace_period_days
                );
                match self.rotate_ksk(config) {
                    Ok(_) => {
                        result.ksk_rotated = true;
                        result.ksk_new_key_id = Some(format!("ksk-{}", now));
                    }
                    Err(e) => {
                        result.ksk_error = Some(e);
                    }
                }
            }
        }

        // Clone key data to avoid borrow checker issues
        let zsk_needs_rotation = self.zone_signing_key.as_ref().map(|zsk| {
            let age_days = (now - zsk.created_at) / 86400;
            let rollover_threshold = config.zsk_rollover_days - config.grace_period_days;
            (age_days >= rollover_threshold as u64, age_days)
        });

        if let Some((needs_rotation, age_days)) = zsk_needs_rotation {
            result.zsk_age_days = Some(age_days);

            if needs_rotation {
                tracing::info!(
                    "ZSK key rotation needed (age: {} days, threshold: {} days)",
                    age_days,
                    config.zsk_rollover_days - config.grace_period_days
                );
                match self.rotate_zsk(config) {
                    Ok(_) => {
                        result.zsk_rotated = true;
                        result.zsk_new_key_id = Some(format!("zsk-{}", now));
                    }
                    Err(e) => {
                        result.zsk_error = Some(e);
                    }
                }
            }
        }

        if result.ksk_rotated || result.zsk_rotated {
            tracing::info!("DNSSEC key rotation completed: {:?}", result);
        }

        Ok(result)
    }

    pub fn get_key_status(&self) -> Result<DnsSecKeyStatus, String> {
        let now = synvoid_core::time::current_timestamp_secs();

        let ksk_info = self.key_signing_key.as_ref().map(|k| KeyInfo {
            key_type: "KSK".to_string(),
            algorithm: k.algorithm.dns_algorithm_name().to_string(),
            key_tag: k.key_tag,
            created_at: k.created_at,
            expires_at: k.expires_at,
            age_days: (now - k.created_at) / 86400,
            days_until_expiry: if k.expires_at > now {
                Some((k.expires_at - now) / 86400)
            } else {
                None
            },
        });

        let zsk_info = self.zone_signing_key.as_ref().map(|k| KeyInfo {
            key_type: "ZSK".to_string(),
            algorithm: k.algorithm.dns_algorithm_name().to_string(),
            key_tag: k.key_tag,
            created_at: k.created_at,
            expires_at: k.expires_at,
            age_days: (now - k.created_at) / 86400,
            days_until_expiry: if k.expires_at > now {
                Some((k.expires_at - now) / 86400)
            } else {
                None
            },
        });

        Ok(DnsSecKeyStatus {
            ksk: ksk_info,
            zsk: zsk_info,
        })
    }

    pub fn cleanup_expired_keys(&self) -> Result<(), String> {
        let now = synvoid_core::time::current_timestamp_secs();

        for key_type in ["ksk", "zsk"] {
            let key_dir = self.key_path.join(key_type);
            if key_dir.exists() {
                let entries = std::fs::read_dir(key_dir)
                    .map_err(|e| format!("Failed to read key directory: {}", e))?;
                for entry in entries {
                    let entry =
                        entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
                    let path = entry.path();
                    if path.is_file() && path.extension().map(|e| e == "key").unwrap_or(false) {
                        let content = std::fs::read_to_string(&path)
                            .map_err(|e| format!("Failed to read key file: {}", e))?;
                        if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(expires_at) =
                                meta.get("expires_at").and_then(|v| v.as_u64())
                            {
                                if expires_at < now {
                                    std::fs::remove_file(&path).map_err(|e| {
                                        format!("Failed to remove expired key: {}", e)
                                    })?;
                                    tracing::info!("Removed expired key: {:?}", path);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn get_key_info(&self, key_id: &str) -> Result<serde_json::Value, String> {
        let key_dir = self.key_path.join(key_id);
        if !key_dir.exists() {
            return Err(format!("Key directory not found: {:?}", key_dir));
        }

        let mut keys = Vec::new();
        let entries = std::fs::read_dir(key_dir)
            .map_err(|e| format!("Failed to read key directory: {}", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "key").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| format!("Failed to read key file: {}", e))?;
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                    keys.push(meta);
                }
            }
        }

        if keys.is_empty() {
            return Err(format!("No keys found for: {}", key_id));
        }

        Ok(serde_json::json!({
            "key_type": key_id,
            "keys": keys,
        }))
    }

    pub fn export_keys_to_file(&self, file_path: &str) -> Result<(), String> {
        let keys = self.get_active_keys()?;
        let export_data = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "keys": keys.iter().map(|k| {
                serde_json::json!({
                    "key_id": k.key_id,
                    "algorithm": k.algorithm.dns_algorithm_name(),
                    "key_type": if k.key_type == KeyType::KSK { "KSK" } else { "ZSK" },
                    "created_at": k.created_at,
                    "expires_at": k.expires_at,
                    "key_tag": k.key_tag,
                    "flags": k.flags,
                    "key_size": k.key_size,
                })
            }).collect::<Vec<_>>(),
        });

        std::fs::write(
            file_path,
            serde_json::to_string_pretty(&export_data).map_err(|e| format!("JSON error: {}", e))?,
        )
        .map_err(|e| format!("Failed to write key export file: {}", e))?;

        tracing::info!("Exported DNSSEC keys to: {}", file_path);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_key_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "dnssec_key_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        dir
    }

    #[test]
    fn test_initialize_creates_directories() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();
        assert!(dir.exists());
        assert!(dir.join("ksk").exists());
        assert!(dir.join("zsk").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_ed25519_ksk() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().expect("KSK should be set");
        assert_eq!(ksk.algorithm, Algorithm::Ed25519);
        assert_eq!(ksk.key_type, KeyType::KSK);
        assert_eq!(ksk.flags, 257);
        assert_eq!(ksk.public_key.len(), 32);
        assert_eq!(ksk.private_key.len(), 32);
        assert!(ksk.key_tag > 0);
        assert!(ksk.expires_at > ksk.created_at);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_ed25519_zsk() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();

        let zsk = mgr.zone_signing_key.as_ref().expect("ZSK should be set");
        assert_eq!(zsk.algorithm, Algorithm::Ed25519);
        assert_eq!(zsk.key_type, KeyType::ZSK);
        assert_eq!(zsk.flags, 256);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_rsa_ksk() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::RSA, KeyType::KSK, 2048, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().expect("KSK should be set");
        assert_eq!(ksk.algorithm, Algorithm::RSA);
        assert_eq!(ksk.key_type, KeyType::KSK);
        assert_eq!(ksk.flags, 257);
        assert_eq!(ksk.key_size, Some(2048));
        assert!(!ksk.public_key.is_empty());
        assert!(!ksk.private_key.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_rsa_1024_auto_upgrades() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::RSA, KeyType::KSK, 1024, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().expect("KSK should be set");
        assert_eq!(ksk.key_size, Some(2048));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_standby_key() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_standby_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        assert!(mgr.key_signing_key.is_none());
        assert!(mgr.standby_ksk.is_some());
        let standby = mgr.standby_ksk.as_ref().unwrap();
        assert_eq!(standby.algorithm, Algorithm::Ed25519);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_start_and_complete_key_rollover() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        let original_tag = mgr.key_signing_key.as_ref().unwrap().key_tag;

        mgr.start_key_rollover(KeyType::KSK).unwrap();
        assert!(mgr.rollover_state.ksk_in_rollover);
        assert!(mgr.standby_ksk.is_some());

        mgr.complete_key_rollover(KeyType::KSK).unwrap();
        assert!(!mgr.rollover_state.ksk_in_rollover);
        assert!(mgr.standby_ksk.is_none());

        let new_tag = mgr.key_signing_key.as_ref().unwrap().key_tag;
        assert_ne!(original_tag, new_tag);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_duplicate_standby_rejected() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        mgr.generate_standby_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let result = mgr.start_key_rollover(KeyType::KSK);
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_complete_without_start_fails() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let result = mgr.complete_key_rollover(KeyType::KSK);
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_private_key_permissions() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk_dir = dir.join("ksk");
        let entries: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "priv")
                    .unwrap_or(false)
            })
            .collect();

        assert!(!entries.is_empty(), "Should have a .priv file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let priv_file = &entries[0].path();
            let perms = std::fs::metadata(priv_file).unwrap().permissions();
            assert_eq!(
                perms.mode() & 0o777,
                0o600,
                "Private key should have 0o600 permissions"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_keys_from_disk() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        mgr.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();

        let ksk_tag = mgr.key_signing_key.as_ref().unwrap().key_tag;
        let zsk_tag = mgr.zone_signing_key.as_ref().unwrap().key_tag;

        drop(mgr);

        let mut mgr2 = DnsSecKeyManager::new(dir.clone());
        mgr2.load_keys_from_disk().unwrap();

        assert!(mgr2.key_signing_key.is_some());
        assert!(mgr2.zone_signing_key.is_some());
        assert_eq!(mgr2.key_signing_key.as_ref().unwrap().key_tag, ksk_tag);
        assert_eq!(mgr2.zone_signing_key.as_ref().unwrap().key_tag, zsk_tag);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_load_keys_skips_expired() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().unwrap();
        let ksk_dir = dir.join("ksk");
        let entries: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let key_file = entries
            .iter()
            .find(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "key")
                    .unwrap_or(false)
            })
            .unwrap();
        let key_path = key_file.path();
        let stem = key_path.file_stem().unwrap().to_str().unwrap();
        let pub_file = ksk_dir.join(format!("{}.pub", stem));
        let priv_file = ksk_dir.join(format!("{}.priv", stem));

        let meta = serde_json::json!({
            "key_id": "ksk",
            "algorithm": 15,
            "key_type": 0,
            "created_at": 1,
            "expires_at": 1,
            "key_tag": ksk.key_tag,
            "flags": 257,
            "key_size": null,
        });
        std::fs::write(
            key_file.path(),
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        std::fs::write(&pub_file, &ksk.public_key).unwrap();
        std::fs::write(&priv_file, &ksk.private_key).unwrap();

        drop(mgr);

        let mut mgr2 = DnsSecKeyManager::new(dir.clone());
        mgr2.load_keys_from_disk().unwrap();
        assert!(
            mgr2.key_signing_key.is_none(),
            "Expired key should not be loaded"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_get_signing_keys() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        mgr.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();

        let keys = mgr.get_signing_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, KeyType::ZSK);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_get_all_dnskeys() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        mgr.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();

        let keys = mgr.get_all_dnskeys();
        assert_eq!(keys.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_get_key_status() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        mgr.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();

        let status = mgr.get_key_status().unwrap();
        assert!(status.ksk.is_some());
        assert!(status.zsk.is_some());

        let ksk = status.ksk.unwrap();
        assert_eq!(ksk.key_type, "KSK");
        assert_eq!(ksk.algorithm, "ED25519");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_cleanup_expired_keys() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().unwrap();
        let ksk_dir = dir.join("ksk");
        let entries: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        let key_file_entry = entries
            .iter()
            .find(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "key")
                    .unwrap_or(false)
            })
            .unwrap();
        let key_path = key_file_entry.path();
        let _stem = key_path.file_stem().unwrap().to_str().unwrap();

        let meta = serde_json::json!({
            "key_id": "ksk",
            "algorithm": 15,
            "key_type": 0,
            "created_at": 1,
            "expires_at": 1,
            "key_tag": ksk.key_tag,
            "flags": 257,
            "key_size": null,
        });
        std::fs::write(&key_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

        mgr.cleanup_expired_keys().unwrap();

        let key_files: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "key")
                    .unwrap_or(false)
            })
            .collect();

        assert!(key_files.is_empty(), "Expired key files should be removed");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_rollover_status() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        let status = mgr.get_rollover_status();
        assert_eq!(status["ksk_in_rollover"], false);
        assert_eq!(status["zsk_in_rollover"], false);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_cds_record() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().unwrap();
        let cds = mgr.generate_cds_record(ksk).unwrap();
        assert!(!cds.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generate_cdnskey_record() {
        let dir = temp_key_dir();
        let mut mgr = DnsSecKeyManager::new(dir.clone());
        mgr.initialize().unwrap();

        mgr.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();

        let ksk = mgr.key_signing_key.as_ref().unwrap();
        let cdnskey = mgr.generate_cdnskey_record(ksk).unwrap();
        assert!(!cdnskey.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
