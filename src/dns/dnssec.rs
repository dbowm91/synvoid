// DNSSEC signing module
//
// NOTE: This module currently uses manual DNS wire format construction.
// For production use, consider switching to the `dns-parser` or `hickory` crate
// for proper DNS message parsing and construction. This would provide:
// - Proper handling of DNS message compression
// - Correct RDATA encoding for all record types
// - Better RFC compliance
// - Easier maintenance

use std::path::PathBuf;
use std::result::Result;

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256, Sha384};

/// RNG adapter that wraps getrandom to implement rand_core 0.6 traits.
/// Required because rsa 0.9 depends on rand_core 0.6 while our project uses rand 0.9.
struct CryptoRngAdapter;

impl rand_core_06::RngCore for CryptoRngAdapter {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u32::from_le_bytes(buf)
    }
    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        getrandom::getrandom(&mut buf).expect("getrandom failed");
        u64::from_le_bytes(buf)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("getrandom failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        getrandom::getrandom(dest).map_err(rand_core_06::Error::new)
    }
}

impl rand_core_06::CryptoRng for CryptoRngAdapter {}

use super::crypto_rng;

#[derive(Debug, Clone, Copy)]
pub struct KeyRotationConfig {
    pub ksk_rollover_days: u32,
    pub zsk_rollover_days: u32,
    pub grace_period_days: u32,
    pub key_expiration_days: u32,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        Self {
            ksk_rollover_days: 30,
            zsk_rollover_days: 7,
            grace_period_days: 2,
            key_expiration_days: 365,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct KeyRotationResult {
    pub ksk_rotated: bool,
    pub zsk_rotated: bool,
    pub ksk_new_key_id: Option<String>,
    pub zsk_new_key_id: Option<String>,
    pub ksk_age_days: Option<u64>,
    pub zsk_age_days: Option<u64>,
    pub ksk_error: Option<String>,
    pub zsk_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub key_type: String,
    pub algorithm: String,
    pub key_tag: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub age_days: u64,
    pub days_until_expiry: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DnsSecKeyStatus {
    pub ksk: Option<KeyInfo>,
    pub zsk: Option<KeyInfo>,
}

pub struct DnsSecKeyManager {
    pub key_path: PathBuf,
    pub key_signing_key: Option<ZoneSigningKey>,
    pub zone_signing_key: Option<ZoneSigningKey>,
    pub standby_ksk: Option<ZoneSigningKey>,
    pub standby_zsk: Option<ZoneSigningKey>,
    pub rollover_state: RolloverState,
}

#[derive(Debug, Clone, Default)]
pub struct RolloverState {
    pub ksk_in_rollover: bool,
    pub zsk_in_rollover: bool,
    pub ksk_rollover_started: Option<u64>,
    pub zsk_rollover_started: Option<u64>,
    pub publish_dnssec: bool,
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
        let now = crate::utils::safe_unix_timestamp();
        let expires_at = now + (validity_days as u64 * 86400);

        let (public_key, private_key, key_tag, flags, key_size) = match algorithm {
            Algorithm::Ed25519 => {
                let bytes = super::crypto_rng::random_bytes(32);
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
                    _rsa_key_size as usize
                };
                if !matches!(bits, 1024 | 2048 | 4096) {
                    return Err(format!(
                        "Unsupported RSA key size {}. Use 1024, 2048, or 4096.",
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
        let now = crate::utils::safe_unix_timestamp();

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
        let now = crate::utils::safe_unix_timestamp();

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

        let now = crate::utils::safe_unix_timestamp();

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
        let now = crate::utils::safe_unix_timestamp();

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
        let now = crate::utils::safe_unix_timestamp();

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

#[derive(Clone, Debug)]
pub struct ZoneSigningKey {
    pub key_id: String,
    pub algorithm: Algorithm,
    pub key_type: KeyType,
    pub created_at: u64,
    pub expires_at: u64,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub key_tag: u16,
    pub flags: u16,
    pub key_size: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Ed25519,
    RSA,
}

impl Algorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            Algorithm::Ed25519 => 15,
            Algorithm::RSA => 8, // RSASHA256
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            15 => Some(Algorithm::Ed25519),
            8 => Some(Algorithm::RSA),
            _ => None,
        }
    }

    pub fn dns_algorithm_name(&self) -> &'static str {
        match self {
            Algorithm::Ed25519 => "ED25519",
            Algorithm::RSA => "RSASHA256",
        }
    }
}

impl From<crate::config::dns::DnsSecAlgorithm> for Algorithm {
    fn from(config: crate::config::dns::DnsSecAlgorithm) -> Self {
        match config {
            crate::config::dns::DnsSecAlgorithm::Ed25519 => Algorithm::Ed25519,
            crate::config::dns::DnsSecAlgorithm::RsaSha256 => Algorithm::RSA,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    KSK,
    ZSK,
}

pub fn calculate_key_tag(flags: u16, protocol: u8, algorithm: u8, public_key: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(protocol);
    buf.push(algorithm);
    buf.extend_from_slice(public_key);

    let mut sum: u32 = 0;
    for (i, byte) in buf.iter().enumerate() {
        if i & 1 == 0 {
            sum += (*byte as u32) << 8;
        } else {
            sum += *byte as u32;
        }
    }

    (sum + (sum >> 16)) as u16
}

pub fn compute_dnskey(key: &ZoneSigningKey) -> Vec<u8> {
    let mut dnskey = Vec::new();

    dnskey.extend_from_slice(&key.flags.to_be_bytes());
    dnskey.push(0x03);
    dnskey.push(key.algorithm.to_u8());
    dnskey.extend_from_slice(&key.public_key);

    dnskey
}

pub fn get_dnskey_record(key: &ZoneSigningKey) -> Vec<u8> {
    let mut record = Vec::new();

    record.push(0x00);
    record.push(0x00);

    record.extend_from_slice(&key.flags.to_be_bytes());
    record.push(0x03);
    record.push(key.algorithm.to_u8());
    record.extend_from_slice(&key.public_key);

    record
}

pub fn sign_data(data: &[u8], key: &ZoneSigningKey) -> Result<Vec<u8>, String> {
    match key.algorithm {
        Algorithm::Ed25519 => {
            let signing_key = SigningKey::from_bytes(
                key.private_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| "Invalid Ed25519 private key length")?,
            );
            let sig = signing_key.sign(data);
            Ok(sig.to_bytes().to_vec())
        }
        Algorithm::RSA => {
            use rsa::pkcs1v15::Pkcs1v15Sign;
            use rsa::pkcs8::DecodePrivateKey;
            use rsa::traits::SignatureScheme;
            use sha2::{Digest, Sha256};

            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&key.private_key)
                .map_err(|e| format!("Invalid RSA private key: {}", e))?;
            let hashed = Sha256::digest(data);
            let scheme = Pkcs1v15Sign::new::<Sha256>();
            scheme
                .sign(Some(&mut CryptoRngAdapter), &private_key, &hashed)
                .map_err(|e| format!("RSA signing failed: {}", e))
        }
    }
}

#[allow(dead_code)]
fn extract_rsa_modulus(der_bytes: &[u8]) -> Vec<u8> {
    let mut i = 0;
    if der_bytes.len() < 2 || der_bytes[0] != 0x30 {
        return Vec::new();
    }
    i += 1 + len_of_der_length(der_bytes[i]);

    if i >= der_bytes.len() || der_bytes[i] != 0x02 {
        return Vec::new();
    }
    i += 1 + len_of_der_length(der_bytes[i]);

    while i < der_bytes.len() && der_bytes[i] == 0x02 {
        i += 1 + len_of_der_length(der_bytes[i]);
        while i < der_bytes.len() && (der_bytes[i] & 0x80) == 0x80 {
            i += 1;
        }
        i += 1;
    }

    if i >= der_bytes.len() || der_bytes[i] != 0x03 {
        return Vec::new();
    }
    i += 1 + len_of_der_length(der_bytes[i]);

    i += 1;
    let bit_string_len = decode_der_length(&der_bytes[i..]).unwrap_or(0);
    i += len_of_der_length(der_bytes[i]);

    if i >= der_bytes.len() || der_bytes[i] != 0x30 {
        return Vec::new();
    }
    i += 1 + len_of_der_length(der_bytes[i]);

    if i >= der_bytes.len() || der_bytes[i] != 0x30 {
        return Vec::new();
    }
    i += 1 + len_of_der_length(der_bytes[i]);

    if i >= der_bytes.len() {
        return Vec::new();
    }

    let alg_len = decode_der_length(&der_bytes[i..]).unwrap_or(0);
    i += len_of_der_length(der_bytes[i]);
    i += alg_len;

    if i >= der_bytes.len() {
        return Vec::new();
    }

    let key_start = i;
    let key_end = std::cmp::min(i + bit_string_len - alg_len - 2, der_bytes.len());

    der_bytes[key_start..key_end].to_vec()
}

pub fn create_rrsig_record(
    key: &ZoneSigningKey,
    type_covered: u16,
    original_ttl: u32,
    signer_name: &str,
    signature: &[u8],
    labels_count: u8,
) -> Vec<u8> {
    let mut rrsig = Vec::new();

    rrsig.extend_from_slice(&type_covered.to_be_bytes());
    rrsig.push(key.algorithm.to_u8());
    rrsig.push(labels_count);
    rrsig.extend_from_slice(&original_ttl.to_be_bytes());

    let now = chrono::Utc::now().timestamp() as u64;
    let sig_expire = now + (7 * 86400);
    let sig_inception = now - (86400);

    rrsig.extend_from_slice(&sig_expire.to_be_bytes());
    rrsig.extend_from_slice(&sig_inception.to_be_bytes());
    rrsig.extend_from_slice(&key.key_tag.to_be_bytes());

    let signer_name_labels = signer_name.trim_end_matches('.');
    let signer_name_parts: Vec<&str> = signer_name_labels.split('.').collect();
    for part in &signer_name_parts {
        rrsig.push((*part).len() as u8);
        rrsig.extend_from_slice(part.as_bytes());
    }
    rrsig.push(0);

    rrsig.extend_from_slice(signature);

    rrsig
}

fn build_type_bitmap(type_codes: &[u16]) -> Vec<(u8, Vec<u8>)> {
    let mut window_blocks = Vec::new();
    let mut current_window: u8 = 0;
    let mut block_bits = Vec::new();

    for &rt in type_codes {
        let window = (rt / 256) as u8;
        let bit = rt % 256;

        if window != current_window && !block_bits.is_empty() {
            window_blocks.push((current_window, std::mem::take(&mut block_bits)));
            current_window = window;
        }

        let byte_index = bit / 8;
        let bit_index = bit % 8;

        while block_bits.len() <= byte_index as usize {
            block_bits.push(0);
        }
        block_bits[byte_index as usize] |= 1 << (7 - bit_index);
    }

    if !block_bits.is_empty() {
        window_blocks.push((current_window, block_bits));
    }

    window_blocks
}

pub fn create_nsec_record(_current_name: &str, next_name: &str, type_bitmap: &[u16]) -> Vec<u8> {
    let mut nsec = Vec::new();

    let next_name_labels = next_name.trim_end_matches('.');
    let next_name_parts: Vec<&str> = next_name_labels.split('.').collect();
    for part in &next_name_parts {
        nsec.push((*part).len() as u8);
        nsec.extend_from_slice(part.as_bytes());
    }
    nsec.push(0);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec.push(window);
        nsec.push(bits.len() as u8);
        nsec.extend_from_slice(&bits);
    }

    nsec
}

pub fn get_nsec_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

pub fn find_next_name_in_zone(zone: &super::server::Zone, current_name: &str) -> Option<String> {
    let origin = zone.origin.trim_end_matches('.').to_lowercase();
    let current_lower = current_name
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();

    let mut all_names: Vec<String> = zone
        .records
        .keys()
        .filter(|(name, _)| {
            let full_name = if name.is_empty() || *name == "@" {
                origin.clone()
            } else {
                format!("{}.{}", name, origin)
            };
            !full_name.is_empty()
        })
        .map(|(name, _)| {
            if name.is_empty() || *name == "@" {
                origin.clone()
            } else {
                format!("{}.{}", name, origin)
            }
        })
        .collect();

    all_names.sort();
    all_names.dedup();

    let mut found_current = false;
    for name in &all_names {
        if name.to_lowercase() == current_lower {
            found_current = true;
        } else if found_current {
            return Some(name.clone());
        }
    }

    if !all_names.is_empty() {
        Some(all_names[0].clone())
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsDigestType {
    Sha1 = 1,
    Sha256 = 2,
    Sha384 = 4,
}

impl DsDigestType {
    pub fn to_u8(&self) -> u8 {
        match self {
            DsDigestType::Sha1 => 1,
            DsDigestType::Sha256 => 2,
            DsDigestType::Sha384 => 4,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DsDigestType::Sha1),
            2 => Some(DsDigestType::Sha256),
            4 => Some(DsDigestType::Sha384),
            _ => None,
        }
    }
}

pub fn compute_dnskey_canonical(
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.push(protocol);
    buf.push(algorithm);
    buf.extend_from_slice(public_key);
    buf
}

pub fn compute_ds_digest(
    digest_type: u8,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
) -> Result<Vec<u8>, String> {
    let canonical = compute_dnskey_canonical(flags, protocol, algorithm, public_key);

    match digest_type {
        1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        2 => {
            let mut hasher = Sha256::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        4 => {
            let mut hasher = Sha384::new();
            hasher.update(&canonical);
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(format!("Unsupported DS digest type: {}", digest_type)),
    }
}

pub fn verify_ds_digest(
    digest_type: u8,
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: &[u8],
    expected_digest: &[u8],
) -> Result<bool, String> {
    let computed = compute_ds_digest(digest_type, flags, protocol, algorithm, public_key)?;
    Ok(computed == expected_digest)
}

pub fn create_ds_record(
    key: &ZoneSigningKey,
    digest_type: DsDigestType,
) -> Result<Vec<u8>, String> {
    let mut ds_data = Vec::new();

    ds_data.extend_from_slice(&key.key_tag.to_be_bytes());
    ds_data.push(key.algorithm.to_u8());
    ds_data.push(digest_type.to_u8());

    let canonical_dnskey = compute_dnskey_canonical(
        key.flags,
        3, // protocol
        key.algorithm.to_u8(),
        &key.public_key,
    );

    let digest = match digest_type {
        DsDigestType::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
        DsDigestType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
        DsDigestType::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(&canonical_dnskey);
            hasher.finalize().to_vec()
        }
    };

    ds_data.extend_from_slice(&digest);

    Ok(ds_data)
}

pub fn get_ds_record(key: &ZoneSigningKey) -> Vec<u8> {
    let mut record = Vec::new();

    record.push(0x00);
    record.push(0x00);

    if let Ok(ds_data) = create_ds_record(key, DsDigestType::Sha256) {
        record.extend_from_slice(&ds_data);
    }

    record
}

#[derive(Clone, Debug)]
pub struct Nsec3Config {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    pub salt: Vec<u8>,
}

impl Default for Nsec3Config {
    fn default() -> Self {
        Self {
            algorithm: 1, // SHA-1 is the default NSEC3 algorithm
            flags: 0,
            iterations: 0,
            salt: Vec::new(),
        }
    }
}

impl Nsec3Config {
    pub fn new(iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            algorithm: 1,
            flags: 0,
            iterations,
            salt,
        }
    }

    pub fn new_with_algorithm(algorithm: u8, iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            algorithm,
            flags: 0,
            iterations,
            salt,
        }
    }
}

pub fn hash_name_nsec3(name: &str, config: &Nsec3Config) -> Vec<u8> {
    use sha1::Sha1;

    let mut name_lower = name.to_lowercase();
    if name_lower.ends_with('.') {
        name_lower.pop();
    }
    name_lower.push('.');

    let mut hash = name_lower.as_bytes().to_vec();

    for _ in 0..config.iterations {
        match config.algorithm {
            1 => {
                let mut hasher = Sha1::new();
                hasher.update(&hash);
                hasher.update(&config.salt);
                hash = hasher.finalize().to_vec();
            }
            2 => {
                let mut hasher = Sha256::new();
                hasher.update(&hash);
                hasher.update(&config.salt);
                hash = hasher.finalize().to_vec();
            }
            _ => {
                let mut hasher = Sha1::new();
                hasher.update(&hash);
                hasher.update(&config.salt);
                hash = hasher.finalize().to_vec();
            }
        }
    }

    hash
}

pub fn create_nsec3_record(
    _owner_name: &str,
    next_name: &str,
    config: &Nsec3Config,
    type_bitmap: &[u16],
) -> Vec<u8> {
    let mut nsec3 = Vec::new();

    nsec3.push(config.algorithm);
    nsec3.push(config.flags);
    nsec3.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3.push(config.salt.len() as u8);
    nsec3.extend_from_slice(&config.salt);

    let next_hash = hash_name_nsec3(next_name, config);
    nsec3.extend_from_slice(&next_hash);

    for (window, bits) in build_type_bitmap(type_bitmap) {
        nsec3.push(window);
        nsec3.push(bits.len() as u8);
        nsec3.extend_from_slice(&bits);
    }

    nsec3
}

pub fn create_nsec3param_record(config: &Nsec3Config) -> Vec<u8> {
    let mut nsec3param = Vec::new();

    nsec3param.push(config.algorithm);
    nsec3param.push(config.flags);
    nsec3param.extend_from_slice(&config.iterations.to_be_bytes());
    nsec3param.push(config.salt.len() as u8);
    nsec3param.extend_from_slice(&config.salt);

    nsec3param
}

pub fn get_nsec3_type_bitmap() -> Vec<u16> {
    vec![1, 2, 5, 6, 15, 16, 28, 33, 46, 47, 50]
}

pub fn create_nsec3_owner_name(base_name: &str, hash: &[u8]) -> String {
    let hash_b32 = base32_encode(hash);
    format!("{}.{}.{}", hash.len(), hash_b32, base_name)
}

fn base32_encode(input: &[u8]) -> String {
    const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();

    let mut buffer: u64 = 0;
    let mut bits_in_buffer = 0;

    for &byte in input {
        buffer = (buffer << 8) | (byte as u64);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(BASE32_ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        result.push(BASE32_ALPHABET[index] as char);
    }

    result
}

#[allow(dead_code)]
fn len_of_der_length(byte: u8) -> usize {
    if byte < 0x80 {
        1
    } else {
        1 + (byte & 0x7f) as usize
    }
}

#[allow(dead_code)]
fn decode_der_length(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    if bytes[0] < 0x80 {
        Some(bytes[0] as usize)
    } else {
        let num_bytes = (bytes[0] & 0x7f) as usize;
        if num_bytes > bytes.len() - 1 || num_bytes > 4 {
            return None;
        }
        let mut result = 0usize;
        for i in 1..=num_bytes {
            result = (result << 8) | (bytes[i] as usize);
        }
        Some(result)
    }
}

pub fn canonical_rdata(
    record_type: u16,
    value: &str,
    priority: Option<u32>,
    weight: Option<u32>,
    port: Option<u32>,
    _ttl: u32,
) -> Vec<u8> {
    match record_type {
        1 => {
            if let Ok(ip) = value.parse::<std::net::Ipv4Addr>() {
                return ip.octets().to_vec();
            }
            Vec::new()
        }
        28 => {
            if let Ok(ip) = value.parse::<std::net::Ipv6Addr>() {
                return ip.octets().to_vec();
            }
            Vec::new()
        }
        2 => canonical_name(value),
        5 => canonical_name(value),
        6 => canonical_soa(value),
        15 => {
            let mut rdata = Vec::new();
            let pri = priority.unwrap_or(10) as u16;
            rdata.extend_from_slice(&pri.to_be_bytes());
            rdata.extend_from_slice(&canonical_name(value));
            rdata
        }
        16 => {
            let mut rdata = Vec::new();
            let txt = value.as_bytes();

            let mut pos = 0;
            while pos < txt.len() {
                let remaining = &txt[pos..];
                if remaining.is_empty() {
                    break;
                }
                let len = remaining[0] as usize;
                if len == 0 || pos + 1 + len > txt.len() {
                    rdata.push(txt.len() as u8);
                    rdata.extend_from_slice(txt);
                    break;
                }
                rdata.push(len as u8);
                rdata.extend_from_slice(&remaining[1..1 + len]);
                pos += 1 + len;
            }

            if rdata.is_empty() {
                rdata.push(txt.len() as u8);
                rdata.extend_from_slice(txt);
            }

            rdata
        }
        33 => {
            let mut rdata = Vec::new();
            let pri = priority.unwrap_or(0);
            let w = weight.unwrap_or(0);
            let p = port.unwrap_or(0);
            rdata.extend_from_slice(&pri.to_be_bytes());
            rdata.extend_from_slice(&w.to_be_bytes());
            rdata.extend_from_slice(&p.to_be_bytes());
            rdata.extend_from_slice(&canonical_name(value));
            rdata
        }
        64 | 65 => {
            if let Ok(svcb_data) = crate::dns::server::DnsServer::parse_svcb_value(value) {
                svcb_data
            } else {
                value.as_bytes().to_vec()
            }
        }
        _ => value.as_bytes().to_vec(),
    }
}

fn canonical_name(name: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    let name_lower = name.to_lowercase();
    let name = name_lower.trim_end_matches('.');

    if name.is_empty() {
        rdata.push(0);
        return rdata;
    }

    for part in name.split('.') {
        if !part.is_empty() {
            rdata.push(part.len() as u8);
            rdata.extend_from_slice(part.as_bytes());
        }
    }
    rdata.push(0);
    rdata
}

fn canonical_soa(value: &str) -> Vec<u8> {
    let mut rdata = Vec::new();
    let parts: Vec<&str> = value.split_whitespace().collect();

    if parts.len() >= 7 {
        rdata.extend_from_slice(&canonical_name(parts[0]));
        rdata.extend_from_slice(&canonical_name(parts[1]));

        if let Ok(serial) = parts[2].parse::<u32>() {
            rdata.extend_from_slice(&serial.to_be_bytes());
        } else {
            rdata.extend_from_slice(&0u32.to_be_bytes());
        }

        for i in 3..7 {
            if let Ok(refresh) = parts[i].parse::<u32>() {
                rdata.extend_from_slice(&refresh.to_be_bytes());
            } else {
                rdata.extend_from_slice(&0u32.to_be_bytes());
            }
        }
    }

    rdata
}

pub fn canonical_dns_message(
    name: &str,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    rdata: &[u8],
) -> Vec<u8> {
    let mut msg = Vec::new();

    let name_lower = name.to_lowercase();
    let name = name_lower.trim_end_matches('.');

    if name.is_empty() {
        msg.push(0);
    } else {
        for part in name.split('.') {
            if !part.is_empty() {
                msg.push(part.len() as u8);
                msg.extend_from_slice(part.as_bytes());
            }
        }
        msg.push(0);
    }

    msg.extend_from_slice(&record_type.to_be_bytes());
    msg.extend_from_slice(&record_class.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    msg.extend_from_slice(rdata);

    msg
}

pub fn count_labels(name: &str) -> u8 {
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        return 1;
    }
    name.split('.').count() as u8
}

pub fn sign_record(
    name: &str,
    record_type: u16,
    ttl: u32,
    key: &ZoneSigningKey,
    _signer_name: &str,
) -> Result<Vec<u8>, String> {
    let rdata_value = String::new();
    let priority = None;
    let rdata = canonical_rdata(record_type, &rdata_value, priority, None, None, ttl);

    let canonical_msg = canonical_dns_message(name, record_type, 1, ttl, &rdata);

    sign_data(&canonical_msg, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_name() {
        let result = canonical_name("EXAMPLE.COM");
        assert_eq!(
            result,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );

        let result2 = canonical_name("example.com.");
        assert_eq!(
            result2,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );

        let result3 = canonical_name("");
        assert_eq!(result3, vec![0]);
    }

    #[test]
    fn test_canonical_a_record() {
        let result = canonical_rdata(1, "192.0.2.1", None, None, None, 3600);
        assert_eq!(result, vec![192, 0, 2, 1]);
    }

    #[test]
    fn test_canonical_aaaa_record() {
        let result = canonical_rdata(28, "2001:db8::1", None, None, None, 3600);
        assert_eq!(
            result,
            vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn test_canonical_cname_record() {
        let result = canonical_rdata(5, "example.com", None, None, None, 3600);
        assert_eq!(
            result,
            vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );
    }

    #[test]
    fn test_canonical_txt_record_single_string() {
        let result = canonical_rdata(16, "Hello World", None, None, None, 3600);
        assert_eq!(result.len(), 12);
        assert_eq!(result[0], 11);
        assert_eq!(&result[1..], b"Hello World");
    }

    #[test]
    fn test_canonical_txt_record_multiple_strings() {
        let result = canonical_rdata(16, "\x0bHello World", None, None, None, 3600);
        // TXT record: length byte + text (no trailing null in canonical form)
        assert_eq!(result.len(), 12);
        assert_eq!(result[0], 11);
        assert_eq!(&result[1..12], b"Hello World");
    }

    #[test]
    fn test_canonical_mx_record() {
        let result = canonical_rdata(15, "example.com", Some(10), None, None, 3600);
        eprintln!(
            "DEBUG: result len = {}, result = {:?}",
            result.len(),
            result
        );
        // MX RDATA: 2 bytes priority + canonical name
        // canonical name "example.com" = [7, 'example', 3, 'com', 0] = 13 bytes
        // Total: 2 + 13 = 15 bytes
        assert_eq!(result.len(), 15);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 10);
        assert_eq!(
            &result[2..],
            &vec![7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]
        );
    }

    #[test]
    fn test_canonical_soa_record() {
        let soa_value = "ns.example.com. hostmaster.example.com. 2024010101 3600 600 604800 86400";
        let result = canonical_rdata(6, soa_value, None, None, None, 3600);

        assert!(result.len() > 0);

        // SOA record structure: mname (primary NS) + rname (admin) + serial + refresh + retry + expire + minimum
        // mname: ns.example.com = [2, 'ns', 7, 'example', 3, 'com', 0] = 16 bytes
        // rname: hostmaster.example.com = [10, 'hostmaster', 7, 'example', 3, 'com', 0] = 24 bytes
        // serial: 4 bytes, refresh: 4, retry: 4, expire: 4, minimum: 4 = 20 bytes
        // Total: 16 + 24 + 20 = 60 bytes
        assert_eq!(result.len(), 60);

        // Verify first label is "ns" (length 2)
        assert_eq!(result[0], 2);
        assert_eq!(result[1], b'n');
        assert_eq!(result[2], b's');
    }

    #[test]
    fn test_count_labels() {
        assert_eq!(count_labels("example.com"), 2);
        assert_eq!(count_labels("example.com."), 2);
        assert_eq!(count_labels("@"), 1);
        assert_eq!(count_labels(""), 1);
        assert_eq!(count_labels("a.b.c"), 3);
    }

    #[test]
    fn test_nsec3_hash() {
        let config = Nsec3Config::new(0, vec![0xab, 0xcd]);

        let hash1 = hash_name_nsec3("example.com", &config);
        let hash2 = hash_name_nsec3("example.com", &config);

        assert_eq!(hash1, hash2);

        let hash3 = hash_name_nsec3("test.example.com", &config);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_base32_encode() {
        // 3 bytes = 24 bits = 4 full 5-bit groups + 4 remaining bits = 5 base32 chars
        // Per RFC 4648 base32 without padding (used by NSEC3 in RFC 5155)
        let input = vec![0xfb, 0x53, 0x2c];
        let result = base32_encode(&input);
        assert_eq!(result.len(), 5, "3 bytes should produce 5 base32 chars");
    }

    #[test]
    fn test_algorithm_to_u8() {
        assert_eq!(Algorithm::Ed25519.to_u8(), 15);
    }

    #[test]
    fn test_algorithm_from_u8() {
        assert_eq!(Algorithm::from_u8(15), Some(Algorithm::Ed25519));
        assert_eq!(Algorithm::from_u8(5), None);
        assert_eq!(Algorithm::from_u8(99), None);
    }

    #[test]
    fn test_ds_digest_type() {
        assert_eq!(DsDigestType::Sha1.to_u8(), 1);
        assert_eq!(DsDigestType::Sha256.to_u8(), 2);
        assert_eq!(DsDigestType::from_u8(1), Some(DsDigestType::Sha1));
        assert_eq!(DsDigestType::from_u8(2), Some(DsDigestType::Sha256));
    }

    #[test]
    fn test_key_tag_calculation() {
        let public_key = vec![
            0x04, 0x9f, 0x2c, 0x8e, 0x7a, 0x2f, 0x1a, 0x5c, 0x3a, 0x7d, 0x4b, 0x9a, 0x8c, 0xde,
            0x15, 0x16, 0x2e, 0x86, 0x4a, 0x7f, 0x52, 0x91, 0x3c, 0xc1, 0x96, 0x4d, 0x89, 0x2c,
            0x7b, 0x5e, 0x9f, 0x43,
        ];
        let key_tag = calculate_key_tag(257, 3, Algorithm::Ed25519.to_u8(), &public_key);
        assert!(key_tag > 0);
    }

    #[test]
    fn test_compute_dnskey() {
        let key = ZoneSigningKey {
            key_id: "test".to_string(),
            algorithm: Algorithm::Ed25519,
            key_type: KeyType::KSK,
            created_at: 0,
            expires_at: 0,
            public_key: vec![
                0x04, 0x9f, 0x2c, 0x8e, 0x7a, 0x2f, 0x1a, 0x5c, 0x3a, 0x7d, 0x4b, 0x9a, 0x8c, 0xde,
                0x15, 0x16, 0x2e, 0x86, 0x4a, 0x7f, 0x52, 0x91, 0x3c, 0xc1, 0x96, 0x4d, 0x89, 0x2c,
                0x7b, 0x5e, 0x9f, 0x43,
            ],
            private_key: Vec::new(),
            key_tag: 12345,
            flags: 257,
            key_size: None,
        };

        let dnskey = compute_dnskey(&key);
        assert!(dnskey.len() > 0);
        // DNSKEY format: flags (2 bytes) + protocol (1 byte) + algorithm (1 byte) + public key
        assert_eq!(dnskey[0], 1); // flags high byte (257 = 0x0101)
        assert_eq!(dnskey[1], 1); // flags low byte
        assert_eq!(dnskey[2], 3); // protocol (always 3 for DNSSEC)
        assert_eq!(dnskey[3], 15); // algorithm (15 = Ed25519)
    }

    #[test]
    fn test_nsec3_config_default() {
        let config = Nsec3Config::default();
        assert_eq!(config.algorithm, 1);
        assert_eq!(config.flags, 0);
        assert_eq!(config.iterations, 0);
        assert!(config.salt.is_empty());
    }

    #[test]
    fn test_nsec3_config_new() {
        let salt = vec![0x01, 0x02, 0x03];
        let config = Nsec3Config::new(100, salt.clone());
        assert_eq!(config.algorithm, 1);
        assert_eq!(config.flags, 0);
        assert_eq!(config.iterations, 100);
        assert_eq!(config.salt, salt);
    }

    #[test]
    fn test_key_rotation_config_default() {
        let config = KeyRotationConfig::default();
        assert_eq!(config.ksk_rollover_days, 30);
        assert_eq!(config.zsk_rollover_days, 7);
        assert_eq!(config.grace_period_days, 2);
        assert_eq!(config.key_expiration_days, 365);
    }

    #[test]
    fn test_key_info_structure() {
        let key_info = KeyInfo {
            key_type: "KSK".to_string(),
            algorithm: "Ed25519".to_string(),
            key_tag: 12345,
            created_at: 1000,
            expires_at: 2000,
            age_days: 1,
            days_until_expiry: Some(30),
        };

        assert_eq!(key_info.key_type, "KSK");
        assert_eq!(key_info.key_tag, 12345);
        assert!(key_info.days_until_expiry.is_some());
    }

    #[test]
    fn test_rollover_state_default() {
        let state = RolloverState::default();
        assert!(!state.ksk_in_rollover);
        assert!(!state.zsk_in_rollover);
        assert!(state.ksk_rollover_started.is_none());
    }

    #[test]
    fn test_dnssec_key_status() {
        let key_info = KeyInfo {
            key_type: "ZSK".to_string(),
            algorithm: "Ed25519".to_string(),
            key_tag: 54321,
            created_at: 1000,
            expires_at: 2000,
            age_days: 1,
            days_until_expiry: Some(30),
        };

        let status = DnsSecKeyStatus {
            ksk: None,
            zsk: Some(key_info),
        };

        assert!(status.ksk.is_none());
        assert!(status.zsk.is_some());
    }

    #[test]
    fn test_key_rotation_result() {
        let result = KeyRotationResult {
            ksk_rotated: true,
            zsk_rotated: false,
            ksk_new_key_id: Some("new-ksk".to_string()),
            zsk_new_key_id: None,
            ksk_age_days: Some(0),
            zsk_age_days: Some(5),
            ksk_error: None,
            zsk_error: None,
        };

        assert!(result.ksk_rotated);
        assert!(!result.zsk_rotated);
        assert!(result.ksk_new_key_id.is_some());
    }
}

pub struct ZoneSigner {
    key_manager: DnsSecKeyManager,
    nsec3_config: Nsec3Config,
}

impl ZoneSigner {
    pub fn new(key_manager: DnsSecKeyManager) -> Self {
        let salt = crypto_rng::random_bytes(16);
        let nsec3_config = Nsec3Config::new(50, salt);

        Self {
            key_manager,
            nsec3_config,
        }
    }

    pub fn sign_zone(&mut self, zone: &mut super::server::Zone) -> Result<(), String> {
        let zsk = self
            .key_manager
            .get_active_zsk()
            .map_err(|e| format!("No ZSK available: {}", e))?;

        let ksk = self
            .key_manager
            .get_active_ksk()
            .map_err(|e| format!("No KSK available: {}", e))?;

        self.add_dnskey_record(zone, ksk)?;
        self.add_rrsig_records(zone, zsk)?;
        self.add_nsec_records(zone)?;

        tracing::info!("Zone {} signed successfully", zone.origin);
        Ok(())
    }

    fn add_dnskey_record(
        &self,
        zone: &mut super::server::Zone,
        ksk: &ZoneSigningKey,
    ) -> Result<(), String> {
        let dnskey_rdata = compute_dnskey(ksk);

        let key_record = super::server::DnsZoneRecord {
            name: "@".to_string(),
            record_type: super::server::RecordType::DNSKEY,
            value: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &dnskey_rdata,
            ),
            ttl: 3600,
            priority: None,
        };

        let key = ("@".to_string(), super::server::RecordType::DNSKEY);
        zone.records.entry(key).or_default().push(key_record);

        if let Ok(ds_data) = create_ds_record(ksk, DsDigestType::Sha256) {
            let ds_value =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &ds_data);
            let ds_record = super::server::DnsZoneRecord {
                name: "@".to_string(),
                record_type: super::server::RecordType::DS,
                value: ds_value,
                ttl: 3600,
                priority: None,
            };
            let ds_key = ("@".to_string(), super::server::RecordType::DS);
            zone.records.entry(ds_key).or_default().push(ds_record);
        }

        Ok(())
    }

    fn add_rrsig_records(
        &self,
        zone: &mut super::server::Zone,
        zsk: &ZoneSigningKey,
    ) -> Result<(), String> {
        let signer_name = zone.origin.clone();
        let label_count = count_labels(&zone.origin);

        let record_types_to_sign = vec![
            super::server::RecordType::A,
            super::server::RecordType::AAAA,
            super::server::RecordType::CNAME,
            super::server::RecordType::MX,
            super::server::RecordType::NS,
            super::server::RecordType::SOA,
            super::server::RecordType::TXT,
            super::server::RecordType::SRV,
            super::server::RecordType::DNSKEY,
        ];

        for rt in record_types_to_sign {
            use super::server::RecordTypeExt;

            // Collect records to sign first to avoid borrow issues
            let records_to_sign: Vec<_> = zone
                .records
                .iter()
                .filter(|((_, rt_iter), _)| *rt_iter == rt)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            for ((_name, _), records) in records_to_sign {
                for record in records {
                    let rt_val = rt.to_u16();
                    let canonical = canonical_rdata(
                        rt_val,
                        &record.value,
                        record.priority,
                        None,
                        None,
                        record.ttl,
                    );

                    let canonical_msg =
                        canonical_dns_message(&record.name, rt_val, 1, record.ttl, &canonical);

                    let signature = sign_data(&canonical_msg, zsk)?;

                    let rrsig = create_rrsig_record(
                        zsk,
                        rt_val,
                        record.ttl,
                        &signer_name,
                        &signature,
                        label_count,
                    );

                    let rrsig_value =
                        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &rrsig);

                    let rrsig_record = super::server::DnsZoneRecord {
                        name: record.name.clone(),
                        record_type: super::server::RecordType::RRSIG,
                        value: rrsig_value,
                        ttl: record.ttl,
                        priority: None,
                    };

                    let rrsig_key = (record.name.clone(), super::server::RecordType::RRSIG);
                    zone.records
                        .entry(rrsig_key)
                        .or_default()
                        .push(rrsig_record);
                }
            }
        }

        Ok(())
    }

    fn add_nsec_records(&self, zone: &mut super::server::Zone) -> Result<(), String> {
        let mut all_names: Vec<String> =
            zone.records.keys().map(|(name, _)| name.clone()).collect();
        all_names.sort();
        all_names.dedup();

        for (i, name) in all_names.iter().enumerate() {
            let next_name = if i + 1 < all_names.len() {
                all_names[i + 1].clone()
            } else {
                all_names[0].clone()
            };

            let type_bitmap = get_nsec_type_bitmap();
            let nsec_data = create_nsec_record(name, &next_name, &type_bitmap);
            let nsec_value =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nsec_data);

            let nsec_record = super::server::DnsZoneRecord {
                name: name.clone(),
                record_type: super::server::RecordType::NSEC,
                value: nsec_value,
                ttl: 3600,
                priority: None,
            };

            let nsec_key = (name.clone(), super::server::RecordType::NSEC);
            zone.records.entry(nsec_key).or_default().push(nsec_record);
        }

        let soa_key = ("@".to_string(), super::server::RecordType::SOA);
        let soa_record_opt = zone.records.get(&soa_key).cloned();
        if let Some(soa_records) = soa_record_opt {
            if let Some(soa) = soa_records.first() {
                let nsec3_data =
                    create_nsec3_record("@", "next", &self.nsec3_config, &get_nsec3_type_bitmap());
                let nsec3_value =
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &nsec3_data);

                let nsec3_record = super::server::DnsZoneRecord {
                    name: "@".to_string(),
                    record_type: super::server::RecordType::NSEC3,
                    value: nsec3_value,
                    ttl: soa.ttl,
                    priority: None,
                };

                let nsec3_key = ("@".to_string(), super::server::RecordType::NSEC3);
                zone.records
                    .entry(nsec3_key)
                    .or_default()
                    .push(nsec3_record);

                let nsec3param_data = create_nsec3param_record(&self.nsec3_config);
                let nsec3param_value = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &nsec3param_data,
                );

                let nsec3param_record = super::server::DnsZoneRecord {
                    name: "@".to_string(),
                    record_type: super::server::RecordType::NSEC3PARAM,
                    value: nsec3param_value,
                    ttl: soa.ttl,
                    priority: None,
                };

                let nsec3param_key = ("@".to_string(), super::server::RecordType::NSEC3PARAM);
                zone.records
                    .entry(nsec3param_key)
                    .or_default()
                    .push(nsec3param_record);
            }
        }

        Ok(())
    }
}
