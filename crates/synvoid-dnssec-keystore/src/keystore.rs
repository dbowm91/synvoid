//! Canonical DNSSEC key custody: generation, sealed storage, rotation.
//!
//! This is the Phase 30 extraction target. All private-key generation,
//! sealed persistence, rotation, and signing dispatch live here behind the
//! narrow [`DnssecKeystore`] API. Query/transport/resolver code in
//! `synvoid-dns` holds only opaque [`SealedSigningKey`] handles (or public
//! [`KeyMetadata`]) and calls [`SealedSigningKey::sign`] over
//! caller-supplied canonical bytes; it has no API to read private bytes.
//!
//! On-disk layout is preserved from `synvoid-dns` for compatibility:
//! `{key_path}/{ksk,zsk}/<name>.{key,pub,priv}` with JSON metadata sidecars.
//! Private files are created with mode `0600` on Unix and written atomically
//! (temp file + fsync + rename). No private bytes appear in logs, metrics,
//! errors, or serialized DTOs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::algorithm::Algorithm;
use crate::error::KeystoreError;
use crate::key::{KeyMetadata, KeyType, SealedSigningKey};

/// Rotation timing policy (days).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Public-only key status snapshot (safe for admin DTOs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    pub key_type: String,
    pub algorithm: String,
    pub key_tag: u16,
    pub created_at: u64,
    pub expires_at: u64,
    pub age_days: u64,
    pub days_until_expiry: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSecKeyStatus {
    pub ksk: Option<KeyInfo>,
    pub zsk: Option<KeyInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RolloverState {
    pub ksk_in_rollover: bool,
    pub zsk_in_rollover: bool,
    pub ksk_rollover_started: Option<u64>,
    pub zsk_rollover_started: Option<u64>,
    pub publish_dnssec: bool,
}

fn now_secs() -> u64 {
    synvoid_core::time::current_timestamp_secs()
}

/// Canonical key custodian. Clone shares no key material; share via `Arc`.
pub struct DnssecKeystore {
    key_path: PathBuf,
    ksk: Option<Arc<SealedSigningKey>>,
    zsk: Option<Arc<SealedSigningKey>>,
    standby_ksk: Option<Arc<SealedSigningKey>>,
    standby_zsk: Option<Arc<SealedSigningKey>>,
    rollover_state: RolloverState,
}

// Manual Debug: never include key material.
impl std::fmt::Debug for DnssecKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnssecKeystore")
            .field("key_path", &self.key_path)
            .field("has_ksk", &self.ksk.is_some())
            .field("has_zsk", &self.zsk.is_some())
            .field("has_standby_ksk", &self.standby_ksk.is_some())
            .field("has_standby_zsk", &self.standby_zsk.is_some())
            .field("rollover_state", &self.rollover_state)
            .finish()
    }
}

/// Back-compat alias so `synvoid-dns` facades keep compiling.
pub type DnsSecKeyManager = DnssecKeystore;
/// Back-compat alias for the sealed handle.
pub type ZoneSigningKey = SealedSigningKey;

impl DnssecKeystore {
    pub fn new(key_path: PathBuf) -> Self {
        Self {
            key_path,
            ksk: None,
            zsk: None,
            standby_ksk: None,
            standby_zsk: None,
            rollover_state: RolloverState::default(),
        }
    }

    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    pub fn initialize(&mut self) -> Result<(), KeystoreError> {
        std::fs::create_dir_all(&self.key_path)
            .map_err(|e| KeystoreError::Storage(format!("key directory: {e}")))?;
        secure_dir(&self.key_path)?;
        for sub in ["ksk", "zsk"] {
            let dir = self.key_path.join(sub);
            std::fs::create_dir_all(&dir)
                .map_err(|e| KeystoreError::Storage(format!("{sub} directory: {e}")))?;
            secure_dir(&dir)?;
        }
        tracing::info!("DNSSEC key directory initialized");
        Ok(())
    }

    // -- Narrow signer contract (Part B) ---------------------------------

    /// Sign canonical bytes with the active key of the requested type.
    /// Key management and query signing never share a code path that
    /// exposes private bytes: this is the only signing entry point the
    /// query path needs.
    pub fn sign_canonical(
        &self,
        canonical_bytes: &[u8],
        key_type: KeyType,
    ) -> Result<Vec<u8>, KeystoreError> {
        let handle = match key_type {
            KeyType::KSK => self.ksk.as_ref(),
            KeyType::ZSK => self.zsk.as_ref(),
        }
        .ok_or_else(|| KeystoreError::NotFound(format!("no active {key_type:?} for signing")))?;
        handle.sign(canonical_bytes)
    }

    /// Enumerate public metadata for all published DNSKEYs (active + in-
    /// rollover standbys). Safe for zones, caches, mesh anchors, admin.
    pub fn public_dnskeys(&self) -> Vec<KeyMetadata> {
        let mut out = Vec::new();
        if let Some(k) = self.ksk.as_ref() {
            out.push(k.metadata());
        }
        if self.rollover_state.ksk_in_rollover {
            if let Some(k) = self.standby_ksk.as_ref() {
                out.push(k.metadata());
            }
        }
        if let Some(k) = self.zsk.as_ref() {
            out.push(k.metadata());
        }
        if self.rollover_state.zsk_in_rollover {
            if let Some(k) = self.standby_zsk.as_ref() {
                out.push(k.metadata());
            }
        }
        out
    }

    /// Opaque signing handles for the query path (ZSK + rollover standby).
    /// Handles expose `sign()` and public metadata only.
    pub fn signing_handles(&self) -> Vec<Arc<SealedSigningKey>> {
        let mut out = Vec::new();
        if let Some(z) = self.zsk.as_ref() {
            out.push(Arc::clone(z));
        }
        if self.rollover_state.zsk_in_rollover {
            if let Some(s) = self.standby_zsk.as_ref() {
                out.push(Arc::clone(s));
            }
        }
        out
    }

    /// All DNSKEY handles including KSK (for DNSKEY RRset construction).
    /// Still opaque: callers use `.metadata()` / `.dnskey_rdata()`.
    pub fn dnskey_handles(&self) -> Vec<Arc<SealedSigningKey>> {
        let mut out = Vec::new();
        if let Some(k) = self.ksk.as_ref() {
            out.push(Arc::clone(k));
        }
        if self.rollover_state.ksk_in_rollover {
            if let Some(s) = self.standby_ksk.as_ref() {
                out.push(Arc::clone(s));
            }
        }
        if let Some(z) = self.zsk.as_ref() {
            out.push(Arc::clone(z));
        }
        if self.rollover_state.zsk_in_rollover {
            if let Some(s) = self.standby_zsk.as_ref() {
                out.push(Arc::clone(s));
            }
        }
        out
    }

    pub fn active_ksk(&self) -> Result<Arc<SealedSigningKey>, KeystoreError> {
        self.ksk
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| KeystoreError::NotFound("no active KSK".to_string()))
    }

    pub fn active_zsk(&self) -> Result<Arc<SealedSigningKey>, KeystoreError> {
        self.zsk
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| KeystoreError::NotFound("no active ZSK".to_string()))
    }

    /// Public-only snapshot of active keys (KSK + ZSK). Never includes
    /// private material by construction (`KeyMetadata` has no such field).
    pub fn active_keys_public(&self) -> Result<Vec<KeyMetadata>, KeystoreError> {
        let mut out = Vec::new();
        if let Some(k) = self.ksk.as_ref() {
            out.push(k.metadata());
        }
        if let Some(z) = self.zsk.as_ref() {
            out.push(z.metadata());
        }
        if out.is_empty() {
            return Err(KeystoreError::NotFound(
                "no active DNSSEC keys found".to_string(),
            ));
        }
        Ok(out)
    }

    // -- Generation / import (explicit management methods, Part B) --------

    pub fn generate_key(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        rsa_key_size: u32,
        validity_days: u32,
    ) -> Result<KeyMetadata, KeystoreError> {
        self.generate_key_internal(algorithm, key_type, rsa_key_size, validity_days, false)
    }

    pub fn generate_standby_key(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        rsa_key_size: u32,
        validity_days: u32,
    ) -> Result<KeyMetadata, KeystoreError> {
        self.generate_key_internal(algorithm, key_type, rsa_key_size, validity_days, true)
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_key_internal(
        &mut self,
        algorithm: Algorithm,
        key_type: KeyType,
        rsa_key_size: u32,
        validity_days: u32,
        is_standby: bool,
    ) -> Result<KeyMetadata, KeystoreError> {
        algorithm.validate_for_signing()?;
        let now = now_secs();
        let expires_at = now.saturating_add(validity_days as u64 * 86400);

        let (public_key, private_key, key_tag, flags, key_size) =
            crate::key::generate_keypair(algorithm, key_type, rsa_key_size)?;

        let key_id = match (key_type, is_standby) {
            (KeyType::KSK, false) => "ksk",
            (KeyType::ZSK, false) => "zsk",
            (KeyType::KSK, true) => "ksk-standby",
            (KeyType::ZSK, true) => "zsk-standby",
        };
        let key_name = if is_standby {
            format!("{key_id}-{now}")
        } else {
            format!("dnssec-{key_id}-{now}")
        };
        let key_dir = self.key_path.join(key_id);
        std::fs::create_dir_all(&key_dir)
            .map_err(|e| KeystoreError::Storage(format!("key directory: {e}")))?;
        secure_dir(&key_dir)?;

        let meta = serde_json::json!({
            "key_id": key_id,
            "algorithm": algorithm.to_u8(),
            "key_type": key_type as u8,
            "created_at": now,
            "expires_at": expires_at,
            "key_tag": key_tag,
            "flags": flags,
            "key_size": key_size,
            "standby": is_standby,
        });
        let meta_bytes = serde_json::to_vec_pretty(&meta)
            .map_err(|e| KeystoreError::Storage(format!("metadata encode: {e}")))?;
        atomic_write(&key_dir.join(format!("{key_name}.key")), &meta_bytes, 0o600)?;
        atomic_write(&key_dir.join(format!("{key_name}.pub")), &public_key, 0o644)?;
        atomic_write_private(&key_dir.join(format!("{key_name}.priv")), &private_key)?;

        let sealed = Arc::new(SealedSigningKey::new_sealed(
            key_id.to_string(),
            algorithm,
            key_type,
            now,
            expires_at,
            public_key,
            private_key,
            key_tag,
            flags,
            key_size,
        ));
        let metadata = sealed.metadata();
        match (key_type, is_standby) {
            (KeyType::KSK, true) => self.standby_ksk = Some(sealed),
            (KeyType::ZSK, true) => self.standby_zsk = Some(sealed),
            (KeyType::KSK, false) => self.ksk = Some(sealed),
            (KeyType::ZSK, false) => self.zsk = Some(sealed),
        }

        tracing::info!(
            "Generated {}{} key",
            if is_standby { "standby " } else { "" },
            key_id,
        );
        Ok(metadata)
    }

    // -- Disk loading ------------------------------------------------------

    pub fn load_keys_from_disk(&mut self) -> Result<(), KeystoreError> {
        for (key_type, is_standby) in [
            (KeyType::KSK, false),
            (KeyType::ZSK, false),
            (KeyType::KSK, true),
            (KeyType::ZSK, true),
        ] {
            let dir_name = match key_type {
                KeyType::KSK => "ksk",
                KeyType::ZSK => "zsk",
            };
            let key_dir = self.key_path.join(dir_name);
            if !key_dir.exists() {
                continue;
            }
            let entries = std::fs::read_dir(&key_dir)
                .map_err(|e| KeystoreError::Storage(format!("read key directory: {e}")))?;
            let mut best: Option<SealedSigningKey> = None;
            for entry in entries {
                let entry =
                    entry.map_err(|e| KeystoreError::Storage(format!("read entry: {e}")))?;
                let path = entry.path();
                if !path.is_file() || path.extension().map(|e| e != "key").unwrap_or(true) {
                    continue;
                }
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| KeystoreError::Storage(format!("read key file: {e}")))?;
                let meta: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| KeystoreError::Storage(format!("invalid key metadata: {e}")))?;
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
                if expires_at < now_secs() {
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
                let pub_file = key_dir.join(format!("{stem}.pub"));
                let priv_file = key_dir.join(format!("{stem}.priv"));
                if !pub_file.exists() || !priv_file.exists() {
                    continue;
                }
                check_private_permissions(&priv_file)?;
                let public_key = std::fs::read(&pub_file)
                    .map_err(|e| KeystoreError::Storage(format!("read public key: {e}")))?;
                let private_key = std::fs::read(&priv_file)
                    .map_err(|e| KeystoreError::Storage(format!("read private key: {e}")))?;
                let sealed = SealedSigningKey::from_stored_parts(
                    key_id_str.to_string(),
                    algorithm,
                    key_type,
                    created_at,
                    expires_at,
                    public_key,
                    private_key,
                    key_tag,
                    flags,
                    key_size,
                );
                match &best {
                    Some(existing) if existing.created_at() >= created_at => {}
                    _ => best = Some(sealed),
                }
            }
            if let Some(sealed) = best {
                let tag = sealed.key_tag();
                let handle = Arc::new(sealed);
                match (key_type, is_standby) {
                    (KeyType::KSK, true) => self.standby_ksk = Some(handle),
                    (KeyType::ZSK, true) => self.standby_zsk = Some(handle),
                    (KeyType::KSK, false) => self.ksk = Some(handle),
                    (KeyType::ZSK, false) => self.zsk = Some(handle),
                }
                tracing::info!(
                    "Loaded {}{} key (tag: {})",
                    if is_standby { "standby " } else { "" },
                    if key_type == KeyType::KSK {
                        "KSK"
                    } else {
                        "ZSK"
                    },
                    tag
                );
            }
        }
        Ok(())
    }

    // -- Rollover lifecycle --------------------------------------------------

    pub fn start_key_rollover(&mut self, key_type: KeyType) -> Result<KeyMetadata, KeystoreError> {
        let validity_days = match key_type {
            KeyType::KSK => 365,
            KeyType::ZSK => 90,
        };
        self.start_key_rollover_with_validity(key_type, validity_days)
    }

    fn start_key_rollover_with_validity(
        &mut self,
        key_type: KeyType,
        validity_days: u32,
    ) -> Result<KeyMetadata, KeystoreError> {
        let now = now_secs();
        match key_type {
            KeyType::KSK => {
                if self.standby_ksk.is_some() {
                    return Err(KeystoreError::Management(
                        "standby KSK already exists".to_string(),
                    ));
                }
                let (algorithm, key_size) = self
                    .ksk
                    .as_ref()
                    .map(|k| (k.algorithm(), k.key_size().unwrap_or(2048)))
                    .unwrap_or((Algorithm::Ed25519, 2048));
                let meta =
                    self.generate_standby_key(algorithm, KeyType::KSK, key_size, validity_days)?;
                self.rollover_state.ksk_in_rollover = true;
                self.rollover_state.ksk_rollover_started = Some(now);
                self.rollover_state.publish_dnssec = true;
                tracing::info!("Started KSK rollover");
                Ok(meta)
            }
            KeyType::ZSK => {
                if self.standby_zsk.is_some() {
                    return Err(KeystoreError::Management(
                        "standby ZSK already exists".to_string(),
                    ));
                }
                let (algorithm, key_size) = self
                    .zsk
                    .as_ref()
                    .map(|k| (k.algorithm(), k.key_size().unwrap_or(2048)))
                    .unwrap_or((Algorithm::Ed25519, 2048));
                let meta =
                    self.generate_standby_key(algorithm, KeyType::ZSK, key_size, validity_days)?;
                self.rollover_state.zsk_in_rollover = true;
                self.rollover_state.zsk_rollover_started = Some(now);
                self.rollover_state.publish_dnssec = true;
                tracing::info!("Started ZSK rollover");
                Ok(meta)
            }
        }
    }

    pub fn complete_key_rollover(&mut self, key_type: KeyType) -> Result<(), KeystoreError> {
        match key_type {
            KeyType::KSK => {
                if !self.rollover_state.ksk_in_rollover {
                    return Err(KeystoreError::Management("KSK not in rollover".to_string()));
                }
                if let Some(standby) = self.standby_ksk.take() {
                    self.ksk = Some(standby);
                }
                self.rollover_state.ksk_in_rollover = false;
                self.rollover_state.ksk_rollover_started = None;
                tracing::info!("Completed KSK rollover");
                Ok(())
            }
            KeyType::ZSK => {
                if !self.rollover_state.zsk_in_rollover {
                    return Err(KeystoreError::Management("ZSK not in rollover".to_string()));
                }
                if let Some(standby) = self.standby_zsk.take() {
                    self.zsk = Some(standby);
                }
                self.rollover_state.zsk_in_rollover = false;
                self.rollover_state.zsk_rollover_started = None;
                tracing::info!("Completed ZSK rollover");
                Ok(())
            }
        }
    }

    pub fn rollover_status(&self) -> serde_json::Value {
        serde_json::json!({
            "ksk_in_rollover": self.rollover_state.ksk_in_rollover,
            "zsk_in_rollover": self.rollover_state.zsk_in_rollover,
            "ksk_rollover_started": self.rollover_state.ksk_rollover_started,
            "zsk_rollover_started": self.rollover_state.zsk_rollover_started,
            "publish_dnssec": self.rollover_state.publish_dnssec,
        })
    }

    pub fn check_and_rotate(
        &mut self,
        config: KeyRotationConfig,
    ) -> Result<KeyRotationResult, KeystoreError> {
        let mut result = KeyRotationResult::default();
        let now = now_secs();
        self.complete_ready_rollovers(config.grace_period_days, now)?;

        if let Some(ksk) = self.ksk.as_ref() {
            let age_days = now.saturating_sub(ksk.created_at()) / 86400;
            let threshold =
                (config.ksk_rollover_days as u64).saturating_sub(config.grace_period_days as u64);
            result.ksk_age_days = Some(age_days);
            if age_days >= threshold {
                tracing::info!("KSK rotation needed (age: {age_days} days)");
                match self.rotate_ksk(config) {
                    Ok(_) => {
                        result.ksk_rotated = true;
                        result.ksk_new_key_id =
                            self.standby_ksk.as_ref().map(|k| k.key_id().to_string());
                    }
                    Err(e) => result.ksk_error = Some(e.to_string()),
                }
            }
        }
        if let Some(zsk) = self.zsk.as_ref() {
            let age_days = now.saturating_sub(zsk.created_at()) / 86400;
            let threshold =
                (config.zsk_rollover_days as u64).saturating_sub(config.grace_period_days as u64);
            result.zsk_age_days = Some(age_days);
            if age_days >= threshold {
                tracing::info!("ZSK rotation needed (age: {age_days} days)");
                match self.rotate_zsk(config) {
                    Ok(_) => {
                        result.zsk_rotated = true;
                        result.zsk_new_key_id =
                            self.standby_zsk.as_ref().map(|k| k.key_id().to_string());
                    }
                    Err(e) => result.zsk_error = Some(e.to_string()),
                }
            }
        }
        Ok(result)
    }

    pub fn check_key_rotation(&mut self, config: KeyRotationConfig) -> Result<(), KeystoreError> {
        let _ = self.check_and_rotate(config)?;
        Ok(())
    }

    fn rotate_ksk(&mut self, config: KeyRotationConfig) -> Result<(), KeystoreError> {
        if self.ksk.is_none() {
            return Err(KeystoreError::NotFound("no KSK key to rotate".to_string()));
        }
        self.start_key_rollover_with_validity(KeyType::KSK, config.key_expiration_days)?;
        Ok(())
    }

    fn rotate_zsk(&mut self, config: KeyRotationConfig) -> Result<(), KeystoreError> {
        if self.zsk.is_none() {
            return Err(KeystoreError::NotFound("no ZSK key to rotate".to_string()));
        }
        self.start_key_rollover_with_validity(KeyType::ZSK, config.key_expiration_days)?;
        Ok(())
    }

    fn complete_ready_rollovers(
        &mut self,
        grace_period_days: u32,
        now: u64,
    ) -> Result<(), KeystoreError> {
        let propagation_delay = u64::from(grace_period_days).saturating_mul(86_400);
        if self.rollover_state.ksk_in_rollover
            && self
                .rollover_state
                .ksk_rollover_started
                .is_some_and(|started| now.saturating_sub(started) >= propagation_delay)
        {
            self.complete_key_rollover(KeyType::KSK)?;
        }
        if self.rollover_state.zsk_in_rollover
            && self
                .rollover_state
                .zsk_rollover_started
                .is_some_and(|started| now.saturating_sub(started) >= propagation_delay)
        {
            self.complete_key_rollover(KeyType::ZSK)?;
        }
        Ok(())
    }

    // -- Public status / export (never private) -------------------------------

    pub fn key_status(&self) -> Result<DnsSecKeyStatus, KeystoreError> {
        let now = now_secs();
        let ksk_info = self.ksk.as_ref().map(|k| KeyInfo {
            key_type: "KSK".to_string(),
            algorithm: k.algorithm().dns_algorithm_name().to_string(),
            key_tag: k.key_tag(),
            created_at: k.created_at(),
            expires_at: k.expires_at(),
            age_days: now.saturating_sub(k.created_at()) / 86400,
            days_until_expiry: if k.expires_at() > now {
                Some((k.expires_at() - now) / 86400)
            } else {
                None
            },
        });
        let zsk_info = self.zsk.as_ref().map(|k| KeyInfo {
            key_type: "ZSK".to_string(),
            algorithm: k.algorithm().dns_algorithm_name().to_string(),
            key_tag: k.key_tag(),
            created_at: k.created_at(),
            expires_at: k.expires_at(),
            age_days: now.saturating_sub(k.created_at()) / 86400,
            days_until_expiry: if k.expires_at() > now {
                Some((k.expires_at() - now) / 86400)
            } else {
                None
            },
        });
        Ok(DnsSecKeyStatus {
            ksk: ksk_info,
            zsk: zsk_info,
        })
    }

    pub fn cleanup_expired_keys(&self) -> Result<(), KeystoreError> {
        let now = now_secs();
        for key_type in ["ksk", "zsk"] {
            let key_dir = self.key_path.join(key_type);
            if !key_dir.exists() {
                continue;
            }
            let entries = std::fs::read_dir(&key_dir)
                .map_err(|e| KeystoreError::Storage(format!("read key directory: {e}")))?;
            for entry in entries {
                let entry =
                    entry.map_err(|e| KeystoreError::Storage(format!("read entry: {e}")))?;
                let path = entry.path();
                if !(path.is_file() && path.extension().map(|e| e == "key").unwrap_or(false)) {
                    continue;
                }
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| KeystoreError::Storage(format!("read key file: {e}")))?;
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(expires_at) = meta.get("expires_at").and_then(|v| v.as_u64()) {
                        if expires_at < now {
                            std::fs::remove_file(&path).map_err(|e| {
                                KeystoreError::Storage(format!("remove expired key: {e}"))
                            })?;
                            for ext in ["pub", "priv"] {
                                let sidecar = path.with_extension(ext);
                                if sidecar.exists() {
                                    std::fs::remove_file(&sidecar).map_err(|e| {
                                        KeystoreError::Storage(format!(
                                            "remove expired key material: {e}"
                                        ))
                                    })?;
                                }
                            }
                            tracing::info!("Removed expired key");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Metadata-only key listing for a key id (`ksk`/`zsk`/standbys).
    /// Never includes private material.
    pub fn key_info(&self, key_id: &str) -> Result<serde_json::Value, KeystoreError> {
        let key_dir = self.key_path.join(key_id);
        if !key_dir.exists() {
            return Err(KeystoreError::NotFound(format!(
                "key directory not found: {}",
                key_dir.display()
            )));
        }
        let mut keys = Vec::new();
        let entries = std::fs::read_dir(&key_dir)
            .map_err(|e| KeystoreError::Storage(format!("read key directory: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| KeystoreError::Storage(format!("read entry: {e}")))?;
            let path = entry.path();
            if path.is_file() && path.extension().map(|e| e == "key").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| KeystoreError::Storage(format!("read key file: {e}")))?;
                if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&content) {
                    keys.push(meta);
                }
            }
        }
        if keys.is_empty() {
            return Err(KeystoreError::NotFound(format!(
                "no keys found for: {key_id}"
            )));
        }
        Ok(serde_json::json!({ "key_type": key_id, "keys": keys }))
    }

    /// Explicit public-only backup/export. The output contains key
    /// identifiers, algorithms, tags, and lifetimes — never private bytes.
    /// Documented backup semantics: back up the sealed `{key_path}` directory
    /// with `0600` preserved; restore by restoring the directory then
    /// [`DnssecKeystore::load_keys_from_disk`].
    pub fn export_public_keys_to_file(&self, file_path: &str) -> Result<(), KeystoreError> {
        let keys = self.active_keys_public()?;
        let export_data = serde_json::json!({
            "timestamp_secs": now_secs(),
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
        let bytes = serde_json::to_vec_pretty(&export_data)
            .map_err(|e| KeystoreError::Storage(format!("encode export: {e}")))?;
        atomic_write(Path::new(file_path), &bytes, 0o600)?;
        tracing::info!("Exported DNSSEC public key metadata");
        Ok(())
    }

    /// Shared rotation-task helper for composition roots. Spawns a Tokio
    /// task that periodically calls [`DnssecKeystore::check_and_rotate`].
    /// The keystore must be shared via `Arc<RwLock<..>>` by the caller.
    pub fn spawn_rotation_task(keystore: Arc<RwLock<DnssecKeystore>>, interval_secs: u64) {
        let rotation_interval = std::time::Duration::from_secs(interval_secs);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(rotation_interval);
            loop {
                interval.tick().await;
                let mut guard = keystore.write();
                match guard.check_and_rotate(KeyRotationConfig::default()) {
                    Ok(result) if result.ksk_rotated || result.zsk_rotated => {
                        tracing::info!("DNSSEC key rotation completed");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::error!("DNSSEC key rotation check failed: {e}"),
                }
            }
        });
        tracing::info!("DNSSEC key rotation task started");
    }
}

// -- Secure storage helpers (Part D) ----------------------------------------

/// Restrict a key directory to owner-only access on Unix. Best-effort on
/// other platforms (no silent private-key exposure: files are still 0600
/// where the platform supports it via the platform crate at a higher layer).
fn secure_dir(dir: &Path) -> Result<(), KeystoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir, perms)
            .map_err(|e| KeystoreError::Storage(format!("secure key directory: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Atomic write: temp file in the same directory + fsync + rename, so a
/// crash never leaves a half-written key file. Mode is applied to the temp
/// file before rename on Unix.
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), KeystoreError> {
    let parent = path.parent().ok_or_else(|| {
        KeystoreError::Storage(format!("key path has no parent: {}", path.display()))
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|e| KeystoreError::Storage(format!("create parent: {e}")))?;
    static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ctr = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut rand_suffix = [0u8; 8];
    getrandom::getrandom(&mut rand_suffix)
        .map_err(|e| KeystoreError::Storage(format!("entropy for temp name: {e}")))?;
    let tmp = parent.join(format!(
        ".tmp-{}-{}-{}-{}",
        std::process::id(),
        now_secs() % 1_000_000,
        ctr,
        hex_suffix(&rand_suffix),
    ));
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .map_err(|e| KeystoreError::Storage(format!("write temp key file: {e}")))?;
        file.write_all(bytes)
            .map_err(|e| KeystoreError::Storage(format!("write temp key file: {e}")))?;
        file.sync_all()
            .map_err(|e| KeystoreError::Storage(format!("fsync temp key file: {e}")))?;
        drop(file);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        std::fs::write(&tmp, bytes)
            .map_err(|e| KeystoreError::Storage(format!("write temp key file: {e}")))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| KeystoreError::Storage(format!("atomic rename key file: {e}")))?;
    Ok(())
}

fn hex_suffix(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Private-key atomic write, always `0600` on Unix regardless of umask.
fn atomic_write_private(path: &Path, private_bytes: &[u8]) -> Result<(), KeystoreError> {
    atomic_write(path, private_bytes, 0o600)
}

/// Fail-closed permission check on load: a private key file that is
/// group/world-readable is refused rather than silently used.
fn check_private_permissions(path: &Path) -> Result<(), KeystoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| KeystoreError::Storage(format!("stat private key: {e}")))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeystoreError::Storage(format!(
                "private key file has overly permissive mode {:o}; refusing to load {}",
                mode,
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        tempfile::Builder::new()
            .prefix("dnssec_keystore_test_")
            .tempdir()
            .unwrap()
            .keep()
    }

    #[test]
    fn initialize_creates_secure_dirs() {
        let dir = temp_dir();
        // Use a fresh subdir so initialize() actually creates it.
        let root = dir.join("ks");
        let mut ks = DnssecKeystore::new(root.clone());
        ks.initialize().unwrap();
        assert!(root.join("ksk").exists());
        assert!(root.join("zsk").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generate_ed25519_ksk_and_zsk() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        let ksk = ks
            .generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        assert_eq!(ksk.algorithm, Algorithm::Ed25519);
        assert_eq!(ksk.flags, 257);
        assert_eq!(ksk.public_key.len(), 32);
        assert!(ksk.key_tag > 0);
        let zsk = ks
            .generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();
        assert_eq!(zsk.flags, 256);
        // Private material exists behind the handle but is not in metadata.
        assert!(ks.active_ksk().unwrap().has_private());
        assert!(ks.active_zsk().unwrap().has_private());
        let serialized = serde_json::to_string(&ksk).unwrap();
        assert!(!serialized.contains("private"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn private_files_are_0600_and_atomic() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        let ksk_dir = dir.join("ksk");
        let privs: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|x| x == "priv").unwrap_or(false))
            .collect();
        assert!(!privs.is_empty());
        // No temp files left behind after atomic rename.
        let tmps: Vec<_> = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with(".tmp-"))
                    .unwrap_or(false)
            })
            .collect();
        assert!(tmps.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(privs[0].path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn overly_permissive_private_file_refused() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        let ksk_dir = dir.join("ksk");
        let priv_path = std::fs::read_dir(&ksk_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().map(|x| x == "priv").unwrap_or(false))
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut ks2 = DnssecKeystore::new(dir.clone());
            let err = ks2.load_keys_from_disk().unwrap_err();
            assert!(err.to_string().contains("overly permissive"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sign_roundtrip_ed25519_known_answer() {
        use ed25519_dalek::Verifier;
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();
        let zsk = ks.active_zsk().unwrap();
        let msg = b"canonical rrset bytes";
        let sig = zsk.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);
        // Verify against the public half (known-answer shape).
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(zsk.public_key()[..32].try_into().unwrap())
                .unwrap();
        vk.verify(
            msg,
            &ed25519_dalek::Signature::from_bytes(&sig[..64].try_into().unwrap()),
        )
        .unwrap();
        // Keystore-level entry point agrees.
        let sig2 = ks.sign_canonical(msg, KeyType::ZSK).unwrap();
        vk.verify(
            msg,
            &ed25519_dalek::Signature::from_bytes(&sig2[..64].try_into().unwrap()),
        )
        .unwrap();
        // Deterministic for Ed25519.
        assert_eq!(sig, sig2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rsa_generate_sign_verify_roundtrip() {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        use rsa::traits::PublicKeyParts;
        use sha2::Sha256;
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::RSA, KeyType::ZSK, 2048, 90)
            .unwrap();
        let zsk = ks.active_zsk().unwrap();
        assert_eq!(zsk.key_size(), Some(2048));
        let msg = b"canonical rsa rrset";
        let sig = zsk.sign(msg).unwrap();
        assert!(!sig.is_empty());
        // Rebuild the public key from DNSKEY wire encoding and verify.
        let pub_wire = zsk.public_key();
        let e_len = pub_wire[0] as usize;
        let e = rsa::BigUint::from_bytes_be(&pub_wire[1..1 + e_len]);
        let n = rsa::BigUint::from_bytes_be(&pub_wire[1 + e_len..]);
        let pub_key = rsa::RsaPublicKey::new(n, e).unwrap();
        let _ = pub_key.n();
        VerifyingKey::<Sha256>::new(pub_key)
            .verify(msg, &Signature::try_from(sig.as_slice()).unwrap())
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rsa_1024_auto_upgrades_and_bad_size_rejected() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        let meta = ks
            .generate_key(Algorithm::RSA, KeyType::KSK, 1024, 365)
            .unwrap();
        assert_eq!(meta.key_size, Some(2048));
        assert!(ks
            .generate_key(Algorithm::RSA, KeyType::ZSK, 3072, 90)
            .is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rollover_lifecycle() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        let before = ks.active_ksk().unwrap().key_tag();
        ks.start_key_rollover(KeyType::KSK).unwrap();
        assert!(ks.rollover_status()["ksk_in_rollover"] == true);
        // DNSKEY publication includes the standby during rollover.
        assert_eq!(ks.public_dnskeys().len(), 2); // KSK + standby KSK (no ZSK yet)
        ks.complete_key_rollover(KeyType::KSK).unwrap();
        assert!(!ks.rollover_status()["ksk_in_rollover"].as_bool().unwrap());
        assert_ne!(ks.active_ksk().unwrap().key_tag(), before);
        assert!(ks.complete_key_rollover(KeyType::KSK).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_is_public_only() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::ZSK, 0, 90)
            .unwrap();
        let out = dir.join("export.json");
        ks.export_public_keys_to_file(out.to_str().unwrap())
            .unwrap();
        let content = std::fs::read_to_string(&out).unwrap();
        assert!(!content.to_lowercase().contains("private"));
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["keys"].as_array().unwrap().len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_snapshot_is_public_only() {
        let dir = temp_dir();
        let mut ks = DnssecKeystore::new(dir.clone());
        ks.initialize().unwrap();
        ks.generate_key(Algorithm::Ed25519, KeyType::KSK, 0, 365)
            .unwrap();
        let status = ks.key_status().unwrap();
        assert!(status.ksk.is_some());
        let serialized = serde_json::to_string(&status).unwrap();
        assert!(!serialized.to_lowercase().contains("private"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
