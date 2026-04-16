use parking_lot::RwLock;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// RFC 5011 Trust Anchor States
///
/// RFC 5011 defines a state machine for trust anchor management:
/// - Keys start as Unknown (never observed)
/// - When first seen in DNSKEY RRset: Unknown -> Seen
/// - When validated via CDS/CDNSKEY: Seen -> Pending (30-day observation)
/// - After observation period: Pending -> Valid (trusted)
/// - When REVOKE bit observed: Valid -> Revoked
/// - After 30-day absence: Revoked -> Removed
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum TrustAnchorState {
    /// Key is fully trusted and actively used for validation
    Valid,
    /// Key observed in DNSKEY RRset but not yet validated via CDS/CDNSKEY (RFC 5011 Section 3)
    Seen,
    /// Key validated via CDS/CDNSKEY, awaiting 30-day observation period (RFC 5011 Section 3.2)
    Pending,
    /// Key has REVOKE bit set (RFC 5011 Section 4)
    Revoked,
    /// Key was removed from zone, waiting for confirmation period
    Removed,
    /// Key was configured but never observed
    Missing,
}

impl TrustAnchorState {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustAnchorState::Valid => "Valid",
            TrustAnchorState::Seen => "Seen",
            TrustAnchorState::Pending => "Pending",
            TrustAnchorState::Revoked => "Revoked",
            TrustAnchorState::Removed => "Removed",
            TrustAnchorState::Missing => "Missing",
        }
    }

    pub fn from_state_str(s: &str) -> Option<Self> {
        match s {
            "Valid" => Some(TrustAnchorState::Valid),
            "Seen" => Some(TrustAnchorState::Seen),
            "Pending" => Some(TrustAnchorState::Pending),
            "Revoked" => Some(TrustAnchorState::Revoked),
            "Removed" => Some(TrustAnchorState::Removed),
            "Missing" => Some(TrustAnchorState::Missing),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct TrustAnchor {
    pub key_id: String,
    pub key_tag: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub state: TrustAnchorState,
    pub added_at: u64,
    pub last_seen: u64,
    pub trust_point: u64,
    pub first_seen_at: Option<u64>,
    pub pending_since: Option<u64>,
    pub revoked_at: Option<u64>,
    pub removed_at: Option<u64>,
}

impl TrustAnchor {
    pub fn new(key_id: String, key_tag: u16, algorithm: u8, public_key: Vec<u8>) -> Self {
        let now = crate::utils::safe_unix_timestamp();

        Self {
            key_id,
            key_tag,
            algorithm,
            public_key,
            state: TrustAnchorState::Valid,
            added_at: now,
            last_seen: now,
            trust_point: now,
            first_seen_at: None,
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        }
    }

    pub fn from_initial(key_id: String, key_tag: u16, algorithm: u8, public_key: Vec<u8>) -> Self {
        let now = crate::utils::safe_unix_timestamp();

        Self {
            key_id,
            key_tag,
            algorithm,
            public_key,
            state: TrustAnchorState::Valid,
            added_at: now,
            last_seen: now,
            trust_point: now,
            first_seen_at: Some(now),
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        }
    }

    pub fn is_expired(&self, max_age_days: u64) -> bool {
        let now = crate::utils::safe_unix_timestamp();

        let max_age_secs = max_age_days * 86400;
        now.saturating_sub(self.last_seen) > max_age_secs
    }

    pub fn refresh(&mut self) {
        let now = crate::utils::safe_unix_timestamp();
        self.last_seen = now;
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self.state, TrustAnchorState::Valid)
    }

    pub fn generate_key_id(key_tag: u16, algorithm: u8) -> String {
        format!("{}-{}", key_tag, algorithm)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive, RkyvSerialize, RkyvDeserialize)]
pub struct TrustAnchorConfig {
    pub enabled: bool,
    pub db_path: String,
    pub anchor_file_path: String,
    pub refresh_interval_secs: u64,
    pub pending_observation_days: u64,
    pub revocation_grace_days: u64,
    pub extended_removal_days: u64,
    pub trust_anchor_retention_days: u64,
    pub allow_key_rotation: bool,
}

impl Default for TrustAnchorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            db_path: "/var/lib/maluwaf/dns/trust_anchors.db".to_string(),
            anchor_file_path: "/var/lib/maluwaf/dns/trusted-key.key".to_string(),
            refresh_interval_secs: 3600,
            pending_observation_days: 30,
            revocation_grace_days: 30,
            extended_removal_days: 60,
            trust_anchor_retention_days: 7,
            allow_key_rotation: true,
        }
    }
}

pub struct TrustAnchorManager {
    config: TrustAnchorConfig,
    anchors: RwLock<HashMap<String, TrustAnchor>>,
    pending_keys: RwLock<HashMap<String, TrustAnchor>>,
    last_refresh: RwLock<u64>,
    db_path: String,
}

#[derive(Debug, Clone)]
pub struct TrustAnchorStatus {
    pub total_anchors: usize,
    pub valid_anchors: usize,
    pub revoked_anchors: usize,
    pub pending_anchors: usize,
}

impl TrustAnchorManager {
    pub fn new(config: TrustAnchorConfig) -> Self {
        Self {
            config: config.clone(),
            anchors: RwLock::new(HashMap::new()),
            pending_keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(0),
            db_path: config.db_path.clone(),
        }
    }

    pub fn add_anchor(
        &self,
        key_id: String,
        key_tag: u16,
        algorithm: u8,
        public_key: Vec<u8>,
    ) -> Result<(), String> {
        let mut anchors = self.anchors.write();

        if anchors.contains_key(&key_id) {
            return Err(format!("Anchor {} already exists", key_id));
        }

        let anchor = TrustAnchor::new(key_id.clone(), key_tag, algorithm, public_key);
        anchors.insert(key_id, anchor);

        self.save_anchors(&anchors)?;

        Ok(())
    }

    pub fn remove_anchor(&self, key_id: &str) -> Result<(), String> {
        let mut anchors = self.anchors.write();

        if let Some(anchor) = anchors.get_mut(key_id) {
            anchor.state = TrustAnchorState::Revoked;
        } else {
            return Err(format!("Anchor {} not found", key_id));
        }

        self.save_anchors(&anchors)?;

        Ok(())
    }

    pub fn get_anchors(&self) -> Vec<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors
            .values()
            .filter(|a| a.state == TrustAnchorState::Valid)
            .cloned()
            .collect()
    }

    pub fn get_anchor_by_keytag(&self, key_tag: u16) -> Option<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors
            .values()
            .find(|a| a.key_tag == key_tag && a.state == TrustAnchorState::Valid)
            .cloned()
    }

    pub fn get_anchor_by_key_id(&self, key_id: &str) -> Option<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors.get(key_id).cloned()
    }

    fn init_db(&self) -> Result<Connection, String> {
        if let Some(parent) = Path::new(&self.db_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        let conn = Connection::open(&self.db_path)
            .map_err(|e| format!("Failed to open database: {}", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS trust_anchors (
                key_id TEXT PRIMARY KEY,
                key_tag INTEGER NOT NULL,
                algorithm INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                state TEXT NOT NULL,
                added_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                trust_point INTEGER NOT NULL,
                first_seen_at INTEGER,
                pending_since INTEGER,
                revoked_at INTEGER,
                removed_at INTEGER
            )",
            [],
        )
        .map_err(|e| format!("Failed to create table: {}", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_key_tag ON trust_anchors(key_tag)",
            [],
        )
        .map_err(|e| format!("Failed to create index: {}", e))?;

        Ok(conn)
    }

    pub fn save_anchors(&self, anchors: &HashMap<String, TrustAnchor>) -> Result<(), String> {
        let mut conn = self.init_db()?;

        let tx = conn
            .transaction()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        tx.execute("DELETE FROM trust_anchors", [])
            .map_err(|e| format!("Failed to delete old anchors: {}", e))?;

        for anchor in anchors.values() {
            if !self.config.allow_key_rotation && anchor.state == TrustAnchorState::Removed {
                continue;
            }

            tx.execute(
                "INSERT OR REPLACE INTO trust_anchors 
                (key_id, key_tag, algorithm, public_key, state, added_at, last_seen, trust_point, 
                first_seen_at, pending_since, revoked_at, removed_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    anchor.key_id,
                    anchor.key_tag,
                    anchor.algorithm,
                    anchor.public_key,
                    anchor.state.as_str(),
                    anchor.added_at,
                    anchor.last_seen,
                    anchor.trust_point,
                    anchor.first_seen_at,
                    anchor.pending_since,
                    anchor.revoked_at,
                    anchor.removed_at,
                ],
            )
            .map_err(|e| format!("Failed to insert anchor: {}", e))?;
        }

        tx.commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        Ok(())
    }

    pub fn load_anchors(&self) -> Result<(), String> {
        let conn = match self.init_db() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to initialize database: {}", e);
                return Ok(());
            }
        };

        let mut stmt = conn
            .prepare("SELECT key_id, key_tag, algorithm, public_key, state, added_at, last_seen, trust_point, first_seen_at, pending_since, revoked_at, removed_at FROM trust_anchors")
            .map_err(|e| format!("Failed to prepare statement: {}", e))?;

        let anchor_iter = stmt
            .query_map([], |row| {
                let state_str: String = row.get(4)?;
                let state = TrustAnchorState::from_state_str(&state_str)
                    .unwrap_or(TrustAnchorState::Missing);

                Ok(TrustAnchor {
                    key_id: row.get(0)?,
                    key_tag: row.get(1)?,
                    algorithm: row.get(2)?,
                    public_key: row.get(3)?,
                    state,
                    added_at: row.get(5)?,
                    last_seen: row.get(6)?,
                    trust_point: row.get(7)?,
                    first_seen_at: row.get(8)?,
                    pending_since: row.get(9)?,
                    revoked_at: row.get(10)?,
                    removed_at: row.get(11)?,
                })
            })
            .map_err(|e| format!("Failed to query anchors: {}", e))?;

        let mut anchors = self.anchors.write();
        for anchor in anchor_iter.flatten() {
            anchors.insert(anchor.key_id.clone(), anchor);
        }

        Ok(())
    }

    pub fn get_status(&self) -> TrustAnchorStatus {
        let anchors = self.anchors.read();

        TrustAnchorStatus {
            total_anchors: anchors.len(),
            valid_anchors: anchors
                .values()
                .filter(|a| a.state == TrustAnchorState::Valid)
                .count(),
            revoked_anchors: anchors
                .values()
                .filter(|a| a.state == TrustAnchorState::Revoked)
                .count(),
            pending_anchors: self.pending_keys.read().len(),
        }
    }

    pub fn observe_dnskey_at_root(
        &self,
        key_tag: u16,
        algorithm: u8,
        public_key: &[u8],
        is_revoked: bool,
    ) -> Rfc5011Event {
        // RFC 5011 §2.2: Reject deprecated algorithms
        // 0 = DELETE, 3 = DSA, 5 = RSASHA1, 6 = DSA-NSEC3-SHA1
        // Only support algorithms 8 (RSASHA256), 13 (ECDSAP256SHA256),
        // 14 (ECDSAP384SHA384), 15 (ED25519), 16 (ED448)
        if matches!(algorithm, 0 | 3 | 5 | 6) {
            tracing::warn!(
                "RFC 5011: Key {} uses deprecated algorithm {}, rejecting",
                key_tag,
                algorithm
            );
            return Rfc5011Event::KeyIgnored {
                key_tag,
                reason: format!("deprecated algorithm {}", algorithm),
            };
        }

        let mut anchors = self.anchors.write();
        let now = crate::utils::safe_unix_timestamp();

        let key_id = TrustAnchor::generate_key_id(key_tag, algorithm);

        if let Some(anchor) = anchors.get_mut(&key_id) {
            if anchor.public_key != public_key.to_vec() {
                tracing::warn!("RFC 5011: Key {} public key mismatch - ignoring", key_tag);
                return Rfc5011Event::KeyIgnored {
                    key_tag,
                    reason: "public key mismatch".to_string(),
                };
            }

            anchor.last_seen = now;

            if is_revoked {
                if anchor.state != TrustAnchorState::Revoked {
                    anchor.state = TrustAnchorState::Revoked;
                    anchor.revoked_at = Some(now);
                    tracing::info!("RFC 5011: Key {} revoked", key_tag);
                    return Rfc5011Event::KeyRevoked { key_tag };
                }
            } else if anchor.state == TrustAnchorState::Revoked {
                anchor.removed_at = Some(now);
                return Rfc5011Event::KeyRemoved { key_tag };
            } else if anchor.state == TrustAnchorState::Missing {
                anchor.state = TrustAnchorState::Pending;
                anchor.pending_since = Some(now);
                anchor.first_seen_at = Some(now);
                tracing::info!(
                    "RFC 5011: Key {} reappeared, entering Pending state",
                    key_tag
                );
                return Rfc5011Event::KeyPending { key_tag };
            }
            return Rfc5011Event::KeySeen { key_tag };
        }

        if is_revoked {
            return Rfc5011Event::KeyIgnored {
                key_tag,
                reason: "unknown revoked key".to_string(),
            };
        }

        let anchor = TrustAnchor {
            key_id: key_id.clone(),
            key_tag,
            algorithm,
            public_key: public_key.to_vec(),
            state: TrustAnchorState::Seen,
            added_at: now,
            last_seen: now,
            trust_point: 0,
            first_seen_at: Some(now),
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        };

        tracing::info!("RFC 5011: New key {} observed (Seen state)", key_tag);
        anchors.insert(key_id, anchor);

        Rfc5011Event::NewKeySeen { key_tag }
    }

    pub fn trust_anchor_check(
        &self,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &[u8],
        current_dnskey_keytags: Option<&[u16]>,
    ) -> Rfc5011Event {
        let mut anchors = self.anchors.write();
        let now = crate::utils::safe_unix_timestamp();

        let key_id = TrustAnchor::generate_key_id(key_tag, algorithm);

        if let Some(anchor) = anchors.get_mut(&key_id) {
            match anchor.state {
                TrustAnchorState::Seen => {
                    let computed_digest = match crate::dns::dnssec::compute_ds_digest(
                        digest_type,
                        257,
                        3,
                        algorithm,
                        &anchor.public_key,
                    ) {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!(
                                "RFC 5011: Failed to compute digest for key {}: {}",
                                key_tag,
                                e
                            );
                            return Rfc5011Event::KeyIgnored {
                                key_tag,
                                reason: format!("digest computation failed: {}", e),
                            };
                        }
                    };

                    if computed_digest != digest {
                        tracing::warn!(
                            "RFC 5011: Digest mismatch for key {} (expected: {}, computed: {})",
                            key_tag,
                            hex::encode(digest),
                            hex::encode(&computed_digest)
                        );
                        return Rfc5011Event::KeyIgnored {
                            key_tag,
                            reason: "digest mismatch".to_string(),
                        };
                    }

                    anchor.state = TrustAnchorState::Pending;
                    anchor.pending_since = Some(now);
                    tracing::info!(
                        "RFC 5011: Key {} passed trust anchor check, entering Pending state ({} seconds observation)",
                        key_tag,
                        self.config.pending_observation_days * 86400
                    );
                    Rfc5011Event::KeyPending { key_tag }
                }
                TrustAnchorState::Pending => {
                    let pending_secs = now.saturating_sub(anchor.pending_since.unwrap_or(now));
                    let required_secs = self.config.pending_observation_days * 86400;

                    if pending_secs >= required_secs {
                        if let Some(keytags) = current_dnskey_keytags {
                            if !keytags.contains(&key_tag) {
                                tracing::warn!(
                                    "RFC 5011: Key {} no longer in DNSKEY RRset, not promoting to Valid",
                                    key_tag
                                );
                                return Rfc5011Event::KeyWaiting {
                                    key_tag,
                                    remaining_secs: 0,
                                };
                            }
                        }
                        anchor.state = TrustAnchorState::Valid;
                        anchor.trust_point = now;
                        tracing::info!("RFC 5011: Key {} promoted to Valid", key_tag);
                        Rfc5011Event::KeyPromoted { key_tag }
                    } else {
                        let remaining_secs = required_secs - pending_secs;
                        tracing::debug!(
                            "RFC 5011: Key {} still in Pending ({} seconds remaining)",
                            key_tag,
                            remaining_secs
                        );
                        Rfc5011Event::KeyWaiting {
                            key_tag,
                            remaining_secs,
                        }
                    }
                }
                TrustAnchorState::Valid => Rfc5011Event::KeySeen { key_tag },
                TrustAnchorState::Revoked => Rfc5011Event::KeyRevoked { key_tag },
                TrustAnchorState::Removed => Rfc5011Event::KeyRemoved { key_tag },
                TrustAnchorState::Missing => {
                    anchor.state = TrustAnchorState::Pending;
                    anchor.pending_since = Some(now);
                    anchor.first_seen_at = Some(now);
                    Rfc5011Event::KeyPending { key_tag }
                }
            }
        } else {
            Rfc5011Event::KeyIgnored {
                key_tag,
                reason: "key not found".to_string(),
            }
        }
    }

    pub fn process_rfc5011_updates(&self) -> Vec<Rfc5011Event> {
        let mut events = Vec::new();
        let now = crate::utils::safe_unix_timestamp();

        let mut anchors = self.anchors.write();
        let mut keys_to_remove = Vec::new();

        for (key_id, anchor) in anchors.iter_mut() {
            match anchor.state {
                TrustAnchorState::Pending => {
                    if let Some(pending_since) = anchor.pending_since {
                        let pending_secs = now.saturating_sub(pending_since);
                        let required_secs = self.config.pending_observation_days * 86400;

                        if pending_secs >= required_secs {
                            anchor.state = TrustAnchorState::Valid;
                            anchor.trust_point = now;
                            tracing::info!(
                                "RFC 5011: Key {} promoted to Valid (observation period complete)",
                                anchor.key_tag
                            );
                            events.push(Rfc5011Event::KeyPromoted {
                                key_tag: anchor.key_tag,
                            });
                        }
                    }
                }
                TrustAnchorState::Revoked => {
                    if let Some(revoked_at) = anchor.revoked_at {
                        let revoked_secs = now.saturating_sub(revoked_at);
                        let removal_secs = self.config.revocation_grace_days * 86400;

                        if revoked_secs >= removal_secs {
                            anchor.state = TrustAnchorState::Removed;
                            tracing::info!(
                                "RFC 5011: Key {} removed after revocation grace period",
                                anchor.key_tag
                            );
                            events.push(Rfc5011Event::KeyRemoved {
                                key_tag: anchor.key_tag,
                            });
                        }
                    }
                }
                TrustAnchorState::Removed => {
                    if let Some(removed_at) = anchor.removed_at {
                        let removed_secs = now.saturating_sub(removed_at);
                        let purge_secs = self.config.extended_removal_days * 86400;

                        if removed_secs >= purge_secs {
                            let key_tag = anchor.key_tag;
                            keys_to_remove.push(key_id.clone());
                            events.push(Rfc5011Event::KeyPurged { key_tag });
                            tracing::info!(
                                "RFC 5011: Key {} purged from storage after extended removal period",
                                key_tag
                            );
                        }
                    }
                }
                TrustAnchorState::Valid => {
                    if anchor.is_expired(self.config.trust_anchor_retention_days) {
                        anchor.state = TrustAnchorState::Missing;
                        tracing::warn!(
                            "RFC 5011: Key {} expired (not seen for {} days)",
                            anchor.key_tag,
                            self.config.trust_anchor_retention_days
                        );
                        events.push(Rfc5011Event::KeyMissing {
                            key_tag: anchor.key_tag,
                        });
                    }
                }
                _ => {}
            }
        }

        for key_id in keys_to_remove {
            anchors.remove(&key_id);
        }

        if !events.is_empty() || !anchors.is_empty() {
            if let Err(e) = self.save_anchors(&anchors) {
                tracing::error!("Failed to save trust anchors: {}", e);
            }
        }

        events
    }

    pub fn get_trusted_anchors(&self) -> Vec<TrustAnchor> {
        let anchors = self.anchors.read();
        anchors
            .values()
            .filter(|a| a.is_trusted())
            .cloned()
            .collect()
    }

    pub fn load_initial_anchors_from_file(&self, path: &str) -> Result<usize, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read anchor file: {}", e))?;

        let mut count = 0;
        let now = crate::utils::safe_unix_timestamp();

        let mut anchors = self.anchors.write();

        let combined_content = content.replace('\n', " ");
        let records = Self::parse_all_dnskey_records(&combined_content);

        for (key_tag, algorithm, public_key) in records {
            let key_id = TrustAnchor::generate_key_id(key_tag, algorithm);

            if !anchors.contains_key(&key_id) {
                let anchor = TrustAnchor {
                    key_id,
                    key_tag,
                    algorithm,
                    public_key,
                    state: TrustAnchorState::Valid,
                    added_at: now,
                    last_seen: now,
                    trust_point: now,
                    first_seen_at: Some(now),
                    pending_since: None,
                    revoked_at: None,
                    removed_at: None,
                };
                tracing::info!(
                    "Loaded initial trust anchor: key_tag={}, algorithm={}",
                    key_tag,
                    algorithm
                );
                anchors.insert(anchor.key_id.clone(), anchor);
                count += 1;
            }
        }

        if count > 0 {
            self.save_anchors(&anchors)?;
        }

        Ok(count)
    }

    fn parse_all_dnskey_records(content: &str) -> Vec<(u16, u8, Vec<u8>)> {
        let mut results = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || !trimmed.contains("DNSKEY") {
                continue;
            }

            if let Some(record) = Self::parse_dnskey_record_line(trimmed) {
                results.push(record);
            }
        }

        results
    }

    fn parse_dnskey_record_line(line: &str) -> Option<(u16, u8, Vec<u8>)> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            return None;
        }

        let flags: u16 = parts.get(2)?.parse().ok()?;
        let protocol: u8 = parts.get(3)?.parse().ok()?;
        let algorithm: u8 = parts.get(4)?.parse().ok()?;

        if flags != 257 || protocol != 3 {
            return None;
        }

        let key_data = if let Some(idx) = line.find('(') {
            let rest = &line[idx..];
            rest.chars()
                .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
                .collect::<String>()
        } else {
            parts.get(5)?.to_string()
        };

        let public_key =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key_data).ok()?;

        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, algorithm, &public_key);

        Some((key_tag, algorithm, public_key))
    }

    pub fn needs_refresh(&self) -> bool {
        let now = crate::utils::safe_unix_timestamp();

        let last = *self.last_refresh.read();

        now.saturating_sub(last) >= self.config.refresh_interval_secs
    }

    pub fn mark_refreshed(&self) {
        let now = crate::utils::safe_unix_timestamp();

        *self.last_refresh.write() = now;
    }

    pub fn check_for_revoked_keys(&self, revoked_key_tags: &[u16]) -> Vec<u16> {
        let mut anchors = self.anchors.write();
        let mut revoked = Vec::new();

        for key_tag in revoked_key_tags {
            if let Some(anchor) = anchors.values_mut().find(|a| a.key_tag == *key_tag) {
                anchor.state = TrustAnchorState::Revoked;
                anchor.revoked_at = Some(crate::utils::safe_unix_timestamp());
                tracing::info!(
                    "RFC 5011: Key {} marked as revoked via check_for_revoked_keys",
                    key_tag
                );
                revoked.push(*key_tag);
            }
        }

        if !revoked.is_empty() {
            let _ = self.save_anchors(&anchors);
        }

        revoked
    }
}

#[derive(Debug, Clone)]
pub enum Rfc5011Event {
    NewKeySeen { key_tag: u16 },
    KeySeen { key_tag: u16 },
    KeyPending { key_tag: u16 },
    KeyWaiting { key_tag: u16, remaining_secs: u64 },
    KeyPromoted { key_tag: u16 },
    KeyRevoked { key_tag: u16 },
    KeyRemoved { key_tag: u16 },
    KeyPurged { key_tag: u16 },
    KeyMissing { key_tag: u16 },
    KeyIgnored { key_tag: u16, reason: String },
}

pub struct TrustAnchorManagerFactory;

impl TrustAnchorManagerFactory {
    pub fn create(config: TrustAnchorConfig) -> Option<Arc<TrustAnchorManager>> {
        if !config.enabled {
            return None;
        }

        let manager = Arc::new(TrustAnchorManager::new(config));

        if let Err(e) = manager.load_anchors() {
            tracing::warn!("Failed to load trust anchors: {}", e);
        }

        Some(manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_id_generation() {
        let key_id = TrustAnchor::generate_key_id(20326, 8);
        assert_eq!(key_id, "20326-8");
    }

    #[test]
    fn test_trust_anchor_creation() {
        let anchor = TrustAnchor::new("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);

        assert_eq!(anchor.key_tag, 12345);
        assert_eq!(anchor.state, TrustAnchorState::Valid);
        assert!(anchor.is_trusted());
    }

    #[test]
    fn test_key_tag_calculation() {
        let public_key = vec![
            0x04, 0x8F, 0xF1, 0xBE, 0x04, 0x1F, 0x9E, 0x4A, 0x22, 0xD5, 0x6E, 0xE8, 0x0A, 0x5C,
            0x9D, 0xE5, 0x80, 0xF8, 0x64, 0x97, 0xD7, 0xF3, 0xBF, 0x1C, 0x9C, 0x7E, 0x2B, 0x8F,
            0xE3, 0x1E, 0x8C, 0x9C, 0xB5, 0x6E, 0xF8, 0x0C, 0xF8, 0x0E, 0xC7, 0x89, 0x2C, 0x3E,
            0xD3, 0x65, 0x4F, 0x5E, 0x70, 0x7F, 0x1E, 0x4D, 0x8E, 0x4A, 0x7B, 0x8A, 0x03, 0x8A,
            0x6D, 0xD0, 0x7F, 0x9E, 0xF1, 0xC4, 0x6A, 0x1C, 0x9C, 0x5E, 0x4B, 0x3D, 0x8D, 0xF7,
            0x6E, 0x0D, 0x5A, 0x8E, 0x4F, 0x3D, 0xAA, 0xB5, 0xA8, 0x5E, 0x0B, 0x1F, 0xC2, 0x9B,
            0xE1, 0xE5, 0x8E, 0x5B, 0x6B, 0x7F, 0xA6, 0xE8, 0xE0, 0xF9, 0x89, 0x5D,
        ];

        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);
        assert_eq!(key_tag, 51192);
    }

    #[test]
    fn test_key_tag_calculation_iana_ksk() {
        let public_key = vec![
            0x03, 0x01, 0x00, 0x01, 0xAC, 0xFF, 0xB4, 0x09, 0xBC, 0xC9, 0x39, 0xF8, 0x31, 0xF7,
            0xA1, 0xE5, 0xEC, 0x88, 0xF7, 0xA5, 0x92, 0x55, 0xEC, 0x53, 0x04, 0x0B, 0xE4, 0x32,
            0x02, 0x73, 0x90, 0xA4, 0xCE, 0x89, 0x6D, 0x6F, 0x90, 0x86, 0xF3, 0xC5, 0xE1, 0x77,
            0xFB, 0xFE, 0x11, 0x81, 0x63, 0xAA, 0xEC, 0x7A, 0xF1, 0x46, 0x2C, 0x47, 0x94, 0x59,
            0x44, 0xC4, 0xE2, 0xC0, 0x26, 0xBE, 0x5E, 0x98, 0xBB, 0xCD, 0xED, 0x25, 0x97, 0x82,
            0x72, 0xE1, 0xE3, 0xE0, 0x79, 0xC5, 0x09, 0x4D, 0x57, 0x3F, 0x0E, 0x83, 0xC9, 0x2F,
            0x02, 0xB3, 0x2D, 0x35, 0x13, 0xB1, 0x55, 0x0B, 0x82, 0x69, 0x29, 0xC8, 0x0D, 0xD0,
            0xF9, 0x2C, 0xAC, 0x96, 0x6D, 0x17, 0x76, 0x9F, 0xD5, 0x86, 0x7B, 0x64, 0x7C, 0x3F,
            0x38, 0x02, 0x9A, 0xBD, 0xC4, 0x81, 0x52, 0xEB, 0x8F, 0x20, 0x71, 0x59, 0xEC, 0xC5,
            0xD2, 0x32, 0xC7, 0xC1, 0x53, 0x7C, 0x79, 0xF4, 0xB7, 0xAC, 0x28, 0xFF, 0x11, 0x68,
            0x2F, 0x21, 0x68, 0x1B, 0xF6, 0xD6, 0xAB, 0xA5, 0x55, 0x03, 0x2B, 0xF6, 0xF9, 0xF0,
            0x36, 0xBE, 0xB2, 0xAA, 0xA5, 0xB3, 0x77, 0x8D, 0x6E, 0xEB, 0xFB, 0xA6, 0xBF, 0x9E,
            0xA1, 0x91, 0xBE, 0x4A, 0xB0, 0xCA, 0xEA, 0x75, 0x9E, 0x2F, 0x77, 0x3A, 0x1F, 0x90,
            0x29, 0xC7, 0x3E, 0xCB, 0x8D, 0x57, 0x35, 0xB9, 0x32, 0x1D, 0xB0, 0x85, 0xF1, 0xB8,
            0xE2, 0xD8, 0x03, 0x8F, 0xE2, 0x94, 0x19, 0x92, 0x54, 0x8C, 0xEE, 0x0D, 0x67, 0xDD,
            0x45, 0x47, 0xE1, 0x1D, 0xD6, 0x3A, 0xF9, 0xC9, 0xFC, 0x1C, 0x54, 0x66, 0xFB, 0x68,
            0x4C, 0xF0, 0x09, 0xD7, 0x19, 0x7C, 0x2C, 0xF7, 0x9E, 0x79, 0x2A, 0xB5, 0x01, 0xE6,
            0xA8, 0xA1, 0xCA, 0x51, 0x9A, 0xF2, 0xCB, 0x9B, 0x5F, 0x63, 0x67, 0xE9, 0x4C, 0x0D,
            0x47, 0x50, 0x24, 0x51, 0x35, 0x7B, 0xE1, 0xB5,
        ];

        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);
        assert_eq!(key_tag, 20326);
    }

    #[test]
    fn test_trust_anchor_state_transitions() {
        let anchor = TrustAnchor::new("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);

        assert_eq!(anchor.state, TrustAnchorState::Valid);
        assert!(anchor.is_trusted());
    }

    #[test]
    fn test_is_expired() {
        let anchor = TrustAnchor::new("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);

        assert!(!anchor.is_expired(30));
    }

    #[test]
    fn test_trust_anchor_state_serialization() {
        assert_eq!(TrustAnchorState::Valid.as_str(), "Valid");
        assert_eq!(TrustAnchorState::Seen.as_str(), "Seen");
        assert_eq!(TrustAnchorState::Pending.as_str(), "Pending");
        assert_eq!(
            TrustAnchorState::from_state_str("Valid"),
            Some(TrustAnchorState::Valid)
        );
        assert_eq!(TrustAnchorState::from_state_str("Invalid"), None);
    }

    #[test]
    fn test_trust_anchor_manager_new() {
        let config = TrustAnchorConfig::default();
        let manager = TrustAnchorManager::new(config);

        let status = manager.get_status();
        assert_eq!(status.total_anchors, 0);
        assert_eq!(status.valid_anchors, 0);
    }

    #[test]
    fn test_observe_dnskey_new_key() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![
            0x04, 0x8F, 0xF1, 0xBE, 0x04, 0x1F, 0x9E, 0x4A, 0x22, 0xD5, 0x6E, 0xE8, 0x0A, 0x5C,
            0x9D, 0xE5, 0x80, 0xF8, 0x64, 0x97, 0xD7, 0xF3, 0xBF, 0x1C, 0x9C, 0x7E, 0x2B, 0x8F,
            0xE3, 0x1E, 0x8C, 0x9C, 0xB5, 0x6E, 0xF8, 0x0C, 0xF8, 0x0E, 0xC7, 0x89, 0x2C, 0x3E,
            0xD3, 0x65, 0x4F, 0x5E, 0x70, 0x7F, 0x1E, 0x4D, 0x8E, 0x4A, 0x7B, 0x8A, 0x03, 0x8A,
            0x6D, 0xD0, 0x7F, 0x9E, 0xF1, 0xC4, 0x6A, 0x1C, 0x9C, 0x5E, 0x4B, 0x3D, 0x8D, 0xF7,
            0x6E, 0x0D, 0x5A, 0x8E, 0x4F, 0x3D, 0xAA, 0xB5, 0xA8, 0x5E, 0x0B, 0x1F, 0xC2, 0x9B,
            0xE1, 0xE5, 0x8E, 0x5B, 0x6B, 0x7F, 0xA6, 0xE8, 0xE0, 0xF9, 0x89, 0x5D,
        ];

        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);
        assert_eq!(key_tag, 51192);

        let event = manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        match event {
            Rfc5011Event::NewKeySeen { key_tag: kt } => {
                assert_eq!(kt, 51192);
            }
            _ => panic!("Expected NewKeySeen event"),
        }

        let status = manager.get_status();
        assert_eq!(status.total_anchors, 1);
    }

    #[test]
    fn test_observe_dnskey_repeated() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        let event1 = manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        assert!(matches!(event1, Rfc5011Event::NewKeySeen { .. }));

        let event2 = manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        assert!(matches!(event2, Rfc5011Event::KeySeen { .. }));
    }

    #[test]
    fn test_observe_dnskey_revoked() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        let event = manager.observe_dnskey_at_root(key_tag, 8, &public_key, true);
        assert!(matches!(event, Rfc5011Event::KeyRevoked { .. }));
    }

    #[test]
    fn test_trust_anchor_check_pending() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        let digest = crate::dns::dnssec::compute_ds_digest(2, 257, 3, 8, &public_key)
            .expect("digest computation should succeed");

        let event = manager.trust_anchor_check(key_tag, 8, 2, &digest, None);
        assert!(matches!(event, Rfc5011Event::KeyPending { .. }));
    }

    #[test]
    fn test_trust_anchor_check_digest_mismatch() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        let wrong_digest = vec![0xFF, 0xFE, 0xFD, 0xFC];

        let event = manager.trust_anchor_check(key_tag, 8, 2, &wrong_digest, None);
        match event {
            Rfc5011Event::KeyIgnored { reason, .. } => {
                assert!(reason.contains("mismatch"));
            }
            _ => panic!("Expected KeyIgnored event for digest mismatch"),
        }
    }

    #[test]
    fn test_trust_anchor_check_unknown_key() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        let digest = vec![0xAA, 0xBB, 0xCC, 0xDD];

        let event = manager.trust_anchor_check(key_tag, 8, 2, &digest, None);
        assert!(matches!(event, Rfc5011Event::KeyIgnored { .. }));
    }

    #[test]
    fn test_get_trusted_anchors() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 30,
            allow_key_rotation: false,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        let trusted = manager.get_trusted_anchors();
        assert!(trusted.is_empty());

        let digest = crate::dns::dnssec::compute_ds_digest(2, 257, 3, 8, &public_key)
            .expect("digest computation should succeed");
        manager.trust_anchor_check(key_tag, 8, 2, &digest, None);

        let trusted = manager.get_trusted_anchors();
        assert_eq!(trusted.len(), 1);

        let pending_trusted = manager.get_anchors();
        assert!(pending_trusted.is_empty());
    }

    #[test]
    fn test_ds_digest_sha1() {
        let public_key = vec![
            0x04, 0x8F, 0xF1, 0xBE, 0x04, 0x1F, 0x9E, 0x4A, 0x22, 0xD5, 0x6E, 0xE8, 0x0A, 0x5C,
            0x9D, 0xE5, 0x80, 0xF8, 0x64, 0x97, 0xD7, 0xF3, 0xBF, 0x1C, 0x9C, 0x7E, 0x2B, 0x8F,
            0xE3, 0x1E, 0x8C, 0x9C, 0xB5, 0x6E, 0xF8, 0x0C, 0xF8, 0x0E, 0xC7, 0x89, 0x2C, 0x3E,
            0xD3, 0x65, 0x4F, 0x5E, 0x70, 0x7F, 0x1E, 0x4D, 0x8E, 0x4A, 0x7B, 0x8A, 0x03, 0x8A,
            0x6D, 0xD0, 0x7F, 0x9E, 0xF1, 0xC4, 0x6A, 0x1C, 0x9C, 0x5E, 0x4B, 0x3D, 0x8D, 0xF7,
            0x6E, 0x0D, 0x5A, 0x8E, 0x4F, 0x3D, 0xAA, 0xB5, 0xA8, 0x5E, 0x0B, 0x1F, 0xC2, 0x9B,
            0xE1, 0xE5, 0x8E, 0x5B, 0x6B, 0x7F, 0xA6, 0xE8, 0xE0, 0xF9, 0x89, 0x5D,
        ];

        let digest = crate::dns::dnssec::compute_ds_digest(1, 257, 3, 8, &public_key);
        assert!(digest.is_ok());
        let digest = digest.unwrap();
        assert_eq!(digest.len(), 20);
    }

    #[test]
    fn test_ds_digest_sha384() {
        let public_key = vec![
            0x04, 0x8F, 0xF1, 0xBE, 0x04, 0x1F, 0x9E, 0x4A, 0x22, 0xD5, 0x6E, 0xE8, 0x0A, 0x5C,
            0x9D, 0xE5, 0x80, 0xF8, 0x64, 0x97, 0xD7, 0xF3, 0xBF, 0x1C, 0x9C, 0x7E, 0x2B, 0x8F,
            0xE3, 0x1E, 0x8C, 0x9C, 0xB5, 0x6E, 0xF8, 0x0C, 0xF8, 0x0E, 0xC7, 0x89, 0x2C, 0x3E,
            0xD3, 0x65, 0x4F, 0x5E, 0x70, 0x7F, 0x1E, 0x4D, 0x8E, 0x4A, 0x7B, 0x8A, 0x03, 0x8A,
            0x6D, 0xD0, 0x7F, 0x9E, 0xF1, 0xC4, 0x6A, 0x1C, 0x9C, 0x5E, 0x4B, 0x3D, 0x8D, 0xF7,
            0x6E, 0x0D, 0x5A, 0x8E, 0x4F, 0x3D, 0xAA, 0xB5, 0xA8, 0x5E, 0x0B, 0x1F, 0xC2, 0x9B,
            0xE1, 0xE5, 0x8E, 0x5B, 0x6B, 0x7F, 0xA6, 0xE8, 0xE0, 0xF9, 0x89, 0x5D,
        ];

        let digest = crate::dns::dnssec::compute_ds_digest(4, 257, 3, 8, &public_key);
        assert!(digest.is_ok());
        let digest = digest.unwrap();
        assert_eq!(digest.len(), 48);
    }

    #[test]
    fn test_ds_digest_unsupported_type() {
        let public_key = vec![0x01, 0x02, 0x03, 0x04];

        let digest = crate::dns::dnssec::compute_ds_digest(3, 257, 3, 8, &public_key);
        assert!(digest.is_err());
        assert!(digest.unwrap_err().contains("Unsupported"));
    }

    #[test]
    fn test_digest_verification_roundtrip() {
        let public_key = vec![
            0x04, 0x8F, 0xF1, 0xBE, 0x04, 0x1F, 0x9E, 0x4A, 0x22, 0xD5, 0x6E, 0xE8, 0x0A, 0x5C,
            0x9D, 0xE5, 0x80, 0xF8, 0x64, 0x97, 0xD7, 0xF3, 0xBF, 0x1C, 0x9C, 0x7E, 0x2B, 0x8F,
            0xE3, 0x1E, 0x8C, 0x9C, 0xB5, 0x6E, 0xF8, 0x0C, 0xF8, 0x0E, 0xC7, 0x89, 0x2C, 0x3E,
            0xD3, 0x65, 0x4F, 0x5E, 0x70, 0x7F, 0x1E, 0x4D, 0x8E, 0x4A, 0x7B, 0x8A, 0x03, 0x8A,
            0x6D, 0xD0, 0x7F, 0x9E, 0xF1, 0xC4, 0x6A, 0x1C, 0x9C, 0x5E, 0x4B, 0x3D, 0x8D, 0xF7,
            0x6E, 0x0D, 0x5A, 0x8E, 0x4F, 0x3D, 0xAA, 0xB5, 0xA8, 0x5E, 0x0B, 0x1F, 0xC2, 0x9B,
            0xE1, 0xE5, 0x8E, 0x5B, 0x6B, 0x7F, 0xA6, 0xE8, 0xE0, 0xF9, 0x89, 0x5D,
        ];

        let digest = crate::dns::dnssec::compute_ds_digest(2, 257, 3, 8, &public_key)
            .expect("digest computation should succeed");

        let verified = crate::dns::dnssec::verify_ds_digest(2, 257, 3, 8, &public_key, &digest)
            .expect("verification should succeed");
        assert!(verified);
    }

    #[test]
    fn test_public_key_change_rejection() {
        let config = TrustAnchorConfig {
            pending_observation_days: 30,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key1 = vec![0x01, 0x02, 0x03, 0x04];
        let public_key2 = vec![0x05, 0x06, 0x07, 0x08];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key1);

        let event1 = manager.observe_dnskey_at_root(key_tag, 8, &public_key1, false);
        assert!(matches!(event1, Rfc5011Event::NewKeySeen { .. }));

        let event2 = manager.observe_dnskey_at_root(key_tag, 8, &public_key2, false);
        match event2 {
            Rfc5011Event::KeyIgnored { reason, .. } => {
                assert!(reason.contains("mismatch"));
            }
            _ => panic!("Expected KeyIgnored event for public key mismatch"),
        }
    }

    #[test]
    fn test_separate_timeout_config() {
        let config = TrustAnchorConfig {
            pending_observation_days: 30,
            revocation_grace_days: 30,
            extended_removal_days: 60,
            trust_anchor_retention_days: 7,
            ..TrustAnchorConfig::default()
        };

        assert_eq!(config.pending_observation_days, 30);
        assert_eq!(config.revocation_grace_days, 30);
        assert_eq!(config.extended_removal_days, 60);
        assert_eq!(config.trust_anchor_retention_days, 7);
    }

    #[test]
    fn test_trust_anchor_state_from_str() {
        assert_eq!(
            TrustAnchorState::from_state_str("Valid"),
            Some(TrustAnchorState::Valid)
        );
        assert_eq!(
            TrustAnchorState::from_state_str("Seen"),
            Some(TrustAnchorState::Seen)
        );
        assert_eq!(
            TrustAnchorState::from_state_str("Pending"),
            Some(TrustAnchorState::Pending)
        );
        assert_eq!(
            TrustAnchorState::from_state_str("Revoked"),
            Some(TrustAnchorState::Revoked)
        );
        assert_eq!(
            TrustAnchorState::from_state_str("Removed"),
            Some(TrustAnchorState::Removed)
        );
        assert_eq!(
            TrustAnchorState::from_state_str("Missing"),
            Some(TrustAnchorState::Missing)
        );
        assert_eq!(TrustAnchorState::from_state_str("InvalidState"), None);
    }

    #[test]
    fn test_anchor_is_trusted() {
        let valid_anchor = TrustAnchor {
            key_id: "test".to_string(),
            key_tag: 12345,
            algorithm: 8,
            public_key: vec![1, 2, 3],
            state: TrustAnchorState::Valid,
            added_at: 0,
            last_seen: 0,
            trust_point: 0,
            first_seen_at: None,
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        };
        assert!(valid_anchor.is_trusted());

        let pending_anchor = TrustAnchor {
            key_id: "test2".to_string(),
            key_tag: 12346,
            algorithm: 8,
            public_key: vec![1, 2, 3],
            state: TrustAnchorState::Pending,
            added_at: 0,
            last_seen: 0,
            trust_point: 0,
            first_seen_at: None,
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        };
        assert!(pending_anchor.is_trusted());

        let seen_anchor = TrustAnchor {
            key_id: "test3".to_string(),
            key_tag: 12347,
            algorithm: 8,
            public_key: vec![1, 2, 3],
            state: TrustAnchorState::Seen,
            added_at: 0,
            last_seen: 0,
            trust_point: 0,
            first_seen_at: None,
            pending_since: None,
            revoked_at: None,
            removed_at: None,
        };
        assert!(!seen_anchor.is_trusted());
    }

    #[test]
    fn test_get_anchors_only_valid() {
        let config = TrustAnchorConfig::default();
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        assert!(manager.get_anchors().is_empty());

        let digest = crate::dns::dnssec::compute_ds_digest(2, 257, 3, 8, &public_key)
            .expect("digest should compute");
        manager.trust_anchor_check(key_tag, 8, 2, &digest, None);

        assert!(manager.get_anchors().is_empty());

        let trusted = manager.get_trusted_anchors();
        assert_eq!(trusted.len(), 1);
    }

    #[test]
    fn test_revoked_key_ignored_on_new_observation() {
        let config = TrustAnchorConfig::default();
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        manager.observe_dnskey_at_root(key_tag, 8, &public_key, true);

        let event = manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        match event {
            Rfc5011Event::KeyRemoved { key_tag: kt } => {
                assert_eq!(kt, key_tag);
            }
            _ => panic!("Expected KeyRemoved event"),
        }
    }

    #[test]
    fn test_missing_key_restoration() {
        let config = TrustAnchorConfig {
            trust_anchor_retention_days: 7,
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);

        let events = manager.process_rfc5011_updates();
        assert!(events.is_empty());

        let mut anchors = manager.anchors.write();
        if let Some(anchor) = anchors.get_mut(&format!("{}-8", key_tag)) {
            anchor.state = TrustAnchorState::Missing;
        }
        drop(anchors);

        let event = manager.observe_dnskey_at_root(key_tag, 8, &public_key, false);
        match event {
            Rfc5011Event::KeyPromoted { key_tag: kt } => {
                assert_eq!(kt, key_tag);
            }
            _ => panic!("Expected KeyPromoted event for missing key restoration"),
        }
    }

    #[test]
    fn test_add_remove_anchor() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_anchors.db");

        let config = TrustAnchorConfig {
            db_path: db_path.to_string_lossy().to_string(),
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let result = manager.add_anchor("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);
        assert!(result.is_ok());

        let result = manager.add_anchor("test-key".to_string(), 12345, 8, vec![1, 2, 3, 4]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        let result = manager.remove_anchor("test-key");
        assert!(result.is_ok());

        let result = manager.remove_anchor("nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_get_anchor_by_keytag() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_anchors2.db");

        let config = TrustAnchorConfig {
            db_path: db_path.to_string_lossy().to_string(),
            ..TrustAnchorConfig::default()
        };
        let manager = TrustAnchorManager::new(config);

        let public_key = vec![0x01, 0x02, 0x03, 0x04];
        let key_tag = crate::dns::dnssec::calculate_key_tag(257, 3, 8, &public_key);

        let result = manager.add_anchor(format!("{}-8", key_tag), key_tag, 8, public_key.clone());
        assert!(result.is_ok());

        let anchor = manager.get_anchor_by_keytag(key_tag);
        assert!(anchor.is_some());
        assert_eq!(anchor.unwrap().key_tag, key_tag);

        let anchor = manager.get_anchor_by_keytag(65535);
        assert!(anchor.is_none());
    }
}
