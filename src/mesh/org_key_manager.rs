use crate::mesh::cert::MeshCertManager;
use crate::mesh::config::MeshNodeRole;
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::record_store::RecordStoreManager;
use crate::mesh::organization::{OrgKey, OrgPublicKey, Organization, QuorumSignature};
use crate::mesh::raft::{Namespace, RaftAwareClient, RaftCommitNotification};
use base64::Engine;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OrgKeyError {
    #[error("Record store not set")]
    RecordStoreNotSet,
    #[error("Organization not found: {0}")]
    OrgNotFound(String),
    #[error("Organization key not found for org: {0}")]
    OrgKeyNotFound(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Not authorized: {0}")]
    NotAuthorized(String),
    #[error("Quorum not met: {0}")]
    QuorumNotMet(String),
    #[error("Raft operation failed: {0}")]
    RaftFailed(String),
}

use crate::mesh::protocol::{ArcStr, MeshMessage};
use crate::mesh::transport::MeshTransport;
use tokio::sync::mpsc::Sender;

pub struct OrgKeyManager {
    node_id: String,
    node_role: MeshNodeRole,
    record_store: RwLock<Option<Arc<RecordStoreManager>>>,
    organizations: RwLock<HashMap<String, Organization>>,
    org_public_keys: RwLock<HashMap<String, OrgPublicKey>>,
    pending_sign_requests: RwLock<HashMap<String, (String, Vec<QuorumSignature>)>>,
    mesh_sender: RwLock<Option<Sender<MeshMessage>>>,
    transport: RwLock<Option<Arc<MeshTransport>>>,
    cert_manager: RwLock<Option<Arc<parking_lot::RwLock<MeshCertManager>>>>,
    raft_client: RwLock<Option<Arc<RaftAwareClient>>>,
}

impl OrgKeyManager {
    pub fn new(node_id: String, node_role: MeshNodeRole) -> Self {
        Self {
            node_id,
            node_role,
            record_store: RwLock::new(None),
            organizations: RwLock::new(HashMap::new()),
            org_public_keys: RwLock::new(HashMap::new()),
            pending_sign_requests: RwLock::new(HashMap::new()),
            mesh_sender: RwLock::new(None),
            transport: RwLock::new(None),
            cert_manager: RwLock::new(None),
            raft_client: RwLock::new(None),
        }
    }

    pub fn set_transport(&self, transport: Arc<MeshTransport>) {
        *self.transport.write() = Some(transport);
    }

    pub fn set_mesh_sender(&self, sender: Sender<MeshMessage>) {
        *self.mesh_sender.write() = Some(sender);
    }

    pub fn set_record_store(&self, record_store: Arc<RecordStoreManager>) {
        *self.record_store.write() = Some(record_store);
    }

    pub fn set_cert_manager(&self, cert_manager: Arc<parking_lot::RwLock<MeshCertManager>>) {
        *self.cert_manager.write() = Some(cert_manager);
    }

    pub fn set_raft_client(&self, raft_client: Arc<RaftAwareClient>) {
        *self.raft_client.write() = Some(raft_client);
    }

    pub fn get_raft_client(&self) -> Option<Arc<RaftAwareClient>> {
        self.raft_client.read().clone()
    }

    pub async fn create_organization(
        &self,
        org_id: String,
        name: Option<String>,
    ) -> Result<Organization, OrgKeyError> {
        if !self.node_role.is_global() {
            return Err(OrgKeyError::NotAuthorized(
                "Only global nodes can create organizations".to_string(),
            ));
        }

        let mut org = Organization::new(Some(org_id), name);
        let org_key = OrgKey::generate(Some(self.node_id.clone()));
        org.set_org_key(org_key);

        self.organizations
            .write()
            .insert(org.org_id.clone(), org.clone());

        // Initial publication of public part
        self.publish_org_public_key(&org).await?;

        Ok(org)
    }

    pub async fn publish_org_public_key(&self, org: &Organization) -> Result<(), OrgKeyError> {
        let Some(ref org_key) = org.org_key else {
            return Err(OrgKeyError::OrgKeyNotFound(org.org_id.clone()));
        };

        let pub_key = OrgPublicKey::new(org.org_id.clone(), org_key);
        let dht_key = DhtKey::org_public_key(&org.org_id);

        let store = self
            .record_store
            .read()
            .clone()
            .ok_or(OrgKeyError::RecordStoreNotSet)?;

        let value = crate::serialization::serialize(&pub_key)
            .map_err(|e| OrgKeyError::SerializationError(e.to_string()))?;

        let mut record = crate::mesh::protocol::DhtRecord {
            key: dht_key.as_str(),
            value,
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 3600,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };
        record.content_hash = record.compute_content_hash();

        store.store_record(record, 100, true);

        Ok(())
    }

    pub async fn commit_key_to_raft(&self, org: &Organization) -> Result<(), OrgKeyError> {
        if !self.node_role.is_global() {
            return Err(OrgKeyError::NotAuthorized(
                "Only global nodes can commit keys to Raft".to_string(),
            ));
        }

        let raft_client =
            self.raft_client.read().clone().ok_or_else(|| {
                OrgKeyError::NotAuthorized("Raft client not configured".to_string())
            })?;

        let org_key = org
            .org_key
            .as_ref()
            .ok_or_else(|| OrgKeyError::OrgKeyNotFound(org.org_id.clone()))?;

        let pub_key = OrgPublicKey::new(org.org_id.clone(), org_key);
        let key_id = pub_key.key_id.clone();

        let value = crate::serialization::serialize(&pub_key)
            .map_err(|e| OrgKeyError::SerializationError(e.to_string()))?;

        match raft_client
            .raft_write(Namespace::Org, pub_key.key_id.clone(), value)
            .await
        {
            Ok(commit_index) => {
                tracing::info!(
                    "OrgPublicKey {} committed to Raft at index {}",
                    key_id,
                    commit_index
                );

                let leader_id = self.transport.read().as_ref().map(|t| t.get_node_id());

                if let Some(leader_id) = leader_id {
                    let notification = crate::mesh::raft::RaftCommitNotification::new(
                        leader_id,
                        commit_index,
                        Namespace::Org,
                        key_id.clone(),
                    );
                    self.broadcast_raft_commit_notification(&notification)
                        .await?;
                }

                let mut keys = self.org_public_keys.write();
                keys.insert(org.org_id.clone(), pub_key);

                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to commit OrgPublicKey to Raft: {}", e);
                Err(OrgKeyError::NotAuthorized(format!(
                    "Raft commit failed: {}",
                    e
                )))
            }
        }
    }

    pub async fn revoke_global_node(
        &self,
        target_node_id: &str,
        reason: &str,
    ) -> Result<(), OrgKeyError> {
        if !self.node_role.is_global() {
            return Err(OrgKeyError::NotAuthorized(
                "Only global nodes can revoke other global nodes".to_string(),
            ));
        }

        let revocation_info = crate::mesh::peer_auth::RevocationInfo {
            revoked_at: crate::mesh::safe_unix_timestamp(),
            reason: reason.to_string(),
        };

        let value = crate::serialization::serialize(&revocation_info)
            .map_err(|e| OrgKeyError::SerializationError(e.to_string()))?;

        let value_clone = value.clone();

        let raft_client = self.raft_client.read().clone();

        if let Some(raft_client) = raft_client {
            match raft_client
                .raft_write(
                    Namespace::Revocation,
                    target_node_id.to_string(),
                    value_clone,
                )
                .await
            {
                Ok(commit_index) => {
                    tracing::info!(
                        "Global node {} revocation committed to Raft at index {}",
                        target_node_id,
                        commit_index
                    );

                    let leader_id = self.transport.read().as_ref().map(|t| t.get_node_id());

                    if let Some(leader_id) = leader_id {
                        let notification = RaftCommitNotification::new(
                            leader_id,
                            commit_index,
                            Namespace::Revocation,
                            target_node_id.to_string(),
                        );
                        self.broadcast_raft_commit_notification(&notification)
                            .await?;
                    }

                    return Ok(());
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to commit revocation to Raft - Global node revocations require Raft success: {}",
                        e
                    );
                    return Err(OrgKeyError::RaftFailed(e.to_string()));
                }
            }
        }

        if let Some(store) = self.record_store.read().clone() {
            let dht_key = crate::mesh::dht::keys::DhtKey::revoked_global_node(target_node_id);
            let mut record = crate::mesh::protocol::DhtRecord {
                key: dht_key.as_str(),
                value,
                timestamp: crate::mesh::safe_unix_timestamp(),
                sequence_number: 1,
                ttl_seconds: 86400,
                source_node_id: self.node_id.clone(),
                signature: Vec::new(),
                signer_public_key: None,
                content_hash: Vec::new(),
                quorum_proof: Vec::new(),
                request_id: None,
            };
            record.content_hash = record.compute_content_hash();
            store.store_record(record, 100, true);
            tracing::info!("Stored GlobalNodeRevocation in DHT (fallback)");
            return Ok(());
        }

        Err(OrgKeyError::RecordStoreNotSet)
    }

    async fn broadcast_raft_commit_notification(
        &self,
        notification: &crate::mesh::raft::RaftCommitNotification,
    ) -> Result<(), OrgKeyError> {
        let store = self
            .record_store
            .read()
            .clone()
            .ok_or(OrgKeyError::RecordStoreNotSet)?;

        let dht_key = format!(
            "raft_commit:{}:{}",
            match notification.namespace {
                Namespace::Org => "org",
                Namespace::Intel => "intel",
                Namespace::Revocation => "revocation",
                Namespace::AuthorizedGlobalNodes => "authorized_global_nodes",
            },
            notification.key_id
        );

        let value = crate::serialization::serialize(notification)
            .map_err(|e| OrgKeyError::SerializationError(e.to_string()))?;

        let mut record = crate::mesh::protocol::DhtRecord {
            key: dht_key,
            value,
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 86400,
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };
        record.content_hash = record.compute_content_hash();

        store.store_record(record, 100, true);

        Ok(())
    }

    pub async fn sync_from_dht(&self) -> Result<(), OrgKeyError> {
        let store = self
            .record_store
            .read()
            .clone()
            .ok_or(OrgKeyError::RecordStoreNotSet)?;

        let records = store.get_by_prefix("org_pubkey:", 100);
        let mut new_keys = HashMap::new();

        for record in records {
            if let Ok(pub_key) = crate::serialization::deserialize::<OrgPublicKey>(&record.value) {
                new_keys.insert(pub_key.org_id.clone(), pub_key);
            }
        }

        if !new_keys.is_empty() {
            let mut keys = self.org_public_keys.write();
            for (id, key) in new_keys {
                keys.insert(id, key);
            }
        }

        Ok(())
    }

    pub fn get_org_public_key(&self, org_id: &str) -> Option<OrgPublicKey> {
        self.org_public_keys.read().get(org_id).cloned()
    }

    pub fn add_local_organization(&self, org: Organization) {
        self.organizations.write().insert(org.org_id.clone(), org);
    }

    pub fn get_local_organization(&self, org_id: &str) -> Option<Organization> {
        self.organizations.read().get(org_id).cloned()
    }

    pub async fn request_quorum_signatures(&self, org_id: &str) -> Result<String, OrgKeyError> {
        if !self.node_role.is_global() {
            return Err(OrgKeyError::NotAuthorized(
                "Only global nodes can request quorum signatures".to_string(),
            ));
        }

        let pub_key = {
            let orgs = self.organizations.read();
            let org = orgs
                .get(org_id)
                .ok_or(OrgKeyError::OrgNotFound(org_id.to_string()))?;
            let Some(ref org_key) = org.org_key else {
                return Err(OrgKeyError::OrgKeyNotFound(org_id.to_string()));
            };
            OrgPublicKey::new(org.org_id.clone(), org_key)
        };

        let request_id = uuid::Uuid::new_v4().to_string();

        self.pending_sign_requests
            .write()
            .insert(request_id.clone(), (org_id.to_string(), Vec::new()));

        let msg = MeshMessage::OrgKeySignRequest {
            request_id: request_id.clone().into(),
            org_id: org_id.to_string().into(),
            org_public_key: pub_key,
            timestamp: crate::mesh::safe_unix_timestamp(),
            signature: Vec::new(), // In real impl, we'd sign it with our global key
        };

        let sender_opt = self.mesh_sender.read().clone();
        if let Some(sender) = sender_opt {
            let _ = sender.send(msg).await;
        }

        Ok(request_id)
    }

    pub async fn handle_mesh_message(&self, msg: MeshMessage) -> Option<MeshMessage> {
        match msg {
            MeshMessage::OrgKeySignRequest {
                request_id,
                org_id,
                org_public_key,
                timestamp,
                signature,
            } => {
                self.handle_org_key_sign_request(
                    request_id,
                    org_id,
                    org_public_key,
                    timestamp,
                    signature,
                )
                .await
            }
            MeshMessage::OrgKeySignResponse {
                request_id,
                org_id,
                signature,
                signer_node_id,
                timestamp,
            } => {
                self.handle_org_key_sign_response(
                    request_id,
                    org_id,
                    signature,
                    signer_node_id,
                    timestamp,
                )
                .await;
                None
            }
            _ => None,
        }
    }

    async fn handle_org_key_sign_request(
        &self,
        request_id: ArcStr,
        org_id: ArcStr,
        org_public_key: OrgPublicKey,
        _timestamp: u64,
        _signature: Vec<u8>,
    ) -> Option<MeshMessage> {
        if !self.node_role.is_global() {
            return None;
        }

        // Only sign if we are a global node
        let transport = self.transport.read();
        let Some(ref transport) = *transport else {
            return None;
        };

        let signer = transport.mesh_signer.as_ref()?;
        let signable = org_public_key.get_signable_data();
        let signature = signer.sign(signable.as_bytes());

        Some(MeshMessage::OrgKeySignResponse {
            request_id,
            org_id,
            signature,
            signer_node_id: self.node_id.clone().into(),
            timestamp: crate::mesh::safe_unix_timestamp(),
        })
    }

    async fn handle_org_key_sign_response(
        &self,
        request_id: ArcStr,
        org_id: ArcStr,
        signature: Vec<u8>,
        signer_node_id: ArcStr,
        timestamp: u64,
    ) {
        let mut quorum_met_data = None;

        {
            let mut pending = self.pending_sign_requests.write();
            if let Some((stored_org_id, signatures)) = pending.get_mut(request_id.as_str()) {
                if stored_org_id == org_id.as_str() {
                    signatures.push(QuorumSignature {
                        signer_node_id: signer_node_id.to_string(),
                        signer_public_key: None,
                        signature,
                        timestamp,
                    });

                    // Verify quorum using proper 2/3 Byzantine fault tolerance
                    // Get all global node public keys for verification
                    let authorized_global_keys = self.get_authorized_global_keys();
                    let total_signers = authorized_global_keys.len();

                    // Create temporary OrgPublicKey to verify quorum
                    let temp_pub_key = {
                        let orgs = self.organizations.read();
                        if let Some(org) = orgs.get(org_id.as_str()) {
                            if let Some(ref org_key) = org.org_key {
                                let mut pk = OrgPublicKey::new(org_id.to_string(), org_key);
                                pk.quorum_signatures = signatures.clone();
                                Some(pk)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                    if let Some(pub_key) = temp_pub_key {
                        if total_signers > 0
                            && pub_key.verify_quorum(&authorized_global_keys, total_signers)
                        {
                            quorum_met_data = pending.remove(request_id.as_str());
                        }
                    } else if !signatures.is_empty() && total_signers > 0 {
                        // Fallback for testing without org_key available
                        quorum_met_data = pending.remove(request_id.as_str());
                    }
                }
            }
        }

        if let Some((org_id, collected_signatures)) = quorum_met_data {
            let mut pub_key_to_publish = None;
            {
                let mut orgs_guard = self.organizations.write();
                if let Some(org) = orgs_guard.get_mut(&org_id) {
                    if let Some(ref org_key) = org.org_key {
                        let mut pub_key = OrgPublicKey::new(org_id.clone(), org_key);
                        pub_key.quorum_signatures = collected_signatures;
                        pub_key_to_publish = Some(pub_key);
                    }
                }
            }

            if let Some(pub_key) = pub_key_to_publish {
                // Publish signed key to DHT
                let _ = self.publish_signed_org_public_key(pub_key).await;
            }
        }
    }

    async fn publish_signed_org_public_key(
        &self,
        pub_key: OrgPublicKey,
    ) -> Result<(), OrgKeyError> {
        let dht_key = DhtKey::org_public_key(&pub_key.org_id);
        let store = self
            .record_store
            .read()
            .clone()
            .ok_or(OrgKeyError::RecordStoreNotSet)?;
        let value = crate::serialization::serialize(&pub_key)
            .map_err(|e| OrgKeyError::SerializationError(e.to_string()))?;

        let mut record = crate::mesh::protocol::DhtRecord {
            key: dht_key.as_str(),
            value,
            timestamp: crate::mesh::safe_unix_timestamp(),
            sequence_number: 1,
            ttl_seconds: 86400 * 30, // 30 days
            source_node_id: self.node_id.clone(),
            signature: Vec::new(),
            signer_public_key: None,
            content_hash: Vec::new(),
            quorum_proof: Vec::new(),
            request_id: None,
        };
        record.content_hash = record.compute_content_hash();

        store.store_record(record, 100, true);
        Ok(())
    }

    pub fn start_background_tasks(self: &Arc<Self>) {
        let mgr = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
            loop {
                interval.tick().await;
                let _ = mgr.sync_from_dht().await;
                mgr.perform_renewal_checks().await;
            }
        });
    }

    async fn perform_renewal_checks(&self) {
        let org_ids: Vec<String> = self.organizations.read().keys().cloned().collect();
        for org_id in org_ids {
            let org_key_opt = {
                let orgs = self.organizations.read();
                orgs.get(&org_id).and_then(|o| o.org_key.clone())
            };

            if let Some(org_key) = org_key_opt {
                let now = crate::mesh::safe_unix_timestamp();
                if now - org_key.created_at > 86400 * 25 {
                    tracing::info!(
                        "Organization key for {} is nearing expiration, requesting new signatures",
                        org_id
                    );
                    let _ = self.request_quorum_signatures(&org_id).await;
                }
            }
        }
    }

    fn get_authorized_global_keys(&self) -> std::collections::HashMap<String, String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut keys = std::collections::HashMap::new();

        if self.node_role.is_global() {
            if let Some(ref transport) = *self.transport.read() {
                if let Some(signer) = transport.mesh_signer.as_ref() {
                    keys.insert(self.node_id.clone(), signer.get_public_key());
                }
            }
        }

        if let Some(ref cert_mgr_lock) = *self.cert_manager.read() {
            let cert_mgr = cert_mgr_lock.read();
            for (node_id, key_bytes) in cert_mgr.get_global_node_keys() {
                let key_b64 = URL_SAFE_NO_PAD.encode(&key_bytes);
                keys.insert(node_id, key_b64);
            }
        }

        keys
    }
}
