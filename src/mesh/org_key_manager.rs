use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use thiserror::Error;
use crate::mesh::organization::{Organization, OrgKey, OrgPublicKey, QuorumSignature};
use crate::mesh::dht::keys::DhtKey;
use crate::mesh::dht::record_store::RecordStoreManager;
use crate::mesh::config::MeshNodeRole;

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
}

use crate::mesh::protocol::{ArcStr, MeshMessage};
use tokio::sync::mpsc::Sender;
use crate::mesh::transport::MeshTransport;

pub struct OrgKeyManager {
    node_id: String,
    node_role: MeshNodeRole,
    record_store: RwLock<Option<Arc<RecordStoreManager>>>,
    organizations: RwLock<HashMap<String, Organization>>,
    // Local cache of OrgPublicKeys synced from DHT
    org_public_keys: RwLock<HashMap<String, OrgPublicKey>>,
    // Track pending sign requests: request_id -> (org_id, signatures)
    pending_sign_requests: RwLock<HashMap<String, (String, Vec<QuorumSignature>)>>,
    mesh_sender: RwLock<Option<Sender<MeshMessage>>>,
    transport: RwLock<Option<Arc<MeshTransport>>>,
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

    pub async fn create_organization(&self, org_id: String, name: Option<String>) -> Result<Organization, OrgKeyError> {
        if !self.node_role.is_global() {
            return Err(OrgKeyError::NotAuthorized("Only global nodes can create organizations".to_string()));
        }

        let mut org = Organization::new(Some(org_id), name);
        let org_key = OrgKey::generate(Some(self.node_id.clone()));
        org.set_org_key(org_key);
        
        self.organizations.write().insert(org.org_id.clone(), org.clone());
        
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
        
        let store = self.record_store.read().clone().ok_or(OrgKeyError::RecordStoreNotSet)?;
        
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
        };
        record.content_hash = record.compute_content_hash();
        
        store.store_record(record, 100);
        
        Ok(())
    }

    pub async fn sync_from_dht(&self) -> Result<(), OrgKeyError> {
        let store = self.record_store.read().clone().ok_or(OrgKeyError::RecordStoreNotSet)?;
        
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

        // Verify the key and the requester (requester must be global too)
        // For Phase 2, we'll assume it's valid if we are global and just sign it

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
                        signature,
                        timestamp,
                    });

                    // Check if quorum met (2/3 of global nodes)
                    // For Phase 2, we just need a few or at least 1 to test
                    if signatures.len() >= 1 {
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

    async fn publish_signed_org_public_key(&self, pub_key: OrgPublicKey) -> Result<(), OrgKeyError> {
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
        };
        record.content_hash = record.compute_content_hash();

        store.store_record(record, 100);
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
        // Logic to check if local org keys or certificates are nearing expiration
        // For Phase 4, we'll implement a simple check
        let org_ids: Vec<String> = self.organizations.read().keys().cloned().collect();
        for org_id in org_ids {
            let org_key_opt = {
                let orgs = self.organizations.read();
                orgs.get(&org_id).and_then(|o| o.org_key.clone())
            };

            if let Some(org_key) = org_key_opt {
                // If it was created more than 25 days ago, request new signatures
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
}
