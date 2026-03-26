#![allow(unused_variables, unused_mut)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub const GENESIS_ORG_ID: &str = "_genesis";
pub const ADMIN_ORG_ID: &str = "_admin";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgKey {
    pub key_id: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub created_at: u64,
    pub issued_by: Option<String>,
}

impl OrgKey {
    pub fn generate(issued_by: Option<String>) -> Self {
        use rand::RngCore;
        let mut private_key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut private_key);
        let public_key = derive_org_public_key(&private_key);

        Self {
            key_id: Uuid::new_v4().to_string(),
            private_key,
            public_key,
            created_at: crate::mesh::safe_unix_timestamp(),
            issued_by,
        }
    }

    pub fn sign(&self, data: &str) -> Vec<u8> {
        crate::mesh::cert::sign_ed25519(data, &self.private_key).unwrap_or_default()
    }

    pub fn verify(&self, data: &str, signature: &[u8]) -> bool {
        crate::mesh::cert::verify_ed25519(data, signature, &self.public_key)
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

fn derive_org_public_key(private_key: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"org-key-v1:");
    hasher.update(private_key);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberCertificate {
    pub cert_id: String,
    pub mesh_id: String,
    pub org_id: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub org_public_key_id: String,
    pub signature: Vec<u8>,
}

impl MemberCertificate {
    pub fn new(mesh_id: String, org_id: String, org_key: &OrgKey, validity_days: u64) -> Self {
        let now = crate::mesh::safe_unix_timestamp();

        let valid_from = now;
        let valid_until = if validity_days == 0 {
            now - 1 // Already expired
        } else {
            now + (validity_days * 86400)
        };

        let cert = Self {
            cert_id: Uuid::new_v4().to_string(),
            mesh_id: mesh_id.clone(),
            org_id: org_id.clone(),
            valid_from,
            valid_until,
            org_public_key_id: org_key.key_id.clone(),
            signature: Vec::new(),
        };

        let signature = org_key.sign(&cert.get_signable_data());
        Self { signature, ..cert }
    }

    pub fn sign(&mut self, org_key: &OrgKey) {
        self.signature = org_key.sign(&self.get_signable_data());
    }

    fn get_signable_data(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.mesh_id, self.org_id, self.valid_from, self.valid_until, self.org_public_key_id
        )
    }

    pub fn verify(&self, org_private_key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        if !self.is_valid() {
            return false;
        }
        let Some(org_public_key) = crate::mesh::cert::get_ed25519_public_key(org_private_key)
        else {
            return false;
        };
        crate::mesh::cert::verify_ed25519(
            &self.get_signable_data(),
            &self.signature,
            &org_public_key,
        )
    }

    pub fn is_valid(&self) -> bool {
        let now = crate::mesh::safe_unix_timestamp();
        self.valid_from <= now && self.valid_until >= now
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub org_id: String,
    pub name: Option<String>,
    pub org_key: Option<OrgKey>,
    pub tier_keys: Vec<TierKey>,
    pub member_certificates: Vec<MemberCertificate>,
    pub member_nodes: Vec<String>,
    pub created_at: u64,
    pub is_genesis: bool,
    pub genesis_signed: bool,
}

impl Organization {
    pub fn new(org_id: Option<String>, name: Option<String>) -> Self {
        let id = org_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        Self {
            org_id: id,
            name,
            org_key: None,
            tier_keys: Vec::new(),
            member_certificates: Vec::new(),
            member_nodes: Vec::new(),
            created_at: crate::mesh::safe_unix_timestamp(),
            is_genesis: false,
            genesis_signed: false,
        }
    }

    pub fn new_genesis_org() -> Self {
        Self {
            org_id: GENESIS_ORG_ID.to_string(),
            name: Some("Genesis".to_string()),
            org_key: None,
            tier_keys: Vec::new(),
            member_certificates: Vec::new(),
            member_nodes: Vec::new(),
            created_at: crate::mesh::safe_unix_timestamp(),
            is_genesis: true,
            genesis_signed: true,
        }
    }

    pub fn new_admin_org() -> Self {
        Self {
            org_id: ADMIN_ORG_ID.to_string(),
            name: Some("Admin".to_string()),
            org_key: None,
            tier_keys: Vec::new(),
            member_certificates: Vec::new(),
            member_nodes: Vec::new(),
            created_at: crate::mesh::safe_unix_timestamp(),
            is_genesis: false,
            genesis_signed: false,
        }
    }

    pub fn with_org_key(mut self, key: OrgKey) -> Self {
        self.org_key = Some(key);
        self
    }

    pub fn set_org_key(&mut self, key: OrgKey) {
        self.org_key = Some(key);
    }

    pub fn update_name(
        &mut self,
        new_name: String,
    ) -> Result<String, crate::mesh::NameValidationError> {
        let validated = crate::mesh::sanitize_org_name(&new_name)?;
        let old_name = self.name.clone();
        self.name = Some(validated.clone());
        tracing::info!(
            "Organization {} name changed from {:?} to {}",
            self.org_id,
            old_name,
            validated
        );
        Ok(validated)
    }

    pub fn is_genesis_org(&self) -> bool {
        self.org_id == GENESIS_ORG_ID || self.is_genesis
    }

    pub fn can_manage_global_nodes(&self) -> bool {
        self.is_genesis_org() || self.genesis_signed
    }

    pub fn get_valid_member_certificate(&self, mesh_id: &str) -> Option<&MemberCertificate> {
        self.member_certificates
            .iter()
            .find(|c| c.mesh_id == mesh_id && c.is_valid())
    }

    pub fn get_all_valid_member_certificates(&self) -> Vec<&MemberCertificate> {
        self.member_certificates
            .iter()
            .filter(|c| c.is_valid())
            .collect()
    }

    pub fn add_member_certificate(&mut self, cert: MemberCertificate) {
        self.member_certificates.push(cert);
    }

    pub fn revoke_member_certificate(&mut self, cert_id: &str) -> bool {
        if let Some(cert) = self
            .member_certificates
            .iter_mut()
            .find(|c| c.cert_id == cert_id)
        {
            cert.valid_until = 0;
            return true;
        }
        false
    }

    pub fn add_member_node(&mut self, node_id: String) {
        if !self.member_nodes.contains(&node_id) {
            self.member_nodes.push(node_id);
        }
    }

    pub fn remove_member_node(&mut self, node_id: &str) {
        self.member_nodes.retain(|n| n != node_id);
    }

    pub fn is_member(&self, node_id: &str) -> bool {
        self.member_nodes.contains(&node_id.to_string())
    }

    pub fn get_valid_tier_key(&self, tier: u32) -> Option<&TierKey> {
        let now = crate::mesh::safe_unix_timestamp();

        self.tier_keys
            .iter()
            .find(|k| k.tier == tier && k.valid_from <= now && k.valid_until >= now && !k.revoked)
    }

    pub fn get_all_valid_keys(&self) -> Vec<&TierKey> {
        let now = crate::mesh::safe_unix_timestamp();

        self.tier_keys
            .iter()
            .filter(|k| k.valid_from <= now && k.valid_until >= now && !k.revoked)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKey {
    pub key_id: String,
    pub tier: u32,
    pub key: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub issued_by: String,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
    pub bound_to: Option<String>,
    pub is_unspent: bool,
}

impl TierKey {
    pub fn new(
        tier: u32,
        key: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
        issued_by: String,
    ) -> Self {
        Self {
            key_id: Uuid::new_v4().to_string(),
            tier,
            key,
            valid_from,
            valid_until,
            issued_by,
            revoked: false,
            revoked_at: None,
            bound_to: None,
            is_unspent: true,
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = crate::mesh::safe_unix_timestamp();

        !self.revoked && self.valid_from <= now && self.valid_until >= now
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
        self.revoked_at = Some(crate::mesh::safe_unix_timestamp());
    }

    pub fn bind(&mut self, org_id: &str) {
        self.bound_to = Some(org_id.to_string());
        self.is_unspent = false;
    }

    pub fn unbind(&mut self) {
        self.bound_to = None;
        self.is_unspent = true;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierClaim {
    pub tier: u32,
    pub key_id: String,
    pub org_id: String,
    pub mesh_id: String,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: Vec<u8>,
}

impl TierClaim {
    pub fn new(tier: u32, key_id: String, org_id: String, mesh_id: String, nonce: String) -> Self {
        Self {
            tier,
            key_id,
            org_id,
            mesh_id,
            timestamp: crate::mesh::safe_unix_timestamp(),
            nonce,
            signature: Vec::new(),
        }
    }

    pub fn sign(&mut self, key: &[u8]) {
        let data = self.get_signable_data();
        self.signature = crate::mesh::cert::sign_ed25519(&data, key).unwrap_or_default();
    }

    pub fn verify_signature(&self, key: &[u8]) -> bool {
        if self.signature.is_empty() {
            return false;
        }
        let data = self.get_signable_data();
        let Some(public_key) = crate::mesh::cert::get_ed25519_public_key(key) else {
            return false;
        };
        crate::mesh::cert::verify_ed25519(&data, &self.signature, &public_key)
    }

    fn get_signable_data(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.org_id, self.mesh_id, self.tier, self.timestamp, self.nonce
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameValidationError {
    TooShort,
    TooLong,
    InvalidCharacters,
    ContainsBadWord,
}

impl std::fmt::Display for NameValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NameValidationError::TooShort => write!(f, "name must be at least 2 characters"),
            NameValidationError::TooLong => write!(f, "name must be at most 50 characters"),
            NameValidationError::InvalidCharacters => {
                write!(
                    f,
                    "name can only contain letters, numbers, spaces, hyphens, and underscores"
                )
            }
            NameValidationError::ContainsBadWord => write!(f, "name contains disallowed content"),
        }
    }
}

const DEFAULT_BAD_ORG_NAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "help",
    "info",
    "contact",
    "security",
    "abuse",
    "moderator",
    "moderation",
    "nsfw",
    "porn",
    "sex",
    "xxx",
    "adult",
    "gamble",
    "casino",
    "bitcoin",
    "crypto",
    "wallet",
    "free",
    "gift",
    "win",
    "winner",
    "prize",
    "click",
    "link",
    "spam",
    "scam",
    "phish",
    "hack",
    "cracker",
    "terrorist",
    "violence",
    "weapon",
    "bomb",
    "kill",
    "death",
    "die",
    "suicide",
    "drug",
    "weapon",
    "child",
    "nude",
    "naked",
];

const DEFAULT_BAD_MESH_NAMES: &[&str] = &[
    "admin",
    "root",
    "system",
    "test",
    "default",
    "null",
    "none",
    "undefined",
];

pub fn sanitize_org_name(name: &str) -> Result<String, NameValidationError> {
    let trimmed = name.trim();
    let collapsed = collapse_whitespace(trimmed);

    if collapsed.len() < 2 {
        return Err(NameValidationError::TooShort);
    }
    if collapsed.len() > 50 {
        return Err(NameValidationError::TooLong);
    }

    if !is_valid_name_chars(&collapsed) {
        return Err(NameValidationError::InvalidCharacters);
    }

    let lower = collapsed.to_lowercase();
    for bad in DEFAULT_BAD_ORG_NAMES {
        if lower.contains(bad) {
            return Err(NameValidationError::ContainsBadWord);
        }
    }

    Ok(collapsed)
}

pub fn sanitize_org_name_with_config(
    name: &str,
    extra_bad_names: &[String],
) -> Result<String, NameValidationError> {
    let base_result = sanitize_org_name(name)?;

    let lower = base_result.to_lowercase();
    for bad in extra_bad_names {
        if lower.contains(&bad.to_lowercase()) {
            return Err(NameValidationError::ContainsBadWord);
        }
    }

    Ok(base_result)
}

pub fn sanitize_mesh_name(name: &str) -> Result<String, NameValidationError> {
    let trimmed = name.trim();
    let collapsed = collapse_whitespace(trimmed);

    if collapsed.len() < 2 {
        return Err(NameValidationError::TooShort);
    }
    if collapsed.len() > 50 {
        return Err(NameValidationError::TooLong);
    }

    if !is_valid_name_chars(&collapsed) {
        return Err(NameValidationError::InvalidCharacters);
    }

    let lower = collapsed.to_lowercase();
    for bad in DEFAULT_BAD_MESH_NAMES {
        if lower.contains(bad) {
            return Err(NameValidationError::ContainsBadWord);
        }
    }

    Ok(collapsed)
}

pub fn sanitize_mesh_name_with_config(
    name: &str,
    extra_bad_names: &[String],
) -> Result<String, NameValidationError> {
    let base_result = sanitize_mesh_name(name)?;

    let lower = base_result.to_lowercase();
    for bad in extra_bad_names {
        if lower.contains(&bad.to_lowercase()) {
            return Err(NameValidationError::ContainsBadWord);
        }
    }

    Ok(base_result)
}

fn collapse_whitespace(s: &str) -> String {
    let mut result = String::new();
    let mut last_was_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                result.push(' ');
                last_was_space = true;
            }
        } else {
            result.push(c);
            last_was_space = false;
        }
    }
    result.trim().to_string()
}

fn is_valid_name_chars(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || c == '-' || c == '_')
}

pub fn is_org_name_allowed(name: &str) -> bool {
    sanitize_org_name(name).is_ok()
}

pub fn is_mesh_name_allowed(name: &str) -> bool {
    sanitize_mesh_name(name).is_ok()
}

pub fn generate_invitation_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn derive_symmetric_key_from_token_and_pubkey(
    invitation_token: &str,
    node_public_key: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::mesh::cert::sign_hmac;
    let data = format!("{}:{}", invitation_token, hex::encode(node_public_key));
    sign_hmac(&data, invitation_token.as_bytes())
}

pub fn generate_invitation_proof(
    signing_key: &[u8],
    invitation_token: &str,
    org_id: &str,
    node_id: &str,
    node_public_key: &[u8],
) -> Result<String, String> {
    use crate::mesh::cert::sign_hmac;
    let symmetric_key =
        derive_symmetric_key_from_token_and_pubkey(invitation_token, node_public_key)?;
    let data = format!("{}:{}:{}", org_id, node_id, invitation_token);
    let hash = sign_hmac(&data, &symmetric_key)?;
    Ok(hex::encode(hash))
}

pub fn verify_invitation_proof(
    proof: &str,
    invitation_token: &str,
    org_id: &str,
    node_id: &str,
    node_public_key: &[u8],
) -> bool {
    use crate::mesh::cert::sign_hmac;
    let symmetric_key =
        match derive_symmetric_key_from_token_and_pubkey(invitation_token, node_public_key) {
            Ok(k) => k,
            Err(_) => return false,
        };
    let data = format!("{}:{}:{}", org_id, node_id, invitation_token);
    let expected = match sign_hmac(&data, &symmetric_key) {
        Ok(h) => h,
        Err(_) => return false,
    };
    if let Ok(decoded) = hex::decode(proof) {
        expected == decoded
    } else {
        false
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKeyAnnounce {
    pub org_id: String,
    pub key: TierKey,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKeyRevoke {
    pub org_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKeyQuery {
    pub request_id: String,
    pub org_id: String,
    pub requested_tier: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierKeyQueryResponse {
    pub request_id: String,
    pub keys: Vec<TierKey>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentTierKeyAnnounce {
    pub org_id: String,
    pub tier_keys: Vec<TierKey>,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrgPendingRequest {
    pub request_id: String,
    pub org_name: String,
    pub requesting_node_id: String,
    pub requesting_node_pubkey: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub status: OrgRequestStatus,
    pub created_at: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OrgRequestStatus {
    Pending,
    Approved,
    Rejected,
}

impl OrgPendingRequest {
    pub fn new(
        request_id: String,
        org_name: String,
        requesting_node_id: String,
        requesting_node_pubkey: String,
    ) -> Self {
        Self {
            request_id,
            org_name,
            requesting_node_id,
            requesting_node_pubkey,
            timestamp: crate::mesh::safe_unix_timestamp(),
            signature: Vec::new(),
            status: OrgRequestStatus::Pending,
            created_at: crate::mesh::safe_unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrgInvitation {
    pub request_id: String,
    pub org_id: String,
    pub inviter_node_id: String,
    pub invited_node_id: String,
    pub invited_node_pubkey: Option<String>,
    pub invitation_token: String,
    pub expires_at: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub status: OrgInvitationStatus,
    pub accepted_at: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OrgInvitationStatus {
    Pending,
    Accepted,
    Expired,
    Revoked,
}

impl OrgInvitation {
    pub fn new(
        request_id: String,
        org_id: String,
        inviter_node_id: String,
        invited_node_id: String,
        invited_node_pubkey: Option<String>,
        invitation_token: String,
        validity_hours: u64,
    ) -> Self {
        let now = crate::mesh::safe_unix_timestamp();
        Self {
            request_id,
            org_id,
            inviter_node_id,
            invited_node_id,
            invited_node_pubkey,
            invitation_token,
            expires_at: now + (validity_hours * 3600),
            timestamp: now,
            signature: Vec::new(),
            status: OrgInvitationStatus::Pending,
            accepted_at: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = crate::mesh::safe_unix_timestamp();
        now > self.expires_at
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OrganizationMember {
    pub node_id: String,
    pub node_pubkey: String,
    pub joined_at: u64,
    pub role: OrganizationRole,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum OrganizationRole {
    Admin,
    Member,
}

pub struct OrganizationManager {
    organizations: HashMap<String, Organization>,
    pending_requests: HashMap<String, OrgPendingRequest>,
    invitations: HashMap<String, OrgInvitation>,
    member_pubkeys: HashMap<String, String>,
    genesis_org_id: Option<String>,
}

impl OrganizationManager {
    pub fn new() -> Self {
        Self {
            organizations: HashMap::new(),
            pending_requests: HashMap::new(),
            invitations: HashMap::new(),
            member_pubkeys: HashMap::new(),
            genesis_org_id: None,
        }
    }

    pub fn set_genesis_org_id(&mut self, org_id: String) {
        if self.genesis_org_id.is_none() {
            self.genesis_org_id = Some(org_id);
        }
    }

    pub fn get_genesis_org_id(&self) -> Option<&String> {
        self.genesis_org_id.as_ref()
    }

    pub fn init_genesis_org(&mut self) {
        let genesis_org = Organization::new_genesis_org();
        let admin_org = Organization::new_admin_org();
        let genesis_org_id = genesis_org.org_id.clone();
        let admin_org_id = admin_org.org_id.clone();
        self.organizations.insert(genesis_org_id, genesis_org);
        self.organizations.insert(admin_org_id, admin_org);
        self.genesis_org_id = Some(ADMIN_ORG_ID.to_string());
        tracing::info!("Initialized genesis and admin organizations");
    }

    pub fn register_organization(&mut self, mut org: Organization) {
        let org_id = org.org_id.clone();
        self.organizations.insert(org_id, org);
    }

    pub fn get_organization(&self, org_id: &str) -> Option<&Organization> {
        self.organizations.get(org_id)
    }

    pub fn org_name_exists(&self, name: &str) -> bool {
        let lower_name = name.to_lowercase();
        self.organizations.values().any(|org| {
            org.name
                .as_ref()
                .map(|n| n.to_lowercase() == lower_name)
                .unwrap_or(false)
        })
    }

    pub fn get_all_organizations(&self) -> impl Iterator<Item = (&String, &Organization)> {
        self.organizations.iter()
    }

    pub fn get_organization_mut(&mut self, org_id: &str) -> Option<&mut Organization> {
        self.organizations.get_mut(org_id)
    }

    pub fn add_pending_request(&mut self, request: OrgPendingRequest) {
        let request_id = request.request_id.clone();
        self.pending_requests.insert(request_id, request);
    }

    pub fn get_pending_request(&self, request_id: &str) -> Option<&OrgPendingRequest> {
        self.pending_requests.get(request_id)
    }

    pub fn approve_pending_request(&mut self, request_id: &str) -> Option<OrgPendingRequest> {
        if let Some(req) = self.pending_requests.get_mut(request_id) {
            req.status = OrgRequestStatus::Approved;
            Some(req.clone())
        } else {
            None
        }
    }

    pub fn reject_pending_request(&mut self, request_id: &str) -> Option<OrgPendingRequest> {
        if let Some(req) = self.pending_requests.get_mut(request_id) {
            req.status = OrgRequestStatus::Rejected;
            Some(req.clone())
        } else {
            None
        }
    }

    pub fn get_all_pending_requests(&self) -> Vec<&OrgPendingRequest> {
        self.pending_requests
            .values()
            .filter(|r| r.status == OrgRequestStatus::Pending)
            .collect()
    }

    pub fn add_invitation(&mut self, invitation: OrgInvitation) {
        let node_id = invitation.invited_node_id.clone();
        self.invitations.insert(node_id, invitation);
    }

    pub fn get_invitation(&self, node_id: &str) -> Option<&OrgInvitation> {
        self.invitations.get(node_id)
    }

    pub fn accept_invitation(&mut self, node_id: &str) -> Option<OrgInvitation> {
        if let Some(inv) = self.invitations.get_mut(node_id) {
            if inv.status == OrgInvitationStatus::Pending && !inv.is_expired() {
                inv.status = OrgInvitationStatus::Accepted;
                inv.accepted_at = Some(crate::mesh::safe_unix_timestamp());
                return Some(inv.clone());
            }
        }
        None
    }

    pub fn register_member_pubkey(&mut self, node_id: &str, pubkey: String) {
        self.member_pubkeys.insert(node_id.to_string(), pubkey);
    }

    pub fn get_member_pubkey(&self, node_id: &str) -> Option<&String> {
        self.member_pubkeys.get(node_id)
    }

    pub fn issue_tier_key(
        &mut self,
        org_id: &str,
        tier: u32,
        key: Vec<u8>,
        valid_from: u64,
        valid_until: u64,
        issued_by: String,
    ) -> Option<TierKey> {
        if let Some(org) = self.organizations.get_mut(org_id) {
            let tier_key = TierKey::new(tier, key, valid_from, valid_until, issued_by);
            let result = tier_key.clone();
            org.tier_keys.push(tier_key);
            Some(result)
        } else {
            None
        }
    }

    pub fn revoke_tier_key(&mut self, org_id: &str, key_id: &str) -> bool {
        if let Some(org) = self.organizations.get_mut(org_id) {
            if let Some(key) = org.tier_keys.iter_mut().find(|k| k.key_id == key_id) {
                key.revoke();
                return true;
            }
        }
        false
    }

    pub fn unbind_tier_key(&mut self, org_id: &str, key_id: &str) -> bool {
        if let Some(org) = self.organizations.get_mut(org_id) {
            if let Some(key) = org.tier_keys.iter_mut().find(|k| k.key_id == key_id) {
                key.unbind();
                return true;
            }
        }
        false
    }

    pub fn bind_tier_key(&mut self, org_id: &str, key_id: &str) -> bool {
        if let Some(org) = self.organizations.get_mut(org_id) {
            if let Some(key) = org.tier_keys.iter_mut().find(|k| k.key_id == key_id) {
                key.bind(org_id);
                return true;
            }
        }
        false
    }

    pub fn get_unspent_tier_keys(&self, org_id: &str) -> Option<Vec<&TierKey>> {
        self.organizations.get(org_id).map(|org| {
            org.tier_keys
                .iter()
                .filter(|k| k.is_unspent && !k.revoked && k.is_valid())
                .collect()
        })
    }

    pub fn get_all_unspent_tier_keys(&self) -> Vec<(&str, &TierKey)> {
        let mut result = Vec::new();
        for (org_id, org) in &self.organizations {
            for key in &org.tier_keys {
                if key.is_unspent && !key.revoked && key.is_valid() {
                    result.push((org_id.as_str(), key));
                }
            }
        }
        result
    }

    pub fn get_all_tier_keys(&self) -> Vec<(&str, &TierKey)> {
        let mut result = Vec::new();
        for (org_id, org) in &self.organizations {
            for key in &org.tier_keys {
                result.push((org_id.as_str(), key));
            }
        }
        result
    }

    pub fn get_tier_key(&self, key_id: &str) -> Option<TierKey> {
        for org in self.organizations.values() {
            for key in &org.tier_keys {
                if key.key_id == key_id {
                    return Some(key.clone());
                }
            }
        }
        None
    }

    pub fn validate_tier_claim(&self, claim: &TierClaim) -> bool {
        if let Some(org) = self.organizations.get(&claim.org_id) {
            if let Some(key) = org.get_valid_tier_key(claim.tier) {
                if key.key_id == claim.key_id && claim.verify_signature(&key.key) {
                    // Organization must have an org_key to validate tier claims
                    let Some(ref org_key) = org.org_key else {
                        return false;
                    };
                    // Member must have a valid certificate
                    if let Some(cert) = org.get_valid_member_certificate(&claim.mesh_id) {
                        if cert.org_public_key_id == org_key.key_id {
                            return cert.verify(&org_key.private_key);
                        }
                    }
                    return false;
                }
            }
        }
        false
    }

    pub fn validate_tier_claim_with_org_verification(&self, claim: &TierClaim) -> bool {
        if let Some(org) = self.organizations.get(&claim.org_id) {
            if let Some(key) = org.get_valid_tier_key(claim.tier) {
                if key.key_id == claim.key_id && claim.verify_signature(&key.key) {
                    if let Some(ref org_key) = org.org_key {
                        if let Some(cert) = org.get_valid_member_certificate(&claim.mesh_id) {
                            return cert.verify(&org_key.private_key);
                        }
                    }
                }
            }
        }
        false
    }

    pub fn issue_member_certificate(
        &mut self,
        org_id: &str,
        mesh_id: String,
        validity_days: u64,
    ) -> Option<MemberCertificate> {
        if let Some(org) = self.organizations.get_mut(org_id) {
            if let Some(ref org_key) = org.org_key {
                let cert =
                    MemberCertificate::new(mesh_id, org_id.to_string(), org_key, validity_days);
                let result = cert.clone();
                org.add_member_certificate(cert);
                return Some(result);
            }
        }
        None
    }

    pub fn revoke_member_certificate(&mut self, org_id: &str, cert_id: &str) -> bool {
        if let Some(org) = self.organizations.get_mut(org_id) {
            return org.revoke_member_certificate(cert_id);
        }
        false
    }

    pub fn get_member_certificates(&self, org_id: &str) -> Option<Vec<&MemberCertificate>> {
        self.organizations
            .get(org_id)
            .map(|org| org.get_all_valid_member_certificates())
    }

    pub fn add_member_node(&mut self, org_id: &str, node_id: &str) -> bool {
        if let Some(org) = self.organizations.get_mut(org_id) {
            org.add_member_node(node_id.to_string());
            return true;
        }
        false
    }

    pub fn is_member(&self, org_id: &str, node_id: &str) -> bool {
        self.organizations
            .get(org_id)
            .map(|org| org.is_member(node_id))
            .unwrap_or(false)
    }
}

impl Default for OrganizationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_creation() {
        let org = Organization::new(Some("test-org".to_string()), Some("Test Org".to_string()));
        assert_eq!(org.org_id, "test-org");
        assert_eq!(org.name, Some("Test Org".to_string()));
        assert!(org.tier_keys.is_empty());
        assert!(org.member_nodes.is_empty());
    }

    #[test]
    fn test_add_remove_member_nodes() {
        let mut org = Organization::new(None, Some("Test".to_string()));
        org.add_member_node("node1".to_string());
        org.add_member_node("node2".to_string());
        org.add_member_node("node1".to_string()); // duplicate

        assert_eq!(org.member_nodes.len(), 2);
        assert!(org.is_member("node1"));
        assert!(org.is_member("node2"));
        assert!(!org.is_member("node3"));

        org.remove_member_node("node1");
        assert!(!org.is_member("node1"));
        assert!(org.is_member("node2"));
    }

    #[test]
    fn test_tier_key_validity() {
        let now = crate::mesh::safe_unix_timestamp();

        let mut org = Organization::new(None, Some("Test".to_string()));
        let key = TierKey::new(
            1,
            b"test_key".to_vec(),
            now - 100,
            now + 1000,
            "issuer".to_string(),
        );
        org.tier_keys.push(key);

        assert!(org.get_valid_tier_key(1).is_some());
        assert!(org.get_valid_tier_key(2).is_none()); // wrong tier
    }

    #[test]
    fn test_tier_key_expiration() {
        let now = crate::mesh::safe_unix_timestamp();

        let mut org = Organization::new(None, Some("Test".to_string()));
        let key = TierKey::new(
            1,
            b"expired_key".to_vec(),
            now - 1000,
            now - 100, // expired
            "issuer".to_string(),
        );
        org.tier_keys.push(key);

        assert!(
            org.get_valid_tier_key(1).is_none(),
            "Expired key should not be valid"
        );
    }

    #[test]
    fn test_tier_key_revocation() {
        let now = crate::mesh::safe_unix_timestamp();

        let mut org = Organization::new(None, Some("Test".to_string()));
        let mut key = TierKey::new(
            1,
            b"revokable_key".to_vec(),
            now - 100,
            now + 1000,
            "issuer".to_string(),
        );
        org.tier_keys.push(key.clone());

        assert!(key.is_valid());
        key.revoke();
        assert!(!key.is_valid());
    }

    #[test]
    fn test_tier_claim_signing() {
        let key = b"secret_signing_key";
        let mut claim = TierClaim::new(
            1,
            "key_id".to_string(),
            "org_id".to_string(),
            "mesh_id_123".to_string(),
            "nonce123".to_string(),
        );

        assert!(claim.signature.is_empty());
        claim.sign(key);
        assert!(!claim.signature.is_empty());
        assert!(claim.verify_signature(key));
        assert!(!claim.verify_signature(b"wrong_key"));
    }

    #[test]
    fn test_invitation_token_generation() {
        let token1 = generate_invitation_token();
        let token2 = generate_invitation_token();

        assert_eq!(token1.len(), 64); // 32 bytes = 64 hex chars
        assert_ne!(token1, token2, "Tokens should be unique");
    }

    #[test]
    fn test_invitation_proof_roundtrip() {
        let signing_key = b"org_signing_key_1234567890";
        let node_pubkey = b"node_public_key_bytes";

        let token = generate_invitation_token();
        let org_id = "test_org";
        let node_id = "test_node";

        let proof =
            generate_invitation_proof(signing_key, &token, org_id, node_id, node_pubkey).unwrap();

        assert!(verify_invitation_proof(
            &proof,
            &token,
            org_id,
            node_id,
            node_pubkey
        ));
        assert!(!verify_invitation_proof(
            &proof,
            &token,
            org_id,
            node_id,
            b"wrong_pubkey"
        ));
        assert!(!verify_invitation_proof(
            &proof,
            "wrong_token",
            org_id,
            node_id,
            node_pubkey
        ));
    }

    #[test]
    fn test_organization_manager_pending_requests() {
        let mut mgr = OrganizationManager::new();

        let request = OrgPendingRequest::new(
            "req_1".to_string(),
            "My Org".to_string(),
            "node_1".to_string(),
            "pubkey_1".to_string(),
        );

        mgr.add_pending_request(request);
        assert!(mgr.get_pending_request("req_1").is_some());

        let approved = mgr.approve_pending_request("req_1").unwrap();
        assert_eq!(approved.status, OrgRequestStatus::Approved);

        assert!(mgr.get_all_pending_requests().is_empty());
    }

    #[test]
    fn test_organization_manager_invitations() {
        let mut mgr = OrganizationManager::new();

        let invitation = OrgInvitation::new(
            "req_1".to_string(),
            "org_1".to_string(),
            "inviter_node".to_string(),
            "invited_node".to_string(),
            Some("pubkey".to_string()),
            "token123".to_string(),
            24, // 24 hours
        );

        mgr.add_invitation(invitation);
        assert!(mgr.get_invitation("invited_node").is_some());

        let accepted = mgr.accept_invitation("invited_node").unwrap();
        assert_eq!(accepted.status, OrgInvitationStatus::Accepted);
        assert!(accepted.accepted_at.is_some());
    }

    #[test]
    fn test_invitation_expiration() {
        let now = crate::mesh::safe_unix_timestamp();

        let mut invitation = OrgInvitation {
            request_id: "req_1".to_string(),
            org_id: "org_1".to_string(),
            inviter_node_id: "inviter".to_string(),
            invited_node_id: "invited".to_string(),
            invited_node_pubkey: None,
            invitation_token: "token".to_string(),
            expires_at: now - 1, // already in the past
            timestamp: now - 2,
            signature: Vec::new(),
            status: OrgInvitationStatus::Pending,
            accepted_at: None,
        };

        assert!(invitation.is_expired());

        invitation.expires_at = now + 3600; // 1 hour from now
        assert!(!invitation.is_expired());
    }

    #[test]
    fn test_tier_key_issuance() {
        let mut mgr = OrganizationManager::new();

        let org = Organization::new(Some("org_1".to_string()), Some("Test".to_string()));
        mgr.register_organization(org);

        let key = mgr.issue_tier_key(
            "org_1",
            2,
            b"tier_2_key".to_vec(),
            0,
            1000,
            "admin".to_string(),
        );

        assert!(key.is_some());
        assert_eq!(mgr.get_organization("org_1").unwrap().tier_keys.len(), 1);
    }

    #[test]
    fn test_org_name_exists() {
        let mut mgr = OrganizationManager::new();

        let org = Organization::new(None, Some("UniqueOrg".to_string()));
        mgr.register_organization(org);

        assert!(mgr.org_name_exists("UniqueOrg"));
        assert!(!mgr.org_name_exists("NonExistent"));
    }

    #[test]
    fn test_org_key_generation() {
        let org_key = OrgKey::generate(Some("global_node".to_string()));

        assert_eq!(org_key.key_id.len(), 36); // UUID format
        assert_eq!(org_key.private_key.len(), 32);
        assert!(org_key.public_key.len() > 0);
        assert!(org_key.issued_by.is_some());
    }

    #[test]
    fn test_org_key_sign_verify() {
        let org_key = OrgKey::generate(None);

        let message = "test message for signing";
        let signature = org_key.sign(message);

        assert!(!signature.is_empty());
        assert!(org_key.verify(message, &signature));
        assert!(!org_key.verify("wrong message", &signature));
    }

    #[test]
    fn test_member_certificate_creation() {
        let org_key = OrgKey::generate(None);
        let mesh_id = "node_123".to_string();
        let org_id = "org_456".to_string();

        let cert = MemberCertificate::new(
            mesh_id.clone(),
            org_id.clone(),
            &org_key,
            30, // 30 days validity
        );

        assert_eq!(cert.mesh_id, mesh_id);
        assert_eq!(cert.org_id, org_id);
        assert!(cert.is_valid());
        assert!(!cert.signature.is_empty());
    }

    #[test]
    fn test_member_certificate_verification() {
        let org_key = OrgKey::generate(None);

        let cert =
            MemberCertificate::new("node_123".to_string(), "org_456".to_string(), &org_key, 30);

        assert!(cert.verify(&org_key.private_key));
        assert!(!cert.verify(b"wrong_key"));
    }

    #[test]
    fn test_organization_with_org_key() {
        let org_key = OrgKey::generate(None);

        let mut org = Organization::new(Some("org_1".to_string()), Some("Test Org".to_string()));
        org.set_org_key(org_key.clone());

        assert!(org.org_key.is_some());
        assert_eq!(
            org.org_key.as_ref().unwrap().public_key_hex().len(),
            org_key.public_key_hex().len()
        );
    }

    #[test]
    fn test_organization_member_certificates() {
        let org_key = OrgKey::generate(None);

        let mut org = Organization::new(Some("org_1".to_string()), Some("Test Org".to_string()));
        org.set_org_key(org_key.clone());

        let cert = MemberCertificate::new("node_1".to_string(), "org_1".to_string(), &org_key, 30);

        org.add_member_certificate(cert.clone());

        assert_eq!(org.member_certificates.len(), 1);
        assert!(org.get_valid_member_certificate("node_1").is_some());
        assert!(org.get_valid_member_certificate("node_2").is_none());
    }

    #[test]
    fn test_validate_tier_claim_with_certificate() {
        let org_key = OrgKey::generate(None);

        let now = crate::mesh::safe_unix_timestamp();
        let future = now + 86400 * 365; // 1 year from now

        let mut org = Organization::new(Some("org_1".to_string()), Some("Test Org".to_string()));

        // Issue tier key to org first
        let tier_key = TierKey::new(
            1,
            b"tier_1_key".to_vec(),
            now - 100, // valid from: 100 seconds ago
            future,    // valid until: 1 year from now
            "global_node".to_string(),
        );
        let tier_key_id = tier_key.key_id.clone();
        let tier_key_bytes = tier_key.key.clone();
        org.tier_keys.push(tier_key);

        // Set org key BEFORE creating certificate (so cert has correct key_id ref)
        org.set_org_key(org_key.clone());

        // Add member certificate
        let cert = MemberCertificate::new("node_1".to_string(), "org_1".to_string(), &org_key, 30);
        org.add_member_certificate(cert);

        let mut mgr = OrganizationManager::new();
        mgr.register_organization(org);

        // Create tier claim for the node
        let mut claim = TierClaim::new(
            1,
            tier_key_id.clone(),
            "org_1".to_string(),
            "node_1".to_string(),
            "nonce123".to_string(),
        );
        claim.sign(&tier_key_bytes);

        let result = mgr.validate_tier_claim(&claim);
        assert!(result, "Tier claim with valid certificate should validate");

        // Wrong mesh_id should fail
        let mut bad_claim = TierClaim::new(
            1,
            tier_key_id,
            "org_1".to_string(),
            "unknown_node".to_string(),
            "nonce123".to_string(),
        );
        bad_claim.sign(&tier_key_bytes);

        assert!(!mgr.validate_tier_claim(&bad_claim));
    }
}
