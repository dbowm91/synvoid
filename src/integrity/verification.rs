//! Verification of signed HTTP messages

use http::HeaderMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::integrity::signing::{headers_to_map, parse_integrity_headers, HttpMessageVerifier};
use crate::integrity::{IntegrityConfig, SessionKey};

#[derive(Debug, Clone)]
pub enum VerificationResult {
    Valid,
    Invalid(String),
    NoIntegrityHeader,
    SessionNotFound,
    SessionExpired,
    SignatureMismatch,
    EdgeTamperingDetected,
}

pub struct IntegrityVerifier {
    verifier: Arc<HttpMessageVerifier>,
    config: Arc<IntegrityConfig>,
    sessions: Arc<RwLock<HashMap<String, SessionKey>>>,
}

impl IntegrityVerifier {
    pub fn new(config: IntegrityConfig) -> Self {
        Self {
            verifier: Arc::new(HttpMessageVerifier::new()),
            config: Arc::new(config),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_session(&self, session: SessionKey) {
        self.verifier.add_session(session.clone());
        self.sessions
            .write()
            .insert(session.session_id.clone(), session);
    }

    pub fn remove_session(&self, session_id: &str) {
        self.verifier.remove_session(session_id);
        self.sessions.write().remove(session_id);
    }

    pub fn verify_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> VerificationResult {
        if !self.config.is_enabled() {
            return VerificationResult::NoIntegrityHeader;
        }

        let (integrity_header, signature) = match parse_integrity_headers(headers) {
            Some(h) => h,
            None => {
                if self.config.is_enforced() {
                    return VerificationResult::NoIntegrityHeader;
                }
                return VerificationResult::NoIntegrityHeader;
            }
        };

        let session = {
            let sessions = self.sessions.read();
            match sessions.get(&integrity_header.session_id) {
                Some(s) => s.clone(),
                None => {
                    if self.config.is_audit_only() {
                        tracing::warn!(
                            "Integrity session not found: {}",
                            integrity_header.session_id
                        );
                        return VerificationResult::SessionNotFound;
                    }
                    return VerificationResult::SessionNotFound;
                }
            }
        };

        if session.is_expired() {
            if self.config.is_audit_only() {
                tracing::warn!("Integrity session expired: {}", integrity_header.session_id);
                return VerificationResult::SessionExpired;
            }
            return VerificationResult::SessionExpired;
        }

        let headers_map = headers_to_map(headers);

        match self.verifier.verify_request(
            method,
            path,
            query,
            &headers_map,
            body,
            &integrity_header,
            &signature,
        ) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid("Verification returned false".to_string()),
            Err(e) => {
                tracing::warn!("Integrity verification failed: {}", e);
                VerificationResult::SignatureMismatch
            }
        }
    }

    pub fn verify_response(
        &self,
        status: u16,
        headers: &HeaderMap,
        body: Option<&[u8]>,
    ) -> VerificationResult {
        if !self.config.is_enabled() {
            return VerificationResult::NoIntegrityHeader;
        }

        let (integrity_header, signature) = match parse_integrity_headers(headers) {
            Some(h) => h,
            None => {
                if self.config.is_enforced() {
                    return VerificationResult::NoIntegrityHeader;
                }
                return VerificationResult::NoIntegrityHeader;
            }
        };

        let session = {
            let sessions = self.sessions.read();
            match sessions.get(&integrity_header.session_id) {
                Some(s) => s.clone(),
                None => {
                    if self.config.is_audit_only() {
                        tracing::warn!(
                            "Integrity session not found for response: {}",
                            integrity_header.session_id
                        );
                        return VerificationResult::SessionNotFound;
                    }
                    return VerificationResult::SessionNotFound;
                }
            }
        };

        if session.is_expired() {
            if self.config.is_audit_only() {
                tracing::warn!(
                    "Integrity session expired for response: {}",
                    integrity_header.session_id
                );
                return VerificationResult::SessionExpired;
            }
            return VerificationResult::SessionExpired;
        }

        let headers_map = headers_to_map(headers);

        match self.verifier.verify_response(
            status,
            &headers_map,
            body,
            &integrity_header,
            &signature,
        ) {
            Ok(true) => VerificationResult::Valid,
            Ok(false) => VerificationResult::Invalid("Verification returned false".to_string()),
            Err(e) => {
                tracing::warn!("Integrity response verification failed: {}", e);
                VerificationResult::SignatureMismatch
            }
        }
    }

    pub fn is_session_active(&self, session_id: &str) -> bool {
        self.sessions
            .read()
            .get(session_id)
            .map(|s| !s.is_expired())
            .unwrap_or(false)
    }

    pub fn get_session_count(&self) -> usize {
        self.sessions.read().len()
    }

    pub fn cleanup_expired(&self) {
        let expired: Vec<String> = self
            .sessions
            .read()
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        for id in expired {
            self.remove_session(&id);
        }
    }
}

pub struct AuditReporter {
    config: Arc<IntegrityConfig>,
}

impl AuditReporter {
    pub fn new(config: IntegrityConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn report_failure(&self, report: AuditReport) {
        if !self.config.is_enabled() {
            return;
        }

        if let Some(ref url) = self.config.audit_report_url {
            tracing::info!("Would report integrity failure to {}: {:?}", url, report);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditReport {
    pub timestamp: i64,
    pub session_id: String,
    pub mesh_id: String,
    pub node_id: String,
    pub failure_type: String,
    pub details: String,
    pub request_path: Option<String>,
    pub response_status: Option<u16>,
}

impl AuditReport {
    pub fn new(
        session_id: String,
        mesh_id: String,
        node_id: String,
        failure_type: VerificationResult,
        details: String,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            session_id,
            mesh_id,
            node_id,
            failure_type: format!("{:?}", failure_type),
            details,
            request_path: None,
            response_status: None,
        }
    }
}
