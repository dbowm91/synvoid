use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Clone)]
pub struct HoneypotContext {
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub service: String,
    pub protocol: String,
    pub payload: Vec<u8>,
    pub payload_hex: String,
    pub detected_pattern: Option<String>,
    pub bytes_received: u32,
    pub duration_ms: u32,
    pub connection_start: Instant,
}

impl HoneypotContext {
    pub fn from_record(record: &super::storage::HoneypotRecord) -> Self {
        Self {
            remote_ip: record.remote_ip.clone(),
            remote_port: record.remote_port,
            local_port: record.local_port,
            service: record.service.clone(),
            protocol: record.protocol.clone(),
            payload: record.payload.clone(),
            payload_hex: record.payload_hex.clone(),
            detected_pattern: record.detected_pattern.clone(),
            bytes_received: record.bytes_received,
            duration_ms: record.duration_ms,
            connection_start: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HoneypotResponse {
    pub data: Vec<u8>,
    pub response_type: ResponseType,
    pub close_connection: bool,
    pub follow_up_expected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseType {
    Static,
    Dynamic,
    AiGenerated,
    VulnerableApp,
    Error,
}

impl HoneypotResponse {
    pub fn static_response(data: Vec<u8>) -> Self {
        Self {
            data,
            response_type: ResponseType::Static,
            close_connection: false,
            follow_up_expected: false,
        }
    }

    pub fn with_options(
        data: Vec<u8>,
        response_type: ResponseType,
        close_connection: bool,
        follow_up_expected: bool,
    ) -> Self {
        Self {
            data,
            response_type,
            close_connection,
            follow_up_expected,
        }
    }
}

#[async_trait::async_trait]
pub trait HoneypotResponder: Send + Sync {
    fn name(&self) -> &str;

    fn service_type(&self) -> &str;

    fn respond(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse;

    async fn respond_async(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        self.respond(payload, context)
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder>;
}

#[async_trait::async_trait]
pub trait AiResponder: Send + Sync {
    async fn generate_response(
        &self,
        prompt: &str,
        context: &HoneypotContext,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>>;

    fn clone_box(&self) -> Box<dyn AiResponder>;
}

pub struct HoneypotResponderRegistry {
    pub responders: std::collections::HashMap<String, std::sync::Arc<dyn HoneypotResponder>>,
    pub ai_responders: std::collections::HashMap<String, std::sync::Arc<dyn AiResponder>>,
}

impl HoneypotResponderRegistry {
    pub fn new() -> Self {
        Self {
            responders: std::collections::HashMap::new(),
            ai_responders: std::collections::HashMap::new(),
        }
    }

    pub fn register(&mut self, responder: std::sync::Arc<dyn HoneypotResponder>) {
        self.responders
            .insert(responder.name().to_string(), responder);
    }

    pub fn register_ai(&mut self, name: String, responder: std::sync::Arc<dyn AiResponder>) {
        self.ai_responders.insert(name, responder);
    }

    pub fn get(&self, name: &str) -> Option<std::sync::Arc<dyn HoneypotResponder>> {
        self.responders.get(name).cloned()
    }

    pub fn get_ai(&self, name: &str) -> Option<std::sync::Arc<dyn AiResponder>> {
        self.ai_responders.get(name).cloned()
    }

    pub fn get_or_default(&self, service: &str) -> Option<std::sync::Arc<dyn HoneypotResponder>> {
        self.responders
            .get(service)
            .or_else(|| self.responders.get("default"))
            .cloned()
    }

    pub fn list_services(&self) -> Vec<String> {
        self.responders.keys().cloned().collect()
    }
}

impl Clone for HoneypotResponderRegistry {
    fn clone(&self) -> Self {
        Self {
            responders: self.responders.clone(),
            ai_responders: self.ai_responders.clone(),
        }
    }
}

impl Default for HoneypotResponderRegistry {
    fn default() -> Self {
        Self::new()
    }
}
