pub mod r#static;
pub mod vulnerable;
pub mod ai;

pub use r#static::StaticResponder;
pub use vulnerable::VulnerableAppResponder;
pub use ai::{OllamaResponder, OpenAIResponder, AnthropicResponder, default_ssh_system_prompt, http_system_prompt, mysql_system_prompt, redis_system_prompt, postgresql_system_prompt, smb_system_prompt, rdp_system_prompt, vnc_system_prompt, smtp_system_prompt, AiProvider};
pub use crate::honeypot_port::responses::AiResponder;

use crate::honeypot_port::responses::{HoneypotContext, HoneypotResponder, HoneypotResponse, ResponseType};
use async_trait::async_trait;

pub struct AiHoneypotResponder {
    name: String,
    service_type: String,
    ai_responder: Box<dyn AiResponder>,
    system_prompt: String,
}

impl AiHoneypotResponder {
    pub fn new(
        name: String,
        service_type: String,
        ai_responder: Box<dyn AiResponder>,
        system_prompt: String,
    ) -> Self {
        Self {
            name,
            service_type,
            ai_responder,
            system_prompt,
        }
    }

    pub fn ssh(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_ssh".to_string(),
            "ssh".to_string(),
            ai_responder,
            default_ssh_system_prompt(),
        )
    }

    pub fn http(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_http".to_string(),
            "http".to_string(),
            ai_responder,
            http_system_prompt(),
        )
    }

    pub fn mysql(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_mysql".to_string(),
            "mysql".to_string(),
            ai_responder,
            mysql_system_prompt(),
        )
    }

    pub fn redis(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_redis".to_string(),
            "redis".to_string(),
            ai_responder,
            redis_system_prompt(),
        )
    }

    pub fn postgresql(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_postgresql".to_string(),
            "postgresql".to_string(),
            ai_responder,
            postgresql_system_prompt(),
        )
    }

    pub fn smb(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_smb".to_string(),
            "smb".to_string(),
            ai_responder,
            smb_system_prompt(),
        )
    }

    pub fn rdp(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_rdp".to_string(),
            "rdp".to_string(),
            ai_responder,
            rdp_system_prompt(),
        )
    }

    pub fn vnc(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_vnc".to_string(),
            "vnc".to_string(),
            ai_responder,
            vnc_system_prompt(),
        )
    }

    pub fn smtp(ai_responder: Box<dyn AiResponder>) -> Self {
        Self::new(
            "ai_smtp".to_string(),
            "smtp".to_string(),
            ai_responder,
            smtp_system_prompt(),
        )
    }
}

impl Clone for Box<dyn HoneypotResponder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[async_trait]
impl HoneypotResponder for AiHoneypotResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn service_type(&self) -> &str {
        &self.service_type
    }

    fn respond(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        let payload_str = if let Ok(s) = std::str::from_utf8(payload) {
            s.trim().to_string()
        } else {
            format!("[binary data: {} bytes]", payload.len())
        };

        let prompt = format!(
            "Context: {} connecting from {} to port {} ({} service)\n\
            Previous data: {}\n\
            The attacker sent: {}\n\
            Provide an appropriate response as the simulated service would.",
            context.remote_ip,
            context.remote_port,
            context.local_port,
            context.service,
            context.payload_hex.chars().take(100).collect::<String>(),
            payload_str
        );

        let response_text = tokio::runtime::Handle::current()
            .block_on(self.ai_responder.generate_response(&prompt, context))
            .unwrap_or_else(|e| format!("Error generating response: {}", e));

        HoneypotResponse::with_options(
            response_text.into_bytes(),
            ResponseType::AiGenerated,
            false,
            true,
        )
    }

    async fn respond_async(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        let payload_str = if let Ok(s) = std::str::from_utf8(payload) {
            s.trim().to_string()
        } else {
            format!("[binary data: {} bytes]", payload.len())
        };

        let prompt = format!(
            "Context: {} connecting from {} to port {} ({} service)\n\
            Previous data: {}\n\
            The attacker sent: {}\n\
            Provide an appropriate response as the simulated service would.",
            context.remote_ip,
            context.remote_port,
            context.local_port,
            context.service,
            context.payload_hex.chars().take(100).collect::<String>(),
            payload_str
        );

        match self.ai_responder.generate_response(&prompt, context).await {
            Ok(response_text) => HoneypotResponse::with_options(
                response_text.into_bytes(),
                ResponseType::AiGenerated,
                false,
                true,
            ),
            Err(e) => HoneypotResponse::static_response(
                format!("Error: {}", e).into_bytes(),
            ),
        }
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder> {
        Box::new(Self {
            name: self.name.clone(),
            service_type: self.service_type.clone(),
            ai_responder: self.ai_responder.clone_box(),
            system_prompt: self.system_prompt.clone(),
        })
    }
}
