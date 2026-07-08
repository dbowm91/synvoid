pub mod ai;
pub mod r#static;
pub mod vulnerable;

pub use crate::responses::AiResponder;
pub use ai::{
    default_ssh_system_prompt, http_system_prompt, mysql_system_prompt, postgresql_system_prompt,
    rdp_system_prompt, redis_system_prompt, smb_system_prompt, smtp_system_prompt,
    vnc_system_prompt, AiProvider, AiResponderBudget, AnthropicResponder, OllamaResponder,
    OpenAIResponder,
};
pub use r#static::StaticResponder;
pub use vulnerable::VulnerableAppResponder;

use crate::ai_budget::{fallback_response, AiTurnCounter};
use crate::config::AiBudgetConfig;
use crate::responses::{HoneypotContext, HoneypotResponder, HoneypotResponse, ResponseType};
use async_trait::async_trait;

// ---------------------------------------------------------------------------
// Template-only responder — deterministic, no external calls
// ---------------------------------------------------------------------------

/// Deterministic template responder. Produces protocol-appropriate banner bytes
/// without any external calls, AI providers, or unbounded generation.
pub struct TemplateResponder {
    name: String,
    service_type: String,
    template: Vec<u8>,
}

impl TemplateResponder {
    pub fn new(name: String, service_type: String, template: Vec<u8>) -> Self {
        Self {
            name,
            service_type,
            template,
        }
    }

    pub fn ssh() -> Self {
        Self::new(
            "template_ssh".to_string(),
            "ssh".to_string(),
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n".to_vec(),
        )
    }

    pub fn http() -> Self {
        Self::new(
            "template_http".to_string(),
            "http".to_string(),
            b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n".to_vec(),
        )
    }

    pub fn mysql() -> Self {
        Self::new(
            "template_mysql".to_string(),
            "mysql".to_string(),
            vec![
                0x0a, 0x00, 0x00, 0x01, 0xff, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        )
    }

    pub fn redis() -> Self {
        Self::new(
            "template_redis".to_string(),
            "redis".to_string(),
            b"+OK\r\n".to_vec(),
        )
    }

    pub fn postgresql() -> Self {
        Self::new(
            "template_postgresql".to_string(),
            "postgresql".to_string(),
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
        )
    }

    pub fn ftp() -> Self {
        Self::new(
            "template_ftp".to_string(),
            "ftp".to_string(),
            b"220 (vsFTPd 3.0.3)\r\n".to_vec(),
        )
    }

    pub fn smtp() -> Self {
        Self::new(
            "template_smtp".to_string(),
            "smtp".to_string(),
            b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
        )
    }
}

impl Clone for Box<dyn HoneypotResponder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[async_trait]
impl HoneypotResponder for TemplateResponder {
    fn name(&self) -> &str {
        &self.name
    }

    fn service_type(&self) -> &str {
        &self.service_type
    }

    fn respond(&self, _payload: &[u8], _context: &HoneypotContext) -> HoneypotResponse {
        HoneypotResponse::with_options(self.template.clone(), ResponseType::Static, false, false)
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder> {
        Box::new(Self {
            name: self.name.clone(),
            service_type: self.service_type.clone(),
            template: self.template.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// AI-backed honeypot responder — fully async, budget-enforced
// ---------------------------------------------------------------------------

pub struct AiHoneypotResponder {
    name: String,
    service_type: String,
    ai_responder: Box<dyn AiResponder>,
    system_prompt: String,
    turn_counter: AiTurnCounter,
    budget_config: AiBudgetConfig,
}

impl AiHoneypotResponder {
    pub fn new(
        name: String,
        service_type: String,
        ai_responder: Box<dyn AiResponder>,
        system_prompt: String,
        budget_config: AiBudgetConfig,
    ) -> Self {
        let max_turns = budget_config.max_turns_per_connection;
        Self {
            name,
            service_type,
            ai_responder,
            system_prompt,
            turn_counter: AiTurnCounter::new(max_turns),
            budget_config,
        }
    }

    pub fn ssh(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_ssh".to_string(),
            "ssh".to_string(),
            ai_responder,
            default_ssh_system_prompt(),
            budget_config,
        )
    }

    pub fn http(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_http".to_string(),
            "http".to_string(),
            ai_responder,
            http_system_prompt(),
            budget_config,
        )
    }

    pub fn mysql(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_mysql".to_string(),
            "mysql".to_string(),
            ai_responder,
            mysql_system_prompt(),
            budget_config,
        )
    }

    pub fn redis(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_redis".to_string(),
            "redis".to_string(),
            ai_responder,
            redis_system_prompt(),
            budget_config,
        )
    }

    pub fn postgresql(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_postgresql".to_string(),
            "postgresql".to_string(),
            ai_responder,
            postgresql_system_prompt(),
            budget_config,
        )
    }

    pub fn smb(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_smb".to_string(),
            "smb".to_string(),
            ai_responder,
            smb_system_prompt(),
            budget_config,
        )
    }

    pub fn rdp(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_rdp".to_string(),
            "rdp".to_string(),
            ai_responder,
            rdp_system_prompt(),
            budget_config,
        )
    }

    pub fn vnc(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_vnc".to_string(),
            "vnc".to_string(),
            ai_responder,
            vnc_system_prompt(),
            budget_config,
        )
    }

    pub fn smtp(ai_responder: Box<dyn AiResponder>, budget_config: AiBudgetConfig) -> Self {
        Self::new(
            "ai_smtp".to_string(),
            "smtp".to_string(),
            ai_responder,
            smtp_system_prompt(),
            budget_config,
        )
    }

    fn build_prompt(&self, payload: &[u8], context: &HoneypotContext) -> String {
        let payload_str = if let Ok(s) = std::str::from_utf8(payload) {
            s.trim().to_string()
        } else {
            format!("[binary data: {} bytes]", payload.len())
        };

        format!(
            "Context: connection from {}:{} to port {} ({} service)\n\
             The client sent: {}\n\
             Provide an appropriate response as the simulated service would.",
            context.remote_ip,
            context.remote_port,
            context.local_port,
            context.service,
            payload_str,
        )
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

    /// Synchronous path — returns a generic fallback. Callers MUST prefer
    /// `respond_async` for AI-backed generation. The sync path exists only to
    /// satisfy the trait contract and never calls `block_on`.
    fn respond(&self, _payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        HoneypotResponse::with_options(
            fallback_response(&context.service),
            ResponseType::Static,
            false,
            false,
        )
    }

    async fn respond_async(&self, payload: &[u8], context: &HoneypotContext) -> HoneypotResponse {
        // Turn budget check
        if !self.turn_counter.try_increment() {
            metrics::counter!("honeypot_ai_turns_exceeded").increment(1);
            return HoneypotResponse::with_options(
                fallback_response(&context.service),
                ResponseType::Static,
                false,
                false,
            );
        }

        let prompt = self.build_prompt(payload, context);

        match self.ai_responder.generate_response(&prompt, context).await {
            Ok(response_text) => {
                metrics::counter!("honeypot_ai_responses_success").increment(1);
                HoneypotResponse::with_options(
                    response_text.into_bytes(),
                    ResponseType::AiGenerated,
                    false,
                    true,
                )
            }
            Err(e) => {
                metrics::counter!("honeypot_ai_responses_fallback").increment(1);
                tracing::debug!(
                    error = %e,
                    service = %context.service,
                    remote_ip = %context.remote_ip,
                    "AI responder fallback — provider error"
                );
                // Never leak error details to attacker
                HoneypotResponse::with_options(
                    fallback_response(&context.service),
                    ResponseType::Static,
                    false,
                    false,
                )
            }
        }
    }

    fn clone_box(&self) -> Box<dyn HoneypotResponder> {
        Box::new(Self {
            name: self.name.clone(),
            service_type: self.service_type.clone(),
            ai_responder: self.ai_responder.clone_box(),
            system_prompt: self.system_prompt.clone(),
            turn_counter: AiTurnCounter::new(self.budget_config.max_turns_per_connection),
            budget_config: self.budget_config.clone(),
        })
    }
}
