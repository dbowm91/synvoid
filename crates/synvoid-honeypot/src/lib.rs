pub mod ai_budget;
#[cfg(test)]
mod ai_responder_containment_tests;
pub mod config;
pub mod controller;
pub mod listener;
pub mod mesh_control;
pub mod protocol;
pub mod responders;
pub mod responses;
pub mod rotation;
pub mod runner;
pub mod storage;
pub mod storage_writer;
pub mod threat_intel;

pub use ai_budget::{
    AiCircuitBreaker, AiConcurrencyLimiter, AiConcurrencyPermit, AiTurnCounter, BudgetExceeded,
};
pub use config::{
    AiBudgetConfig, AiConfig, AiResponderMode, PayloadRetentionMode, PortHoneypotConfig,
    ResponseModeConfig, StablePortConfig, StorageWriterConfig, ThreatIntelConfig,
};
pub use controller::PortHoneypotController;
pub use listener::PortHoneypotListener;
pub use mesh_control::{
    HoneypotControlCommand, HoneypotControlError, HoneypotMeshController, HoneypotStatus,
};
pub use protocol::{Confidence, ProtocolDetector, ProtocolMatch, ServiceBanner};
pub use responders::{
    default_ssh_system_prompt, http_system_prompt, mysql_system_prompt, redis_system_prompt,
    AiHoneypotResponder, AiProvider, AiResponder, AiResponderBudget, AnthropicResponder,
    OllamaResponder, OpenAIResponder, StaticResponder, TemplateResponder, VulnerableAppResponder,
};
pub use responses::{
    HoneypotContext, HoneypotResponder, HoneypotResponderRegistry, HoneypotResponse, ResponseType,
};
pub use rotation::{PortInfo, PortManager, PortMode, StablePort};
pub use runner::PortHoneypotRunner;
pub use storage::HoneypotStorage;
pub use storage_writer::HoneypotWriter;
pub use threat_intel::{
    HoneypotIndicator, HoneypotIntelExtractor, HoneypotSignalScore, IndicatorActionClass,
    IndicatorType, ScoringConfig, SeverityLevel, SignalClass,
};

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod storage_writer_tests;
