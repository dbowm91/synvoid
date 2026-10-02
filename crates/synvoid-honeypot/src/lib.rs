pub mod ai_budget;
#[cfg(test)]
mod ai_responder_containment_tests;
pub mod config;
#[cfg(test)]
mod config_tests;
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
mod time;

pub use ai_budget::{
    AiCircuitBreaker, AiConcurrencyLimiter, AiConcurrencyPermit, AiTurnCounter, BudgetExceeded,
};
pub use config::{
    AiBudgetConfig, AiConfig, AiResponderMode, HoneypotConfigError, PayloadRetentionMode,
    PortHoneypotConfig, ResponseModeConfig, StablePortConfig, StorageWriterConfig,
    ThreatIntelConfig, MAX_AI_CONCURRENCY, MAX_AI_PROMPT_BYTES, MAX_AI_RESPONSE_BYTES,
    MAX_CONFIGURED_RESPONSE_BYTES, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP, MAX_LISTENERS,
    MAX_PORT_SCAN_SPAN, MAX_RETAINED_PAYLOAD_BYTES, MAX_STORAGE_BATCH_SIZE,
    MAX_STORAGE_QUEUE_CAPACITY,
};
pub use controller::PortHoneypotController;
pub use listener::PortHoneypotListener;
pub use mesh_control::{
    HoneypotControlCommand, HoneypotControlError, HoneypotMeshController, HoneypotStatus,
};
pub use protocol::{Confidence, ProtocolDetector, ProtocolMatch, ServiceBanner};
pub use responders::{
    default_ssh_system_prompt, http_system_prompt, mysql_system_prompt, redis_system_prompt,
    AiHoneypotResponder, AiProvider, AiProviderResponse, AiProviderTransport,
    AiProviderTransportError, AiResponder, AiResponderBudget, AnthropicResponder, OllamaResponder,
    OpenAIResponder, StaticResponder, TemplateResponder, VulnerableAppResponder,
};
pub use responses::{
    HoneypotContext, HoneypotResponder, HoneypotResponderRegistry, HoneypotResponse, ResponseType,
};
pub use rotation::{PortInfo, PortManager, PortMode, StablePort};
pub use runner::PortHoneypotRunner;
pub use storage::HoneypotStorage;
pub use storage_writer::HoneypotWriter;
pub use threat_intel::{
    HoneypotIndicator, HoneypotIntelExtractor, HoneypotSignalScore, HoneypotThreatPublisher,
    IndicatorActionClass, IndicatorType, ScoringConfig, SeverityLevel, SignalClass,
};

#[cfg(test)]
mod listener_tests;
#[cfg(test)]
mod storage_writer_tests;
