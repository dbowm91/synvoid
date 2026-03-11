pub mod config;
pub mod storage;
pub mod protocol;
pub mod listener;
pub mod runner;
pub mod responses;
pub mod responders;
pub mod rotation;
pub mod mesh_control;
pub mod threat_intel;

pub use config::{PortHoneypotConfig, StablePortConfig, ResponseModeConfig, AiConfig};
pub use storage::HoneypotStorage;
pub use protocol::{ProtocolDetector, ProtocolMatch, ServiceBanner};
pub use listener::PortHoneypotListener;
pub use runner::PortHoneypotRunner;
pub use responses::{
    HoneypotContext, HoneypotResponse, ResponseType, HoneypotResponder, HoneypotResponderRegistry,
};
pub use responders::{
    StaticResponder, VulnerableAppResponder,
    AiResponder, AiProvider, OllamaResponder, OpenAIResponder, AnthropicResponder,
    default_ssh_system_prompt, http_system_prompt, mysql_system_prompt, redis_system_prompt,
    AiHoneypotResponder,
};
pub use rotation::{PortManager, PortMode, StablePort, PortInfo};
pub use mesh_control::{HoneypotMeshController, HoneypotControlCommand, HoneypotStatus, HoneypotControlError};
pub use threat_intel::{HoneypotIntelExtractor, HoneypotIndicator, IndicatorType, SeverityLevel, HoneypotThreatPublisher};
