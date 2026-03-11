use std::sync::Arc;

pub type VpnEventCallback = Arc<dyn Fn(VpnEvent) + Send + Sync>;

#[derive(Debug, Clone)]
pub enum VpnEvent {
    Connected {
        session_id: String,
        access_level: String,
    },
    Disconnected {
        reason: String,
    },
    Reconnecting {
        attempt: u32,
    },
    PortMappingAdded {
        identifier: String,
    },
    PortMappingRemoved {
        identifier: String,
    },
    Error {
        error: String,
    },
}
