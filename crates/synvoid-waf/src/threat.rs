use serde::{Deserialize, Serialize};

/// A threat intelligence entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub key: String,
    pub reason: String,
    pub severity: u8,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
}

/// Result of a threat lookup.
#[derive(Debug, Clone, Default)]
pub struct ThreatLookup {
    pub score: u32,
    pub reasons: Vec<String>,
}

pub trait ThreatPersistence: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;
    fn load_entries(&self) -> Result<Vec<ThreatEntry>, Self::Error>;
    fn save_entry(&self, entry: &ThreatEntry) -> Result<(), Self::Error>;
}

pub trait ThreatMetrics: Send + Sync + 'static {
    fn record_threat_entry(&self, _severity: u8) {}
    fn record_feed_update(&self, _count: usize) {}
}
