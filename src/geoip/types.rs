use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeoIpResult {
    Allowed,
    Blocked,
    Neutral,
}

impl GeoIpResult {
    pub fn is_blocked(&self) -> bool {
        matches!(self, GeoIpResult::Blocked)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryInfo {
    pub code: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpStatus {
    pub enabled: bool,
    pub database_loaded: bool,
    pub database_path: Option<String>,
    pub blocked_countries_count: usize,
    pub allowed_countries_count: usize,
    pub last_update: Option<u64>,
}
