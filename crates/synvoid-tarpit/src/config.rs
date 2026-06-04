use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TarpitConfig {
    pub enabled: bool,
    pub max_depth: u32,
    pub links_per_page: u32,
    pub response_delay_ms: u64,
    pub scraper_patterns: Vec<String>,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_depth: 10,
            links_per_page: 50,
            response_delay_ms: 100,
            scraper_patterns: vec![
                "scrapy".to_string(),
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                "python-urllib".to_string(),
                "aiohttp".to_string(),
                "httpx".to_string(),
            ],
        }
    }
}
