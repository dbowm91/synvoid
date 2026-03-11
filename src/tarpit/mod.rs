pub mod generator;
pub mod handler;

pub use generator::MarkovChain;
pub use handler::TarpitHandler;

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

pub struct TarpitManager {
    chain: Arc<RwLock<MarkovChain>>,
    config: TarpitConfig,
}

#[derive(Clone)]
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

impl TarpitManager {
    pub fn new(config: TarpitConfig) -> Self {
        let chain = Arc::new(RwLock::new(MarkovChain::new()));
        
        Self { chain, config }
    }

    pub fn generate_page(&self, current_depth: u32, path_seed: &str) -> String {
        let chain = self.chain.read();
        chain.generate_html_page(current_depth, self.config.max_depth, self.config.links_per_page, path_seed)
    }

    pub fn is_scraper_user_agent(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        self.config.scraper_patterns.iter().any(|pattern| ua_lower.contains(&pattern.to_lowercase()))
    }

    pub fn should_tarpit(&self, is_bot: bool, user_agent: Option<&str>) -> bool {
        if !self.config.enabled {
            return false;
        }

        if is_bot {
            return true;
        }

        if let Some(ua) = user_agent {
            return self.is_scraper_user_agent(ua);
        }

        false
    }
}
