pub mod handler;

// Re-export from the extracted crate
pub use synvoid_tarpit::{MarkovChain, TarpitConfig};

use parking_lot::RwLock;
use std::sync::Arc;

pub struct TarpitManager {
    chain: Arc<RwLock<MarkovChain>>,
    config: TarpitConfig,
}

impl TarpitManager {
    pub fn new(config: TarpitConfig) -> Self {
        let chain = Arc::new(RwLock::new(MarkovChain::new()));

        Self { chain, config }
    }

    pub fn generate_page(&self, current_depth: u32, path_seed: &str) -> String {
        let chain = self.chain.read();
        chain.generate_html_page(
            current_depth,
            self.config.max_depth,
            self.config.links_per_page,
            path_seed,
        )
    }

    pub fn is_scraper_user_agent(&self, user_agent: &str) -> bool {
        let ua_lower = user_agent.to_lowercase();
        self.config
            .scraper_patterns
            .iter()
            .any(|pattern| ua_lower.contains(&pattern.to_lowercase()))
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
