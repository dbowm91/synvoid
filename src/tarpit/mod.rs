//! Compatibility facade for `synvoid-tarpit`.
//!
//! Markov chain text generation and tarpit configuration are provided by the
//! dedicated `synvoid-tarpit` crate. The root-owned [`TarpitHandler`] and
//! [`TarpitManager`] remain here because they depend on root infrastructure
//! (metrics, tokio async streams).

pub mod handler;

pub use handler::TarpitHandler;
pub use synvoid_tarpit::{
    admission::{AdmissionGuard, TarpitAdmission},
    budget::{BudgetState, SessionBudget},
    escaping, MarkovChain, TarpitConfig,
};

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
        let effective_max = self.config.max_depth.max(1);
        chain.generate_html_page(
            current_depth,
            effective_max,
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
