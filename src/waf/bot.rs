use isbot::Bots;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::sync::Arc;

static DEFAULT_BOTS: Lazy<Bots> = Lazy::new(Bots::default);

pub struct BotDetector {
    known_bots_allow: Arc<HashSet<String>>,
    ai_crawlers_block: Arc<HashSet<String>>,
    scraper_patterns: Arc<HashSet<String>>,
    block_ai_crawlers: bool,
    block_scrapers: bool,
}

impl BotDetector {
    pub fn new(
        known_bots_allow: Vec<String>,
        ai_crawlers_block: Vec<String>,
        block_ai_crawlers: bool,
    ) -> Self {
        let known_bots_allow: HashSet<String> = known_bots_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let ai_crawlers_block: HashSet<String> = ai_crawlers_block
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let scraper_patterns: HashSet<String> = vec![
            "scrapy".to_string(),
            "curl".to_string(),
            "wget".to_string(),
            "python-requests".to_string(),
            "python-urllib".to_string(),
            "aiohttp".to_string(),
            "httpx".to_string(),
            "go-http".to_string(),
            "node-fetch".to_string(),
            "axios".to_string(),
            "rubygems".to_string(),
            "java".to_string(),
            "okhttp".to_string(),
            "feedparser".to_string(),
            " UniversalFeedParser".to_string(),
            "libwww-perl".to_string(),
            "pyspider".to_string(),
            "scrapeloader".to_string(),
            "siteanalyzer".to_string(),
            "screaming frog".to_string(),
        ]
        .into_iter()
        .collect();

        BotDetector {
            known_bots_allow: Arc::new(known_bots_allow),
            ai_crawlers_block: Arc::new(ai_crawlers_block),
            scraper_patterns: Arc::new(scraper_patterns),
            block_ai_crawlers,
            block_scrapers: true,
        }
    }

    pub fn check(&self, user_agent: Option<&str>) -> BotDetectionResult {
        let ua = match user_agent {
            Some(ua) => ua,
            None => {
                return BotDetectionResult::Allowed {
                    reason: "no_user_agent".to_string(),
                };
            }
        };

        let ua_lower = ua.to_lowercase();

        if self.is_allowed_bot(&ua_lower) {
            return BotDetectionResult::Allowed {
                reason: "known_search_bot".to_string(),
            };
        }

        if self.block_scrapers && self.is_scraper(&ua_lower) {
            return BotDetectionResult::Tarpit {
                reason: "scraper_detected".to_string(),
                bot_type: "scraper".to_string(),
            };
        }

        if DEFAULT_BOTS.is_bot(ua) {
            return BotDetectionResult::Blocked {
                reason: "detected_as_bot".to_string(),
                bot_type: "isbot".to_string(),
            };
        }

        if self.block_ai_crawlers && self.is_ai_crawler(&ua_lower) {
            return BotDetectionResult::Blocked {
                reason: "ai_crawler_detected".to_string(),
                bot_type: "ai".to_string(),
            };
        }

        BotDetectionResult::Allowed {
            reason: "legitimate".to_string(),
        }
    }

    fn is_allowed_bot(&self, ua_lower: &str) -> bool {
        self.known_bots_allow
            .iter()
            .any(|bot| ua_lower.contains(bot))
    }

    fn is_ai_crawler(&self, ua_lower: &str) -> bool {
        self.ai_crawlers_block
            .iter()
            .any(|crawler| ua_lower.contains(crawler))
    }

    fn is_scraper(&self, ua_lower: &str) -> bool {
        self.scraper_patterns
            .iter()
            .any(|pattern| ua_lower.contains(pattern))
    }
}

#[derive(Debug, Clone)]
pub enum BotDetectionResult {
    Allowed { reason: String },
    Blocked { reason: String, bot_type: String },
    Tarpit { reason: String, bot_type: String },
}
