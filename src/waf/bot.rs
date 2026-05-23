use isbot::Bots;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::LazyLock;

static DEFAULT_BOTS: LazyLock<Bots> = LazyLock::new(Bots::default);

pub struct BotDetector {
    known_bots_allow: Arc<HashSet<String>>,
    ai_crawlers_block: Arc<HashSet<String>>,
    scraper_patterns: Arc<HashSet<String>>,
    known_bot_ja3_hashes: Arc<HashSet<String>>,
    known_bot_ja4_hashes: Arc<HashSet<String>>,
    block_ai_crawlers: bool,
    block_scrapers: bool,
}

impl BotDetector {
    pub fn new(
        known_bots_allow: Vec<String>,
        ai_crawlers_block: Vec<String>,
        scraper_patterns: Vec<String>,
        block_ai_crawlers: bool,
    ) -> Self {
        Self::with_ja3(
            known_bots_allow,
            ai_crawlers_block,
            scraper_patterns,
            block_ai_crawlers,
            Vec::new(),
        )
    }

    pub fn with_ja3(
        known_bots_allow: Vec<String>,
        ai_crawlers_block: Vec<String>,
        scraper_patterns: Vec<String>,
        block_ai_crawlers: bool,
        known_bot_ja3_hashes: Vec<String>,
    ) -> Self {
        Self::with_ja4(
            known_bots_allow,
            ai_crawlers_block,
            scraper_patterns,
            block_ai_crawlers,
            known_bot_ja3_hashes,
            Vec::new(),
        )
    }

    pub fn with_ja4(
        known_bots_allow: Vec<String>,
        ai_crawlers_block: Vec<String>,
        scraper_patterns: Vec<String>,
        block_ai_crawlers: bool,
        block_scrapers: bool,
        known_bot_ja3_hashes: Vec<String>,
        known_bot_ja4_hashes: Vec<String>,
    ) -> Self {
        let known_bots_allow: HashSet<String> = known_bots_allow
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let ai_crawlers_block: HashSet<String> = ai_crawlers_block
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let scraper_patterns: HashSet<String> = scraper_patterns
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let known_bot_ja3_hashes: HashSet<String> = known_bot_ja3_hashes
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        let known_bot_ja4_hashes: HashSet<String> = known_bot_ja4_hashes
            .into_iter()
            .map(|s| s.to_lowercase())
            .collect();

        BotDetector {
            known_bots_allow: Arc::new(known_bots_allow),
            ai_crawlers_block: Arc::new(ai_crawlers_block),
            scraper_patterns: Arc::new(scraper_patterns),
            known_bot_ja3_hashes: Arc::new(known_bot_ja3_hashes),
            known_bot_ja4_hashes: Arc::new(known_bot_ja4_hashes),
            block_ai_crawlers,
            block_scrapers,
        }
    }

    pub fn check(&self, user_agent: Option<&str>) -> BotDetectionResult {
        self.check_with_ja3(user_agent, None, None)
    }

    pub fn check_with_override(
        &self,
        user_agent: Option<&str>,
        site_block_ai_crawlers: Option<bool>,
    ) -> BotDetectionResult {
        self.check_with_ja3(user_agent, site_block_ai_crawlers, None)
    }

    pub fn check_with_ja3(
        &self,
        user_agent: Option<&str>,
        site_block_ai_crawlers: Option<bool>,
        ja3_hash: Option<&str>,
    ) -> BotDetectionResult {
        if let Some(result) = self.check_fingerprints(ja3_hash, None) {
            return result;
        }

        self.check_user_agent(user_agent, site_block_ai_crawlers)
    }

    pub fn check_with_fingerprints(
        &self,
        user_agent: Option<&str>,
        site_block_ai_crawlers: Option<bool>,
        ja3_hash: Option<&str>,
        ja4_hash: Option<&str>,
    ) -> BotDetectionResult {
        if let Some(result) = self.check_fingerprints(ja3_hash, ja4_hash) {
            return result;
        }

        self.check_user_agent(user_agent, site_block_ai_crawlers)
    }

    fn check_fingerprints(
        &self,
        ja3_hash: Option<&str>,
        ja4_hash: Option<&str>,
    ) -> Option<BotDetectionResult> {
        if let Some(hash) = ja3_hash {
            if let Some(result) = self.check_ja3(hash) {
                return Some(result);
            }
        }
        if let Some(hash) = ja4_hash {
            if let Some(result) = self.check_ja4(hash) {
                return Some(result);
            }
        }
        None
    }

    pub fn check_ja3(&self, ja3_hash: &str) -> Option<BotDetectionResult> {
        let hash_lower = ja3_hash.to_lowercase();
        if self.known_bot_ja3_hashes.contains(&hash_lower) {
            Some(BotDetectionResult::Blocked {
                reason: "ja3_bot_fingerprint_matched".to_string(),
                bot_type: "ja3".to_string(),
            })
        } else {
            None
        }
    }

    pub fn check_ja4(&self, ja4_hash: &str) -> Option<BotDetectionResult> {
        let hash_lower = ja4_hash.to_lowercase();
        if self.known_bot_ja4_hashes.contains(&hash_lower) {
            Some(BotDetectionResult::Blocked {
                reason: "ja4_bot_fingerprint_matched".to_string(),
                bot_type: "ja4".to_string(),
            })
        } else {
            None
        }
    }

    fn check_user_agent(
        &self,
        user_agent: Option<&str>,
        site_block_ai_crawlers: Option<bool>,
    ) -> BotDetectionResult {
        let ua = match user_agent {
            Some(ua) => ua,
            None => {
                return BotDetectionResult::Allowed {
                    reason: "no_user_agent".to_string(),
                };
            }
        };

        if ua.is_empty() {
            return BotDetectionResult::Tarpit {
                reason: "empty_user_agent".to_string(),
                bot_type: "missing_ua".to_string(),
            };
        }

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

        let effective_block_ai = site_block_ai_crawlers.unwrap_or(self.block_ai_crawlers);
        if effective_block_ai && self.is_ai_crawler(&ua_lower) {
            return BotDetectionResult::Blocked {
                reason: "ai_crawler_detected".to_string(),
                bot_type: "ai".to_string(),
            };
        }

        if effective_block_ai {
            self.warn_unknown_ai_pattern(ua, &ua_lower);
        }

        BotDetectionResult::Allowed {
            reason: "legitimate".to_string(),
        }
    }

    fn warn_unknown_ai_pattern(&self, ua: &str, ua_lower: &str) {
        let ai_keywords = [
            "gpt", "claude", "llama", "gemini", "copilot", "bard", "chatbot",
        ];
        if ai_keywords.iter().any(|kw| ua_lower.contains(kw)) {
            tracing::warn!(
                user_agent = %ua,
                "Potential unknown AI bot pattern detected - consider adding to ai_crawlers_block"
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_detector() -> BotDetector {
        BotDetector::new(
            vec![
                "googlebot".to_string(),
                "bingbot".to_string(),
                "yandex".to_string(),
            ],
            vec![
                "gptbot".to_string(),
                "claudebot".to_string(),
                "chatgpt".to_string(),
                "anthropic-ai".to_string(),
                "ccbot".to_string(),
            ],
            vec![
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
                "axios".to_string(),
            ],
            true,
        )
    }

    #[test]
    fn test_no_user_agent_allowed() {
        let detector = create_test_detector();
        let result = detector.check(None);
        assert!(
            matches!(result, BotDetectionResult::Allowed { reason } if reason == "no_user_agent")
        );
    }

    #[test]
    fn test_googlebot_allowed() {
        let detector = create_test_detector();
        let result = detector.check(Some(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ));
        assert!(
            matches!(result, BotDetectionResult::Allowed { reason } if reason == "known_search_bot")
        );
    }

    #[test]
    fn test_bingbot_allowed() {
        let detector = create_test_detector();
        let result = detector.check(Some(
            "Mozilla/5.0 (compatible; bingbot/2.1; +http://www.bing.com/bingbot.htm)",
        ));
        assert!(
            matches!(result, BotDetectionResult::Allowed { reason } if reason == "known_search_bot")
        );
    }

    #[test]
    fn test_yandex_allowed() {
        let detector = create_test_detector();
        let result = detector.check(Some(
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        ));
        assert!(
            matches!(result, BotDetectionResult::Allowed { reason } if reason == "known_search_bot")
        );
    }

    #[test]
    fn test_gptbot_blocked() {
        let detector = create_test_detector();
        let result = detector.check(Some("GPTBot/1.0"));
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, ref bot_type } 
            if reason == "detected_as_bot" && bot_type == "isbot")
        );
    }

    #[test]
    fn test_claudebot_blocked() {
        let detector = create_test_detector();
        let result = detector.check(Some("ClaudeBot/1.0"));
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, ref bot_type } 
            if reason == "detected_as_bot" && bot_type == "isbot")
        );
    }

    #[test]
    fn test_chatgpt_blocked() {
        let detector = create_test_detector();
        let result = detector.check(Some("ChatGPT-User/1.0"));
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, ref bot_type } 
            if reason == "ai_crawler_detected" && bot_type == "ai")
        );
    }

    #[test]
    fn test_curl_scraper_tarpit() {
        let detector = create_test_detector();
        let result = detector.check(Some("curl/7.88.1"));
        assert!(
            matches!(result, BotDetectionResult::Tarpit { ref reason, ref bot_type } 
            if reason == "scraper_detected" && bot_type == "scraper")
        );
    }

    #[test]
    fn test_wget_scraper_tarpit() {
        let detector = create_test_detector();
        let result = detector.check(Some("Wget/1.21.3"));
        assert!(
            matches!(result, BotDetectionResult::Tarpit { ref reason, ref bot_type } 
            if reason == "scraper_detected" && bot_type == "scraper")
        );
    }

    #[test]
    fn test_python_requests_scraper_tarpit() {
        let detector = create_test_detector();
        let result = detector.check(Some("python-requests/2.31.0"));
        assert!(
            matches!(result, BotDetectionResult::Tarpit { ref reason, ref bot_type } 
            if reason == "scraper_detected" && bot_type == "scraper")
        );
    }

    #[test]
    fn test_normal_browser_allowed() {
        let detector = create_test_detector();
        let result = detector.check(Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
        assert!(matches!(result, BotDetectionResult::Allowed { reason } if reason == "legitimate"));
    }

    #[test]
    fn test_firefox_allowed() {
        let detector = create_test_detector();
        let result = detector.check(Some(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
        ));
        assert!(matches!(result, BotDetectionResult::Allowed { reason } if reason == "legitimate"));
    }

    #[test]
    fn test_empty_user_agent_blocked() {
        let detector = create_test_detector();
        let result = detector.check(Some(""));
        assert!(
            matches!(result, BotDetectionResult::Tarpit { reason, bot_type } 
            if reason == "empty_user_agent" && bot_type == "missing_ua")
        );
    }

    #[test]
    fn test_unknown_bot_blocked_by_isbot() {
        let detector = create_test_detector();
        let result = detector.check(Some("AhrefsBot/6.1"));
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, ref bot_type } 
            if reason == "detected_as_bot" && bot_type == "isbot")
        );
    }

    #[test]
    fn test_per_site_override_blocks_ai() {
        let detector = BotDetector::new(
            vec!["googlebot".to_string()],
            vec!["mycustomapp".to_string()],
            vec![],
            false, // global: AI blocking disabled
        );
        // Site override: block AI crawlers
        let result = detector.check_with_override(Some("MyCustomApp/1.0"), Some(true));
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, .. }
            if reason == "ai_crawler_detected"),
            "Expected ai_crawler_detected, got {:?}",
            result
        );
    }

    #[test]
    fn test_per_site_override_allows_ai() {
        let detector = BotDetector::new(
            vec!["googlebot".to_string()],
            vec!["mycustomapp".to_string()],
            vec![],
            true, // global: AI blocking enabled
        );
        // Site override: allow AI crawlers - should pass through
        let result = detector.check_with_override(Some("MyCustomApp/1.0"), Some(false));
        assert!(
            matches!(result, BotDetectionResult::Allowed { .. }),
            "Expected Allowed, got {:?}",
            result
        );
    }

    #[test]
    fn test_per_site_none_uses_global() {
        let detector = BotDetector::new(
            vec!["googlebot".to_string()],
            vec!["mycustomapp".to_string()],
            vec![],
            true, // global: AI blocking enabled
        );
        // No override - should use global setting (block)
        let result = detector.check_with_override(Some("MyCustomApp/1.0"), None);
        assert!(
            matches!(result, BotDetectionResult::Blocked { ref reason, .. }
            if reason == "ai_crawler_detected"),
            "Expected ai_crawler_detected, got {:?}",
            result
        );
    }
}
