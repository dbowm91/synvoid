use synvoid_challenge::ChallengeType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafDecision {
    Pass,
    Block(u16, String),
    Drop,
    Tarpit(String),
    Stall,
    Challenge(ChallengeType, String),
    ChallengeWithCookie {
        challenge_type: ChallengeType,
        html: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
}

#[derive(Clone, Debug, Default)]
pub struct TestModeConfig {
    pub enabled: bool,
    pub ratelimit_off: bool,
    pub attack_off: bool,
    pub bot_off: bool,
    pub challenge_off: bool,
    pub flood_off: bool,
    pub asn_off: bool,
}

impl TestModeConfig {
    pub fn all_off() -> Self {
        Self {
            enabled: true,
            ratelimit_off: true,
            attack_off: true,
            bot_off: true,
            challenge_off: true,
            flood_off: true,
            asn_off: true,
        }
    }
}

#[derive(Clone)]
pub struct WafConfig {
    pub enable_css_honeypot: bool,
    pub enable_pow_challenge: bool,
    pub enable_auth_challenge: bool,
    pub auth_login_path: String,
    pub block_ai_crawlers: bool,
    pub drop_blocked_requests: bool,
    pub test_mode: TestModeConfig,
    pub honeypot_ban_duration_secs: u64,
    pub css_exempt_paths: Vec<String>,
}

impl WafConfig {
    pub fn new(
        enable_css_honeypot: bool,
        enable_pow_challenge: bool,
        enable_auth_challenge: bool,
        auth_login_path: String,
        block_ai_crawlers: bool,
        drop_blocked_requests: bool,
        test_mode: TestModeConfig,
        honeypot_ban_duration_secs: u64,
    ) -> Self {
        Self {
            enable_css_honeypot,
            enable_pow_challenge,
            enable_auth_challenge,
            auth_login_path,
            block_ai_crawlers,
            drop_blocked_requests,
            test_mode,
            honeypot_ban_duration_secs,
            css_exempt_paths: vec![
                "/_waf_css_challenge".to_string(),
                "/_waf_assets".to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waf_decision_pass() {
        assert_eq!(WafDecision::Pass, WafDecision::Pass);
    }

    #[test]
    fn test_waf_decision_block() {
        let d = WafDecision::Block(403, "Forbidden".to_string());
        match d {
            WafDecision::Block(code, msg) => {
                assert_eq!(code, 403);
                assert_eq!(msg, "Forbidden");
            }
            _ => panic!("Expected Block"),
        }
    }

    #[test]
    fn test_test_mode_config_all_off() {
        let config = TestModeConfig::all_off();
        assert!(config.enabled);
        assert!(config.ratelimit_off);
        assert!(config.attack_off);
        assert!(config.bot_off);
        assert!(config.challenge_off);
        assert!(config.flood_off);
        assert!(config.asn_off);
    }

    #[test]
    fn test_test_mode_config_default() {
        let config = TestModeConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn test_waf_config_new() {
        let test_mode = TestModeConfig::default();
        let config = WafConfig::new(
            true,
            false,
            true,
            "/login".to_string(),
            true,
            false,
            test_mode,
            3600,
        );
        assert!(config.enable_css_honeypot);
        assert!(!config.enable_pow_challenge);
        assert!(config.enable_auth_challenge);
        assert_eq!(config.auth_login_path, "/login");
        assert!(config.block_ai_crawlers);
        assert!(!config.drop_blocked_requests);
        assert_eq!(config.honeypot_ban_duration_secs, 3600);
        assert!(config.css_exempt_paths.contains(&"/_waf_css_challenge".to_string()));
    }
}
