mod css;
mod honeypot;
mod pow;

pub use css::{AssetRequestResult, CssChallengeData, CssManager, CssVerificationResult};
pub use honeypot::{HoneypotEntry, HoneypotTracker, HONEYPOT_PREFIX};
pub use pow::{PowChallenge, PowManager, PowResult};

use crate::theme::{ChallengePageTemplate, ThemeConfig};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeResult {
    Passed,
    NotSet,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ChallengeType {
    #[default]
    None,
    PowChallenge,
    CssChallenge,
}

pub struct ChallengeManager {
    pow: Option<PowManager>,
    css: Option<CssManager>,
    honeypot: HoneypotTracker,
    cookie_name: String,
    theme: ThemeConfig,
}

pub struct ChallengeConfig {
    pub cookie_name: String,
    pub pow_enabled: bool,
    pub pow_difficulty: u8,
    pub pow_window_secs: u64,
    pub pow_timeout_secs: u64,
    pub css_enabled: bool,
    pub css_window_secs: u64,
    pub css_invalid_min: u32,
    pub css_invalid_max: u32,
    pub css_valid_count: u32,
    pub css_asset_path: String,
    pub css_valid_ratios: Vec<String>,
    pub css_verification_window_secs: u32,
    pub honeypot_enabled: bool,
    pub honeypot_paths_per_ip: usize,
    pub honeypot_ttl_secs: u64,
    pub theme: ThemeConfig,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            cookie_name: "waf_challenge".to_string(),
            pow_enabled: true,
            pow_difficulty: 6,
            pow_window_secs: 300,
            pow_timeout_secs: 60,
            css_enabled: true,
            css_window_secs: 300,
            css_invalid_min: 80,
            css_invalid_max: 120,
            css_valid_count: 3,
            css_asset_path: "/_waf_assets".to_string(),
            css_valid_ratios: vec!["16/9".to_string(), "4/3".to_string(), "1/1".to_string()],
            css_verification_window_secs: 30,
            honeypot_enabled: true,
            honeypot_paths_per_ip: 5,
            honeypot_ttl_secs: 86400,
            theme: ThemeConfig::default(),
        }
    }
}

impl ChallengeManager {
    pub fn new(config: ChallengeConfig) -> Self {
        let theme = config.theme.clone();
        
        let pow = if config.pow_enabled {
            Some(PowManager::new(
                config.pow_difficulty,
                config.pow_window_secs,
                config.pow_timeout_secs,
                config.cookie_name.clone(),
            ).with_theme(theme.clone()))
        } else {
            None
        };

        let css = if config.css_enabled {
            Some(CssManager::new(
                config.cookie_name.clone(),
                config.css_window_secs,
                config.css_invalid_min,
                config.css_invalid_max,
                config.css_valid_count,
                config.css_asset_path,
                config.css_valid_ratios,
                config.css_verification_window_secs,
            ).with_theme(theme.clone()))
        } else {
            None
        };

        let honeypot = HoneypotTracker::new(config.honeypot_paths_per_ip, config.honeypot_ttl_secs);

        Self {
            pow,
            css,
            honeypot,
            cookie_name: config.cookie_name,
            theme,
        }
    }

    pub fn generate_challenge_page(&self, ip: &IpAddr) -> String {
        let honeypot_html = if self.honeypot_enabled() {
            self.honeypot.generate_html(ip)
        } else {
            String::new()
        };

        if let Some(ref pow) = self.pow {
            pow.generate_challenge_page(&honeypot_html)
        } else if let Some(ref css) = self.css {
            css.generate_challenge_page(*ip, &honeypot_html)
        } else {
            self.generate_no_challenge_page(&honeypot_html)
        }
    }

    pub async fn generate_css_challenge_and_start_session(&self, ip: IpAddr) -> String {
        let honeypot_html = if self.honeypot_enabled() {
            self.honeypot.generate_html(&ip)
        } else {
            String::new()
        };

        if let Some(ref css) = self.css {
            let (css_rules, data) = css.generate_challenge();
            let html = css.generate_challenge_page(ip, &honeypot_html);
            css.start_session(ip, &data).await;
            html
        } else {
            self.generate_no_challenge_page(&honeypot_html)
        }
    }

    pub fn generate_nojs_page(&self, ip: &IpAddr) -> String {
        let honeypot_html = if self.honeypot_enabled() {
            self.honeypot.generate_html(ip)
        } else {
            String::new()
        };

        if let Some(ref pow) = self.pow {
            pow.generate_nojs_page(&honeypot_html)
        } else {
            self.generate_nojs_fallback()
        }
    }

    pub fn check_cookie(&self, cookie_value: Option<&str>) -> ChallengeResult {
        if let Some(ref pow) = self.pow {
            match pow.check_cookie(cookie_value) {
                PowResult::Valid => return ChallengeResult::Passed,
                PowResult::NotSet => return ChallengeResult::NotSet,
                PowResult::Invalid => {}
            }
        }

        if let Some(css_value) = cookie_value {
            if css_value == "verified" && self.css.is_some() {
                return ChallengeResult::Passed;
            }
        }

        ChallengeResult::Failed
    }

    pub async fn start_css_session(&self, ip: IpAddr) {
        if let Some(ref css) = self.css {
            let (_, data) = css.generate_challenge();
            css.start_session(ip, &data).await;
        }
    }

    pub async fn record_css_asset_request(&self, ip: IpAddr, asset_name: &str) -> AssetRequestResult {
        if let Some(ref css) = self.css {
            css.record_asset_request(ip, asset_name).await
        } else {
            AssetRequestResult::NoSession
        }
    }

    pub async fn verify_css_challenge(&self, ip: IpAddr) -> CssVerificationResult {
        if let Some(ref css) = self.css {
            css.verify_challenge(ip).await
        } else {
            CssVerificationResult::NoSession
        }
    }

    pub async fn cleanup_css_expired(&self) {
        if let Some(ref css) = self.css {
            css.cleanup_expired().await;
        }
    }

    pub fn verify_pow(&self, challenge: &str, nonce: &str) -> bool {
        if let Some(ref pow) = self.pow {
            pow.verify_solution(challenge, nonce)
        } else {
            false
        }
    }

    pub fn is_honeypot_hit(&self, ip: &IpAddr, path: &str) -> bool {
        self.honeypot.is_honeypot_hit(ip, path)
    }

    pub fn honeypot_enabled(&self) -> bool {
        true
    }

    pub fn pow_enabled(&self) -> bool {
        self.pow.is_some()
    }

    pub fn css_enabled(&self) -> bool {
        self.css.is_some()
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn cleanup_expired(&self) {
        self.honeypot.cleanup_expired();
    }

    fn generate_no_challenge_page(&self, honeypot_html: &str) -> String {
        let content = r#"<p class="waf-message">Your request has been blocked.</p>"#;
        
        ChallengePageTemplate::new(self.theme.clone())
            .title("Access Denied")
            .subtitle("")
            .spinner(false)
            .content(content)
            .honeypot(honeypot_html)
            .render()
    }

    fn generate_nojs_fallback(&self) -> String {
        let content = r#"<p class="waf-message">Please enable JavaScript to verify your browser.</p>"#;
        
        ChallengePageTemplate::new(self.theme.clone())
            .title("Verification Required")
            .subtitle("")
            .spinner(false)
            .content(content)
            .render()
    }

    pub fn generate_css_challenge(&self) -> Option<(String, CssChallengeData)> {
        self.css.as_ref().map(|css| css.generate_challenge())
    }
}
