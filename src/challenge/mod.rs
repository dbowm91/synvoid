mod css;
pub mod honeypot;
mod mesh_pow;
mod pow;

pub use css::{
    AssetRequestResult, CssAssetAction, CssChallengeData, CssManager, CssVerificationResult,
};
pub use honeypot::{HoneypotEntry, HoneypotTracker, HONEYPOT_PREFIX};
pub use mesh_pow::{
    MeshAuditResult, MeshPowConfig, MeshPowManager, MeshPowResult, MeshPowSolution,
};
pub use pow::{PowChallenge, PowManager, PowResult};

use crate::theme::{ChallengePageTemplate, ThemeConfig};
use crate::utils::current_timestamp;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeResult {
    Passed,
    NotSet,
    Failed,
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChallengeType {
    #[default]
    None,
    PowChallenge,
    MeshPowChallenge,
    CssChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChallengePriority {
    #[default]
    PowThenCss,
    CssThenPow,
    PowOnly,
    CssOnly,
    MeshPowThenCss,
    MeshPowOnly,
}

struct ChallengeAttempt {
    count: u32,
    first_attempt: u64,
}

pub struct ChallengeManager {
    pow: Option<PowManager>,
    mesh_pow: Option<MeshPowManager>,
    css: Option<CssManager>,
    honeypot: HoneypotTracker,
    cookie_name: String,
    theme: ThemeConfig,
    priority: ChallengePriority,
    max_attempts: u32,
    rate_limit_window_secs: u64,
    attempts: RwLock<HashMap<IpAddr, ChallengeAttempt>>,
    max_attempts_entries: usize,
    use_mesh_pow_when_available: bool,
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
    pub css_verification_window_secs: u32,
    pub honeypot_enabled: bool,
    pub honeypot_paths_per_ip: usize,
    pub honeypot_ttl_secs: u64,
    pub theme: ThemeConfig,
    pub challenge_max_attempts: u32,
    pub challenge_rate_limit_window_secs: u64,
    pub challenge_priority: ChallengePriority,
    pub mesh_pow_enabled: bool,
    pub mesh_pow_key_exchange_enabled: bool,
    pub mesh_pow_auditing_enabled: bool,
    pub mesh_id: Option<String>,
    pub mesh_global_node_url: Option<String>,
    pub mesh_audit_urls: Vec<String>,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            cookie_name: "waf_challenge".to_string(),
            pow_enabled: true,
            pow_difficulty: 12,
            pow_window_secs: 300,
            pow_timeout_secs: 12,
            css_enabled: true,
            css_window_secs: 300,
            css_invalid_min: 80,
            css_invalid_max: 120,
            css_valid_count: 3,
            css_asset_path: "/_waf_assets".to_string(),
            css_verification_window_secs: 30,
            honeypot_enabled: true,
            honeypot_paths_per_ip: 5,
            honeypot_ttl_secs: 86400,
            theme: ThemeConfig::default(),
            challenge_max_attempts: 5,
            challenge_rate_limit_window_secs: 3600,
            challenge_priority: ChallengePriority::PowThenCss,
            mesh_pow_enabled: false,
            mesh_pow_key_exchange_enabled: false,
            mesh_pow_auditing_enabled: false,
            mesh_id: None,
            mesh_global_node_url: None,
            mesh_audit_urls: vec![],
        }
    }
}

impl ChallengeManager {
    pub fn new(config: ChallengeConfig) -> Self {
        let theme = config.theme.clone();

        let css_available =
            config.css_enabled && !matches!(config.challenge_priority, ChallengePriority::PowOnly);

        let pow = if config.pow_enabled {
            Some(
                PowManager::new(
                    config.pow_difficulty,
                    config.pow_window_secs,
                    config.pow_timeout_secs,
                    config.cookie_name.clone(),
                )
                .with_theme(theme.clone())
                .with_css_fallback(css_available),
            )
        } else {
            None
        };

        let mesh_pow = if config.mesh_pow_enabled {
            let mesh_config = MeshPowConfig {
                mesh_id: config.mesh_id.unwrap_or_default(),
                global_node_url: config.mesh_global_node_url.unwrap_or_default(),
                audit_urls: config.mesh_audit_urls,
                key_exchange_enabled: config.mesh_pow_key_exchange_enabled,
                auditing_enabled: config.mesh_pow_auditing_enabled,
                pow_difficulty: config.pow_difficulty,
                session_timeout_secs: config.pow_window_secs,
            };
            Some(
                MeshPowManager::new(
                    config.pow_difficulty,
                    config.pow_window_secs,
                    config.pow_timeout_secs,
                    config.cookie_name.clone(),
                    mesh_config,
                )
                .with_theme(theme.clone()),
            )
        } else {
            None
        };

        let css = if config.css_enabled {
            Some(
                CssManager::new(
                    config.cookie_name.clone(),
                    config.css_window_secs,
                    config.css_invalid_min,
                    config.css_invalid_max,
                    config.css_valid_count,
                    config.css_asset_path,
                    config.css_verification_window_secs,
                )
                .with_theme(theme.clone()),
            )
        } else {
            None
        };

        let honeypot = HoneypotTracker::new(config.honeypot_paths_per_ip, config.honeypot_ttl_secs);

        const DEFAULT_MAX_ATTEMPTS_ENTRIES: usize = 10_000;

        Self {
            pow,
            mesh_pow,
            css,
            honeypot,
            cookie_name: config.cookie_name,
            theme,
            priority: config.challenge_priority,
            max_attempts: config.challenge_max_attempts,
            rate_limit_window_secs: config.challenge_rate_limit_window_secs,
            attempts: RwLock::new(HashMap::new()),
            max_attempts_entries: DEFAULT_MAX_ATTEMPTS_ENTRIES,
            use_mesh_pow_when_available: config.mesh_pow_enabled
                && (config.mesh_pow_key_exchange_enabled || config.mesh_pow_auditing_enabled),
        }
    }

    pub fn priority(&self) -> ChallengePriority {
        self.priority.clone()
    }

    pub fn is_rate_limited(&self, ip: &IpAddr) -> bool {
        if self.max_attempts == 0 {
            return false;
        }

        let attempts = self.attempts.read();
        if let Some(attempt) = attempts.get(ip) {
            let now = current_timestamp();
            if now < attempt.first_attempt + self.rate_limit_window_secs {
                return attempt.count >= self.max_attempts;
            }
        }
        false
    }

    pub fn record_attempt(&self, ip: &IpAddr) {
        if self.max_attempts == 0 {
            return;
        }

        let mut attempts = self.attempts.write();
        let now = current_timestamp();

        if attempts.len() >= self.max_attempts_entries {
            attempts.retain(|_, a| now < a.first_attempt + self.rate_limit_window_secs);
            if attempts.len() >= self.max_attempts_entries {
                tracing::warn!("Challenge attempts table full, rejecting new entries");
                return;
            }
        }

        attempts
            .entry(*ip)
            .and_modify(|a| {
                if now >= a.first_attempt + self.rate_limit_window_secs {
                    a.count = 1;
                    a.first_attempt = now;
                } else {
                    a.count += 1;
                }
            })
            .or_insert(ChallengeAttempt {
                count: 1,
                first_attempt: now,
            });
    }

    pub fn clear_attempts(&self, ip: &IpAddr) {
        let mut attempts = self.attempts.write();
        attempts.remove(ip);
    }

    pub fn cleanup_expired_attempts(&self) {
        let now = current_timestamp();
        let mut attempts = self.attempts.write();
        attempts.retain(|_, a| now < a.first_attempt + self.rate_limit_window_secs);
    }

    pub fn generate_challenge_page(
        &self,
        ip: &IpAddr,
        app_path: Option<&str>,
    ) -> (String, Option<String>) {
        if self.is_rate_limited(ip) {
            return (self.generate_rate_limited_page(), None);
        }

        self.record_attempt(ip);

        let honeypot_html = if self.honeypot_enabled() {
            self.honeypot.generate_html(ip, app_path.unwrap_or("/"))
        } else {
            String::new()
        };

        if self.use_mesh_pow_when_available {
            if let Some(ref mesh_pow) = self.mesh_pow {
                return (mesh_pow.generate_challenge_page(&honeypot_html), None);
            }
        }

        match self.priority {
            ChallengePriority::PowThenCss => {
                if let Some(ref pow) = self.pow {
                    (pow.generate_challenge_page(&honeypot_html), None)
                } else if let Some(ref css) = self.css {
                    let (html, session_id, data) = css.generate_challenge_page(&honeypot_html);
                    css.start_session(&session_id, &data);
                    (html, Some(session_id))
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
            ChallengePriority::CssThenPow => {
                if let Some(ref css) = self.css {
                    let (html, session_id, data) = css.generate_challenge_page(&honeypot_html);
                    css.start_session(&session_id, &data);
                    (html, Some(session_id))
                } else if let Some(ref pow) = self.pow {
                    (pow.generate_challenge_page(&honeypot_html), None)
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
            ChallengePriority::PowOnly => {
                if let Some(ref pow) = self.pow {
                    (pow.generate_challenge_page(&honeypot_html), None)
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
            ChallengePriority::CssOnly => {
                if let Some(ref css) = self.css {
                    let (html, session_id, data) = css.generate_challenge_page(&honeypot_html);
                    css.start_session(&session_id, &data);
                    (html, Some(session_id))
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
            ChallengePriority::MeshPowThenCss => {
                if let Some(ref mesh_pow) = self.mesh_pow {
                    (mesh_pow.generate_challenge_page(&honeypot_html), None)
                } else if let Some(ref pow) = self.pow {
                    (pow.generate_challenge_page(&honeypot_html), None)
                } else if let Some(ref css) = self.css {
                    let (html, session_id, data) = css.generate_challenge_page(&honeypot_html);
                    css.start_session(&session_id, &data);
                    (html, Some(session_id))
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
            ChallengePriority::MeshPowOnly => {
                if let Some(ref mesh_pow) = self.mesh_pow {
                    (mesh_pow.generate_challenge_page(&honeypot_html), None)
                } else {
                    (self.generate_no_challenge_page(&honeypot_html), None)
                }
            }
        }
    }

    pub fn generate_nojs_page(&self, ip: &IpAddr, app_path: Option<&str>) -> String {
        let honeypot_html = if self.honeypot_enabled() {
            self.honeypot.generate_html(ip, app_path.unwrap_or("/"))
        } else {
            String::new()
        };

        match self.priority {
            ChallengePriority::PowOnly | ChallengePriority::PowThenCss => {
                if let Some(ref pow) = self.pow {
                    pow.generate_nojs_page(&honeypot_html)
                } else if let Some(ref _css) = self.css {
                    self.generate_css_nojs_page(&honeypot_html)
                } else {
                    self.generate_nojs_fallback()
                }
            }
            ChallengePriority::CssOnly | ChallengePriority::CssThenPow => {
                if let Some(ref _css) = self.css {
                    self.generate_css_nojs_page(&honeypot_html)
                } else if let Some(ref pow) = self.pow {
                    pow.generate_nojs_page(&honeypot_html)
                } else {
                    self.generate_nojs_fallback()
                }
            }
            ChallengePriority::MeshPowOnly | ChallengePriority::MeshPowThenCss => {
                if let Some(ref mesh_pow) = self.mesh_pow {
                    mesh_pow.generate_challenge_page(&honeypot_html)
                } else if let Some(ref pow) = self.pow {
                    pow.generate_nojs_page(&honeypot_html)
                } else {
                    self.generate_nojs_fallback()
                }
            }
        }
    }

    fn generate_css_nojs_page(&self, honeypot_html: &str) -> String {
        ChallengePageTemplate::new(self.theme.clone())
            .title("Verification Required")
            .subtitle("Please enable JavaScript to continue.")
            .content(r#"<p class="waf-message">This site requires JavaScript for browser verification.</p>"#)
            .spinner(false)
            .honeypot(honeypot_html)
            .render()
    }

    pub fn check_cookie(&self, cookie_value: Option<&str>) -> ChallengeResult {
        if let Some(ref mesh_pow) = self.mesh_pow {
            match mesh_pow.check_cookie(cookie_value) {
                MeshPowResult::Valid(_) => return ChallengeResult::Passed,
                MeshPowResult::NotSet => return ChallengeResult::NotSet,
                MeshPowResult::Invalid => {}
            }
        }

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

    pub async fn start_css_session(&self, _ip: IpAddr) {
        // Deprecated - sessions now started in generate_css_challenge_and_start_session
    }

    pub fn record_css_asset_request(
        &self,
        session_id: &str,
        asset_name: &str,
    ) -> (AssetRequestResult, CssAssetAction) {
        if let Some(ref css) = self.css {
            css.record_asset_request(session_id, asset_name)
        } else {
            (
                AssetRequestResult::NoSession,
                CssAssetAction::DropConnection,
            )
        }
    }

    pub fn cleanup_css_expired(&self) {
        if let Some(ref css) = self.css {
            css.cleanup_expired();
        }
    }

    pub fn verify_pow(&self, challenge: &str, nonce: &str) -> bool {
        if let Some(ref pow) = self.pow {
            pow.verify_solution(challenge, nonce)
        } else {
            false
        }
    }

    pub fn is_honeypot_hit(&self, ip: &IpAddr, path: &str) -> Option<String> {
        self.honeypot.is_honeypot_hit(ip, path)
    }

    pub fn honeypot_enabled(&self) -> bool {
        true
    }

    pub fn pow_enabled(&self) -> bool {
        self.pow.is_some()
    }

    pub fn mesh_pow_enabled(&self) -> bool {
        self.mesh_pow.is_some()
    }

    pub fn mesh_pow_config(&self) -> Option<&MeshPowConfig> {
        self.mesh_pow.as_ref().map(|m| m.mesh_config())
    }

    pub fn is_mesh_mode(&self) -> bool {
        if let Some(ref config) = self.mesh_pow {
            config.is_mesh_enabled()
        } else {
            false
        }
    }

    pub fn get_challenge_type(&self) -> ChallengeType {
        if self.mesh_pow.is_some() && self.is_mesh_mode() {
            ChallengeType::MeshPowChallenge
        } else if self.pow.is_some() {
            ChallengeType::PowChallenge
        } else if self.css.is_some() {
            ChallengeType::CssChallenge
        } else {
            ChallengeType::None
        }
    }

    pub fn css_enabled(&self) -> bool {
        self.css.is_some()
    }

    pub fn css_session_cookie_name(&self) -> String {
        self.css
            .as_ref()
            .map(|c| c.session_cookie_name().to_string())
            .unwrap_or_else(|| format!("{}_css_session", self.cookie_name))
    }

    pub fn css_verified_cookie_name(&self) -> String {
        self.css
            .as_ref()
            .map(|c| c.verified_cookie_name().to_string())
            .unwrap_or_else(|| format!("{}_css_verified", self.cookie_name))
    }

    pub fn css_window_secs(&self) -> u64 {
        self.css
            .as_ref()
            .map(|c| c.verification_window_secs() as u64)
            .unwrap_or(30)
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
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
        let content =
            r#"<p class="waf-message">Please enable JavaScript to verify your browser.</p>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Verification Required")
            .subtitle("")
            .spinner(false)
            .content(content)
            .render()
    }

    fn generate_rate_limited_page(&self) -> String {
        let content =
            r#"<p class="waf-message">Too many verification attempts. Please try again later.</p>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Rate Limited")
            .subtitle("")
            .spinner(false)
            .content(content)
            .render()
    }

    pub fn generate_css_challenge(&self) -> Option<(String, CssChallengeData, String)> {
        self.css.as_ref().map(|css| css.generate_challenge())
    }
}
