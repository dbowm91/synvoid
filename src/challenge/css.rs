use crate::theme::{ChallengePageTemplate, ThemeConfig};
use crate::utils::current_timestamp;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

const SESSION_CLEANUP_INTERVAL_SECS: u64 = 60;

pub struct CssManager {
    session_cookie_name: String,
    verified_cookie_name: String,
    window_secs: u64,
    invalid_min: u32,
    invalid_max: u32,
    valid_count: u32,
    asset_path: String,
    verification_window_secs: u32,
    sessions: Arc<RwLock<CssSessionStore>>,
    theme: ThemeConfig,
}

struct CssSessionStore {
    sessions: HashMap<String, CssSession>,
    max_sessions: usize,
}

impl CssSessionStore {
    fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            max_sessions,
        }
    }
}

#[derive(Clone)]
struct CssSession {
    valid_names: Vec<String>,
    invalid_names: Vec<String>,
    requested_valid: HashSet<String>,
    created_at: u64,
    verification_started: bool,
}

impl CssManager {
    pub fn new(
        cookie_name: String,
        window_secs: u64,
        invalid_min: u32,
        invalid_max: u32,
        valid_count: u32,
        asset_path: String,
        verification_window_secs: u32,
    ) -> Self {
        const DEFAULT_MAX_SESSIONS: usize = 10_000;
        let verified_name = format!("{}_verified", cookie_name);

        Self {
            session_cookie_name: cookie_name,
            verified_cookie_name: verified_name,
            window_secs,
            invalid_min: invalid_min.max(1),
            invalid_max: invalid_max.max(invalid_min),
            valid_count,
            asset_path,
            verification_window_secs: verification_window_secs.max(30),
            sessions: Arc::new(RwLock::new(CssSessionStore::new(DEFAULT_MAX_SESSIONS))),
            theme: ThemeConfig::default(),
        }
    }

    pub fn with_theme(mut self, theme: ThemeConfig) -> Self {
        self.theme = theme;
        self
    }

    pub fn theme(&self) -> &ThemeConfig {
        &self.theme
    }

    pub fn generate_session_id(&self) -> String {
        let mut rng = rand::rng();
        let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..32)
            .map(|_| {
                let idx = rng.random_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    pub fn generate_challenge(&self) -> (String, CssChallengeData, String) {
        let mut rng = rand::rng();

        let session_id = self.generate_session_id();

        let invalid_count = rng.random_range(self.invalid_min..=self.invalid_max);
        let valid_count = self.valid_count;

        let mut all_names: HashSet<String> = HashSet::new();

        let valid_names: Vec<String> = (0..valid_count)
            .map(|i| {
                let name = self.generate_random_name();
                format!("{}-{}", name, i)
            })
            .collect();

        for name in &valid_names {
            all_names.insert(name.clone());
        }

        let mut invalid_names: Vec<String> = Vec::new();
        while invalid_names.len() < invalid_count as usize {
            let name = self.generate_random_name();
            if !all_names.contains(&name) {
                all_names.insert(name.clone());
                invalid_names.push(name);
            }
        }

        let mut css_rules = String::new();

        for name in &valid_names {
            // Use ranges to ensure real browsers match something
            let (min_num, min_den, max_num, max_den) = match rng.random_range(0..4) {
                0 => (1, 10, 1, 1), // Tall portrait
                1 => (1, 1, 10, 1), // Wide landscape
                2 => (1, 2, 2, 1),  // Normal range
                _ => (1, 5, 5, 1),  // Broad range
            };

            css_rules.push_str(&format!(
                "@media (min-aspect-ratio: {}/{}) and (max-aspect-ratio: {}/{}) {{ .waf-rnd-{} {{ background-image: url('{}/rnd-{}.png'); }} }}\n",
                min_num, min_den, max_num, max_den, name, self.asset_path, name
            ));
        }

        for name in &invalid_names {
            // Impossible aspect ratios (negative or zero)
            let (num, den) = if rng.random_bool(0.5) {
                (
                    -(rng.random_range(1..1000) as i32),
                    rng.random_range(1..1000),
                )
            } else {
                (
                    rng.random_range(1..1000) as i32,
                    -(rng.random_range(1..1000) as i32),
                )
            };

            css_rules.push_str(&format!(
                "@media (aspect-ratio: {}/{}) {{ .waf-rnd-{} {{ background-image: url('{}/rnd-{}.png'); }} }}\n",
                num, den, name, self.asset_path, name
            ));
        }

        let data = CssChallengeData {
            valid_names: valid_names.clone(),
            invalid_names: invalid_names.clone(),
            created_at: current_timestamp(),
        };

        (css_rules, data, session_id)
    }

    pub fn start_session(&self, session_id: &str, data: &CssChallengeData) {
        let mut store = self.sessions.write();
        let now = current_timestamp();

        // Proactive cleanup: clean expired sessions when table is >50% full
        if store.sessions.len() >= store.max_sessions / 2 {
            store
                .sessions
                .retain(|_, s| now < s.created_at + self.verification_window_secs as u64);
        }

        // If still full after cleanup, reject new session
        if store.sessions.len() >= store.max_sessions {
            tracing::warn!("CSS session table full, rejecting new session");
            return;
        }

        store.sessions.insert(
            session_id.to_string(),
            CssSession {
                valid_names: data.valid_names.clone(),
                invalid_names: data.invalid_names.clone(),
                requested_valid: HashSet::new(),
                created_at: current_timestamp(),
                verification_started: false,
            },
        );
    }

    pub fn record_asset_request(
        &self,
        session_id: &str,
        asset_name: &str,
    ) -> (AssetRequestResult, CssAssetAction) {
        let mut store = self.sessions.write();

        if let Some(session) = store.sessions.get_mut(session_id) {
            let now = current_timestamp();

            if now > session.created_at + self.verification_window_secs as u64 {
                store.sessions.remove(session_id);
                return (AssetRequestResult::Expired, CssAssetAction::DropConnection);
            }

            session.verification_started = true;

            for valid_name in &session.valid_names {
                if asset_name.starts_with(valid_name) {
                    session.requested_valid.insert(valid_name.clone());

                    let required = session.valid_names.len();
                    let received = session.requested_valid.len();

                    if received >= required {
                        store.sessions.remove(session_id);
                        return (
                            AssetRequestResult::ValidAssetComplete,
                            CssAssetAction::RedirectWithCookie,
                        );
                    } else {
                        return (
                            AssetRequestResult::ValidAsset,
                            CssAssetAction::DropConnection,
                        );
                    }
                }
            }

            for invalid_name in &session.invalid_names {
                if asset_name.starts_with(invalid_name) {
                    store.sessions.remove(session_id);
                    return (
                        AssetRequestResult::InvalidAsset,
                        CssAssetAction::DropConnection,
                    );
                }
            }

            (
                AssetRequestResult::UnknownAsset,
                CssAssetAction::DropConnection,
            )
        } else {
            (
                AssetRequestResult::NoSession,
                CssAssetAction::DropConnection,
            )
        }
    }

    pub fn cleanup_expired(&self) {
        let now = current_timestamp();
        let mut store = self.sessions.write();

        store.sessions.retain(|_id, session| {
            now < session.created_at
                + self.verification_window_secs as u64
                + SESSION_CLEANUP_INTERVAL_SECS
        });
    }

    fn generate_random_name(&self) -> String {
        let mut rng = rand::rng();
        let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..8)
            .map(|_| {
                let idx = rng.random_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    pub fn generate_challenge_page(
        &self,
        honeypot_html: &str,
    ) -> (String, String, CssChallengeData) {
        let (css_rules, data, session_id) = self.generate_challenge();

        let scripts = format!(
            r#"<style>{css_rules}</style>

<div class="waf-verification-area">
    {honeypot}
</div>

<meta http-equiv="refresh" content="{verification_window_secs};url=/">"#,
            css_rules = css_rules,
            honeypot = honeypot_html,
            verification_window_secs = self.verification_window_secs
        );

        let content = r#"<div class="waf-progress" id="waf-progress">Verifying browser...</div>"#;

        let page = ChallengePageTemplate::new(self.theme.clone())
            .title("Verifying")
            .subtitle("Please wait while we verify your browser.")
            .content(content)
            .scripts(&scripts)
            .render();

        (page, session_id, data)
    }

    pub fn session_cookie_name(&self) -> &str {
        &self.session_cookie_name
    }

    pub fn verified_cookie_name(&self) -> &str {
        &self.verified_cookie_name
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }

    pub fn asset_path(&self) -> &str {
        &self.asset_path
    }

    pub fn verification_window_secs(&self) -> u32 {
        self.verification_window_secs
    }
}

#[derive(Debug, Clone)]
pub struct CssChallengeData {
    pub valid_names: Vec<String>,
    pub invalid_names: Vec<String>,
    pub created_at: u64,
}

impl CssChallengeData {
    pub fn is_valid_asset(&self, name: &str) -> bool {
        self.valid_names.iter().any(|n| name.starts_with(n))
    }

    pub fn is_invalid_asset(&self, name: &str) -> bool {
        self.invalid_names.iter().any(|n| name.starts_with(n))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CssAssetAction {
    DropConnection,
    RedirectWithCookie,
}

#[derive(Debug, PartialEq)]
pub enum AssetRequestResult {
    ValidAsset,
    ValidAssetComplete,
    InvalidAsset,
    UnknownAsset,
    NoSession,
    Expired,
}

#[derive(Debug, PartialEq)]
pub enum CssVerificationResult {
    Passed,
    Failed { required: usize, received: usize },
    NoSession,
    NoAssetsRequested,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_css_challenge_generation() {
        let manager = CssManager::new(
            "test_cookie".to_string(),
            300,
            5,
            10,
            3,
            "/assets".to_string(),
            30,
        );

        let (css, data, session_id) = manager.generate_challenge();

        assert!(css.contains("@media"));
        assert_eq!(data.valid_names.len(), 3);
        assert!(data.invalid_names.len() >= 5 && data.invalid_names.len() <= 10);
        assert_eq!(session_id.len(), 32);
    }

    #[test]
    fn test_valid_asset_detection() {
        let manager = CssManager::new(
            "test_cookie".to_string(),
            300,
            5,
            10,
            2,
            "/assets".to_string(),
            30,
        );

        let (_, data, _) = manager.generate_challenge();

        assert!(data.is_valid_asset(&data.valid_names[0]));
        assert!(data.is_invalid_asset(&data.invalid_names[0]));
    }
}
