use crate::theme::{ChallengePageTemplate, ThemeConfig};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

const SESSION_CLEANUP_INTERVAL_SECS: u64 = 60;

pub struct CssManager {
    cookie_name: String,
    window_secs: u64,
    invalid_min: u32,
    invalid_max: u32,
    valid_count: u32,
    asset_path: String,
    valid_ratios: Vec<String>,
    verification_window_secs: u32,
    sessions: Arc<RwLock<CssSessionStore>>,
    theme: ThemeConfig,
}

struct CssSessionStore {
    sessions: HashMap<IpAddr, CssSession>,
    cleanup_counter: u64,
}

impl CssSessionStore {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            cleanup_counter: 0,
        }
    }
}

#[derive(Clone)]
struct CssSession {
    challenge_id: String,
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
        valid_ratios: Vec<String>,
        verification_window_secs: u32,
    ) -> Self {
        let valid_ratios = if valid_ratios.is_empty() {
            vec!["16/9".to_string(), "4/3".to_string(), "1/1".to_string()]
        } else {
            valid_ratios
        };

        Self {
            cookie_name,
            window_secs,
            invalid_min: invalid_min.max(1),
            invalid_max: invalid_max.max(invalid_min),
            valid_count,
            asset_path,
            valid_ratios,
            verification_window_secs,
            sessions: Arc::new(RwLock::new(CssSessionStore::new())),
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

    pub fn generate_challenge(&self) -> (String, CssChallengeData) {
        let mut rng = rand::thread_rng();

        let invalid_count = rng.gen_range(self.invalid_min..=self.invalid_max);
        let valid_count = self.valid_count;

        let mut all_names: HashSet<String> = HashSet::new();

        let valid_ratios: Vec<String> = (0..valid_count)
            .map(|_| self.valid_ratios[rng.gen_range(0..self.valid_ratios.len())].clone())
            .collect();

        let valid_names: Vec<String> = valid_ratios
            .iter()
            .enumerate()
            .map(|(i, _)| {
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

        let challenge_id = self.generate_random_name();

        let mut css_rules = String::new();

        for (i, ratio) in valid_ratios.iter().enumerate() {
            css_rules.push_str(&format!(
                "@media (aspect-ratio: {}) {{ .waf-rnd-{} {{ background-image: url('{}/rnd-{}.png'); }} }}\n",
                ratio, valid_names[i], self.asset_path, valid_names[i]
            ));
        }

        for name in &invalid_names {
            let num = rng.gen_range(50..2000);
            let den = rng.gen_range(50..2000);
            css_rules.push_str(&format!(
                "@media (aspect-ratio: {}/{}) {{ .waf-rnd-{} {{ background-image: url('{}/rnd-{}.png'); }} }}\n",
                num, den, name, self.asset_path, name
            ));
        }

        let data = CssChallengeData {
            challenge_id: challenge_id.clone(),
            valid_names: valid_names.clone(),
            invalid_names: invalid_names.clone(),
            created_at: current_timestamp(),
        };

        (css_rules, data)
    }

    pub async fn start_session(&self, client_ip: IpAddr, data: &CssChallengeData) {
        let mut store = self.sessions.write().await;
        store.sessions.insert(
            client_ip,
            CssSession {
                challenge_id: data.challenge_id.clone(),
                valid_names: data.valid_names.clone(),
                invalid_names: data.invalid_names.clone(),
                requested_valid: HashSet::new(),
                created_at: current_timestamp(),
                verification_started: false,
            },
        );
    }

    pub async fn record_asset_request(&self, client_ip: IpAddr, asset_name: &str) -> AssetRequestResult {
        let mut store = self.sessions.write().await;
        
        if let Some(session) = store.sessions.get_mut(&client_ip) {
            let now = current_timestamp();
            
            if now > session.created_at + self.verification_window_secs as u64 {
                store.sessions.remove(&client_ip);
                return AssetRequestResult::Expired;
            }

            session.verification_started = true;

            for valid_name in &session.valid_names {
                if asset_name.starts_with(valid_name) {
                    session.requested_valid.insert(valid_name.clone());
                    return AssetRequestResult::ValidAsset;
                }
            }

            for invalid_name in &session.invalid_names {
                if asset_name.starts_with(invalid_name) {
                    store.sessions.remove(&client_ip);
                    return AssetRequestResult::InvalidAsset;
                }
            }

            AssetRequestResult::UnknownAsset
        } else {
            AssetRequestResult::NoSession
        }
    }

    pub async fn verify_challenge(&self, client_ip: IpAddr) -> CssVerificationResult {
        let mut store = self.sessions.write().await;
        
        if let Some(session) = store.sessions.remove(&client_ip) {
            let now = current_timestamp();
            
            if now > session.created_at + self.verification_window_secs as u64 {
                return CssVerificationResult::Expired;
            }

            if !session.verification_started {
                return CssVerificationResult::NoAssetsRequested;
            }

            let required_count = session.valid_names.len();
            let requested_count = session.requested_valid.len();

            if requested_count >= required_count {
                CssVerificationResult::Passed
            } else {
                CssVerificationResult::Failed {
                    required: required_count,
                    received: requested_count,
                }
            }
        } else {
            CssVerificationResult::NoSession
        }
    }

    pub async fn cleanup_expired(&self) {
        let now = current_timestamp();
        let mut store = self.sessions.write().await;
        
        store.sessions.retain(|_ip, session| {
            now < session.created_at + self.verification_window_secs as u64 + SESSION_CLEANUP_INTERVAL_SECS
        });
    }

    fn generate_random_name(&self) -> String {
        let mut rng = rand::thread_rng();
        let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..8)
            .map(|_| {
                let idx = rng.gen_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    pub fn generate_challenge_page(&self, client_ip: IpAddr, honeypot_html: &str) -> String {
        let (css_rules, data) = self.generate_challenge();

        let asset_path = &self.asset_path;
        let hidden_images: String = data.valid_names.iter()
            .map(|name| {
                format!(
                    r#"<img src="{}/rnd-{}.png" style="display:none;" alt="">"#,
                    asset_path, name
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let scripts = format!(
            r#"<style>{css_rules}</style>

<div class="waf-verification-area">
    {honeypot}
    {hidden_images}
</div>

<script>
    let verified = false;
    const verificationTime = {verification_window_secs};
    
    async function checkVerification() {{
        try {{
            const response = await fetch('/_waf_css_verify?ip=' + encodeURIComponent(window.location.hostname));
            const data = await response.json();
            if (data.verified) {{
                verified = true;
                document.cookie = '{cookie_name}=verified; path=/; max-age={window_secs}; Secure; SameSite=Strict';
                setTimeout(function() {{ window.location.reload(); }}, 500);
            }}
        }} catch(e) {{}}
    }}

    const startTime = Date.now();
    const checkInterval = setInterval(() => {{
        const elapsed = (Date.now() - startTime) / 1000;
        if (elapsed >= verificationTime) {{
            clearInterval(checkInterval);
            if (!verified) {{
                window.location.reload();
            }}
        }}
        checkVerification();
    }}, 500);
</script>"#,
            css_rules = css_rules,
            honeypot = honeypot_html,
            hidden_images = hidden_images,
            verification_window_secs = self.verification_window_secs,
            cookie_name = self.cookie_name,
            window_secs = self.window_secs
        );

        let content = r#"<div class="waf-progress" id="waf-progress">Checking browser...</div>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Verifying")
            .subtitle("Please wait while we verify your browser.")
            .content(content)
            .scripts(&scripts)
            .render()
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
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
    pub challenge_id: String,
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

#[derive(Debug, PartialEq)]
pub enum AssetRequestResult {
    ValidAsset,
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

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
            vec![],
            30,
        );

        let (css, data) = manager.generate_challenge();

        assert!(css.contains("@media"));
        assert_eq!(data.valid_names.len(), 3);
        assert!(data.invalid_names.len() >= 5 && data.invalid_names.len() <= 10);
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
            vec![],
            30,
        );

        let (_, data) = manager.generate_challenge();

        assert!(data.is_valid_asset(&data.valid_names[0]));
        assert!(data.is_invalid_asset(&data.invalid_names[0]));
    }
}
