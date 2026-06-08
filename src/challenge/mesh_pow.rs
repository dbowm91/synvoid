use crate::theme::{ChallengePageTemplate, ThemeConfig};
use crate::utils::current_timestamp;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct MeshPowChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_at: u64,
    pub mesh_config: MeshPowConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPowConfig {
    pub mesh_id: String,
    pub global_node_url: String,
    pub audit_urls: Vec<String>,
    pub key_exchange_enabled: bool,
    pub auditing_enabled: bool,
    pub pow_difficulty: u8,
    pub session_timeout_secs: u64,
}

impl Default for MeshPowConfig {
    fn default() -> Self {
        Self {
            mesh_id: String::new(),
            global_node_url: String::new(),
            audit_urls: vec![],
            key_exchange_enabled: false,
            auditing_enabled: false,
            pow_difficulty: 4,
            session_timeout_secs: 3600,
        }
    }
}

pub struct MeshPowManager {
    secret_key: [u8; 32],
    difficulty: u8,
    window_secs: u64,
    timeout_secs: u64,
    cookie_name: String,
    theme: ThemeConfig,
    mesh_config: MeshPowConfig,
    fallback_pow_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeshAuditResult {
    pub node_url: String,
    pub upstream_ip: Option<String>,
    pub routed_to_allowed_ip: bool,
    pub node_id: Option<String>,
    pub success: bool,
    pub error: Option<String>,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MeshPowSolution {
    pub pow_nonce: String,
    pub audit_results: Vec<MeshAuditResult>,
    pub session_id: Option<String>,
    pub session_key: Option<String>,
    pub key_exchange_completed: bool,
    pub audit_completed: bool,
}

impl MeshPowManager {
    pub fn new(
        difficulty: u8,
        window_secs: u64,
        timeout_secs: u64,
        cookie_name: String,
        mesh_config: MeshPowConfig,
    ) -> Self {
        let mut secret_key = [0u8; 32];
        rand::fill(&mut secret_key);

        Self {
            secret_key,
            difficulty: difficulty.clamp(1, 20),
            window_secs,
            timeout_secs,
            cookie_name,
            theme: ThemeConfig::default(),
            mesh_config,
            fallback_pow_enabled: true,
        }
    }

    pub fn with_theme(mut self, theme: ThemeConfig) -> Self {
        self.theme = theme;
        self
    }

    pub fn with_fallback_pow(mut self, enabled: bool) -> Self {
        self.fallback_pow_enabled = enabled;
        self
    }

    pub fn theme(&self) -> &ThemeConfig {
        &self.theme
    }

    pub fn mesh_config(&self) -> &MeshPowConfig {
        &self.mesh_config
    }

    pub fn is_mesh_enabled(&self) -> bool {
        self.mesh_config.key_exchange_enabled || self.mesh_config.auditing_enabled
    }

    pub fn generate_challenge(&self) -> MeshPowChallenge {
        let now = current_timestamp();
        let mut rng = rand::rng();
        let server_nonce: u64 = rng.random();

        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(&self.secret_key);
        challenge_data.extend_from_slice(&now.to_le_bytes());
        challenge_data.extend_from_slice(&server_nonce.to_le_bytes());

        let hash = Sha256::digest(&challenge_data);
        let payload = format!("{}:{}", now, hex::encode(hash));
        let challenge = BASE64.encode(payload.as_bytes());

        MeshPowChallenge {
            challenge,
            difficulty: self.difficulty,
            expires_at: now + self.timeout_secs,
            mesh_config: self.mesh_config.clone(),
        }
    }

    pub fn verify_pow_only(&self, challenge: &str, client_nonce: &str) -> bool {
        let now = current_timestamp();

        let decoded = match BASE64.decode(challenge.as_bytes()) {
            Ok(d) => d,
            Err(_) => return false,
        };

        let payload = match String::from_utf8(decoded) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp: u64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };

        let age = now.saturating_sub(timestamp);
        if age > self.timeout_secs {
            return false;
        }

        if timestamp > now + 60 {
            return false;
        }

        let input = format!("{}{}", challenge, client_nonce);
        let hash = Sha256::digest(input.as_bytes());

        super::has_leading_zeros_ct(&hash, self.difficulty as usize).into()
    }

    pub fn generate_challenge_page(&self, honeypot_html: &str) -> String {
        let challenge = self.generate_challenge();
        let timeout_ms = self.timeout_secs * 1000;
        let mesh_config_json = serde_json::to_string(&challenge.mesh_config).unwrap_or_default();

        let challenge_js = include_str!("../../static/mesh_pow_challenge.js");
        let challenge_js = challenge_js
            .replace("{{challenge}}", &challenge.challenge)
            .replace("{{difficulty}}", &challenge.difficulty.to_string())
            .replace("{{cookie_name}}", &self.cookie_name)
            .replace("{{window_secs}}", &self.window_secs.to_string())
            .replace("{{timeout_ms}}", &timeout_ms.to_string())
            .replace("{{mesh_config_json}}", &mesh_config_json);

        let scripts = format!(
            r#"<noscript>
    <form id="mesh-pow-form" method="POST" action="/_waf_pow_verify" style="display:none;">
        <input type="hidden" name="c" value="{challenge}">
        <input type="hidden" name="d" value="{difficulty}">
        <input type="hidden" name="n" id="mesh-pow-nonce" value="">
    </form>
    <script src="/_mesh_pow.js"></script>
</noscript>

<script type="module">
{challenge_js}
</script>"#,
            challenge = challenge.challenge,
            difficulty = challenge.difficulty
        );

        let content = r#"<div class="waf-progress" id="waf-progress">Computing...</div>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Verifying")
            .subtitle("Please wait while we verify your browser.")
            .content(content)
            .scripts(&scripts)
            .honeypot(honeypot_html)
            .render()
    }

    pub fn check_cookie(&self, cookie_value: Option<&str>) -> MeshPowResult {
        match cookie_value {
            Some(cookie) => match serde_json::from_str::<MeshPowSolution>(cookie) {
                Ok(solution) => {
                    if self.verify_pow_only_internal(&solution.pow_nonce) {
                        MeshPowResult::Valid(solution)
                    } else {
                        MeshPowResult::Invalid
                    }
                }
                Err(_) => MeshPowResult::Invalid,
            },
            None => MeshPowResult::NotSet,
        }
    }

    fn verify_pow_only_internal(&self, nonce: &str) -> bool {
        let challenge = self.generate_challenge();
        self.verify_pow_only(&challenge.challenge, nonce)
    }

    pub fn difficulty(&self) -> u8 {
        self.difficulty
    }

    pub fn cookie_name(&self) -> &str {
        &self.cookie_name
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MeshPowResult {
    Valid(MeshPowSolution),
    NotSet,
    Invalid,
}

#[cfg(test)]
pub(crate) fn solve_pow_sync(challenge: &str, difficulty: u8) -> Option<String> {
    const MAX_NONCE: u64 = 100_000_000;
    let zeros = difficulty as usize;

    for nonce in 0..MAX_NONCE {
        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        if super::has_leading_zeros(&hash, zeros) {
            return Some(nonce.to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_pow_generation() {
        let config = MeshPowConfig {
            mesh_id: "test-mesh".to_string(),
            global_node_url: "https://global.example.com".to_string(),
            audit_urls: vec!["https://edge1.example.com".to_string()],
            key_exchange_enabled: true,
            auditing_enabled: true,
            pow_difficulty: 4,
            session_timeout_secs: 3600,
        };
        let manager = MeshPowManager::new(4, 300, 60, "mesh_test_cookie".to_string(), config);
        let challenge = manager.generate_challenge();

        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.difficulty, 4);
        assert!(challenge.mesh_config.key_exchange_enabled);
    }

    #[test]
    fn test_mesh_pow_solve_and_verify() {
        let config = MeshPowConfig::default();
        let manager = MeshPowManager::new(4, 300, 60, "mesh_test_cookie".to_string(), config);
        let challenge = manager.generate_challenge();

        let solution = solve_pow_sync(&challenge.challenge, challenge.difficulty);
        assert!(solution.is_some());

        let nonce = solution.unwrap();
        assert!(manager.verify_pow_only(&challenge.challenge, &nonce));
    }
}
