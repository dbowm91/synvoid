use crate::theme::{ChallengePageTemplate, ThemeConfig};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_NONCE: u64 = 100_000_000;

#[derive(Debug, Clone)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_at: u64,
}

pub struct PowManager {
    secret_key: [u8; 32],
    difficulty: u8,
    window_secs: u64,
    timeout_secs: u64,
    cookie_name: String,
    theme: ThemeConfig,
}

impl PowManager {
    pub fn new(difficulty: u8, window_secs: u64, timeout_secs: u64, cookie_name: String) -> Self {
        let mut secret_key = [0u8; 32];
        rand::thread_rng().fill(&mut secret_key);

        Self {
            secret_key,
            difficulty: difficulty.clamp(1, 20),
            window_secs,
            timeout_secs,
            cookie_name,
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

    pub fn generate_challenge(&self) -> PowChallenge {
        let now = current_timestamp();
        let mut rng = rand::thread_rng();
        let server_nonce: u64 = rng.gen();

        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(&self.secret_key);
        challenge_data.extend_from_slice(&now.to_le_bytes());
        challenge_data.extend_from_slice(&server_nonce.to_le_bytes());

        let hash = Sha256::digest(&challenge_data);
        let payload = format!("{}:{}", now, hex::encode(hash));
        let challenge = BASE64.encode(payload.as_bytes());

        PowChallenge {
            challenge,
            difficulty: self.difficulty,
            expires_at: now + self.timeout_secs,
        }
    }

    pub fn verify_solution(&self, challenge: &str, client_nonce: &str) -> bool {
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

        if now > timestamp + self.timeout_secs {
            return false;
        }

        let input = format!("{}{}", challenge, client_nonce);
        let hash = Sha256::digest(input.as_bytes());

        has_leading_zeros(&hash, self.difficulty as usize)
    }

    pub fn generate_challenge_page(&self, honeypot_html: &str) -> String {
        let challenge = self.generate_challenge();
        let timeout_ms = self.timeout_secs * 1000;
        let css_fallback_url = "/_waf_css_challenge";

        let scripts = format!(
            r#"<noscript>
    <form id="pow-form" method="POST" action="/_waf_pow_verify" style="display:none;">
        <input type="hidden" name="c" value="{challenge}">
        <input type="hidden" name="d" value="{difficulty}">
        <input type="hidden" name="n" id="pow-nonce" value="">
    </form>
    <script src="/_waf_pow_nojs.js" data-challenge="{challenge}" data-difficulty="{difficulty}"></script>
</noscript>

<script type="module">
    const challenge = "{challenge}";
    const difficulty = {difficulty};
    const cookieName = "{cookie_name}";
    const windowSecs = {window_secs};
    const cssFallbackUrl = "{css_fallback_url}";

    function updateProgress(msg) {{
        const el = document.getElementById('waf-progress');
        if (el) el.textContent = msg;
    }}

    function hasLeadingZeros(hash, zeros) {{
        let bitIndex = 0;
        for (let i = 0; i < hash.length && bitIndex < zeros; i++) {{
            const byte = hash[i];
            for (let j = 7; j >= 0 && bitIndex < zeros; j--) {{
                if ((byte >> j) & 1) return false;
                bitIndex++;
            }}
        }}
        return true;
    }}

    async function sha256(text) {{
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hash);
    }}

    async function solvePow(challenge, difficulty) {{
        const zeros = difficulty;
        for (let nonce = 0; nonce < 100000000; nonce++) {{
            const input = challenge + nonce.toString();
            const hash = await sha256(input);
            if (hasLeadingZeros(hash, zeros)) {{
                return nonce.toString();
            }}
            if (nonce % 1000 === 0) {{
                updateProgress('Computing... ' + nonce + ' hashes');
            }}
        }}
        return null;
    }}

    async function runChallenge() {{
        updateProgress('Loading WASM...');

        try {{
            const wasmModule = await import('/_waf_pow.js');
            await wasmModule.default();
            const nonce = wasmModule.solve_pow(challenge, difficulty);

            if (nonce !== null && nonce !== undefined) {{
                updateProgress('Solution found!');
                document.cookie = cookieName + '=' + nonce + ':' + challenge + '; path=/; max-age=' + windowSecs + '; Secure; SameSite=Strict';
                setTimeout(() => location.reload(), 100);
                return;
            }}
        }} catch (e) {{
            console.log('WASM not available, using JS fallback');
        }}

        updateProgress('Computing...');
        const nonce = await solvePow(challenge, difficulty);

        if (nonce) {{
            updateProgress('Solution found!');
            document.cookie = cookieName + '=' + nonce + ':' + challenge + '; path=/; max-age=' + windowSecs + '; Secure; SameSite=Strict';
            setTimeout(() => location.reload(), 100);
        }} else {{
            updateProgress('Challenge failed, redirecting...');
            setTimeout(() => {{ location.href = cssFallbackUrl; }}, 1000);
        }}
    }}

    runChallenge();

    setTimeout(() => {{
        if (!document.cookie.includes(cookieName + '=')) {{
            location.href = cssFallbackUrl;
        }}
    }}, {timeout_ms});
</script>

<script nomodule src="/_waf_pow_fallback.js"></script>"#,
            challenge = challenge.challenge,
            difficulty = challenge.difficulty,
            cookie_name = self.cookie_name,
            window_secs = self.window_secs,
            css_fallback_url = css_fallback_url,
            timeout_ms = timeout_ms
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

    pub fn generate_nojs_page(&self, honeypot_html: &str) -> String {
        let challenge = self.generate_challenge();

        let scripts = format!(
            r#"<form id="pow-form" method="POST" action="/_waf_pow_verify">
    <input type="hidden" name="c" value="{challenge}">
    <input type="hidden" name="d" value="{difficulty}">
    <input type="hidden" name="n" id="pow-nonce" value="">
</form>

<script src="/_waf_pow_nojs.js"></script>"#,
            challenge = challenge.challenge,
            difficulty = challenge.difficulty
        );

        let content = r#"<div class="waf-progress" id="waf-progress">Loading...</div>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Verifying")
            .subtitle("Computing verification. Please wait...")
            .content(content)
            .scripts(&scripts)
            .honeypot(honeypot_html)
            .render()
    }

    pub fn check_cookie(&self, cookie_value: Option<&str>) -> PowResult {
        match cookie_value {
            Some(cookie) => {
                let parts: Vec<&str> = cookie.splitn(2, ':').collect();
                if parts.len() != 2 {
                    return PowResult::Invalid;
                }

                let nonce = parts[0];
                let challenge = parts[1];

                if self.verify_solution(challenge, nonce) {
                    PowResult::Valid
                } else {
                    PowResult::Invalid
                }
            }
            None => PowResult::NotSet,
        }
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
pub enum PowResult {
    Valid,
    NotSet,
    Invalid,
}

pub fn has_leading_zeros(hash: &[u8], zeros: usize) -> bool {
    let mut bit_index = 0;

    for &byte in hash {
        for j in (0..8).rev() {
            if bit_index >= zeros {
                return true;
            }
            if (byte >> j) & 1 != 0 {
                return false;
            }
            bit_index += 1;
        }
    }

    bit_index >= zeros
}

pub fn solve_pow_sync(challenge: &str, difficulty: u8) -> Option<String> {
    let zeros = difficulty as usize;

    for nonce in 0..MAX_NONCE {
        let input = format!("{}{}", challenge, nonce);
        let hash = Sha256::digest(input.as_bytes());

        if has_leading_zeros(&hash, zeros) {
            return Some(nonce.to_string());
        }
    }

    None
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
    fn test_pow_generation() {
        let manager = PowManager::new(4, 300, 60, "test_cookie".to_string());
        let challenge = manager.generate_challenge();

        assert!(!challenge.challenge.is_empty());
        assert_eq!(challenge.difficulty, 4);
    }

    #[test]
    fn test_pow_solve_and_verify() {
        let manager = PowManager::new(4, 300, 60, "test_cookie".to_string());
        let challenge = manager.generate_challenge();

        let solution = solve_pow_sync(&challenge.challenge, challenge.difficulty);
        assert!(solution.is_some());

        let nonce = solution.unwrap();
        assert!(manager.verify_solution(&challenge.challenge, &nonce));
    }

    #[test]
    fn test_invalid_nonce() {
        let manager = PowManager::new(8, 300, 60, "test_cookie".to_string());
        let challenge = manager.generate_challenge();

        assert!(!manager.verify_solution(&challenge.challenge, "invalid_nonce"));
    }

    #[test]
    fn test_leading_zeros() {
        let hash = hex::decode("0001ff").unwrap();
        assert!(has_leading_zeros(&hash, 15));
        assert!(!has_leading_zeros(&hash, 16));
    }
}
