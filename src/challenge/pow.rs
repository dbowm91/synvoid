#![allow(dead_code)]
// SAFETY_REASON: Proof-of-work challenge system - reserved for anti-abuse mechanisms

use crate::theme::{ChallengePageTemplate, ThemeConfig};
use crate::utils::current_timestamp;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::Rng;
use sha2::{Digest, Sha256};

const MAX_NONCE: u64 = 100_000_000;
const MIN_TIMESTAMP_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct PowChallenge {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_at: u64,
}

pub struct PowManager {
    secret_key: [u8; 32],
    difficulty: u8,
    adaptive_difficulty: bool,
    max_difficulty: u8,
    active_challenges: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    window_secs: u64,
    timeout_secs: u64,
    cookie_name: String,
    theme: ThemeConfig,
    css_fallback_enabled: bool,
}

impl PowManager {
    pub fn new(difficulty: u8, window_secs: u64, timeout_secs: u64, cookie_name: String) -> Self {
        let mut secret_key = [0u8; 32];
        rand::fill(&mut secret_key);

        Self {
            secret_key,
            difficulty: difficulty.clamp(1, 32),
            adaptive_difficulty: false,
            max_difficulty: 16,
            active_challenges: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            window_secs,
            timeout_secs,
            cookie_name,
            theme: ThemeConfig::default(),
            css_fallback_enabled: true,
        }
    }

    pub fn with_adaptive_difficulty(mut self, enabled: bool, max_difficulty: u8) -> Self {
        self.adaptive_difficulty = enabled;
        self.max_difficulty = max_difficulty.clamp(self.difficulty, 32);
        self
    }

    pub fn set_difficulty(&mut self, difficulty: u8) {
        self.difficulty = difficulty.clamp(1, 32);
    }

    pub fn get_computed_difficulty(&self) -> u8 {
        if !self.adaptive_difficulty {
            return self.difficulty;
        }

        let active = self
            .active_challenges
            .load(std::sync::atomic::Ordering::Relaxed);
        if active < 100 {
            self.difficulty
        } else {
            // Logarithmic scaling: increase difficulty based on active challenges
            // Every doubling of active challenges above 100 adds 1 bit of difficulty
            let extra_bits = (active as f32 / 100.0).log2() as u8;
            (self.difficulty + extra_bits).min(self.max_difficulty)
        }
    }

    pub fn with_theme(mut self, theme: ThemeConfig) -> Self {
        self.theme = theme;
        self
    }

    pub fn with_css_fallback(mut self, enabled: bool) -> Self {
        self.css_fallback_enabled = enabled;
        self
    }

    pub fn theme(&self) -> &ThemeConfig {
        &self.theme
    }

    pub fn css_fallback_enabled(&self) -> bool {
        self.css_fallback_enabled
    }

    pub fn generate_challenge(&self) -> PowChallenge {
        let now = current_timestamp();
        let difficulty = self.get_computed_difficulty();

        // Increment active challenges counter
        self.active_challenges
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut challenge_data = Vec::new();
        challenge_data.extend_from_slice(&self.secret_key);
        challenge_data.extend_from_slice(&now.to_le_bytes());

        let hash = Sha256::digest(&challenge_data);
        // Include difficulty in the payload to ensure verification uses the same difficulty
        let payload = format!("{}:{}:{}", now, hex::encode(hash), difficulty);
        let challenge = BASE64.encode(payload.as_bytes());

        PowChallenge {
            challenge,
            difficulty,
            expires_at: now + self.timeout_secs,
        }
    }

    pub fn verify_solution(&self, challenge: &str, client_nonce: &str) -> bool {
        // Decrement active challenges counter on verification attempt (best effort)
        self.active_challenges
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

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
        if parts.len() < 2 {
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

        // Difficulty might be stored in the payload (for adaptive support)
        let difficulty = if parts.len() >= 3 {
            parts[2].parse().unwrap_or(self.difficulty)
        } else {
            self.difficulty
        };

        let input = format!("{}{}", challenge, client_nonce);
        let hash = Sha256::digest(input.as_bytes());

        has_leading_zeros_ct(&hash, difficulty as usize).into()
    }

    pub fn generate_challenge_page(&self, honeypot_html: &str) -> String {
        let challenge = self.generate_challenge();
        let timeout_ms = self.timeout_secs * 1000;

        let css_fallback_action = if self.css_fallback_enabled {
            r#"
        } else {{
            updateProgress('Challenge failed, redirecting...');
            setTimeout(() => {{ location.href = cssFallbackUrl; }}, 1000);
        }}
    }}

    runChallenge();

    setTimeout(() => {{
        if (!document.cookie.includes(cookieName + '=')) {{
            location.href = cssFallbackUrl;
        }}
    }}, timeout_ms);"#
        } else {
            r#"
        } else {{
            updateProgress('Challenge failed. Please refresh the page.');
        }}
    }}

    runChallenge();

    setTimeout(() => {{
        if (!document.cookie.includes(cookieName + '=')) {{
            updateProgress('Verification timed out. Please refresh.');
        }}
    }}, timeout_ms);"#
        };

        let css_fallback_decl = if self.css_fallback_enabled {
            r#"const cssFallbackUrl = "/_waf_css_challenge";"#
        } else {
            ""
        };

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
    const timeout_ms = {timeout_ms};
    {css_fallback_decl}

    function updateProgress(msg) {{
        const el = document.getElementById('waf-progress');
        if (el) el.textContent = msg;
    }}

    function hasLeadingZeros(hash, zeros) {{
        let bitIndex = 0;
        for (let i = 0; i < hash.length && bitIndex < zeros; i++) {{
            const byte = hash[i];
            for (let j = 7; j >= 0 && bitIndex < zeros; j++) {{
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
            setTimeout(() => location.reload(), 100);{css_fallback_action}
</script>

<script nomodule src="/_waf_pow_fallback.js"></script>"#,
            challenge = challenge.challenge,
            difficulty = challenge.difficulty,
            cookie_name = self.cookie_name,
            window_secs = self.window_secs,
            timeout_ms = timeout_ms,
            css_fallback_decl = css_fallback_decl,
            css_fallback_action = css_fallback_action
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

        let content = r#"<div class="waf-progress" id="waf-progress">Computing...</div>"#;

        ChallengePageTemplate::new(self.theme.clone())
            .title("Verifying")
            .subtitle("Please wait while we verify your browser.")
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
    let zeros_u8 = zeros / 8;
    let zeros_remainder = zeros % 8;

    let mut result: u8 = 1;

    for hash_byte in &hash[..zeros_u8] {
        result &= (*hash_byte == 0) as u8;
    }

    if zeros_remainder > 0 && zeros_u8 < hash.len() {
        let mask = (0xFF_u8) << (8 - zeros_remainder);
        result &= ((hash[zeros_u8] & mask) == 0) as u8;
    }

    result == 1
}

pub fn has_leading_zeros_ct(hash: &[u8], zeros: usize) -> subtle::Choice {
    let zeros_u8 = zeros / 8;
    let zeros_remainder = zeros % 8;

    let mut result = subtle::Choice::from(1);

    for hash_byte in hash.iter().take(zeros_u8.min(hash.len())) {
        result &= subtle::Choice::from((*hash_byte == 0) as u8);
    }

    if zeros_remainder > 0 && zeros_u8 < hash.len() {
        let mask = (0xFF_u8) << (8 - zeros_remainder);
        result &= subtle::Choice::from(((hash[zeros_u8] & mask) == 0) as u8);
    }

    result
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
        assert!(!manager.verify_solution(&challenge.challenge, "invalid_nonce"));
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

    #[test]
    fn test_leading_zeros_ct() {
        let hash = hex::decode("0001ff").unwrap();
        assert!(has_leading_zeros_ct(&hash, 15).unwrap_u8() == 1);
        assert!(has_leading_zeros_ct(&hash, 16).unwrap_u8() == 0);
    }
}
