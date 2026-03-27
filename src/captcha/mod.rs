use crate::theme::{CaptchaPageTemplate, ThemeConfig};
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

const CAPTCHA_CHARS: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub struct CaptchaManager {
    challenges: Arc<RwLock<CaptchaStore>>,
    verification_window_secs: u32,
    theme: ThemeConfig,
}

struct CaptchaStore {
    challenges: HashMap<String, CaptchaChallenge>,
}

impl CaptchaStore {
    fn new() -> Self {
        Self {
            challenges: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct CaptchaChallenge {
    answer: String,
    created_at: u64,
}

impl CaptchaManager {
    pub fn new(verification_window_secs: u32) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(CaptchaStore::new())),
            verification_window_secs,
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

    pub async fn generate_challenge(&self) -> (String, String) {
        let answer = self.generate_random_text(6);
        let challenge_id = self.generate_random_id();

        let mut store = self.challenges.write().await;
        store.challenges.insert(
            challenge_id.clone(),
            CaptchaChallenge {
                answer: answer.clone(),
                created_at: current_timestamp(),
            },
        );

        let svg = self.render_captcha_svg(&answer);

        (challenge_id, svg)
    }

    pub async fn verify(&self, challenge_id: &str, answer: &str) -> CaptchaResult {
        let mut store = self.challenges.write().await;

        if let Some(challenge) = store.challenges.remove(challenge_id) {
            let now = current_timestamp();

            if now > challenge.created_at + self.verification_window_secs as u64 {
                return CaptchaResult::Expired;
            }

            if challenge.answer.to_uppercase() == answer.to_uppercase() {
                CaptchaResult::Passed
            } else {
                CaptchaResult::Failed
            }
        } else {
            CaptchaResult::Invalid
        }
    }

    pub async fn cleanup_expired(&self) {
        let now = current_timestamp();
        let mut store = self.challenges.write().await;

        store
            .challenges
            .retain(|_, c| now < c.created_at + self.verification_window_secs as u64 + 60);
    }

    fn generate_random_text(&self, length: usize) -> String {
        let mut rng = rand::rng();
        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..CAPTCHA_CHARS.len());
                CAPTCHA_CHARS.chars().nth(idx).unwrap()
            })
            .collect()
    }

    fn generate_random_id(&self) -> String {
        let mut rng = rand::rng();
        let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..16)
            .map(|_| {
                let idx = rng.random_range(0..charset.len());
                charset[idx] as char
            })
            .collect()
    }

    fn render_captcha_svg(&self, text: &str) -> String {
        let mut rng = rand::rng();

        let lines: String = (0..8)
            .map(|_| {
                let x1 = rng.random_range(0..200);
                let y1 = rng.random_range(0..80);
                let x2 = rng.random_range(0..200);
                let y2 = rng.random_range(0..80);
                format!(r#"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="rgb({},{},{})" stroke-width="1"/>"#,
                    x1, y1, x2, y2,
                    rng.random_range(100..200),
                    rng.random_range(100..200),
                    rng.random_range(100..200)
                )
            })
            .collect();

        let dots: String = (0..100)
            .map(|_| {
                let x = rng.random_range(0..200);
                let y = rng.random_range(0..80);
                format!(
                    r#"<circle cx="{}" cy="{}" r="1" fill="rgb({},{},{})"/>"#,
                    x,
                    y,
                    rng.random_range(150..220),
                    rng.random_range(150..220),
                    rng.random_range(150..220)
                )
            })
            .collect();

        let chars: String = text.chars().enumerate()
            .map(|(i, c)| {
                let x = 20 + i * 28;
                let y = 55;
                let rotation = rng.random_range(-20..20);
                let font_size = rng.random_range(28..36);
                let font_family = ["monospace", "Arial", "Courier New", "Verdana"];
                let ff = font_family[rng.random_range(0..font_family.len())];
                let color = format!("rgb({},{},{})",
                    rng.random_range(0..80),
                    rng.random_range(0..80),
                    rng.random_range(0..80)
                );

                format!(r#"<text x="{}" y="{}" font-family="{}" font-size="{}" fill="{}" transform="rotate({}, {}, {})">{}</text>"#,
                    x, y, ff, font_size, color, rotation, x, y, c
                )
            })
            .collect();

        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="80" viewBox="0 0 200 80">
            <rect width="100%" height="100%" fill="white"/>
            {}
            {}
            {}
        </svg>"#,
            lines, dots, chars
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum CaptchaResult {
    Passed,
    Failed,
    Expired,
    Invalid,
}

fn current_timestamp() -> u64 {
    crate::utils::current_timestamp()
}

pub fn generate_captcha_page(challenge_id: &str, theme: ThemeConfig) -> String {
    CaptchaPageTemplate::new(theme)
        .challenge_id(challenge_id)
        .render()
}
