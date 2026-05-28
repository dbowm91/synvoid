# CAPTCHA Architecture

## 1. Purpose and Responsibility

The CAPTCHA module (`src/captcha/`) provides **text-based CAPTCHA generation and verification** with SVG rendering and expiration-based cleanup. Used as a lightweight alternative to the full challenge system for bot verification.

**Core Responsibilities:**
- Generate text-based CAPTCHA challenges
- SVG-based image rendering
- Time-windowed verification with expiration
- HTML page generation for CAPTCHA display

---

## 2. Key Data Structures

```rust
pub struct CaptchaManager {
    challenges: Arc<RwLock<HashMap<String, CaptchaChallenge>>>,
    verification_window_secs: u64,
    theme: Option<ThemeConfig>,
}

struct CaptchaChallenge {
    answer: String,
    created_at: u64,
}

pub enum CaptchaResult {
    Passed,
    Failed,
    Expired,
    Invalid,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `CaptchaManager::new(verification_window_secs)` | Constructor |
| `with_theme(theme) -> Self` | Builder for ThemeConfig |
| `generate_challenge().await -> (String, String)` | Returns (challenge_id, svg_image) |
| `verify(challenge_id, answer).await -> CaptchaResult` | Verify answer |
| `cleanup_expired().await` | Remove expired challenges |
| `generate_captcha_page(challenge_id, theme) -> String` | Full HTML page |

---

## 4. Integration Points

- **WAF**: Bot challenge pages use CAPTCHA as verification step
- **Theme**: Uses `CaptchaPageTemplate` for branded rendering
- **Utils**: Uses `current_timestamp()` for time-based expiration

---

## 5. Key Implementation Details

- **Expiration**: Challenges automatically expire after configurable window
- **SVG Rendering**: Generates SVG images for text-based CAPTCHAs
- **Theme Support**: Integrates with the theme system for consistent branding
- **Cleanup**: Periodic cleanup of expired challenges to prevent memory growth
