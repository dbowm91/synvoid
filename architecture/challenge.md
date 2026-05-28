# Challenge Architecture

## 1. Purpose and Responsibility

The Challenge module (`src/challenge/`) provides a **multi-modal browser verification system** with Proof-of-Work (SHA-256), CSS-based JavaScript challenges, mesh PoW, and honeypot tracking. Supports adaptive difficulty and rate limiting.

**Core Responsibilities:**
- Multi-modal challenge generation (PoW, CSS, Mesh PoW)
- Browser verification via cookie-based challenge completion
- Adaptive difficulty adjustment
- Rate limiting for challenge attempts
- Honeypot-based bot detection

---

## 2. Key Data Structures

```rust
pub struct ChallengeManager {
    pow_manager: PowManager,
    css_manager: CssManager,
    mesh_pow_manager: MeshPowManager,
    honeypot_tracker: HoneypotTracker,
    rate_limiter: RateLimiter,
    config: ChallengeConfig,
}

pub enum ChallengeResult {
    Passed,
    NotSet,
    Failed,
    RateLimited,
}

pub enum ChallengeType {
    None,
    PowChallenge,
    MeshPowChallenge,
    CssChallenge,
}

pub enum ChallengePriority {
    PowThenCss,
    CssThenPow,
    PowOnly,
    CssOnly,
    MeshPowThenCss,
    MeshPowOnly,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ChallengeManager::new(config)` | Constructor with all sub-managers |
| `generate_challenge_page(ip, app_path).await` | Generate verification page |
| `check_cookie(value) -> ChallengeResult` | Verify challenge completion cookie |
| `is_rate_limited(ip)` | Check if IP is rate limited |
| `record_attempt(ip)` | Record challenge attempt |
| `clear_attempts(ip)` | Reset attempts for IP |
| `verify_pow(challenge, nonce) -> bool` | Verify PoW solution |
| `generate_nojs_page(ip, app_path) -> String` | No-JavaScript fallback |
| `record_css_asset_request(session_id, asset_name)` | Track CSS asset loads |

---

## 4. Submodules

### `pow.rs` — Proof-of-Work Manager
- SHA-256 based PoW with configurable difficulty
- Adaptive difficulty based on threat level
- WASM solver support for browser-side computation
- CSS fallback for non-JavaScript browsers

### `css.rs` — CSS Challenge Manager
- JavaScript-based verification via CSS asset loading
- Asset tracking for challenge completion
- Anti-automation techniques

### `mesh_pow.rs` — Mesh PoW Manager
- Mesh-network-integrated PoW with key exchange
- Distributed verification across mesh nodes
- Auditing of mesh PoW completions

### `honeypot.rs` — Honeypot Tracker
- Hidden link detection for bots
- Per-IP honeypot hit tracking
- Integration with unified honeypot system

---

## 5. Integration Points

- **WAF**: Central to bot protection pipeline
- **Theme**: Uses theme system for challenge page rendering
- **Mesh**: Mesh PoW for distributed verification
- **Unified Honeypot**: Correlates honeypot hits with challenge failures
- **Admin API**: Challenge configuration and metrics

---

## 6. Security Considerations

- **Constant-Time Comparison**: `has_leading_zeros_ct()` for PoW verification
- **Rate Limiting**: Per-IP attempt tracking with configurable limits
- **Adaptive Difficulty**: Increases difficulty for repeat offenders
- **No-JS Fallback**: Graceful degradation without JavaScript
