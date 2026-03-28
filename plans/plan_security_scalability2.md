# Implementation Plan: MaluWAF Security & Scalability Fixes

## Executive Summary

This plan addresses security vulnerabilities, scalability bottlenecks, and code quality issues identified in the MaluWAF codebase review. Key deliverables include:

1. **Image Poisoning** - Integration with cloakrs crate for AI/ML training protection
2. **Security Fixes** - Input validation DoS, plugin permissions, password complexity
3. **Scalability Improvements** - Proxy cache LRU, rate limiter cleanup

---

## Phase 1: Image Poisoning Implementation (cloakrs Integration)

### 1.1 Add cloakrs Dependency

**File:** `Cargo.toml`

Add dependency with `async` feature for non-blocking image processing:

```toml
cloakrs = { path = "/Users/davidbowman/projects/cloak", features = ["async"] }
```

### 1.2 Configuration Schema

**File:** `src/config/site.rs` - Add to `SiteStaticConfig`:

```rust
pub struct SiteImagePoisonConfig {
    /// Enable image poisoning. Default: false (disabled)
    #[serde(default)]
    pub enabled: Option<bool>,
    
    /// Protection level: "disabled"|"light"|"standard"|"enhanced"|"strong"
    /// Default: "strong" when enabled
    #[serde(default = "default_poison_level")]
    pub level: Option<String>,
    
    /// Protection intensity (0.0-1.0). Default: 0.5
    #[serde(default = "default_poison_intensity")]
    pub intensity: Option<f32>,
    
    /// Optional deterministic seed for reproducible protection
    #[serde(default)]
    pub seed: Option<u64>,
    
    /// Output format: "png"|"jpeg"|"webp". Default: matches input
    #[serde(default)]
    pub output_format: Option<String>,
    
    /// Maximum image dimension. Default: 4096
    #[serde(default = "default_max_dimension")]
    pub max_dimension: Option<u32>,
    
    /// JPEG quality (1-100). Default: 85
    #[serde(default = "default_jpeg_quality")]
    pub jpeg_quality: Option<u8>,
    
    /// MIME types to exclude from poisoning. Default: ["image/svg+xml"]
    #[serde(default = "default_excluded_types")]
    pub excluded_types: Option<Vec<String>>,
    
    /// Copyright holder for legal metadata
    #[serde(default)]
    pub legal_copyright: Option<String>,
    
    /// Usage terms for legal metadata
    #[serde(default)]
    pub legal_terms: Option<String>,
    
    /// DMI (Data Mining) value for AI exclusion
    /// Default: "ProhibitedAiMlTraining" (matches cloak crate default)
    #[serde(default = "default_dmi_value")]
    pub dmi_value: Option<String>,
}

// Default values
fn default_poison_level() -> Option<String> { Some("strong".to_string()) }
fn default_poison_intensity() -> Option<f32> { Some(0.5) }
fn default_max_dimension() -> Option<u32> { Some(4096) }
fn default_jpeg_quality() -> Option<u8> { Some(85) }
fn default_excluded_types() -> Option<Vec<String>> { 
    Some(vec!["image/svg+xml".to_string()]) 
}
fn default_dmi_value() -> Option<String> { Some("ProhibitedAiMlTraining".to_string()) }
```

**Design Rationale:**

| Decision | Rationale |
|----------|-----------|
| Disabled by default | Conservative security posture - must be explicitly enabled |
| `strong` when enabled | Maximum protection when opted-in |
| Exclude SVG | SVG is vector-based, not suitable for pixel-level poisoning |
| DMI default | Matches cloak crate default; enables AI training exclusion by default |
| Preserve format | User requirement - don't auto-convert unless specified |

### 1.3 Mesh Propagation

**No changes needed** - The existing `SiteConfigSync` message carries full site config JSON. Image poisoning config automatically flows through when:

- Origin server enables it in `SiteStaticConfig`
- Config is synced via mesh protocol to edge nodes

In mesh mode, the origin's settings are passed through to edge nodes serving the content.

### 1.4 Worker Implementation

**File:** `src/worker/image_poisoning.rs`

```rust
use cloakrs::{process_image_bytes, ProtectionContext, ProtectionLevel, ImageOutputFormat, DmiValue, LegalMetadata};

pub(super) fn poison_image_sync(
    state: &StaticWorkerState,
    site_id: &str,
    body: Vec<u8>,
    _last_modified: Option<String>,
) -> Vec<u8> {
    // 1. Get site config from state via config_manager
    let config_manager = match state.config_manager.read() {
        Ok(guard) => guard,
        Err(_) => return body, // Fail-open: can't read config
    };
    
    let site_config = match config_manager.get_site(site_id) {
        Some(cfg) => cfg,
        None => return body, // Fail-open: site not found
    };
    
    // 2. Check if poisoning is enabled in static config
    let static_config = match &site_config.r#static {
        Some(cfg) => cfg,
        None => return body, // No static config, return original
    };
    
    let poison_config = match &static_config.image_poison {
        Some(cfg) if cfg.enabled.unwrap_or(false) => cfg,
        _ => return body, // Not enabled, return original
    };
    
    // 3. Detect image format from magic bytes
    let format = match ImageOutputFormat::from_magic_bytes(&body) {
        Some(f) => f,
        None => return body, // Not a recognized image format
    };
    
    // 4. Check excluded types
    let mime_type = match format {
        ImageOutputFormat::Png => "image/png",
        ImageOutputFormat::Jpeg => "image/jpeg",
        ImageOutputFormat::WebP => "image/webp",
    };
    if poison_config.excluded_types.as_ref()
        .map(|t| t.contains(&mime_type.to_string()))
        .unwrap_or(false) {
        return body; // Excluded type
    }
    
    // 5. Build ProtectionContext
    let level = match poison_config.level.as_deref() {
        Some("disabled") => ProtectionLevel::Disabled,
        Some("light") => ProtectionLevel::Light,
        Some("standard") => ProtectionLevel::Standard,
        Some("enhanced") => ProtectionLevel::Enhanced,
        Some("strong") | _ => ProtectionLevel::Strong, // Default to strong
    };
    
    let mut ctx = ProtectionContext::new(
        poison_config.intensity.unwrap_or(0.5),
        poison_config.seed.unwrap_or_else(|| cloakrs::util::seed::generate_random_seed()),
    )
    .with_input_format(format)
    .with_max_dimension(poison_config.max_dimension.unwrap_or(4096))
    .with_jpeg_quality(poison_config.jpeg_quality.unwrap_or(85));
    
    // 6. Set output format if specified
    if let Some(out_fmt) = poison_config.output_format.as_deref() {
        if let Some(fmt) = ImageOutputFormat::from_extension(out_fmt) {
            ctx = ctx.with_format(fmt);
        }
    }
    
    // 7. Set DMI value for AI exclusion
    let dmi = match poison_config.dmi_value.as_deref() {
        Some("Allowed") => DmiValue::Allowed,
        Some("ProhibitedAiMlTraining") | _ => DmiValue::ProhibitedAiMlTraining,
    };
    ctx = ctx.with_dmi(dmi);
    
    // 8. Set legal metadata if provided
    if let (Some(copyright), Some(terms)) = (&poison_config.legal_copyright, &poison_config.legal_terms) {
        let legal = LegalMetadata::new()
            .with_copyright_holder(copyright)
            .with_usage_terms(terms);
        ctx = ctx.with_legal_metadata(legal);
    }
    
    // 9. Apply protection
    match process_image_bytes(&body, level, &ctx) {
        Ok(protected) => protected,
        Err(e) => {
            // Fail-open: log error but return original
            tracing::warn!("Image poisoning failed for {}: {}", site_id, e);
            body
        }
    }
}
```

**Key Implementation Notes:**

| Decision | Rationale |
|----------|-----------|
| Fail-open design | Don't block requests if poisoning fails - return original |
| Log failures | Enable debugging without exposing errors to clients |
| Check config per-request | Config may change at runtime via mesh sync |
| Magic bytes detection | Auto-detect format rather than relying on Content-Type |

### 1.5 IPC Handler Wiring

**File:** `src/worker/mod.rs` (around line 765)

The existing IPC message types are already defined:
- `PoisonImageRequest { request_id, site_id, body, last_modified }`
- `PoisonImageResponse { request_id, poisoned_body }`
- `PoisonImageError { request_id, error }`

Wire up the handler to call the new implementation:

```rust
crate::process::Message::PoisonImageRequest { request_id, site_id, body, last_modified } => {
    let poisoned = image_poisoning::poison_image_sync(&state, &site_id, body, last_modified);
    let response = crate::process::Message::PoisonImageResponse {
        request_id,
        poisoned_body: poisoned,
    };
    // Send response...
}
```

### 1.6 Integration Points

**Files to modify:**

| File | Changes |
|------|---------|
| `Cargo.toml` | Add cloakrs dependency |
| `src/config/site.rs` | Add SiteImagePoisonConfig struct |
| `src/worker/image_poisoning.rs` | Implement poisoning logic |
| `src/worker/mod.rs` | Wire up IPC handler |

---

## Phase 2: Security Fixes

### 2.1 Input Normalizer DoS Protection

**File:** `src/waf/attack_detection/normalizer.rs`

**Problem:** 10-pass loop without size tracking could amplify input exponentially.

**Fix:** Add output size growth limit:

```rust
const MAX_OUTPUT_RATIO: usize = 100; // Max 100x input size

pub fn normalize(&self, input: &str) -> NormalizedInput {
    let mut buffer = String::with_capacity(input.len());
    let max_output_size = input.len() * MAX_OUTPUT_RATIO;
    let mut passes = 0;

    buffer.push_str(input);

    for _ in 0..self.max_decode_passes {
        // Prevent amplification DoS
        if buffer.len() > max_output_size {
            break;
        }
        
        let prev_len = buffer.len();
        let decoded = self.decode_single_pass_inplace(&mut buffer);
        if decoded == prev_len {
            break;
        }
        passes += 1;
    }

    self.apply_normalizations_inplace(&mut buffer);

    NormalizedInput {
        normalized: buffer,
        passes,
    }
}
```

### 2.2 Plugin Permission Enforcement

**File:** `src/plugin/axum_loader.rs` (line 42-48)

**Problem:** Only warns on insecure permissions, doesn't block.

**Current code:**
```rust
if mode & 0o777 != 0o755 && mode & 0o777 != 0o500 {
    tracing::warn!("Plugin {} has insecure permissions {:o}...", ...);
    // Only warns, doesn't reject
}
```

**Fix:** Change from warning to rejection:

```rust
if mode & 0o777 != 0o755 && mode & 0o777 != 0o500 {
    return Err(AxumPluginError::LoadFailed(format!(
        "Plugin has insecure permissions {:o}, must be 755 or 500",
        mode & 0o777
    )));
}
```

### 2.3 Password Complexity

**File:** `src/auth/mod.rs`

**Problem:** Only enforces minimum 8 characters (via `min_password_length` config, defaults to 8).

**Fix:** Add complexity validation:

```rust
fn validate_password_complexity(password: &str) -> Result<(), AuthError> {
    // Minimum length: 12 characters (update min_password_length config default)
    if password.len() < 12 {
        return Err(AuthError::PasswordTooShort(12));
    }
    
    // Require uppercase
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AuthError::PasswordComplexity {
            requirement: "at least one uppercase letter".to_string(),
        });
    }
    
    // Require lowercase
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(AuthError::PasswordComplexity {
            requirement: "at least one lowercase letter".to_string(),
        });
    }
    
    // Require digit
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AuthError::PasswordComplexity {
            requirement: "at least one digit".to_string(),
        });
    }
    
    // Require special character
    if !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(AuthError::PasswordComplexity {
            requirement: "at least one special character".to_string(),
        });
    }
    
    Ok(())
}
```

**Also update the default config:**
```rust
// In AuthManager::new() or similar
min_password_length: 12,  // Changed from 8
```

**Add to AuthError enum:**
```rust
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    // ... existing variants
    #[error("Password must contain {requirement}")]
    PasswordComplexity { requirement: String },
}
```

**Wire up validation in create_user:**
```rust
pub async fn create_user(&self, username: String, password: String, ...) -> Result<User, AuthError> {
    // Existing length check (now also checks complexity)
    validate_password_complexity(&password)?;
    // ... rest of function
}
```

---

## Phase 3: Scalability Fixes

### 3.1 Proxy Cache LRU Optimization

**File:** `src/proxy_cache/store.rs`

**Problem:** `VecDeque::position/remove` is O(n), write lock held during LRU update.

**Current structure:**
```rust
struct CacheState {
    entries: AHashMap<CacheKey, CacheEntryInner>,
    access_order: VecDeque<CacheKey>,  // O(n) operations
    current_memory_size: usize,
}
```

**Fix:** Replace `VecDeque` with `LinkedHashMap` (already in Cargo.toml):

```rust
use linked_hash_map::LinkedHashMap;

struct CacheState {
    entries: AHashMap<CacheKey, CacheEntryInner>,
    access_order: LinkedHashMap<CacheKey, ()>,  // O(1) move_to_back
    current_memory_size: usize,
}

impl CacheState {
    fn touch(&mut self, key: &CacheKey) {
        // O(1) instead of O(n)
        if self.access_order.remove(key).is_some() {
            self.access_order.insert(key.clone(), ());
        }
    }
    
    fn evict_lru(&mut self) -> Option<CacheKey> {
        // O(1) instead of O(n)
        self.access_order.pop_front()
    }
}
```

**Files to modify:**
- `src/proxy_cache/store.rs` - Replace VecDeque with LinkedHashMap

### 3.2 Rate Limiter Cleanup

**File:** `src/waf/ratelimit.rs`

**Problem:** Global O(n) cleanup across 256 shards causes latency spikes.

**Current cleanup:**
```rust
async fn cleanup_loop(&self) {
    loop {
        tokio::time::sleep(Duration::from_secs(self.cleanup_interval_secs)).await;
        for shard in &self.shards {
            // O(n) retain across all shards
            shard.cleanup_expired();
        }
    }
}
```

**Fix:** Per-shard lazy cleanup with time-based expiration:

```rust
struct RateLimiterShard {
    ip_requests: RwLock<HashMap<IpAddr, IpRateLimitState>>,
    last_cleanup: RwLock<Instant>,
}

impl RateLimiterShard {
    fn try_cleanup(&self, now: Instant, max_age: Duration) -> bool {
        let mut last = self.last_cleanup.write();
        if now.duration_since(*last) < Duration::from_secs(60) {
            return false; // Skip if cleaned recently
        }
        *last = now;
        drop(last);
        
        // Cleanup only this shard
        let mut requests = self.ip_requests.write();
        requests.retain(|_, state| {
            state.last_access.map(|t| now.duration_since(t) < max_age).unwrap_or(true)
        });
        true
    }
}
```

---

## Phase 4: Code Quality

### 4.1 Error Handling Cleanup

Focus hot paths (replace `unwrap()`/`expect()` with proper error handling):

| File | Priority |
|------|----------|
| `src/proxy.rs` | High - request handling |
| `src/waf/mod.rs` | High - attack detection |
| `src/http/server.rs` | Medium - response building |

### 4.2 Remove TODO

**File:** `src/worker/image_poisoning.rs:13`

Remove the TODO comment after Phase 1 implementation:
```rust
// TODO: Implement actual image poisoning algorithm
```

---

## Implementation Order & Effort

| # | Task | Effort | Priority | Dependencies |
|---|------|--------|----------|--------------|
| 1 | Add cloakrs dependency | 0.5 day | P0 | - |
| 2 | Config schema (SiteImagePoisonConfig) | 1 day | P0 | 1 |
| 3 | Worker implementation (image_poisoning.rs) | 2 days | P0 | 2 |
| 4 | IPC handler wiring | 0.5 day | P0 | 3 |
| 5 | Input Normalizer DoS fix | 0.5 day | P1 | - |
| 6 | Plugin permission enforcement | 0.5 day | P1 | - |
| 7 | Password complexity | 1 day | P1 | - |
| 8 | Proxy cache LRU optimization | 2 days | P2 | - |
| 9 | Rate limiter cleanup | 1 day | P2 | - |
| 10 | Error handling cleanup | 3 days | P3 | - |

---

## Verification Commands

After each phase, run:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run tests
cargo test --test integration_test

# Check specific module compiles
cargo check --lib
```

---

## Risk Assessment

| Risk Level | Tasks |
|------------|-------|
| **Low** | Input normalizer fix, plugin permissions, password complexity |
| **Medium** | Image poisoning (new dependency), proxy cache LRU, rate limiter |
| **Low** | Error handling cleanup (mechanical changes) |

---

## Notes

- **Image Poisoning Caching**: With edge caching, most images served from cache - poisoning happens once on cache miss, then cached
- **Mesh Behavior**: Edge nodes inherit origin's image poisoning config via existing SiteConfigSync
- **cloakrs Async**: Use async feature for non-blocking processing in worker pool
- **Fail-open Design**: Image poisoning errors don't block requests (defensive)
- **Performance Budget**: cloakrs can do ~50ms for standard protection on 1MP image, acceptable for cache-miss scenarios

---

*Plan Version: 1.0*
*Created: 2026-03-27*