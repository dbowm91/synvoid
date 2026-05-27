# Auth Module Architecture

## 1. Purpose and Responsibility

The Auth module (`src/auth/`) provides **user authentication, session management, and access control** for the SynVoid proxy server. It handles:

- **User Management**: Registration, deletion, role assignment, and site permissions
- **Password Handling**: Bcrypt hashing with configurable cost factor
- **Session Lifecycle**: Creation, validation, refresh, and destruction
- **Brute-Force Protection**: Account locking after repeated failed login attempts
- **Login Audit Logging**: All authentication events are recorded
- **HTTP Basic Authentication**: Per-site Basic Auth support via the `basic` submodule
- **CSRF Protection**: Token generation and validation for sessions

**No feature gates** - the Auth module is always compiled and available.

---

## 2. Key Submodules and Their Responsibilities

### `src/auth/mod.rs` - Core Authentication

The main module containing:

| Component | Responsibility |
|-----------|----------------|
| `AuthManager` | Central authentication manager with in-memory store + async disk persistence |
| `User` / `UserInfo` | User account data structures |
| `Session` / `SessionInfo` | Session data structures |
| `AuthStore` | Persistent storage combining users, sessions, and login logs |
| `LoginLog` | Audit log entry for authentication events |
| `AuthError` | Error type enumeration for all auth failures |
| `basic` | HTTP Basic authentication implementation |

### `src/auth/basic.rs` - HTTP Basic Auth

Provides per-site HTTP Basic authentication:

- `BasicAuthManager`: Manages realm and user credentials
- `BasicAuthResult`: Enum indicating authentication outcome (`Authenticated`, `CredentialsRequired`, `Unauthorized`)
- Uses bcrypt for password verification (same as main auth)
- Integrated via `SiteBasicAuthConfig`

---

## 3. Major Data Structures and Types

### User and Authentication

```rust
// Core user account (stored in AuthStore)
pub struct User {
    pub id: String,                      // UUID v4
    pub username: String,                // Case-insensitive (lowercase key)
    pub password_hash: String,           // Bcrypt hash
    pub role: UserRole,                  // Admin or User (default)
    pub sites: Vec<String>,              // Assigned site permissions
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_attempts: u32,            // Brute-force counter
    pub locked_until: Option<DateTime<Utc>>,  // Account lock expiry
}

// User role enumeration
pub enum UserRole {
    Admin,
    #[default]
    User,
}

// Public user info (excludes password hash)
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub sites: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub failed_attempts: u32,
    pub locked_until: Option<DateTime<Utc>>,
}
```

### Session Management

```rust
// Full session (stored in AuthStore)
pub struct Session {
    pub id: String,                      // UUID v4
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,      // For session binding
    pub user_agent: Option<String>,
    pub csrf_token: Option<String>,      // CSRF protection token
}

// Session info returned by validate_session
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub expires_at: DateTime<Utc>,
}

// Internal session data (used in validation logic)
struct SessionData {
    user_id: String,
    username: String,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}
```

### Persistent Storage

```rust
// AuthStore - saved to disk as JSON
pub struct AuthStore {
    pub users: HashMap<String, User>,         // Key: lowercase username
    pub sessions: HashMap<String, Session>,    // Key: session ID
    pub login_logs: Vec<LoginLog>,             // Audit log (max 10,000)
}

// Login audit log entry
pub struct LoginLog {
    pub id: String,
    pub username: String,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub reason: Option<String>,              // E.g., "Too many failed attempts"
}
```

### Error Handling

```rust
pub enum AuthError {
    #[error("Invalid username or password")]
    InvalidCredentials,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid username")]
    InvalidUsername,
    #[error("Password must be at least {0} characters")]
    PasswordTooShort(usize),
    #[error("Account locked until {0}")]
    AccountLocked(DateTime<Utc>),
    #[error("Password hashing error")]
    HashingError,
}
```

---

## 4. Key APIs and Entry Points

### AuthManager Construction

```rust
impl AuthManager {
    pub fn new(
        data_dir: PathBuf,           // Base data directory
        session_duration_secs: u64,   // Session TTL (default: 3600)
        max_failed_attempts: u32,     // Lockout threshold (default: 3)
        lockout_duration_secs: u64,  // Lockout duration (default: 300)
    ) -> Self
```

### User Management

| Method | Signature | Description |
|--------|-----------|-------------|
| Create User | `pub async fn create_user(&self, username: String, password: String, role: UserRole, sites: Vec<String>) -> Result<User, AuthError>` | Register new user (min 8-char password) |
| Delete User | `pub async fn delete_user(&self, user_id: &str) -> Result<(), AuthError>` | Remove user and all their sessions |
| Update Sites | `pub async fn update_user_sites(&self, user_id: &str, sites: Vec<String>) -> Result<(), AuthError>` | Modify user's site assignments |
| List Users | `pub async fn list_users(&self) -> Vec<UserInfo>` | Get all users (excludes password hashes) |
| Update Password | `pub async fn update_password(&self, user_id: &str, new_password: &str) -> Result<(), AuthError>` | Change password (invalidates all sessions) |

### Authentication

| Method | Signature | Description |
|--------|-----------|-------------|
| Verify Login | `pub async fn verify_login(&self, username: &str, password: &str, ip_address: Option<&str>, user_agent: Option<&str>) -> Result<Session, AuthError>` | Authenticate user, create session, enforce lockout |
| Validate Session | `pub async fn validate_session(&self, session_id: &str) -> Option<SessionInfo>` | Check session validity, auto-refresh if >50% elapsed |
| Validate with IP | `pub async fn validate_session_with_ip(&self, session_id: &str, client_ip: &str) -> Option<SessionInfo>` | Session validation with IP binding check (hijacking detection) |
| Destroy Session | `pub async fn destroy_session(&self, session_id: &str)` | Explicit logout |

### CSRF Protection

| Method | Signature | Description |
|--------|-----------|-------------|
| Validate CSRF | `pub async fn validate_csrf_token(&self, session_id: &str, csrf_token: &str) -> bool` | Constant-time CSRF token comparison |
| Get CSRF Token | `pub async fn get_csrf_token(&self, session_id: &str) -> Option<String>` | Retrieve current CSRF token for session |

### Session Management

| Method | Signature | Description |
|--------|-----------|-------------|
| Get Active Sessions | `pub async fn get_active_sessions(&self) -> Vec<SessionInfo>` | List all non-expired sessions |
| Cleanup Expired | `pub async fn cleanup_expired_sessions(&self)` | Remove expired sessions, unlock expired accounts |
| Flush | `pub async fn flush(&self)` | Force synchronous persistence |

### Admin/Audit

| Method | Signature | Description |
|--------|-----------|-------------|
| Get Login Logs | `pub async fn get_login_logs(&self, limit: usize) -> Vec<LoginLog>` | Retrieve recent authentication events |
| Max Failed Attempts | `pub fn max_failed_attempts(&self) -> u32` | Config getter |
| Lockout Duration | `pub fn lockout_duration_secs(&self) -> u64` | Config getter |

---

## 5. How Authentication Works

### Login Flow

```
Client                    AuthManager                      AuthStore
  |                            |                               |
  | verify_login() ----------> |                               |
  |                            |--+ get user (lowercase key)    |
  |                            |                               |
  |                            | (user exists?)                |
  |                            |   |                           |
  |                            |   +-- YES: check lockout      |
  |                            |   |      |                    |
  |                            |   |      +-- locked? --> Err  |
  |                            |   |                           |
  |                            |   +-- NO: verify password     |
  |                            |        |                      |
  |                            |        +-- invalid?           |
  |                            |             |-- inc failed     |
  |                            |             |-- lock if >= max |
  |                            |             |-- log failure   |
  |                            |             +-- verify_dummy() |
  |                            |             +-- return Err    |
  |                            |                               |
  |                            |        +-- valid?              |
  |                            |             |-- reset failed   |
  |                            |             |-- update last_login|
  |                            |             |-- create Session |
  |                            |             |-- evict oldest if|
  |                            |             |   >= 5 sessions   |
  |                            |             |-- log success    |
  |                            |             +-- return Session |
  |                            |                               |
  <-- Session -----------------+                               |
```

### Password Verification Security

1. **Timing-attack mitigation**: For non-existent users, a dummy password hash is used to ensure consistent timing
2. **Constant-time comparison**: CSRF tokens use `subtle::ConstantTimeEq`
3. **Bcrypt**: Pure Rust implementation (no C bindings)

```rust
// From verify_login():
let (user_exists, stored_hash) = match store.users.get_mut(&username_key) {
    Some(user) => (true, user.password_hash.clone()),
    None => (false, DUMMY_PASSWORD_HASH.to_string()),
};

// ... later for timing normalization:
verify_dummy_password(password).await;
```

### Session Refresh Logic

Sessions auto-refresh when >50% of their lifetime has elapsed:

```rust
let elapsed_ratio = 1.0 - (remaining.num_seconds() as f64 / total_duration.num_seconds() as f64);
if elapsed_ratio > self.session_refresh_threshold {  // 0.5
    // Create new session with new ID and CSRF token
}
```

### Brute-Force Protection

1. Failed attempts counter per user
2. After `max_failed_attempts` (default: 3), account locked for `lockout_duration_secs` (default: 300s)
3. Lock expires automatically; cleanup also runs on `cleanup_expired_sessions()`

---

## 6. Session Management

### Session Lifecycle

```
create (verify_login)     validate (with refresh)     destroy (explicit)
     |                         |                          |
     v                         v                          v
[CREATED] -----> [VALID] -----> [EXPIRED] -----> [REMOVED]
                    |
                    +-----> validate_session_with_ip() --> [HIJACKED] --> [REMOVED]
```

### Session Storage

- In-memory `Arc<RwLock<AuthStore>>` for fast access
- Async persistence to `{data_dir}/auth/store.json` every 5 seconds
- Batched writes merge multiple updates before flushing

### Persistence Architecture

```rust
// Async writer task
tokio::spawn(async move {
    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Periodic flush every 5 seconds
                if !pending_stores.is_empty() {
                    let merged = Self::merge_stores(&pending_stores);
                    Self::write_store_to_disk(&data_dir_clone, &merged).await;
                }
            }
            Some((store, flush_tx)) = write_rx.recv() => {
                // On-demand flush (e.g., during shutdown)
                pending_stores.push(store);
                flush_completion_tx = flush_tx;
            }
        }
    }
});
```

### Session Limits

- Maximum **5 sessions per user** (configurable via `MAX_SESSIONS_PER_USER`)
- On overflow, oldest sessions are evicted first

### IP Binding (Optional Security)

`validate_session_with_ip()` validates that the session was created from the same IP:
- Mismatch triggers session removal (potential hijacking)
- Logs warning with session ID, current IP, and original IP

---

## 7. Challenge/CAPTCHA System (Related Module)

The Challenge module (`src/challenge/`) is **related but separate** from Auth. It handles bot detection and challenge challenges, not user authentication.

### Challenge Types

| Type | Module | Purpose |
|------|--------|---------|
| `PowChallenge` | `pow.rs` | Proof-of-work challenge |
| `MeshPowChallenge` | `mesh_pow.rs` | Mesh-network enhanced PoW |
| `CssChallenge` | `css.rs` | CSS/JavaScript browser verification |

### Challenge Manager

```rust
pub struct ChallengeManager {
    pow: Option<PowManager>,
    mesh_pow: Option<MeshPowManager>,
    css: Option<CssManager>,
    honeypot: HoneypotTracker,
    // ...
}

pub enum ChallengePriority {
    PowThenCss,      // Default
    CssThenPow,
    PowOnly,
    CssOnly,
    MeshPowThenCss,
    MeshPowOnly,
}
```

### Challenge Flow

```
Request --> ChallengeManager.generate_challenge_page() --> Challenge Page HTML
              |
              +--> Honeypot: inject hidden links
              |
              +--> Priority-based challenge selection
                        |
                        +--> PoW: Generates challenge page with JS solver
                        +--> CSS: Generates session + asset requests
                        +--> MeshPoW: Uses mesh network for verification

Cookie Check --> ChallengeManager.check_cookie() --> ChallengeResult
```

### Key Challenge APIs

| Method | Purpose |
|--------|---------|
| `generate_challenge_page()` | Create challenge HTML with honeypot |
| `check_cookie()` | Verify challenge cookie (`PowResult`, `MeshPowResult`, or "verified") |
| `is_rate_limited()` | Check if IP exceeded max challenge attempts |
| `record_attempt()` / `clear_attempts()` | Track challenge attempts |
| `verify_pow()` | Verify PoW nonce solution |

---

## 8. Feature Gates

**No feature gates** - the Auth module is always compiled and available.

However, the Challenge module supports optional sub-features:
- `pow_enabled`: Enable proof-of-work challenges
- `css_enabled`: Enable CSS-based challenges
- `mesh_pow_enabled`: Enable mesh-enhanced PoW
- `honeypot_enabled`: Enable honeypot trap detection

---

## 9. Security Considerations

### Constant-Time Operations

```rust
// CSRF token validation (src/auth/mod.rs:772)
if let Some(stored) = session.csrf_token.as_deref() {
    return bool::from(stored.as_bytes().ct_eq(csrf_token.as_bytes()));
}
```

### File Permissions

- Auth directory: `0o700` (owner only)
- Store file: `0o600` (owner read/write)

```rust
#[cfg(unix)]
{
    std::fs::set_permissions(&auth_dir, std::fs::Permissions::from_mode(0o700));
    std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600));
}
```

### Password Hashing

- Uses `bcrypt` crate (pure Rust)
- Default cost factor: `DEFAULT_COST` (12)
- Salt automatically generated by bcrypt

### Session Hijacking Prevention

`validate_session_with_ip()` binds sessions to originating IP and detects anomalies.

---

## 10. Integration Points

### WAF Integration

`AuthManager` is stored in `WafCore` and used for:
- Protecting admin endpoints
- Session validation on protected routes

### Basic Auth

`BasicAuthManager` is created per-site via `SiteBasicAuthConfig`:
- Realm configuration
- Per-site username/password pairs
- Uses same bcrypt verification as main auth

### Admin API

Users and sessions are managed via Admin API endpoints:
- User CRUD operations
- Session listing and destruction
- Login log retrieval

---

## 11. Configuration Example

```rust
// AuthManager instantiation (from src/waf/mod.rs:399)
Arc::new(AuthManager::new(
    data_dir,                    // Path to auth data directory
    session_duration_secs,       // e.g., 3600 (1 hour)
    max_failed_attempts,         // e.g., 3
    lockout_duration_secs,       // e.g., 300 (5 minutes)
))

// Basic Auth per site (from src/auth/basic.rs)
BasicAuthManager::new(&SiteBasicAuthConfig {
    enabled: true,
    realm: Some("Admin Area".to_string()),
    users: HashMap::from([
        ("admin".to_string(), bcrypt_hash),
    ]),
})
```

---

## 12. Testing

The module includes comprehensive unit tests:
- `test_create_user_short_password()` - Password length validation
- `test_create_user_empty_username()` - Username validation
- `test_create_and_verify_user()` - Happy path
- `test_verify_wrong_password()` - Invalid password handling
- `test_verify_nonexistent_user()` - User lookup
- `test_delete_user()` - User removal and session cleanup
- `test_update_user_sites()` - Site permission updates
- `test_list_users()` - User enumeration
- `test_duplicate_user()` - Duplicate prevention
- Property-based tests for `AuthError` (display, equality, clone)

---

## 13. Dependencies

| Dependency | Purpose | Notes |
|------------|---------|-------|
| `bcrypt` | Password hashing | Pure Rust implementation |
| `chrono` | DateTime handling | For timestamps and lockout durations |
| `uuid` | ID generation | For users, sessions, and log entries |
| `serde` | Serialization | JSON persistence |
| `tokio` | Async runtime | File I/O and background tasks |
| `subtle` | Constant-time comparison | CSRF token validation |
