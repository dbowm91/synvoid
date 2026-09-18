# Auth Module Architecture

## 1. Purpose and Responsibility

The Auth module (canonical: `crates/synvoid-auth/`; the former `src/auth/` compatibility facade was removed in Phase 03 — see `facade_disposition_matrix.md` §4) provides **user authentication, session management, and access control** for the SynVoid proxy server. It handles:

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

### `crates/synvoid-auth/src/lib.rs` - Core Authentication (`crates/synvoid-auth/src/lib.rs` is a thin facade)

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

### `crates/synvoid-auth/src/basic.rs` - HTTP Basic Auth

Provides per-site HTTP Basic authentication (Phase 43: async boundary):

- `BasicAuthManager`: Manages realm and user credentials plus a bounded
  `PasswordCrypto` handle (never bcrypt inline on a Tokio core thread)
- `BasicAuthResult`: `Authenticated`, `CredentialsRequired`, `Unauthorized`,
  plus `BackendBusy` for crypto overload (HTTP maps Busy → 503, bad
  credentials → 401, without revealing usernames)
- Async API only (`check_credentials_async` / `authenticate_request_async`);
  no `block_in_place` hidden in a sync wrapper
- Unknown-user and wrong-password paths both execute exactly one bounded
  bcrypt (dummy hash for unknown users); malformed headers fail closed
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
// AuthStore - saved to disk as JSON (Phase 43: atomic temp+fsync+rename)
pub struct AuthStore {
    pub users: HashMap<String, User>,         // Key: lowercase username
    pub sessions: HashMap<String, Session>,    // Key: session ID
    pub login_logs: Vec<LoginLog>,             // Audit log (bounded: MAX_LOGIN_LOGS = 1000, enforced on insertion)
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
    // Fail-closed (Phase 43 F): missing store → Ok(empty); present but
    // unreadable/corrupt/overly-permissive → Err(AuthStoreError).
    pub fn try_new(
        data_dir: PathBuf,           // Base data directory
        session_duration_secs: u64,   // Session TTL (default: 3600)
        max_failed_attempts: u32,     // Lockout threshold (default: 3)
        lockout_duration_secs: u64,  // Lockout duration (default: 300)
    ) -> Result<Self, AuthStoreError>
    // Backward-compatible new() panics on corrupt stores instead of
    // silently starting empty. Production composition uses try_new().
```

**Note:** The following parameters are **hardcoded** and not configurable via `new()`:
- `min_password_length`: 8 characters (enforced in `create_user()` and `update_password()`)
- `session_refresh_threshold`: 0.5 (50% of session duration elapsed triggers refresh)

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

### Password Verification Security (Phase 43)

1. **Bounded CPU isolation**: all bcrypt runs behind `PasswordCrypto`
   (semaphore-bounded `spawn_blocking`, default 4 permits / 2s acquire
   timeout; overload → `AuthBackendBusy`, authenticates nobody). Never on a
   Tokio core thread; never with `RwLock<AuthStore>` held. `create_user` /
   `verify_login` / `update_password` snapshot minimal state, release the
   lock, hash/verify, then reacquire and revalidate the password-hash
   generation before mutating (lock/hash may change while bcrypt runs).
2. **Single-verify timing**: exactly one bounded bcrypt per login (real hash
   or `DUMMY_PASSWORD_HASH` for unknown users) plus a 200ms minimum-delay
   pad — no second dummy bcrypt on failure. Admin bearer verification
   (`verify_admin_token_async` / `verify_dummy_admin_token_async` in
   `synvoid-admin`) follows the same single-verify discipline.
3. **Constant-time comparison**: CSRF tokens use `subtle::ConstantTimeEq`
4. **Bcrypt**: Pure Rust implementation (no C bindings), cost 12; existing
   hashes keep verifying (no format change, no Argon2 migration)

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

### Session Storage (Phase 43 E/G)

- In-memory `Arc<RwLock<AuthStore>>` for fast access
- Async persistence to `{data_dir}/auth/store.json` every 5 seconds
- Atomic durable write (DNSSEC-keystore discipline): restrictive dir,
  owner-only temp from creation (`0600`), write-all, `sync_all`, atomic
  rename, parent-dir sync where supported, temp cleanup on failure. Failures
  preserve the previous valid store; the last valid store is never
  deleted/replaced until the new file is complete. Windows uses same-volume
  replacement with documented (weaker) durability.
- Fail-closed load: `try_new` errors on corrupt/unreadable/overly-permissive
  stores; recovery needs explicit operator action (quarantine + reset).
- Bounded audit: `MAX_LOGIN_LOGS = 1000` enforced on insertion (N/N+1
  eviction); expired sessions pruned from snapshots before queueing.
- Batched writes persist the newest complete snapshot; older queued snapshots
  are never merged back over newer user/session state

The password-update path locates users by their stable `User.id` value (the
store map itself is keyed by lowercase username). Session refresh returns a
new session ID, so callers must replace the session cookie when refresh occurs.

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

The Challenge module (`crates/synvoid-challenge/`) is **related but separate** from Auth. It handles bot detection and challenge challenges, not user authentication.

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
// CSRF token validation (crates/synvoid-auth/src/lib.rs:772)
if let Some(stored) = session.csrf_token.as_deref() {
    return bool::from(stored.as_bytes().ct_eq(csrf_token.as_bytes()));
}
```

### File Permissions (Phase 43 E)

- Auth directory: `0o700` (owner only), enforced at creation
- Store file: `0o600` (owner read/write) applied to the temp file **from
  creation** (`OpenOptionsExt::mode`), never chmod-after-write
- Overly-permissive existing stores (`mode & 0o077 != 0`) are refused at load
  (fail closed), mirroring the DNSSEC keystore boundary

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
// AuthManager instantiation (fail-closed; from src/waf/assembly.rs)
Arc::new(
    AuthManager::try_new(
        data_dir,                    // Path to auth data directory
        session_duration_secs,       // e.g., 3600 (1 hour)
        max_failed_attempts,         // e.g., 3
        lockout_duration_secs,       // e.g., 300 (5 minutes)
    )
    .expect("corrupt auth store: refusing to start with an empty database"),
)

// Basic Auth per site (async; from crates/synvoid-auth/src/basic.rs)
BasicAuthManager::new(&SiteBasicAuthConfig {
    enabled: true,
    realm: Some("Admin Area".to_string()),
    users: HashMap::from([
        ("admin".to_string(), bcrypt_hash),
    ]),
})
// Request path: manager.authenticate_request_async(&headers).await
// BackendBusy → 503; Unauthorized/CredentialsRequired → 401.
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

Phase 43 failure-injection tests (`crates/synvoid-auth`, `crypto.rs`,
`basic.rs`):
- crypto concurrency never exceeds permits; overload fails closed (`Busy`);
  executor progress continues while crypto is saturated
- no store lock held across bcrypt (concurrent read probe)
- wrong-password / unknown-user single-verify paths
- interrupted temp write + serialization failure preserve the previous store
- corrupt store → `AuthStoreError::Corrupt`; `0600`/`0700` present from creation
- login-log retention exact N/N+1 eviction; expired-session cleanup never resurrects

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
