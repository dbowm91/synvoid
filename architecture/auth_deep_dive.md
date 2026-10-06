# Auth Deep Dive

SynVoid's authentication module handles user authentication, session management, brute-force protection, and CSRF validation for the admin API and admin UI.

## Architecture

### Authentication Flow

```
Client ──► Admin API ──► Auth Middleware ──► Token Validation ──► Handler
                │
                ├── Rate Limit Check (3 attempts / 300s, production default in `src/waf/assembly.rs`)
                ├── Token Hash Comparison (bounded async bcrypt: verify_admin_token_async, 4 permits / 2s timeout, single verify + 200ms pad)
                ├── Session Validation
                └── CSRF Token Check (state mutations)
```

Phase 43: no CPU-hard bcrypt runs on a Tokio core thread. `synvoid-auth`
uses `PasswordCrypto` (bounded `spawn_blocking`, no store lock held);
`synvoid-admin` uses the same discipline (`verify_admin_token_async` /
`verify_dummy_admin_token_async`, exactly one bcrypt per request, overload
fails closed). Auth-store writes are atomic (temp + fsync + rename,
`0600`/`0700` from creation); corrupt stores fail closed via `try_new`;
login audit is bounded (`MAX_LOGIN_LOGS = 1000`).

### Token Management

- **Storage**: bcrypt (`PASSWORD_BCRYPT_COST` = 12) applies to **user passwords**
  (`User.password_hash`), not to session tokens. `AuthStore.sessions` is a plain
  `HashMap<String, Session>` holding session records verbatim, keyed by session
  ID; the persisted store is protected by its `0600`/`0700` file permissions
  rather than by hashing.
- **Comparison**: Constant-time via `subtle::ConstantTimeEq`
- **Generation**: `Uuid::new_v4().to_string()` for both the session ID and the
  CSRF token (`crates/synvoid-auth/src/lib.rs`) — i.e. a random v4 UUID
  (122 bits of entropy) rendered as a 36-character hyphenated string, **not** a
  32-byte random token. All session-ID and CSRF-token creation sites use this
  one mechanism, including session refresh and rotation.

### Session Management

```rust
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub csrf_token: Option<String>,
}
```

Sessions are stored in-memory with TTL-based expiration.

### Session Cookie Flags

The browser session cookie is emitted by the admin handler
(`src/admin/handlers/auth.rs`), not by `synvoid-auth`:

```rust
format!("{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600", SESSION_COOKIE_NAME, session_id)
// then, only if state.secure_cookie:
format!("{}; Secure", cookie)
```

- **Name**: `synvoid_session` (`SESSION_COOKIE_NAME`)
- **`HttpOnly`**: always set
- **`Path`**: `/`
- **`SameSite`**: `Strict`
- **`Max-Age`**: `3600`
- **`Secure`**: **conditional**, appended only when `AdminState::secure_cookie`
  is true. It is populated from `MainConfig.admin.secure_cookie`
  (`src/admin/mod.rs`) and defaults to true, so it is operator-settable and can
  be turned off.
- The CSRF token is returned in the `X-CSRF-Token` response header; no
  separate CSRF cookie is set by the admin login handler.

## Brute-Force Protection

### Rate Limiting

The `AuthManager` (`crates/synvoid-auth/src/lib.rs`) handles brute-force protection directly:

- **Max failed attempts**: Configurable (production default 3, see `assemble_auth_manager` in `src/waf/assembly.rs`)
- **Lockout duration**: Configurable (default 300 seconds / 5 minutes)
- **Min password length**: 8 characters
- Per-account lockout via `max_failed_attempts` and `lockout_duration_secs`
  (state lives on the `User` record as `failed_attempts` / `locked_until`, not per-IP)

### Lockout Behavior

1. First 3 failed attempts → lockout (production default)
2. Lockout duration: 5 minutes, measured from the failure that reaches the threshold
3. Successful attempt resets counter and lock
4. Lockout applies per account (username), not per IP

## CSRF Protection

### Token Flow

1. Client requests admin page
2. Server generates CSRF token, stores in session
3. Token included in form as hidden field or `X-CSRF-Token` header
4. Server validates token on state-changing requests (POST, PUT, DELETE)

### Validation

```rust
async fn validate_csrf_token(&self, session_id: &str, csrf_token: &str) -> bool {
    let expected = session.csrf_token.as_bytes();
    let provided = provided_token.as_bytes();
    
    // Constant-time comparison
    expected.ct_eq(provided).into()
}
```

## API Key Authentication

For programmatic access (CLI, mesh agents), the admin API supports token-based authentication via the `Authorization` header or session cookie.

### Role Model

| Role | Description |
|------|-------------|
| `Admin` | Full admin access |
| `User` | Standard user access |

## Password Security

### Hashing

- **Algorithm**: bcrypt (no format change; existing hashes verify; no Argon2 migration in Phase 43)
- **Cost factor**: 12 (`PASSWORD_BCRYPT_COST`, formerly `DEFAULT_COST`)
- **Salt**: Random per-password (handled by bcrypt)
- **Comparison**: Constant-time via bcrypt internals
- **CPU isolation**: bounded `spawn_blocking` behind `PasswordCrypto`
  (unknown-user dummy hash, single verify, `AuthBackendBusy` on overload →
  503 for Basic Auth, fail-closed 401/empty for logins/admin)

### Password Policy

- Minimum 8 characters (configurable via `min_password_length`)
- Not operator-configurable; the constant is private to `synvoid-auth`

## Integration Points

### Admin API

```rust
// Middleware layer
async fn auth_middleware(req: Request, next: Next) -> Response {
    // 1. Extract token from Authorization header or cookie
    // 2. Rate limit check
    // 3. Token validation
    // 4. Session lookup
    // 5. CSRF check (for mutations)
    // 6. Attach session to request extensions
    next.run(req).await
}
```

### CLI Authentication

```rust
// synvoid-cli uses API key authentication
let client = AdminClient::new(
    base_url,
    api_key,  // From config or environment
);
```

## Security Considerations

- **Timing attacks**: All token comparisons use `subtle::ConstantTimeEq`
- **Session fixation**: New session ID generated on login
- **Secure cookies**: `Secure; SameSite=Strict; HttpOnly` flags
- **Audit logging**: All authentication events logged with IP and timestamp
