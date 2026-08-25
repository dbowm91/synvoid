# Auth Deep Dive

SynVoid's authentication module handles user authentication, session management, brute-force protection, and CSRF validation for the admin API and admin UI.

## Architecture

### Authentication Flow

```
Client ──► Admin API ──► Auth Middleware ──► Token Validation ──► Handler
                │
                ├── Rate Limit Check (5 attempts / 300s)
                ├── Token Hash Comparison (bcrypt, DEFAULT_COST)
                ├── Session Validation
                └── CSRF Token Check (state mutations)
```

### Token Management

- **Storage**: Tokens stored as bcrypt hashes (default cost via `DEFAULT_COST`)
- **Comparison**: Constant-time via `subtle::ConstantTimeEq`
- **Generation**: Cryptographically random 32-byte tokens

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

## Brute-Force Protection

### Rate Limiting

The `AuthManager` (`src/auth/mod.rs`) handles brute-force protection directly:

- **Max failed attempts**: Configurable (default 5)
- **Lockout duration**: Configurable (default 300 seconds / 5 minutes)
- **Min password length**: 8 characters
- Per-IP lockout via `max_failed_attempts` and `lockout_duration_secs`

### Lockout Behavior

1. First 5 failed attempts within 5 minutes → lockout
2. Lockout duration: 5 minutes from first failure
3. Successful attempt resets counter
4. Lockout applies per-IP

## CSRF Protection

### Token Flow

1. Client requests admin page
2. Server generates CSRF token, stores in session
3. Token included in form as hidden field or `X-CSRF-Token` header
4. Server validates token on state-changing requests (POST, PUT, DELETE)

### Validation

```rust
fn validate_csrf_token(session: &Session, provided_token: &str) -> bool {
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

- **Algorithm**: bcrypt
- **Cost factor**: `DEFAULT_COST` (12)
- **Salt**: Random per-password (handled by bcrypt)
- **Comparison**: Constant-time via bcrypt internals

### Password Policy

- Minimum 8 characters (configurable via `min_password_length`)
- Configurable via `AdminConfig.password_policy`

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
