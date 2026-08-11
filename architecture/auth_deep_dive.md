# Auth Deep Dive

SynVoid's authentication module handles user authentication, session management, brute-force protection, and CSRF validation for the admin API and admin UI.

## Architecture

### Authentication Flow

```
Client ──► Admin API ──► Auth Middleware ──► Token Validation ──► Handler
                │
                ├── Rate Limit Check (5 attempts / 300s)
                ├── Token Hash Comparison (bcrypt, cost 12)
                ├── Session Validation
                └── CSRF Token Check (state mutations)
```

### Token Management

- **Storage**: Tokens stored as bcrypt hashes (cost 12)
- **Comparison**: Constant-time via `subtle::ConstantTimeEq`
- **Generation**: Cryptographically random 32-byte tokens
- **Format**: `sv_admin_<hex_token>` prefix for identification

### Session Management

```rust
pub struct Session {
    pub token_hash: [u8; 32],  // SHA-256 of raw token
    pub created_at: u64,       // Unix timestamp
    pub expires_at: u64,       // Unix timestamp
    pub ip_address: IpAddr,    // Client IP
    pub user_agent: String,    // Client user agent
}
```

Sessions are stored in-memory with TTL-based expiration.

## Brute-Force Protection

### Rate Limiting

```rust
pub struct AuthRateLimiter {
    max_attempts: usize,      // 5
    window_secs: u64,         // 300 (5 minutes)
    lockout_duration: u64,    // 300 (5 minutes)
    attempts: DashMap<String, AttemptInfo>,  // Keyed by IP
}

struct AttemptInfo {
    count: usize,
    first_attempt: Instant,
    locked_until: Option<Instant>,
}
```

### Lockout Behavior

1. First 5 failed attempts within 5 minutes → lockout
2. Lockout duration: 5 minutes from first failure
3. Successful attempt resets counter
4. Lockout applies per-IP

### Response Headers

```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1234567890
```

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

For programmatic access (CLI, mesh agents):

```rust
pub struct ApiKey {
    pub key_hash: [u8; 32],   // SHA-256 hash
    pub permissions: Vec<Permission>,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}
```

### Permission Model

| Permission | Description |
|------------|-------------|
| `read:config` | View configuration |
| `write:config` | Modify configuration |
| `read:metrics` | View metrics |
| `write:block` | Block/unblock IPs |
| `admin` | Full admin access |

## Password Security

### Hashing

- **Algorithm**: bcrypt
- **Cost factor**: 12 (configurable)
- **Salt**: Random 16-byte salt per password
- **Comparison**: Constant-time via bcrypt internals

### Password Policy

- Minimum 8 characters
- At least one uppercase, one lowercase, one digit
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
- **Token leakage**: Tokens logged at `debug` level, never `info`/`warn`/`error`
- **Secure cookies**: `Secure; SameSite=Strict; HttpOnly` flags
- **Audit logging**: All authentication events logged with IP and timestamp
