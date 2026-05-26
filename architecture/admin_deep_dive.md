# Admin & Auth Deep Dive

## Overview

SynVoid implements a comprehensive admin API and authentication system using the Axum framework. The architecture follows a middleware-based security model with session management, CSRF protection, and rate limiting.

---

## Authentication Architecture

### Dual Authentication Model

SynVoid supports two fundamentally different authentication systems that serve distinct purposes:

| System | Purpose | Users | Token Type |
|--------|---------|-------|------------|
| **Admin Auth** | Protect Admin API (28+ endpoints) | Single admin | Static bearer token |
| **User Auth** | Multi-user access to tenant resources | Multiple users | Username + password |

**Commonality:** Both use bcrypt hashing and support session-based authentication for browser clients.

---

### Admin Auth: Single Token Model

**Use Case:** Server administration, not tenant management.

**Security Model:**
- One static admin token configured in `admin.token`
- Token is hashed using bcrypt (configurable cost, default 12)
- Token verified via `verify_admin_token()` using bcrypt verify
- No registration flow - token is configured, not created

**Key Files:**
- `src/admin/auth.rs:16-26` - `hash_admin_token()` and `verify_admin_token()`

**When Admin Auth is Used:**
- All Admin API endpoints (`/api/*`, `/config/*`, `/sites/*`, `/system/*`, etc.)
- Bearer token authentication via `Authorization: Bearer <token>`
- Session cookie authentication for browser-based admin dashboard

---

### User Auth: Multi-User Registration Model

**Use Case:** Tenant multi-user access with registration.

**Security Model:**
- Multiple users can register via `AuthManager::create_user()`
- Users login with username + password via `AuthManager::verify_login()`
- Each user gets their own session with CSRF token
- Brute-force protection: account locking after configurable failed attempts
- Max 5 sessions per user, configurable session duration

**Key Features:**
- User registration with bcrypt password hashing
- Persistent session storage (JSON-based, `auth/store.json`)
- Brute-force protection with account lockout
- Login audit logging (`login_logs` array in AuthStore)
- Session refresh on activity (sliding window)
- Constant-time CSRF comparison via `subtle::ConstantTimeEq`

**Key Files:**
- `src/auth/mod.rs:91-103` - `AuthManager` struct
- `src/auth/mod.rs:294-333` - `create_user()` registration
- `src/auth/mod.rs:393-533` - `verify_login()` authentication
- `src/auth/mod.rs:561-629` - `validate_session()` session management

**User Auth Flow:**
1. User registration via `POST /api/auth/register` (if enabled) or Admin API
2. User login via `POST /api/auth/login` → returns session + CSRF token
3. Subsequent requests include session cookie + CSRF header
4. Session refresh when 50%+ elapsed (configurable threshold)

---

### Admin Token (Bearer)

**Security Model: Single Admin Token**

- One static admin token configured in `admin.token`
- Token is hashed using bcrypt (configurable cost, default 12)
- Token verified via `verify_admin_token()` using bcrypt verify

**Key Files:**
- `src/admin/auth.rs:20-26` - `hash_admin_token()` and `verify_admin_token()`

### Session Management

**Session Flow (Browser Clients):**
1. Client exchanges bearer token for session via `POST /api/auth/session`
2. Server creates session, returns `synvoid_session` cookie (HttpOnly, Secure, SameSite=Strict)
3. Server generates CSRF token, returns via `X-CSRF-Token` response header
4. Client includes CSRF token in `x-csrf-token` header for mutating requests
5. Session expires after 1 hour (3600 seconds), configurable

**Key Files:**
- `src/admin/state.rs:788-820` - `create_session()` and session data storage
- `src/admin/state.rs:822-844` - `validate_session()` with sliding window expiration
- `src/admin/handlers/auth.rs:14-58` - Session creation endpoint

### Brute-Force Protection

**Global Auth Rate Limiter** (`src/admin/auth.rs`):
- **MAX_AUTH_ATTEMPTS**: 5 failures per IP
- **AUTH_LOCKOUT_DURATION**: 300 seconds (5 minutes)
- **AUTH_WINDOW_DURATION**: 60 seconds (sliding window)

---

## CSRF Protection

### CSRF Token Architecture

**Token Properties:**
- UUID v4 format
- Bound to session via SHA256 hash of session ID
- Max 10 tokens per session
- 1-hour expiration

**Validation Flow:**
1. Extract `x-csrf-token` header from request
2. Extract `synvoid_session` cookie
3. Validate token exists and matches session
4. Check token not expired

**Key Files:**
- `src/admin/state.rs:725-741` - `validate_csrf()`
- `src/admin/state.rs:743-771` - `generate_csrf_token()`
- `src/admin/middleware.rs:185-266` - `csrf_middleware()`

### CSRF Middleware Logic

```rust
// Applies to: POST, PUT, PATCH, DELETE
// Exempts: /ws/*, /stats/*, /health, /config/schema, /logs
// Exempts: Bearer token authenticated requests
```

---

## Middleware Stack

### Middleware Layers (in order)

```
Request
  ├── Client IP Extraction (trusted proxy support)
  ├── Auth Middleware (bearer/session validation)
  ├── CSRF Middleware (session-only mutating requests)
  └── Admin Rate Limit Layer (requests per minute/second)
```

**Note:** No CORS middleware is implemented. The Admin API uses bearer tokens and
session cookies (not browser-based access), so CORS headers are not applicable.
All admin clients are expected to set appropriate Authorization headers.

**Key File:** `src/admin/middleware.rs`

### Auth Middleware (`auth_middleware_with_state`)

```rust
// Public routes bypass auth:
// - GET /health
// - GET /api/openapi.json  
// - GET /api/docs/*
// - WS /ws/* (auth per-connection)
```

**AuthenticatedUser Extension:**
- All valid requests insert `AuthenticatedUser` with:
  - `username`: Always "admin" (single admin model)
  - `role`: Always `RequiredRole::Admin`

---

## Admin API Structure

### API Organization (28 handlers)

**Location:** `src/admin/handlers/` (26 handlers + up to 4 mesh-gated handlers)

| Handler | Purpose |
|---------|---------|
| `alerting` | Alert configuration and webhook testing |
| `api_discovery` | API self-discovery |
| `auth` | Session/CSRF management |
| `behavioral_intel` | Behavioral intelligence for anomaly detection (mesh feature) |
| `common` | Shared types, pagination, auth utilities |
| `config` | All configuration endpoints (40+ sub-endpoints) |
| `honeypot` | Honeypot port management |
| `icmp` | ICMP filtering (mesh feature) |
| `logs` | Log retrieval, error pages, audit logs |
| `mesh_admin` | Mesh node/org/ban management |
| `mesh_topology` | Mesh topology graphs |
| `php` | PHP-FPM pool management |
| `plugins` | WASM plugin management |
| `probes` | Probe tracking, suspicious words, upstream errors |
| `rule_feed` | WAF rule feed management |
| `serverless` | Serverless function stats |
| `sites` | Site configuration CRUD |
| `spin` | Spin framework app management |
| `stats` | Metrics, bandwidth, request logs |
| `system` | Worker management, system info |
| `tcp_udp` | TCP/UDP listener management |
| `theme` | Admin UI theming |
| `threat_level` | Threat level control and history |
| `upstreams` | Upstream backend management |
| `yara_rules` | YARA rules submissions (mesh feature) |

### Key REST Endpoint Groups

**Configuration Endpoints** (`/config/*`):
- `/config/main` - Main config
- `/config/schema` - JSON schema
- `/config/tls`, `/config/http`, `/config/http3` - Protocol configs
- `/config/security` - Security settings
- `/config/rate-limits`, `/config/bot-detection` - Protection configs
- `/config/defaults/*` - Default values for various features
- `/config/versions` - Config version history
- `/config/rollback/{id}` - Rollback capability

**Site Management** (`/sites/*`):
- CRUD operations on site configurations
- Theme, bot-detection, error-pages sub-resources

**System/Process** (`/system/*`):
- `/system/info` - System information
- `/system/workers` - Worker process management
- `/system/master` - Master status
- `/system/overseer` - Supervisor status (legacy endpoint; Supervisor consolidated mode is default)

**Stats/Metrics** (`/stats/*`):
- `/stats/summary` - Aggregated metrics
- `/stats/history` - Historical metrics
- `/stats/attacks` - Attack statistics
- `/stats/cache` - Cache statistics
- `/stats/bandwidth` - Bandwidth usage
- `/stats/requests` - Request logs

**Mesh** (feature-gated, `/mesh/*`):
- Node management, organization, bans
- DHT/Raft status
- YARA rules management

### WebSocket Endpoints

| Endpoint | Purpose | Auth |
|----------|---------|------|
| `/ws/metrics` | Real-time metrics stream | Bearer or cookie token |
| `/ws/logs` | Real-time log stream | Bearer or cookie token |

---

## Key State Structures

### AdminState

**Location:** `src/admin/state.rs:257-267` (AdminState struct definition)

```rust
pub struct AdminState {
    pub metrics: MetricsState,           // Metrics and broadcasters
    pub waf_tracking: WafTrackingState,   // WAF component references
    pub security: SecurityState,          // Auth, sessions, CSRF, rate limiters
    pub mesh: MeshState,                  // Mesh transport (mesh feature)
    pub honeypot: HoneypotState,          // Honeypot controllers
    pub process: ProcessState,           // Config manager, process manager
    pub plugins: PluginsState,           // Plugin reload logs
    pub audit: AuditState,               // Audit logging
    pub config_versions: ConfigVersionManager,
}
```

### SecurityState

```rust
pub struct SecurityState {
    pub admin_token: String,                    // Hashed admin token
    pub csrf_tokens: Arc<RwLock<HashMap<String, CsrfTokenData>>>,
    pub sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    pub rate_limiter: Option<Arc<AdminRateLimiter>>,
    pub yara_rate_limiter: Option<Arc<YaraRateLimiter>>,
}
```

---

## Rate Limiting

### Admin Rate Limiter

**Location:** `src/admin/rate_limit.rs`

- **Per-IP tracking** with minute and second windows
- **Configurable limits** (requests_per_minute, requests_per_second)
- **Automatic cleanup** of expired entries
- **Metrics integration** for monitoring

### YARA-Specific Rate Limiter

**Location:** `src/admin/state.rs:86-143`

Separate rate limits for YARA operations:
- `submit` - 10/minute default
- `broadcast_apply` - 5/minute default  
- `approve_reject` - 10/minute default
- `status_list` - 30/minute default

---

## Authentication Module (`src/auth/`)

### User Authentication System

**Location:** `src/auth/mod.rs`

**Features:**
- User registration with bcrypt password hashing
- Persistent session storage (JSON-based)
- Brute-force protection (account locking)
- Login audit logging
- Session refresh on activity
- CSRF token validation using constant-time comparison

**Security Patterns:**
- Constant-time CSRF comparison via `subtle::ConstantTimeEq`
- Dummy password timing to prevent username enumeration
- Max 5 sessions per user
- Configurable session duration, max failed attempts, lockout duration

### HTTP Basic Auth

**Location:** `src/auth/basic.rs`

- Site-level Basic Auth configuration
- Per-site realm configuration
- Bcrypt password verification
- Returns `BasicAuthResult` enum: `Authenticated`, `CredentialsRequired`, `Unauthorized`

---

## Alerting System

**Location:** `src/admin/alerting/mod.rs`

### Supported Metrics

- `error_rate_percent`
- `requests_per_second`
- `blocked_per_second`
- `time_validation_errors`
- `unhealthy_backends`
- `unhealthy_workers`
- `threat_level`
- `audit_write_failures`

### Alert Conditions

- `GreaterThan`
- `LessThan`
- `Equals`

### SSRF Protection

Webhook URLs are validated:
- Only http/https allowed
- Blocked: localhost, 127.x.x.x, 10.x.x.x, 192.168.x.x, 172.x.x.x

---

## OpenAPI Documentation

**Location:** `src/admin/openapi.rs`

- Title: "SynVoid Admin API"
- Version: 1.0.0
- Bearer authentication scheme defined
- Feature-gated paths (mesh, dns stubs for non-mesh builds)

---

## Audit Logging

**Location:** `src/admin/audit.rs`

- Stores up to 100 config versions
- Automatic versioning on config changes
- Rollback support
- File-based storage with 0o600 permissions

---

## Security Summary

| Aspect | Implementation |
|--------|----------------|
| **Admin Authentication** | Single static bearer token, bcrypt hashed, configured not registered |
| **User Authentication** | Multi-user with registration, bcrypt passwords, persistent sessions |
| **Admin Brute-Force Protection** | Global per-IP rate limiter (5 attempts/60s window), 5-minute lockout |
| **User Brute-Force Protection** | Per-account locking after max failed attempts, configurable lockout duration |
| **CSRF Protection** | Session-bound CSRF tokens, max 10 per session, constant-time comparison |
| **Admin Session Security** | HttpOnly, SameSite=Strict cookies, Secure flag in production, 1-hour TTL |
| **User Session Security** | Sliding window refresh, max 5 sessions per user, IP binding available |
| **File Permissions** | Auth store: 0o700 dir, 0o600 files; Audit log: 0o600 |
| **SSRF Protection** | Webhook URL scheme validation, private IP range blocking |

### Key Distinction

**Admin Auth** (`src/admin/auth.rs`) = Server administration
- Single token, no registration
- Protects admin API endpoints
- Bearer token or session cookie

**User Auth** (`src/auth/mod.rs`) = Multi-tenant user access
- Multiple users with registration
- Protects tenant resources
- Username/password login with session

---

## Related Documentation

- [Overview](overview.md) - Bird's eye view of SynVoid architecture
- [WAF Deep Dive](waf_deep_dive.md) - WAF engine and attack detection
- [Mesh Deep Dive](mesh_deep_dive.md) - Mesh networking (YARA rules management)