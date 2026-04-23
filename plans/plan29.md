# Plan 29: OS-Specific Platform Support Improvements

## Context

During architecture review, six items were identified as incomplete, stub, or requiring improvement:

1. **HTTP/3 Handler Stub** - `src/http3/handler.rs` is a placeholder; real HTTP/3 handling exists but doesn't proxy to backends
2. **Windows Platform Support** - Core infrastructure exists but socket FD passing not wired up
3. **BSD Service Manager** - FreeBSD/OpenBSD/NetBSD return "not implemented" error
4. **Non-Linux Sandbox** - Only Landlock on Linux; StubSandbox provides no enforcement
5. **Direct TLS for Key Exchange** - TLS config exists but unused
6. **Windows WFP ICMP Interface Filtering** - Falls back to all interfaces when specific ones requested

This plan covers items 1-5 in detail. Item 6 (WFP ICMP) is lower priority and documented at the end.

---

## Background: Current Architecture

### Platform Support Matrix

| Platform | IPC | Process Control | Socket FD Passing | Service Management | Sandbox |
|----------|-----|----------------|------------------|-------------------|---------|
| Linux | Unix sockets | Full | SCM_RIGHTS | systemd | Landlock |
| macOS | Named pipes | Full | N/A | launchd | Stub |
| Windows | Named pipes | Full | WSADuplicateSocket | sc.exe | Stub |
| FreeBSD | Unix sockets | Full | N/A | rc.d | Stub |
| OpenBSD | Unix sockets | Full | N/A | rc.d | Stub |
| NetBSD | Unix sockets | Full | N/A | rc.d | Stub |

### Key Platform Abstraction Files

| File | Purpose |
|------|---------|
| `src/platform/mod.rs` | Platform enum, feature flags |
| `src/platform/unix.rs` | Unix implementations |
| `src/platform/windows_impl.rs` | Windows implementations |
| `src/platform/sandbox.rs` | Sandbox backends (Landlock + Stub) |
| `src/platform/service/mod.rs` | Service management exports |
| `src/platform/service/stub_service.rs` | Unix service manager (Linux systemd + BSD stub) |

---

## Phase 1: HTTP/3 Backend Proxy (Critical Gap)

### Problem

The `Http3Server::handle_request()` in `src/http3/server.rs` handles QUIC connections, runs WAF checks, and routes requests, but **returns placeholder text instead of proxying to backends**:

```rust
// server.rs:473-476 - PLACEHOLDER RESPONSE
let body = format!(
    "HTTP/3 proxied to {} - path: {}",
    route_target.upstream, path
);
```

This means HTTP/3 clients receive a text response instead of actual content.

### Architecture Analysis

**Current flow:**
```
QUIC Connection (quinn)
    ↓
h3_quinn::Connection wrapper
    ↓
h3::server::builder() → RequestResolver
    ↓
Per-request: resolve_request() → h3::Request<h3_quinn::Connection>
    ↓
WAF check_request_full() (Block/Challenge/Tarpit/Drop/Pass decisions)
    ↓
router.route() - basic routing
    ↓
RouteResult → placeholder response (NOT actual proxying)
```

**Required flow (what's missing):**
```
QUIC Connection
    ↓
h3 Request parsing
    ↓
WAF check
    ↓
router.route()
    ↓
Backend dispatch (Static/PHP/FastCGI/Upstream/Mesh)
    ↓
Real response from backend
```

### Implementation Strategy

The `HttpServer` in `src/http/server.rs` has 15+ sections handling each backend type. The same dispatch logic needs to be replicated for HTTP/3.

**Key files to examine:**
- `src/http3/server.rs` - main QUIC server
- `src/http3/handler.rs` - stub handler (can remain as-is)
- `src/http/server.rs` - reference for backend dispatch (sections 15+)

### Step 1.1: Add RouteResult Handling

**File**: `src/http3/server.rs`

Currently returns placeholder. Add real dispatch:

```rust
// CURRENT (placeholder):
RouteResult::Found(route_target) => {
    let body = format!(
        "HTTP/3 proxied to {} - path: {}",
        route_target.upstream, path
    );
    (StatusCode::OK, body)
}

// NEEDED: Real backend dispatch
RouteResult::Found(route_target) => {
    match route_target.backend_type {
        BackendType::Static => self.handle_static_backend(...).await?,
        BackendType::Php => self.handle_php_backend(...).await?,
        BackendType::FastCgi => self.handle_fastcgi_backend(...).await?,
        BackendType::Upstream => self.handle_upstream_backend(...).await?,
        BackendType::MeshOrigin => self.handle_mesh_origin_backend(...).await?,
        // ...
    }
}
```

### Step 1.2: Implement Backend Handlers

Copy or adapt handlers from `src/http/server.rs`:

| Handler | HTTP Server Location | HTTP/3 Location |
|---------|---------------------|-----------------|
| Static files | `serve_static_file()` | New `handle_static()` |
| PHP-FPM | `handle_php_request()` | New `handle_php()` |
| FastCGI | `handle_fastcgi_request()` | New `handle_fastcgi()` |
| Upstream proxy | `handle_upstream_request()` | New `handle_upstream()` |
| Mesh origin | `handle_mesh_origin()` | New `handle_mesh_origin()` |

### Step 1.3: Add ConnectionMeta for HTTP/3

**File**: `src/http3/server.rs` or new `src/http3/connection_meta.rs`

```rust
impl ConnectionMeta for Http3ConnectionMeta {
    fn client_ip(&self) -> IpAddr { self.client_addr.ip() }
    fn ja4(&self) -> Option<String> { None /* QUIC doesn't support pre-handshake JA4 */ }
    fn protocol(&self) -> &'static str { "h3" }
    fn supports_websocket(&self) -> bool { false /* QUIC datagrams differ from WS */ }
}
```

### Step 1.4: Wire Up Metrics

Ensure HTTP/3 requests increment existing metrics counters:
- Request counters
- WAF decision counters
- Backend response times
- Connection counts

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 1.1 RouteResult handling | 2-3 hours | Medium |
| 1.2 Backend handlers (all types) | 16-24 hours | High |
| 1.3 ConnectionMeta | 1-2 hours | Low |
| 1.4 Metrics | 1-2 hours | Low |
| **Total** | **20-31 hours** | **High** |

### Files to Modify

| File | Changes |
|------|---------|
| `src/http3/server.rs` | Add RouteResult handling, backend dispatch |
| `src/http3/handler.rs` | Can remain stub (not used) |

### Testing Requirements

1. **Unit tests** for each backend handler with mock backends
2. **Integration test** with real HTTP/3 client connecting to WAF
3. **Verify** static files, PHP, FastCGI, upstream all work over HTTP/3
4. **Performance test** comparing HTTP/3 vs HTTP/1.1 throughput

---

## Phase 2: BSD Service Support

### Problem

The `UnixServiceManager::install()` at `src/platform/service/stub_service.rs:166-179` returns "not implemented" for FreeBSD, OpenBSD, and NetBSD:

```rust
} else if cfg!(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
)) {
    Err(PlatformError::NotSupported(
        "rc.d service installation not yet implemented. Please install manually."
            .to_string(),
    ))
}
```

### Architecture

All BSD variants use the rc.d framework with shell scripts in `/etc/rc.d/` or `/usr/local/etc/rc.d/`. They use `/etc/rc.subr` for common operations.

### Implementation Strategy

Create `src/platform/service/bsd_service.rs` with rc.d script generation. The existing `is_installed()` check at line 237 already expects `/usr/local/etc/rc.d/{name}` for FreeBSD.

#### BSD rc.d Script Template

All three BSD variants can use similar scripts with `/etc/rc.subr`:

```shell
#!/bin/sh
#
# PROVIDE: maluwaf
# REQUIRE: NETWORKING syslogd
# BEFORE:  firewall
#

. /etc/rc.subr

name="maluwaf"
rcvar="${name}_enable"
command="/path/to/maluwaf"
command_args="--overseer --foreground"
pidfile="/var/run/maluwaf/overseer.pid"
required_files="/etc/maluwaf/config.toml"

load_rc_config $name
run_rc_command "$1"
```

### Step 2.1: Create BSD Service Module

**File**: `src/platform/service/bsd_service.rs` (new)

```rust
use std::path::PathBuf;
use crate::platform::PlatformError;

pub struct BsdServiceManager;

impl BsdServiceManager {
    pub fn install(&self, config: &ServiceConfig) -> Result<(), PlatformError> {
        let script = self.generate_rc_script(config);

        #[cfg(target_os = "freebsd")]
        self.install_freebsd(&script, config)?;

        #[cfg(target_os = "openbsd")]
        self.install_openbsd(&script, config)?;

        #[cfg(target_os = "netbsd")]
        self.install_netbsd(&script, config)?;

        Ok(())
    }

    fn generate_rc_script(&self, config: &ServiceConfig) -> String {
        let binary_path = config.binary_path.clone()
            .unwrap_or_else(|| self.default_binary_path());

        format!(r#"#!/bin/sh
#
# PROVIDE: maluwaf
# REQUIRE: NETWORKING syslogd
# BEFORE:  firewall
#

. /etc/rc.subr

name="maluwaf"
rcvar="${{name}}_enable"
command="{}"
command_args="--overseer --foreground"
pidfile="/var/run/maluwaf/overseer.pid"
required_files="/etc/maluwaf/config.toml"

load_rc_config $name
run_rc_command "$1"
"#, binary_path.display())
    }

    fn default_binary_path(&self) -> PathBuf {
        #[cfg(target_os = "freebsd")]
        return PathBuf::from("/usr/local/bin/maluwaf");

        #[cfg(target_os = "openbsd")]
        return PathBuf::from("/usr/local/bin/maluwaf");

        #[cfg(target_os = "netbsd")]
        return PathBuf::from("/usr/pkg/bin/maluwaf");
    }

    // Platform-specific install methods...
}
```

### Step 2.2: Add Enable/Disable Support

BSD requires explicit enable in rc.conf:

```rust
#[cfg(target_os = "freebsd")]
fn enable_freebsd(&self, name: &str) -> Result<(), PlatformError> {
    let output = std::process::Command::new("sysrc")
        .args([&format!("{}_enable=YES", name)])
        .output()
        .map_err(|e| PlatformError::NotSupported(format!("sysrc failed: {}", e)))?;

    if !output.status.success() {
        return Err(PlatformError::NotSupported("Failed to enable service".into()));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn enable_openbsd(&self, name: &str) -> Result<(), PlatformError> {
    // OpenBSD uses rcctl
    let output = std::process::Command::new("rcctl")
        .args(["enable", name])
        .output()
        .map_err(|e| PlatformError::NotSupported(format!("rcctl failed: {}", e)))?;

    if !output.status.success() {
        return Err(PlatformError::NotSupported("Failed to enable service".into()));
    }
    Ok(())
}
```

### Step 2.3: Update Service Module Exports

**File**: `src/platform/service/mod.rs`

```rust
// Add new export
pub use bsd_service::BsdServiceManager;
```

**File**: `src/platform/service/stub_service.rs`

Modify BSD arm to call the new implementation instead of returning error.

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 2.1 Script generation | 2-3 hours | Low |
| 2.2 Enable/disable | 2-3 hours | Low |
| 2.3 Module integration | 1 hour | Low |
| Testing (manual in VM) | 4 hours | Medium |
| **Total** | **9-11 hours** | **Low-Medium** |

### Files to Create/Modify

| File | Action |
|------|--------|
| `src/platform/service/bsd_service.rs` | Create |
| `src/platform/service/mod.rs` | Modify - add exports |
| `src/platform/service/stub_service.rs` | Modify - call BSD impl |

### Testing Requirements

1. **Manual testing** on each BSD variant in VM
2. Test install: script created with correct permissions
3. Test enable: rc.conf updated correctly
4. Test start/stop: daemon starts and PID file created
5. Test status: correct state reported
6. Test uninstall: script removed, rc.conf cleaned

---

## Phase 3: Non-Linux Sandbox

### Problem

The `StubSandbox` in `src/platform/sandbox.rs:138-177` logs a warning but provides **no actual enforcement**:

```rust
fn apply(&self, _allowed_paths: &[&Path], _denied_paths: &[&Path]) -> Result<(), SandboxError> {
    if self.level == SandboxLevel::Off {
        return Ok(());
    }
    tracing::warn!(
        "OS-level sandboxing is not available on this platform ({}). \
         Using basic directory isolation instead...",
        std::env::consts::OS
    );
    Ok(())  // NO ACTUAL ENFORCEMENT
}
```

### Security Implications

| Platform | Enforcement | Impact |
|----------|-------------|--------|
| Linux | Landlock - full | Process can ONLY access allowed paths |
| macOS | None | Compromised process has full user access |
| FreeBSD | None | Compromised process has full user access |
| Windows | None | Compromised process has full user access |

### Available Technologies

| Platform | Technology | Crate | Effort |
|----------|------------|-------|--------|
| macOS | Seatbelt | `nono` | Medium |
| FreeBSD | Capsicum | `capsicum` | Low |
| Windows | AppContainer | `rappct` | High |

### Recommendation: Cross-Platform `nono` Crate

The `nono` crate (v0.40.1) provides Landlock on Linux and Seatbelt on macOS with a unified API:

```rust
// Example from nono crate docs
use nono::preference::{AllowRead, AllowWrite, Preference};

let prefs = Preference::new()
    .allow_read("/var/lib/maluwaf/sandbox")
    .allow_write("/var/lib/maluwaf/quarantine");

nono::spawn("uploader", prefs)?;
```

### Step 3.1: Evaluate `nono` Crate

**Research required:**
1. Check `nono` crate compatibility with current Rust version
2. Verify Seatbelt capabilities match Landlock feature set
3. Test on macOS VM

**Cargo.toml addition:**
```toml
nono = "0.40"
```

### Step 3.2: Create PlatformSandbox Trait Extension

**File**: `src/platform/sandbox.rs`

Add new trait or extend existing:

```rust
pub trait PlatformSandbox: Send + Sync {
    fn apply(&self, paths: &SandboxPaths) -> Result<(), SandboxError>;
    fn is_supported(&self) -> bool;
}

// Extend UnixSandbox to use nono on macOS
#[cfg(target_os = "macos")]
impl PlatformSandbox for UnixSandbox {
    fn apply(&self, paths: &SandboxPaths) -> Result<(), SandboxError> {
        use nono::preference::{AllowRead, AllowWrite, Preference};

        let mut prefs = Preference::new();

        for path in paths.read_paths() {
            prefs = prefs.allow_read(path);
        }
        for path in paths.write_paths() {
            prefs = prefs.allow_write(path);
        }
        for path in paths.no_access_paths() {
            prefs = prefs.deny(path);
        }

        // Spawn sandboxed subprocess
        nono::spawn("maluwaf-worker", prefs)
            .map_err(|e| SandboxError::Syscall(e.to_string()))?;

        Ok(())
    }
}
```

### Step 3.3: FreeBSD Capsicum Implementation

**File**: `src/platform/sandbox.rs` or new `src/platform/sandbox/bsd.rs`

```rust
#[cfg(target_os = "freebsd")]
pub mod bsd {
    use capsicum::{CapParser, RestrictedFileFlags};
    use std::path::Path;

    pub fn enter_sandbox(read_paths: &[&Path], write_paths: &[&Path]) -> Result<(), SandboxError> {
        // Enter capability mode
        capsicum::enter();

        // Restrict file access
        for path in read_paths {
            let fd = std::fs::File::open(path)
                .map_err(|e| SandboxError::Io(e))?
                .into_raw_fd();

            capsicum::restrict_fd(fd)
                .map_err(|e| SandboxError::Syscall(e.to_string()))?;
        }

        Ok(())
    }
}
```

### Step 3.4: Document Security Limitations

Add warning logs when StubSandbox is active:

```rust
if self.level != SandboxLevel::Off {
    tracing::warn!(
        "SECURITY: OS-level sandboxing is not available on {}. \
         A compromised process will have full access to all files and network connections. \
         For production use, run on Linux with kernel 5.13+.",
        std::env::consts::OS
    );
}
```

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 3.1 Evaluate nono crate | 2-3 hours | Low |
| 3.2 macOS implementation | 4-6 hours | Medium |
| 3.3 FreeBSD implementation | 3-4 hours | Medium |
| 3.4 Documentation | 1 hour | Low |
| Testing on each platform | 8-12 hours | High |
| **Total** | **18-26 hours** | **Medium-High** |

### Files to Create/Modify

| File | Action |
|------|--------|
| `src/platform/sandbox.rs` | Modify - add nono integration |
| `src/platform/sandbox/bsd.rs` | Create - FreeBSD capsicum |
| `Cargo.toml` | Add `nono` dependency |

### Testing Requirements

1. **Unit test** for sandbox preference building
2. **Manual testing** on macOS with various path configurations
3. **Manual testing** on FreeBSD with capsicum restrictions
4. **Security verification** that restricted paths are actually inaccessible

---

## Phase 4: Windows Socket FD Passing — ALREADY IMPLEMENTED

### Current State

Upon deeper investigation, **Windows socket FD passing already works** via the standalone functions in `src/platform/windows_impl.rs`:

| Function | Location | Status |
|----------|----------|--------|
| `duplicate_socket_for_child()` | `windows_impl.rs:128` | ✅ Implemented |
| `create_socket_from_duplicate()` | `windows_impl.rs:155` | ✅ Implemented |
| `WindowsSocketFDPassing` trait | `windows_impl.rs:75` | ⚠️ Returns `NotSupported` |

**How it works:**

The socket handoff code in `src/overseer/socket_handoff.rs` directly calls the standalone functions instead of using the trait:

```rust
// socket_handoff.rs:287-296
if let Ok(protocol_info) = crate::platform::windows_impl::duplicate_socket_for_child(
    info.fd as std::os::windows::io::RawSocket,
    target_pid,
) {
    ipc.send(&Message::WindowsSocketInfo {
        protocol_info: protocol_info.into_boxed_slice().into_vec(),
        port: info.port,
    })
}
```

### Step 4.1: Verify Windows Socket Handoff Works (1-2 hours)

**Test scenario:**
1. Start WAF on Windows with socket handoff enabled
2. Trigger graceful reload via `./maluwaf admin reload --graceful`
3. Verify connections migrate to new worker without drops

If it works, Phase 4 is complete. If not, investigate.

### Step 4.2: Clean Up Trait Implementation (Optional)

The `WindowsSocketFDPassing` trait impl returns `NotSupported` but the standalone functions work. Consider:

1. **Option A**: Leave as-is (current standalone approach works)
2. **Option B**: Wire the trait to call the standalone functions for consistency

**Recommended**: Option A - the current approach works and changing it introduces risk.

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 4.1 Verify functionality | 1-2 hours | Medium (requires Windows testing) |
| 4.2 Optional cleanup | 1-2 hours | Low |
| **Total** | **2-4 hours** | **Low** |

### Files to Modify

| File | Changes |
|------|---------|
| `src/overseer/socket_handoff.rs` | Already uses standalone functions |
| `src/platform/windows_impl.rs` | Optionally wire trait to functions |

### Conclusion

**Phase 4 is likely not needed** - the investigation revealed Windows socket passing is already implemented via the standalone functions. The only remaining work is verification and potential optional cleanup.

---

## Phase 5: Direct TLS for Key Exchange

### Problem

The Passover Key Exchange server at `src/mesh/passover_key_exchange.rs:1084-1096` has TLS config but doesn't use it:

```rust
let scheme = if config.tls.cert_path.is_some() && config.tls.key_path.is_some() {
    "https"
} else {
    "http"
};

tracing::warn!(
    "Key exchange server starting on {}://{} (HTTPS proxy required for TLS - direct TLS not yet implemented)",
    scheme,
    addr
);

axum::serve(listener, router).await?;  // Plain HTTP only!
```

### Reference Implementation

The DNS over HTTPS (DoH) implementation at `src/dns/doh.rs:61-93` shows the correct pattern:

```rust
async fn handle_connection(...) {
    // 1. TLS handshake
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
        acceptor.accept(stream),
    )
    .await
    .map_err(|_| "TLS handshake timeout")?
    .map_err(|e| format!("TLS handshake failed: {}", e))?;

    // 2. Wrap with TokioIo
    let io = TokioIo::new(tls_stream);

    // 3. Serve HTTP/2 over TLS
    builder
        .serve_connection(io, service_fn(...))
        .await
}
```

### Step 5.1: Build ServerConfig from MeshTlsConfig

**File**: `src/mesh/passover_key_exchange.rs`

Extract TLS config building:

```rust
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig;

fn build_tls_acceptor(config: &MeshTlsConfig) -> Result<TlsAcceptor, Box<dyn Error>> {
    let cert_path = config.cert_path.as_ref()
        .ok_or("TLS cert path not configured")?;
    let key_path = config.key_path.as_ref()
        .ok_or("TLS key path not configured")?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config error: {}", e))?;

    // Enforce TLS 1.3 for key exchange
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}
```

### Step 5.2: Replace axum::serve with TLS Accept Loop

```rust
let acceptor = build_tls_acceptor(&config.tls)?;

loop {
    tokio::select! {
        result = listener.accept() => {
            let (stream, client_addr) = result?;

            if config.tls.cert_path.is_some() {
                // TLS mode
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            serve_http1(io, router.clone(), client_addr).await;
                        }
                        Err(e) => tracing::warn!("TLS handshake failed: {}", e),
                    }
                });
            } else {
                // Plain HTTP mode
                let router = router.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    serve_http1(io, router, client_addr).await;
                });
            }
        }
    }
}
```

### Step 5.3: Bridge Axum Handlers with Hyper

The existing `create_key_exchange_router()` returns an axum Router. We need to serve it via hyper:

```rust
async fn serve_http1(
    io: TokioIo<impl AsyncRead + AsyncWrite + Unpin>,
    router: Router,
    client_addr: SocketAddr,
) {
    let make_svc = make_service_fn(|_conn| {
        let router = router.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                router.clone().call(req)
            }))
        }
    });

    let builder = hyper::server::conn::http1::Builder::new();
    builder.serve_connection(io, make_svc).await.unwrap();
}
```

### Effort Estimate

| Step | Effort | Complexity |
|------|--------|------------|
| 5.1 TLS config building | 1-2 hours | Low |
| 5.2 TLS accept loop | 2-3 hours | Medium |
| 5.3 Hyper/axum bridge | 3-5 hours | Medium-High |
| Testing | 2-3 hours | Medium |
| **Total** | **8-13 hours** | **Medium** |

### Files to Modify

| File | Changes |
|------|---------|
| `src/mesh/passover_key_exchange.rs` | Add TLS support |

---

## Phase 6: Windows WFP ICMP Interface Filtering (Lower Priority)

### Problem

The WFP backend at `src/icmp_filter/wfp.rs:34-39` cannot filter by interface:

```rust
if !config.interfaces.is_all() {
    tracing::warn!(
        "Interface-specific filtering on Windows WFP requires additional Windows API \
         calls not yet implemented. All interfaces will be filtered."
    );
}
```

### Root Cause

The `wfp` crate doesn't expose `FWPM_CONDITION_ALE_INTERFACE_INDEX` in its `ConditionField` enum.

### Short-Term Fix (2-3 hours)

Fall back to Windows Firewall backend when interface-specific filtering is needed:

```rust
if !config.interfaces.is_all() {
    tracing::warn!(
        "WFP backend does not support interface-specific filtering. \
         Falling back to Windows Firewall backend."
    );
    return Ok(WinfwFilter::new(config)?);
}
```

### Long-Term Fix (12-17 hours)

Fork `wfp` crate to add interface index support. See investigation notes.

### Recommendation

Implement short-term fix only unless interface-specific WFP filtering is a critical requirement.

---

## Implementation Order

| Phase | Item | Priority | Effort | Reason |
|-------|------|----------|--------|--------|
| 1 | HTTP/3 Backend Proxy | **HIGH** | 20-31h | Critical functionality gap |
| 2 | BSD Service Support | MEDIUM | 9-11h | Basic platform parity |
| 5 | Direct TLS Key Exchange | MEDIUM | 8-13h | Security improvement |
| 3 | Non-Linux Sandbox | LOW | 18-26h | Security but high effort |
| 4 | Windows Socket FD | **LOW** | 2-4h | Already implemented (verify only) |
| 6 | WFP Interface Filtering | LOW | 2-3h | Fallback only |

---

## File Change Summary

| File | Phase | Changes |
|------|-------|---------|
| `src/http3/server.rs` | 1 | Backend dispatch implementation |
| `src/platform/service/bsd_service.rs` | 2 | Create - BSD rc.d support |
| `src/platform/service/mod.rs` | 2 | Add BSD exports |
| `src/platform/service/stub_service.rs` | 2 | Call BSD impl |
| `src/platform/sandbox.rs` | 3 | Add nono, capsicum integration |
| `Cargo.toml` | 3 | Add nono dependency |
| `src/mesh/passover_key_exchange.rs` | 5 | Direct TLS support |
| `src/icmp_filter/wfp.rs` | 6 | Fallback to WinFw |
| `src/overseer/socket_handoff.rs` | 4 | Verify Windows path works (optional) |

---

## Testing Strategy

### Unit Tests
- Phase 1: Mock backend handlers
- Phase 5: TLS config building with invalid certs/keys

### Integration Tests
- Phase 1: Real HTTP/3 client connecting to all backend types
- Phase 2: Install/uninstall/start/stop on each BSD variant (manual VM testing)
- Phase 3: Verify sandbox restrictions on macOS/FreeBSD (manual)
- Phase 4: Live upgrade with socket handoff on Windows

### Platform Test Matrix

| Test | Linux | macOS | Windows | FreeBSD | OpenBSD | NetBSD |
|------|-------|-------|---------|---------|---------|--------|
| HTTP/3 proxy | ✅ | ✅ | N/A | N/A | N/A | N/A |
| BSD services | N/A | N/A | N/A | ✅ | ✅ | ✅ |
| Sandbox | ✅ | ✅ | ✅ | ✅ | N/A | N/A |
| Socket handoff | ✅ | N/A | ✅* | N/A | N/A | N/A |
| TLS key exchange | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

*Socket handoff on Windows already implemented via standalone functions

---

## Related Work

### Dependencies

| Crate | Phase | Purpose |
|-------|-------|---------|
| `nono` | 3 | macOS Seatbelt wrapper |
| `capsicum` | 3 | FreeBSD Capsicum bindings |

### Existing Patterns to Reuse

| Pattern | Location | Used By |
|---------|----------|---------|
| TLS acceptor + hyper | `src/dns/doh.rs` | Phase 5 |
| Backend dispatch | `src/http/server.rs` | Phase 1 |
| Service install | `src/platform/service/stub_service.rs` | Phase 2 |

---

## Verification Steps

After implementation, verify for each phase:

### Phase 1 (HTTP/3)
```bash
# Test HTTP/3 with curl
curl -k --http3 https://localhost:8443/static/test.html
# Verify actual file content, not placeholder text
```

### Phase 2 (BSD)
```bash
# On FreeBSD VM
sudo ./target/release/maluwaf service install
sudo service maluwaf start
sudo service maluwaf status
sudo service maluwaf stop
sudo ./target/release/maluwaf service uninstall
```

### Phase 3 (Sandbox)
```bash
# On macOS
# Attempt to access restricted path from sandboxed process
# Should fail with permission denied
```

### Phase 4 (Windows Socket)
```bash
# Trigger live upgrade
./maluwaf admin reload --graceful
# Verify connections transfer without drops
```

### Phase 5 (TLS Key Exchange)
```bash
# Verify TLS is actually used
openssl s_client -connect localhost:KEY_EXCHANGE_PORT
# Should show TLS handshake
```

---

## Rollback Plan

Each phase can be reverted independently:

| Phase | Revert Action |
|-------|---------------|
| 1 | Revert `src/http3/server.rs` to return placeholder |
| 2 | Revert BSD arm in `stub_service.rs` to return error |
| 3 | Remove nono/capsicum code, keep StubSandbox |
| 4 | N/A - verification only (existing code unchanged) |
| 5 | Revert `passover_key_exchange.rs` to `axum::serve()` |
| 6 | Remove WinFw fallback, restore warning |

---

## Open Questions

1. **HTTP/3 Priority**: Should we prioritize fixing HTTP/3 proxy over other items given its impact?

2. **BSD Testing**: Do you have access to BSD VMs for testing service installation?

3. **Non-Linux Sandbox Scope**: Should we target macOS only, or include FreeBSD as well given Capsicum's lower effort?

4. **Windows Testing**: Is Windows a near-term target requiring socket handoff testing?

5. **Key Exchange TLS**: Is direct TLS for key exchange a security requirement or nice-to-have?
