# Windows Service & DX Improvements

## Overview

This skill covers the Windows Service implementation and Developer Experience improvements added in Wave 2.2 (2026-04-27).

## Components

### 1. Windows Service Implementation

**File**: `src/platform/service/windows_service.rs`

Provides Windows service management capabilities:
- `ServiceConfig` - Configuration for service installation
- `WindowsServiceManager` - Manages service lifecycle
- `ServiceControl` trait - Interface for install/uninstall/start/stop operations
- Uses `sc` command for Windows service management
- Properly sets service description via `sc description`

```rust
use crate::platform::service::windows_service::{ServiceConfig, WindowsServiceManager, SERVICE_NAME};

let config = ServiceConfig::new("MaluWAF")
    .with_display_name("MaluWAF Web Application Firewall")
    .with_description("High-performance WAF with advanced attack detection")
    .with_auto_start(true);

let manager = WindowsServiceManager::new();
manager.install(&config)?;
```

### 2. Interface Resolver

**File**: `src/platform/windows/interface_resolver.rs`

Resolves Windows network interface names to interface indices (required for WFP filtering):
- `WindowsInterfaceResolver::resolve(interface_name)` - Get interface index by name
- `WindowsInterfaceResolver::get_all_interfaces()` - Map all interfaces
- `WindowsInterfaceResolver::get_interface_by_index(index)` - Reverse lookup
- Uses PowerShell `Get-NetAdapter` and `Get-NetIPInterface`

```rust
use crate::platform::windows::interface_resolver::WindowsInterfaceResolver;

let index = WindowsInterfaceResolver::resolve("Ethernet 1")?;
let all = WindowsInterfaceResolver::get_all_interfaces();
```

### 3. Firewall Rule Management

**File**: `src/platform/windows/firewall.rs`

Manages Windows Firewall rules for HTTP/HTTPS/QUIC:
- `inject_quic_firewall_rule(port)` - Add UDP firewall rule for QUIC
- `inject_http_firewall_rule(port)` - Add TCP firewall rule for HTTP
- `inject_https_firewall_rule(port)` - Add TCP firewall rule for HTTPS
- `remove_quic_firewall_rule(port)` - Remove QUIC firewall rule
- Uses `netsh advfirewall`

```rust
use crate::platform::windows::firewall;

firewall::inject_quic_firewall_rule(443)?;
firewall::inject_http_firewall_rule(8080)?;
```

## Key Implementation Details

### Service Installation Flow
1. Build `ServiceConfig` with name, display name, description
2. Get binary path (from config or current executable)
3. Use `sc create` with appropriate parameters
4. Set description via `sc description`

### Interface Resolution
- Requires PowerShell for network adapter queries
- Returns `u32` interface index for WFP use
- Gracefully handles missing interfaces

### Firewall Rules
- Rule names prefixed with "MaluWAF"
- Check for existing rules before adding
- Support both UDP (QUIC) and TCP (HTTP/HTTPS)

## Testing

```bash
# Build on Windows
cargo build --target x86_64-pc-windows-msvc

# Service management tests (platform-specific)
cargo test --lib windows_service
```

## Dependencies

- Windows platform (gated by `#[cfg(windows)]`)
- PowerShell for interface resolution
- netsh for firewall management

## Notes

- Non-Windows builds use stub implementations
- Service operations require elevated privileges
- Interface indices may change after network configuration changes