# ICMP Filter Architecture

## 1. Purpose and Responsibility

The ICMP Filter module (`src/icmp_filter/`) provides **cross-platform ICMP packet filtering** with pluggable backends (nftables, eBPF, pf, Windows Firewall, WFP), privilege detection, and feature-gated compilation.

**Core Responsibilities:**
- ICMP flood protection
- Pluggable backend architecture
- Platform-specific implementations
- Privilege detection and management
- Rate limiting per ICMP type/code

---

## 2. Key Data Structures

```rust
pub struct IcmpFilterManager {
    backend: Option<Box<dyn IcmpFilter>>,
    config: IcmpFilterConfig,
}

pub trait IcmpFilter {
    fn enable(&mut self) -> Result<(), IcmpFilterError>;
    fn disable(&mut self) -> Result<(), IcmpFilterError>;
    fn is_enabled(&self) -> bool;
    fn is_enforcing(&self) -> bool;
    fn status(&self) -> FilterStatus;
    fn update_config(&mut self, config: IcmpFilterConfig) -> Result<(), IcmpFilterError>;
}

pub trait IcmpFilterFactory {
    fn create(config: &IcmpFilterConfig) -> Result<Box<dyn IcmpFilter>, IcmpFilterError>;
    fn backend() -> FilterBackend;
    fn is_available() -> bool;
}

pub enum FilterBackend {
    Nftables,
    Ebpf,
    Pf,
    WindowsFirewall,
    Wfp,
}

pub struct BackendCapabilities {
    pub supports_block: bool,
    pub supports_allow: bool,
    pub supports_rate_limit: bool,
    pub supports_type_code: bool,
    pub supports_interface: bool,
    pub requires_admin: bool,
    pub is_enforcing: bool,
}
```

---

## 2. Platform Backends

| Backend | Platform | Feature Gate | Capabilities |
|---------|----------|--------------|--------------|
| Nftables | Linux | `icmp-filter` | block, allow, rate_limit, type_code |
| eBPF | Linux | `icmp-ebpf` | block, rate_limit, type_code |
| pf | macOS/FreeBSD | `icmp-pf` | block, allow, rate_limit |
| Windows Firewall | Windows | `icmp-winfw` | block, allow |
| WFP | Windows | `icmp-wfp` | block, allow, rate_limit, type_code |

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `IcmpFilterManager::new(config)` | Constructor with backend detection |
| `enable()` | Enable ICMP filtering |
| `disable()` | Disable ICMP filtering |
| `is_enabled()` | Check if filtering active |
| `is_enforcing()` | Check if blocking (vs monitoring) |
| `status() -> FilterStatus` | Get filter status |
| `is_available() -> bool` | Check if any backend available |
| `available_backends()` | List available backends |
| `has_privilege_for(operation)` | Check privilege requirements |

---

## 4. Integration Points

- **Supervisor**: ICMP flood protection management
- **Admin API**: Filter status and configuration
- **Platform**: Backend-specific kernel integration

---

## 5. Key Implementation Details

- **Pluggable**: New backends added via trait implementation
- **Auto-detection**: Selects best available backend at runtime
- **Privilege-aware**: Detects required privileges for operations
- **Graceful Degradation**: Falls back to monitoring mode without privileges
