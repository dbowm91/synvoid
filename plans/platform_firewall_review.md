# Platform Firewall, Filtering, and Admin Capability Review

**Status**: Documented
**Priority**: 9
**Date**: 2026-05-02

## Overview

This document reviews firewall/filter support across the MaluWAF codebase, covering:
- ICMP filtering backends (`src/icmp_filter/**`)
- Windows firewall operations (`src/platform/windows/firewall.rs`)
- Windows interface resolution (`src/platform/windows/interface_resolver.rs`)
- TCP listener infrastructure (`src/tcp/listener.rs`)
- eBPF-based flood protection (`src/waf/flood/ebpf_flood.rs`)

## 1. Firewall Backends

### 1.1 Linux Backends

| Backend | Feature Flag | Native/Shell | Notes |
|---------|--------------|--------------|-------|
| **nftables** | (default) | Shell (`nft` CLI) | Always available on Linux if `nft` command exists |
| **eBPF** | `icmp-ebpf` | Native (aya crate) | Falls back to nftables if unavailable |

#### nftables (`src/icmp_filter/nftables.rs`)
- Shell-outs to `nft` CLI for all operations
- Applies rules via stdin: `nft -f -`
- Deletes table on disable: `nft delete table inet <name>`
- No explicit privilege check before operations
- Availability check: `nft --version`

#### eBPF (`src/icmp_filter/ebpf.rs`)
- Uses `aya` crate for native eBPF program loading
- Requires BTF: `/sys/kernel/btf/vmlinux` must exist
- Checks `/proc/sys/kernel/unprivileged_bpf_disabled`:
  - Value `"2"` = permission denied
  - Value `"1"` = disabled for unprivileged
- Attaches XDP for inbound, TC clsact for outbound
- Uses `tc qdisc add dev <iface> clsact` for TC setup
- Bytecode paths checked in order:
  1. Custom path from config
  2. `/usr/lib/maluwaf/ebpf/maluwaf-icmp.bpf`
  3. `/usr/local/lib/maluwaf/ebpf/maluwaf-icmp.bpf`
  4. `./ebpf-icmp/target/bpfel-unknown-none/release/maluwaf-icmp`

### 1.2 macOS/BSD Backends

| Backend | OS | Feature Flag | Native/Shell |
|---------|-----|--------------|--------------|
| **pf** | macOS | `icmp-pf` | Shell (`pfctl` CLI) |
| **pf_bsd** | FreeBSD/OpenBSD/NetBSD | `icmp-pf` | Shell (`pfctl` CLI) |

#### pf (`src/icmp_filter/pf.rs`)
- Shell-outs to `pfctl` for all operations
- Creates anchor: `pfctl -a maluwaf.icmp -f -`
- Anchor rules passed via stdin
- Enables PF: `pfctl -e`
- No explicit privilege check before operations
- Availability check: `pfctl -s info`

#### pf_bsd (`src/icmp_filter/pf_bsd.rs`)
- Similar to macOS pf but with BSD-specific variations
- OpenBSD uses `icmp6-type` keyword (vs `icmp-type`)
- FreeBSD/NetBSD use path `{table_name}.icmp` vs `maluwaf.icmp`
- Availability check: `pfctl -s info`

### 1.3 Windows Backends

| Backend | Feature Flag | Native/Shell | Notes |
|---------|--------------|--------------|-------|
| **Windows Firewall (winfw)** | `icmp-winfw` | Native (windows_firewall crate) | COM-based API |
| **WFP** | `icmp-wfp` | Native (wfp crate) | Transactional filter engine |

#### Windows Firewall (`src/icmp_filter/winfw.rs`)
- Uses `windows_firewall` Rust crate (COM-based)
- Creates rules with `WindowsFirewallRule::builder()`
- Rules named with `Maluwaf_ICMP_*` prefix
- Privilege check at construction time via `is_admin()`
- Stores `has_admin` flag, defers actual operations to `enable()`
- `enable()` returns `PermissionDenied` if not admin

#### WFP (`src/icmp_filter/wfp.rs`)
- Uses `wfp` Rust crate for Windows Filtering Platform
- Uses transaction-based API: `Transaction::new()` → `add()` → `commit()`
- Sublayer name: `Maluwaf_ICMP_Sublayer`
- Privilege check at construction time via `is_admin()`
- Interface filtering requires numeric indices (name resolution not implemented)
- `enable()` returns `PermissionDenied` if not admin

### 1.4 Summary Backend Table

| Platform | Backend | Feature | Privilege Check |
|----------|---------|---------|-----------------|
| Linux | nftables | (default) | Root or CAP_NET_ADMIN via `is_admin()` |
| Linux | eBPF | `icmp-ebpf` | Root + unprivileged_bpf_disabled!=2 |
| macOS | pf | `icmp-pf` | Root via `is_admin()` |
| BSD | pf | `icmp-pf` | Root via `is_admin()` |
| Windows | winfw | `icmp-winfw` | Admin SID check via `is_admin()` |
| Windows | wfp | `icmp-wfp` | Admin SID check via `is_admin()` |
| Other | none | — | `false` |

## 2. Privilege Checks

### 2.1 Platform-Specific `is_admin()` Implementation

#### Linux (`src/icmp_filter/platform.rs:56-88`)
```rust
pub fn is_admin() -> bool {
    if unsafe { libc::getuid() == 0 || libc::geteuid() == 0 } {
        return true;
    }
    if let Ok(content) = std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled") {
        if content.trim() != "0" {
            return false;  // Only allows if explicitly "0"
        }
    }
    has_cap_net_admin()  // Checks CapEff: for CAP_NET_ADMIN (bit 12)
}
```
- Returns `true` if uid 0/euid 0 OR has CAP_NET_ADMIN
- BUT: does not distinguish between eBPF loading needing CAP_NET_ADMIN vs nftables needing root

#### Windows (`src/icmp_filter/platform.rs:1-44`)
```rust
pub fn is_admin() -> bool {
    // Uses AllocateAndInitializeSid + CheckTokenMembership
    // Checks for DOMAIN_ALIAS_RID_ADMINS (S-1-5-32-544)
}
```
- Uses native Windows API (not shell-out)
- Checks if current token is member of Administrators group

#### macOS/BSD (`src/icmp_filter/platform.rs:90-100`)
```rust
pub fn is_admin() -> bool {
    unsafe { libc::getuid() == 0 || libc::geteuid() == 0 }
}
```
- Simple root check only
- No capability-based distinctions

### 2.2 Operation-Specific Privilege Requirements

| Operation | Linux | Windows | macOS/BSD |
|-----------|-------|---------|-----------|
| Load eBPF program | Root + bpf_disabled!=2 | N/A | N/A |
| Run nftables | Root or CAP_NET_ADMIN | N/A | N/A |
| Run pfctl | Root | N/A | Root |
| Create Windows Firewall rules | Admin | Admin | N/A |
| Create WFP filters | Admin | Admin | N/A |
| Bind low port (<1024) | Root | Admin | Root |

### 2.3 Issues with Current Privilege Checks

1. **Single `is_admin()` for all operations**: The `is_admin()` function is used as a broad check regardless of which backend or operation is being performed. Different operations have different requirements.

2. **eBPF privilege check is incomplete**: eBPF code at `src/icmp_filter/ebpf.rs:91-106` and `src/waf/flood/ebpf_flood.rs:88-103` checks `unprivileged_bpf_disabled` but the platform `is_admin()` doesn't incorporate this check. A user with CAP_NET_ADMIN but `unprivileged_bpf_disabled=2` would still pass the admin check but fail eBPF loading.

3. **No distinction between enable vs runtime operations**: Some operations (loading BPF, creating firewall rules) need elevated privileges, while others (updating config, checking status) may not.

4. **Privilege check timing varies**:
   - Windows backends: check at `new()` construction
   - Linux backends: no privilege check at construction; shell commands will simply fail if not privileged

## 3. Shell-Out Usage

### 3.1 ICMP Filter Shell-Outs

| File | Command | Purpose | Arguments Sanitized? |
|------|---------|---------|---------------------|
| `nftables.rs` | `nft --version` | Availability check | N/A (no user input) |
| `nftables.rs` | `nft -f -` | Apply ruleset | Rules built internally, safe |
| `nftables.rs` | `nft delete table inet <name>` | Remove table | Table name from config, validated |
| `ebpf.rs` | `tc qdisc show dev <iface>` | Check qdisc | Interface from config, validated |
| `ebpf.rs` | `tc qdisc add dev <iface> clsact` | Setup clsact | Interface from config, validated |
| `ebpf.rs` | `tc filter del dev <iface> egress` | Remove filter | Interface from config, validated |
| `pf.rs` | `pfctl -s info` | Availability check | N/A |
| `pf.rs` | `pfctl -e` | Enable PF | N/A |
| `pf.rs` | `pfctl -a <anchor> -f -` | Apply rules | Rules built internally, safe |
| `pf.rs` | `pfctl -a <anchor> -F all` | Flush rules | Anchor name hardcoded |
| `pf_bsd.rs` | Same as pf | BSD-specific | Same |

### 3.2 Windows Firewall Shell-Outs

| File | Command | Purpose | Arguments Sanitized? |
|------|---------|---------|---------------------|
| `firewall.rs` | `netsh advfirewall firewall add rule...` | Add rule | Port from config, validated u16 |
| `firewall.rs` | `netsh advfirewall firewall delete rule...` | Delete rule | Rule name formatted internally |
| `firewall.rs` | `netsh advfirewall firewall show rule...` | Check exists | Rule name formatted internally |
| `interface_resolver.rs` | `powershell Get-NetAdapter...` | Resolve interface | Interface name from config |

### 3.3 Shell-Out Analysis

**Low Risk** (arguments from config, not user input):
- ICMP filter rules (built from typed config)
- `netsh` firewall rules (ports are u16, names are formatted internally)
- `tc` commands (interface names from config, validated)

**Medium Risk** (PowerShell injection potential):
- `interface_resolver.rs:7-31`: Interface name passed directly to PowerShell command string
  ```rust
  "(Get-NetAdapter -Name '{}' | Get-NetIPInterface -AddressFamily IPv4).InterfaceIndex"
  ```
  If interface name contains special characters, could affect PowerShell parsing.

**Note**: The actual rule construction in `src/icmp_filter/winfw.rs` and `src/icmp_filter/wfp.rs` use native APIs (windows_firewall and wfp crates), not shell-outs.

## 4. Inactive Stubs and Visibility Issues

### 4.1 Inactive Backend Behavior

| Scenario | Behavior | Issue |
|----------|----------|-------|
| No features enabled | `IcmpFilterManager::new()` returns `UnsupportedPlatform` | ✓ Correct |
| eBPF not available | Falls back to nftables silently | Acceptable fallback |
| WFP not available | Falls back to Windows Firewall silently | Acceptable fallback |
| pf not available on Linux | Returns config error | ✓ Correct |
| `IcmpFilterManager::is_enabled()` on unsupported platform | Returns `false` | ✓ Correct |

### 4.2 Silent Success Without Enforcement

**Windows interface_resolver (`src/icmp_filter/platform.rs:46-54`)**:
```rust
#[cfg(target_os = "windows")]
pub fn get_network_interfaces() -> Vec<String> {
    Vec::new()  // Returns empty without error
}

#[cfg(target_os = "windows")]
pub fn interface_name_to_alias(name: &str) -> Option<String> {
    Some(name.to_string())  // Passes through without resolution
}
```
- These stub functions return empty/safe defaults
- They are NOT used by the actual Windows firewall backends (which use numeric indices directly)
- May confuse debugging if someone expects actual interface resolution

**Inactivity not logged**: When a backend cannot enforce (e.g., Windows without admin), the warning is logged at `new()` but the `status()` method doesn't indicate "created but not enabled due to permissions" clearly.

## 5. Additional Findings

### 5.1 TCP Listener (`src/tcp/listener.rs`)
- No firewall/filter operations
- Handles TCP proxying with protocol detection
- Flood protection via optional `FloodProtector`
- Rate limiting via optional `RateLimiterManager`
- No privilege checks needed (uses standard socket APIs)

### 5.2 eBPF Flood Protection (`src/waf/flood/ebpf_flood.rs`)
- Separate eBPF-based SYN flood protection
- Similar patterns to ICMP eBPF filter
- Has userspace fallback (`SynFloodProtector`)
- Privilege check: BTF available + unprivileged_bpf_disabled != 2

## 6. Recommendations (Documented, Not Implemented)

### 6.1 Operation-Specific Privilege Checks
Instead of single `is_admin()`, introduce operation-specific checks:
- `can_load_ebpf()`: Check unprivileged_bpf_disabled state
- `can_modify_nftables()`: Check root or CAP_NET_ADMIN
- `can_modify_firewall()`: Check admin on Windows
- `can_bind_low_port()`: Check root

### 6.2 Reduce Shell-Outs on Windows
The PowerShell interface resolver at `src/platform/windows/interface_resolver.rs` could use native APIs:
- `GetAdaptersInfo` or `GetAdaptersAddresses` from `iphlpapi.dll`
- `ConvertInterfaceIndexToLuid` / `ConvertInterfaceLuidToName` from `iphlpapi.dll`

### 6.3 Make Inactive Backends Visible
Add explicit state for backends that are "created but not active due to permissions":
```rust
pub enum FilterState {
    InactiveNotPrivileged,
    InactiveConfigError,
    Active,
}
```

### 6.4 Log Backend Selection
When a backend is selected (especially fallback cases), log the selection reason:
```rust
tracing::info!("Using nftables backend: eBPF unavailable ({})", reason);
```

## 7. Test Coverage Gaps

Based on the plan's test requirements:
- Backend reports unsupported without pretending enforcement exists: **Missing**
- Privilege check returns the expected requirement for each operation: **Missing**
- Windows command construction cannot inject additional arguments: **Missing**
- Linux capability parsing handles missing `/proc` fields: **Partial** (handles parse errors gracefully)

## 8. Items Not Fully Investigated

1. **WFP interface filtering limitation**: WFP code at `src/icmp_filter/wfp.rs:76-94` notes that interface filtering requires numeric indices but name resolution is not implemented. The actual behavior needs verification.

2. **Cross-platform compile coverage**: The plan mentions CI should cover multiple platform/feature combinations. This review did not verify if such CI exists.

3. **windows_firewall crate dependencies**: The `windows_firewall` crate uses COM. Its availability and maintenance status should be verified.

4. **eBPF bytecode distribution**: The bytecode search paths assume a specific installation layout. Runtime bytecode loading needs verification.
