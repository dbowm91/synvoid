# Filter Architecture

## 1. Purpose and Responsibility

The Filter module is now the `synvoid-filter` crate (`crates/synvoid-filter/`). The root `src/filter/` path is a thin facade; the canonical implementation lives in the dedicated crate. It provides a **generic, type-parameterized protocol filtering framework** with allowlist/denylist support and strict mode. Used for ICMP filtering and HTTP listener protocol enforcement.

**Core Responsibilities:**
- Generic protocol matching with type parameters
- Allowlist and denylist filtering
- Strict mode for unknown protocol handling
- Port-based protocol expectation enforcement

---

## 2. Key Data Structures

```rust
pub trait FilterAction: Clone + PartialEq + Eq + Debug + Send + Sync + 'static {
    fn is_allow(&self) -> bool;
    fn is_drop(&self) -> bool;
}

pub trait Protocol: Clone + PartialEq + Eq + Debug + Send + Sync + 'static {
    fn as_str(&self) -> &str;
    fn from_str(s: &str) -> Self;
}

pub struct BaseFilterConfig<P: Protocol> {
    pub enabled: bool,
    pub strict_mode: bool,
    pub protocol_allowlist: Vec<String>,
    pub protocol_denylist: Vec<String>,
    pub(crate) _marker: PhantomData<P>,
}

pub struct ProtocolFilterCore<P: Protocol, A: FilterAction> {
    config: BaseFilterConfig<P>,
    _marker: PhantomData<A>,
}

pub struct PortConfigBase {
    pub expected_protocol: String,
    pub action: String,
}
```

---

## 3. Public API

| Method | Description |
|--------|-------------|
| `ProtocolFilterCore::new(config)` | Constructor |
| `check(expected, detected, allow, deny) -> A` | Main filtering logic |
| `with_allowlist(protocols)` | Set allowlist |
| `with_denylist(protocols)` | Set denylist |
| `with_strict_mode(strict)` | Enable strict mode |
| `check_protocol_match(expected, detected) -> bool` | Standalone helper |

---

## 4. Public API — Additional Types

| Type | Description |
|------|-------------|
| `PortConfigBase` | Maps expected protocol to action for a given port |

---

## 5. Integration Points

- **ICMP Filter**: Protocol detection and enforcement for ICMP packets
- **HTTP Listener**: Protocol expectation for incoming connections
- **Listener**: Shared configuration with `ListenerConfigBase`

---

## 6. Key Implementation Details

- **Generic Design**: Type-parameterized over protocol and action types
- **Strict Mode**: When enabled, unknown protocols are denied by default
- **Allow/Deny Priority**: Denylist checked first, then allowlist (deny takes precedence for security)
- **Zero-Cost Abstractions**: `PhantomData` for compile-time type safety
