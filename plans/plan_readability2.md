# Code Readability & Verbosity Improvement Plan

> **Note:** This plan complements [plan_readability.md](./plan_readability.md). That plan focuses on specific code duplication patterns (IP blocking, DNSKEY construction, etc.). This plan addresses structural improvements (derive macros, module sizes, dead code).

## Executive Summary

This plan addresses opportunities to improve code readability, reduce verbosity, and eliminate code duplication in the MaluWAF codebase. The codebase contains ~127,682 lines of Rust code across 100+ modules, with several files exceeding 2,000 lines and significant repetition in common patterns.

---

## Phase 1: Quick Wins (Low Risk, High Impact)

### 1.1 Enable `#[derive(Default)]` for Suitable Types

**Current State**: 278 manual `impl Default for` blocks throughout the codebase.

**Target**: Convert eligible types to use `#[derive(Default)]`.

**Eligibility Criteria**:
- All fields have types that implement `Default`
- No custom initialization logic required
- No field-level validation

**Files to Audit** (representative sample):
- `src/mesh/config.rs` - 15+ Default impls (lines 91, 133, 168, 221, 293, 384, 478, 524, 556, 1034, 1124, 1187, 1215, 1251)
- `src/config/dns.rs` - 8 Default impls
- `src/waf/ratelimit.rs` - 4 Default impls
- Various other config and module files

**Estimated Impact**: 30-50% of existing Default impls can derive automatically.

**Risk**: Low - mechanical change with compiler verification.

---

### 1.2 Prune Unused Derive Traits

**Current State**: ~1,177 `#[derive(...)]` statements; many with unnecessary traits.

**Audit Checklist**:
| Derive Trait | Remove If... |
|--------------|--------------|
| `Clone` | Type never cloned |
| `Serialize` | Not serialized to JSON/TOML/network |
| `Deserialize` | Not deserialized from config/JSON |
| `Default` | Manual impl exists or not needed |
| `Debug` | Only used in `#[cfg(test)]` |
| `PartialEq/Eq` | Only used for serialization |

**Methodology**:
1. Search for each derive trait pattern
2. Verify actual usage via grep
3. Remove unused traits incrementally

**Estimated Impact**: 100-200 trait derivations can be removed.

**Risk**: Low - compiler will catch errors.

---

### 1.3 Remove Dead Code

**Identified Dead Code** (from AGENTS.md):

| File | Lines | Status |
|------|-------|--------|
| `src/http/handler.rs` | 1,657 | Not in module tree - has compile error |
| `src/http/range.rs` | 194 | Not in module tree |

**Recommended Actions**:
1. Delete `src/http/handler.rs` and `src/http/range.rs` if truly unused
2. Or fix compilation and integrate into module tree

**Risk**: Low - code is currently broken/not integrated.

---

### 1.4 Consolidate Result Type Aliases

**Current State**: 8+ different Result type aliases across modules:
- `process/ipc.rs`: `BoxResult<T>` (line 12)
- `dns/resolver.rs`: `ResolverResult<T>` (line 126)
- `dns/recursive.rs`: `RecursiveDnsResult<T>` (line 52)
- `error.rs`: `WafResult<T>` (line 50)
- `tcp/protocol.rs`: `ProtocolResult`
- `udp/protocol.rs`: `UdpProtocolResult`
- `streaming/bidirectional.rs`: `ProxyResult`
- `icmp_filter/error.rs`: `Result<T>`

**Proposed Consolidation**:
1. Use `WafResult<T>` from `error.rs` as the primary alias
2. Add `From` implementations for module-specific errors
3. Deprecate other aliases with clear migration path

**Affected Files** (estimated 20-30 files):
- Convert to use `crate::error::WafResult<T>`
- Add `impl From<ModuleError> for WafError` where needed

**Risk**: Low-Medium - requires cross-module coordination but is mechanical.

---

### 1.5 Simplify Constructor Patterns

**Current State**: 84 `pub fn new() -> Self` methods, many identical to `Self::default()`.

**Pattern Analysis**:
```rust
// Common pattern 1: Direct delegation to Default
pub fn new() -> Self {
    Self::default()
}

// Common pattern 2: Field-by-field with defaults
pub fn new() -> Self {
    Self {
        field1: Default::default(),
        field2: value,
        ..Default::default()
    }
}
```

**Recommended Actions**:
1. Prefer `#[derive(Default)]` + `SomeStruct::default()` over manual `new()`
2. Use struct update syntax `..Default::default()` where applicable
3. Reserve `new()` for non-trivial construction with validation

**Risk**: Low - compiler-verified.

---

## Phase 2: Module Organization (Medium Risk)

### 2.1 Split Oversized Modules

#### Target: `src/dns/dnssec.rs` (2,152 lines)

**Current Structure**: Single file containing DNSSEC functionality.

**Recommended Split**:
```
src/dns/dnssec/
├── mod.rs          # Re-exports and public API
├── signing.rs      # Zone signing logic
├── validation.rs   # Signature verification
├── keys.rs        # Key management
├── algorithms.rs  # Algorithm implementations
├── nsec.rs        # NSEC/NSEC3 logic
└── errors.rs      # DNSSEC-specific errors
```

**Priority**: High - file exceeds 2,000 lines.

**Risk**: Medium - requires careful API preservation.

---

#### Target: `src/mesh/protocol_proto_encode.rs` (1,989 lines)

**Current Structure**: Protobuf serialization code alongside decode file.

**Status**: NOT generated at build time - these are manually maintained checked-in files. The `build.rs` only compiles `.proto` definitions via tonic-build; the encode/decode are written manually.

**Recommended Action**:
1. Keep as-is for now - these serve as a serialization layer
2. Consider extracting to a proc-macro in the future if maintenance burden increases

**Priority**: Low - appears stable and manually maintained.

**Risk**: Low - stable existing code.

---

#### Target: `src/mesh/transport.rs` (1,889 lines)

**Recommended Split**:
```
src/mesh/transport/
├── mod.rs              # Main coordinator
├── connection.rs       # Peer connection management
├── routing.rs          # Routing logic
├── dns.rs              # DNS integration
├── global.rs           # Global node handling
├── org.rs              # Organization handling
└── peer.rs             # Peer discovery
```

**Priority**: High - actively maintained code.

**Risk**: Medium - core mesh functionality.

---

#### Target: `src/config/site.rs` (1,831 lines)

**Recommended Split**:
```
src/config/site/
├── mod.rs           # Re-exports
├── upstream.rs     # Upstream configuration
├── security.rs     # Security settings
├── proxy.rs        # Proxy settings
└── validation.rs   # Site config validation
```

**Priority**: Medium - configuration code.

**Risk**: Medium - affects startup and runtime behavior.

---

### 2.2 Extract Repeated Patterns into Helpers

#### Pattern A: Arc<RwLock<T>> Boilerplate

**Current**: ~204 instances of `Arc::new(RwLock::new(...))` pattern throughout codebase.

**Examples** (widespread usage):
- `src/waf/rule_feed.rs` - 5 instances (current_version, downloaded_rules, etc.)
- `src/mesh/transport.rs` - 8 instances (running, auth_keys, etc.)
- `src/mesh/wireguard_mesh.rs` - 3 instances
- `src/main.rs` - 1 instance (shared_config)
- `src/dns/server/mod.rs` - 5 instances (zones, zone_trie, etc.)
- Many more throughout waf/, mesh/, admin/ modules

**Proposed Helper**:
```rust
// In src/utils/sync.rs
pub fn new_arc_rwlock<T: Default>(value: T) -> Arc<RwLock<T>> {
    Arc::new(RwLock::new(value))
}
```

**Priority**: Low - cosmetic improvement, not a real issue given widespread use.

**Risk**: Very Low.

---

#### Pattern B: Similar Error Transformations

**Current**: Repeated `.map_err(|e| format!("{}: {}", context, e))` patterns.

**Existing Solution** (in `src/error.rs`):
```rust
pub trait WafErrorExt<T> {
    fn waf_internal(self, ctx: &str) -> WafResult<T>;
    fn waf_config(self, ctx: &str) -> WafResult<T>;
    fn waf_upstream(self, ctx: &str) -> WafResult<T>;
}
```

**Recommended Action**:
1. Expand usage of `WafErrorExt` trait
2. Add more context methods as needed

**Priority**: Low - existing solution available.

**Risk**: Very Low.

---

#### Pattern C: Config Construction with Defaults

**Current**: Many config structs with identical patterns:
```rust
impl Default for FooConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 30,
            max_retries: 3,
            ..Default::default()
        }
    }
}
```

**Recommended Action**:
1. Use `#[derive(Default)]` with `#[serde(default)]` on fields
2. Remove manual `impl Default` where possible

**Priority**: Medium.

**Risk**: Low.

---

## Phase 3: Architectural Improvements (Higher Risk)

### 3.1 Reduce Arc/RwLock Boilerplate

**Current Pattern**: ~204 instances of `Arc::new(RwLock::new(...))` pattern throughout codebase.

**Proposed Approach**:
1. Use builder pattern for complex construction
2. Add `#[derive(Default)]` for simpler types
3. Create type aliases for common combinations:
   ```rust
   pub type ArcRwLock<T> = Arc<RwLock<T>>;
   ```

**Risk**: Low - type alias change.

---

### 3.2 Standardize Error Handling

**Current State**: Mix of:
- `thiserror`-based errors (`WafError`)
- `Box<dyn Error>` returns
- Custom error enums per module

**Proposed Approach**:
1. Use `WafError` as primary error type
2. Add `From` implementations for each module error
3. Standardize on `WafResult<T>` return types

**Example**:
```rust
// In module's error.rs
#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Operation failed: {0}")]
    Operation(String),
}

impl From<ModuleError> for WafError {
    fn from(e: ModuleError) -> Self {
        WafError::Internal(e.to_string())
    }
}
```

**Risk**: Medium - requires careful error propagation review.

---

### 3.3 Builder Pattern for Complex Types

**Target Types**:
- Config structs with 10+ fields
- Manager types requiring multiple setup steps

**Example Transformation**:
```rust
// Before
pub fn new(
    field1: Type1,
    field2: Type2,
    field3: Type3,
    // ... 10 more fields
) -> Self {
    Self { field1, field2, field3, ... }
}

// After (builder)
impl TypeName {
    pub fn builder() -> TypeNameBuilder {
        TypeNameBuilder::default()
    }
}

pub struct TypeNameBuilder {
    field1: Type1,
    field2: Type2,
    // ... with Default::default() values
}

impl Default for TypeNameBuilder {
    fn default() -> Self { /* defaults */ }
}

impl TypeNameBuilder {
    pub fn field1(mut self, v: Type1) -> Self { self.field1 = v; self }
    pub fn build(self) -> TypeName { TypeName { ... } }
}
```

**Risk**: Medium - requires API changes.

---

## Prioritized Action Items

### Immediate (1-2 hours each)

| # | Action | Files Affected | Risk |
|---|--------|----------------|------|
| 1.1 | Delete dead code | `http/handler.rs`, `http/range.rs` | Very Low |
| 1.2 | Enable derive for simple configs | `mesh/config.rs` | Low |
| 1.3 | Remove unused derive traits | Multiple files | Low |
| 1.4 | Simplify trivial `new()` methods | Multiple files | Low |

### Short-term (half-day each)

| # | Action | Files Affected | Risk |
|---|--------|----------------|------|
| 2.1 | Split `dns/dnssec.rs` | `dns/dnssec/` | Medium |
| 2.2 | Split `mesh/transport.rs` | `mesh/transport/` | Medium |
| 2.3 | Consolidate Result types | 20-30 files | Low-Medium |
| 2.4 | Add builder to complex configs | `config/site.rs` | Medium |

### Medium-term (full-day each)

| # | Action | Files Affected | Risk |
|---|--------|----------------|------|
| 3.1 | Split remaining large files | Various | Medium |
| 3.2 | Standardize error handling | Multiple modules | Medium |
| 3.3 | Add builder pattern | Config modules | Medium |

---

## Risk Assessment Matrix

| Risk Level | Criteria | Actions in This Plan |
|------------|----------|---------------------|
| **Very Low** | Compiler-verified, no logic changes | Delete dead code, type aliases |
| **Low** | Mechanical changes, compiler-verified | Derive macros, trait pruning |
| **Medium** | Cross-module coordination, API changes | Module splits, builder patterns |
| **High** | Behavioral changes, potential runtime impact | None planned in this phase |

---

## Notes

- **Protocol Proto Files**: `protocol_proto_encode.rs` and `protocol_proto_decode.rs` are manually maintained checked-in code, NOT generated at build time. The `build.rs` only uses tonic-build to compile `.proto` definitions.
- **Dead Code**: `src/http/handler.rs` (1,657 lines) and `src/http/range.rs` (194 lines) exist but are NOT in the module tree (`src/http/mod.rs` only declares: early_parse, headers, server). These files have compilation errors and should be removed or fixed.
- **Feature Flags**: Several modules have conditional compilation (`#[cfg(feature = "...")]`). Ensure changes respect feature boundaries.
- **Testing**: Full test suite (`cargo test`) should pass after each phase.
- **Clippy**: Run `cargo clippy -- -D warnings` after changes to catch regressions.
- **Complementary Plan**: See [plan_readability.md](./plan_readability.md) for specific code duplication patterns (IP blocking, DNSKEY construction, etc.).

---

## Files Requiring Special Attention

| File | Lines | Issue | Recommended Action |
|------|-------|-------|-------------------|
| `dns/dnssec.rs` | 2,152 | Exceeds size threshold | Split into submodules |
| `mesh/protocol_proto_encode.rs` | 1,989 | Manually maintained proto serialization | Keep as-is for now |
| `mesh/transport.rs` | 1,889 | Exceeds size threshold | Split into submodules |
| `http/handler.rs` | 1,657 | Dead code (not in module tree) | Delete |
| `http/range.rs` | 194 | Dead code (not in module tree) | Delete |
| `config/site.rs` | 1,831 | Exceeds size threshold | Split |
| `process/manager.rs` | 1,697 | Large but functional | Review for extraction |
| `http/server.rs` | 1,589 | Large but functional | Review for extraction |
| `mesh/topology.rs` | 1,628 | Large but functional | Review for extraction |

---

## Verification Commands

After each phase, run:

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Run tests
cargo test

# Check module sizes (for tracking)
wc -l src/**/*.rs | sort -rn | head -20
```

---

*Plan Version: 1.0*
*Created: 2026-03-27*
