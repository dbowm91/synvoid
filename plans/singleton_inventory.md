# Singleton Inventory - Priority 4: Remove Process-Wide Singletons

**Created**: 2026-05-02
**Status**: Documentation only - no code changes made

---

## Overview

This document inventories all process-wide singletons in the MaluWAF codebase, classifies them according to their impact on testability, reload behavior, and multi-profile isolation, and outlines the refactoring approach needed.

---

## Inventory

### Category Key
- **ACCEPTABLE**: Immutable or process-global by nature (metrics, caches, constants)
- **QUESTIONABLE**: Request/lifecycle-sensitive components that should be explicit
- **NEEDS_REFACTORING**: Component is request-sensitive and requires explicit context

---

### 1. Request-Sensitive Singletons (NEEDS_REFACTORING)

#### 1.1 Threat Intelligence Manager
- **Location**: `src/waf/mod.rs:108-118`
- **Static**: `static THREAT_INTEL: OnceLock<Arc<ThreatIntelligenceManager>>`
- **Setter**: `set_threat_intel(ti: Arc<ThreatIntelligenceManager>)`
- **Getter**: `get_threat_intel() -> Option<Arc<ThreatIntelligenceManager>>`
- **Initialized by**: `worker/unified_server.rs:463, 574, 901, 1071`
- **Used by**: WAF core, attack detection, mesh threat sync
- **Problem**: Request-serving code depends on hidden global state. Tests leak state. Reload cannot replace cleanly.
- **Refactoring needed**: Thread through `RuntimeSnapshot` or `RequestServices` context struct

#### 1.2 YARA Rules Manager
- **Location**: `src/waf/mod.rs:109, 120-126`
- **Static**: `static YARA_RULES: OnceLock<Arc<YaraRulesManager>>`
- **Setter**: `set_yara_rules(yr: Arc<YaraRulesManager>)`
- **Getter**: `get_yara_rules() -> Option<Arc<YaraRulesManager>>`
- **Initialized by**: `worker/unified_server.rs:965`
- **Used by**: `upload/mod.rs` (reload_yara_rules_if_needed), malware scanner
- **Problem**: Upload validator accesses YARA rules via global, not via injection
- **Refactoring needed**: Pass YaraRulesManager handle to UploadValidator at construction

#### 1.3 Upload Validator
- **Location**: `src/waf/mod.rs:110, 128-134`
- **Static**: `static UPLOAD_VALIDATOR: OnceLock<Arc<UploadValidator>>`
- **Setter**: `set_upload_validator(uv: Arc<UploadValidator>)`
- **Getter**: `get_upload_validator() -> Option<Arc<UploadValidator>>`
- **Initialized by**: `worker/unified_server.rs:463`
- **Used by**: HTTP request handling, WAF core
- **Problem**: Component holds mutable state (malware scanner, config) but is globally accessible
- **Refactoring needed**: Pass to request context at construction; UploadValidator should be owned by RuntimeSnapshot

#### 1.4 Global Plugin Manager
- **Location**: `src/plugin/global.rs:9-10, 168-170`
- **Static**: `static GLOBAL_PLUGIN_MANAGER: LazyLock<Arc<GlobalPluginManager>>`
- **Getter**: `get_global_plugin_manager() -> Arc<GlobalPluginManager>`
- **Initialized by**: Static initialization (LazyLock)
- **Used by**: Plugin loading, WASM execution, admin handlers
- **Problem**: Memory budget is process-wide. Plugin state leaks between test cases. No reload capability.
- **Refactoring needed**: `GlobalPluginManager` should be owned by RuntimeSnapshot with profile-specific limits

#### 1.5 Spin Apps Manager
- **Location**: `src/spin/handler.rs:236-241`
- **Static**: `static SPIN_APPS_MANAGER: LazyLock<Arc<SpinAppsManager>>`
- **Getter**: `get_global_spin_apps_manager() -> Arc<SpinAppsManager>`
- **Initialized by**: Static initialization (LazyLock)
- **Used by**: HTTP server (request path at line 1979), admin handlers (spin.rs)
- **Problem**: Serverless functions registered globally, state leaks between tests
- **Refactoring needed**: Move to runtime-scoped management; thread through request context

---

### 2. Lifecycle Singletons (QUESTIONABLE)

#### 2.1 Global Buffer Pool
- **Location**: `src/buffer/pool.rs:348-349`
- **Static**: `pub static GLOBAL_POOL: LazyLock<Arc<BufferPool>>`
- **Getter**: `GLOBAL_POOL.acquire_*` functions
- **Initialized by**: Static initialization (LazyLock)
- **Used by**: Throughout codebase for memory allocation
- **Problem**: Performance-critical path relies on global. Cannot run multiple isolated pools.
- **Verdict**: **ACCEPTABLE** for performance. At 1000K RPS, per-request allocation is the enemy. Having a single global pool is a valid optimization. Mark as explicitly global with comments.

#### 2.2 Global Pool Registry (Upstream)
- **Location**: `src/upstream/pool.rs:8-9`
- **Static**: `static GLOBAL_POOL_REGISTRY: LazyLock<DashMap<String, Arc<UpstreamPool>>>`
- **Getter**: `get_global_pool(backend_url: &str) -> Option<Arc<UpstreamPool>>`
- **Used by**: Proxy routing, upstream connection pooling
- **Problem**: Per-backend pool is process-wide. Cannot isolate pools per profile.
- **Verdict**: **QUESTIONABLE** - See Priority 4 in plan.md for upstream TLS client ownership rework. This is already tracked separately.

#### 2.3 Serverless Registry
- **Location**: `src/serverless/registry.rs:103-108`
- **Static**: `static SERVERLESS_REGISTRY: LazyLock<Arc<ServerlessRegistry>>`
- **Getter**: `get_global_serverless_registry() -> Arc<ServerlessRegistry>`
- **Initialized by**: Static initialization (LazyLock)
- **Used by**: Serverless function registration, invocation tracking
- **Problem**: Function metadata and invocation stats are process-wide. Test contamination.
- **Verdict**: **NEEDS_REFACTORING** - Should be scoped to runtime/profile, not global

#### 2.4 Unified Honeypot Manager
- **Location**: `src/honeypot_unified/mod.rs:9`
- **Static**: `static UNIFIED_HONEYPOT_MANAGER: OnceLock<UnifiedHoneypotManager>`
- **Problem**: Threat level management is process-wide
- **Verdict**: **QUESTIONABLE** - Should be owned by runtime, not process global

#### 2.5 Record Store Global (DHT)
- **Location**: `src/mesh/mod.rs:158-168`
- **Static**: `static RECORD_STORE_GLOBAL: LazyLock<RwLock<Option<Arc<RecordStoreManager>>>>`
- **Getter/Setter**: `set_global_record_store()`, `get_global_record_store()`
- **Problem**: DHT record store is process-wide singleton
- **Verdict**: **QUESTIONABLE** - Should be owned by mesh subsystem lifecycle

#### 2.6 WASM Distribution Manager
- **Location**: `src/mesh/wasm_dist.rs:152-159`
- **Static**: `static WASM_DIST_MANAGER: LazyLock<Arc<RwLock<Option<Arc<WasmDistManager>>>>>` with set/get
- **Verdict**: **QUESTIONABLE** - Lifecycle-managed, but access via globals is awkward

---

### 3. Acceptable Process-Globals (ACCEPTABLE)

#### 3.1 Metrics Collection
- **Location**: `src/metrics/collection.rs:11-118`
- **Type**: All `LazyLock<AtomicU64>` or `LazyLock<DashMap<String, AtomicU64>>`
- **Purpose**: Process-wide metrics (counters, latencies, DHT stats)
- **Verdict**: **ACCEPTABLE** - Metrics are inherently process-global. No mutable state beyond counters.

#### 3.2 Static Regex Caches
- **Location**: Multiple files:
  - `src/mesh/proxy.rs:24` - WHITELIST_REGEX_CACHE (DashMap<String, Option<Regex>>)
  - `src/http/server.rs:68` - WHITELIST_REGEX_CACHE (immutable regex lookup)
  - `src/http/server.rs:71` - IMAGE_PROTECTION_REGEX
  - `src/http/server.rs:85` - IMAGE_POISON_CACHE
  - `src/proxy/headers.rs:43,46,54` - HOP_BY_HOP_HEADERS_SET, STATIC_HEADERS_TO_FILTER, HOP_BY_HOP_HEADER_NAMES
  - `src/waf/rule_feed.rs:35` - RULE_PATTERN_STORE
  - `src/waf/attack_detection/open_redirect.rs:11` - REDIRECT_PARAM_AC (AhoCorasick)
  - `src/waf/attack_detection/rfi.rs:13` - IP_REGEX
- **Purpose**: Immutable compiled patterns with bounded size
- **Verdict**: **ACCEPTABLE** - Compiled regex is deterministic and bounded. Does not hold request-specific state.

#### 3.3 Hop-by-Hop Header Sets
- **Location**: `src/proxy/headers.rs:43-54`
- **Type**: `LazyLock<AHashSet<&'static str>>` and `LazyLock<AHashSet<HeaderName>>`
- **Purpose**: Header filtering constants
- **Verdict**: **ACCEPTABLE** - Compile-time constants

#### 3.4 Honeypot Pattern Regexes
- **Location**: `src/honeypot_port/threat_intel.rs:7-27`
- **Type**: Multiple `LazyLock<Regex>` for attack pattern matching
- **Purpose**: Honeypot detection patterns (immutable)
- **Verdict**: **ACCEPTABLE** - Compiled patterns, bounded memory

#### 3.5 Nonce Cache
- **Location**: `src/process/ipc_signed.rs:77`
- **Type**: `LazyLock<Mutex<NonceCache>>`
- **Purpose**: IPC replay protection (bounded cache)
- **Verdict**: **ACCEPTABLE** - Bounded cache with TTL eviction

#### 3.6 Upstream Client Cache
- **Location**: `src/http_client/mod.rs:65`
- **Type**: `LazyLock<Cache<UpstreamClientKey, HttpClient>>`
- **Purpose**: HTTP client connection reuse
- **Verdict**: **ACCEPTABLE** - Bounded cache with eviction

---

## Refactoring Approach

### 1. Create RequestServices Context Struct

```rust
// src/waf/request_services.rs (new file)
pub struct RequestServices {
    pub threat_intel: Option<Arc<ThreatIntelligenceManager>>,
    pub upload_validator: Option<Arc<UploadValidator>>,
    pub yara_rules: Option<Arc<YaraRulesManager>>,
    pub plugin_manager: Option<Arc<GlobalPluginManager>>,
    pub serverless_registry: Option<Arc<ServerlessRegistry>>,
}

impl Default for RequestServices {
    fn default() -> Self {
        Self {
            threat_intel: None,
            upload_validator: None,
            yara_rules: None,
            plugin_manager: None,
            serverless_registry: None,
        }
    }
}
```

### 2. RuntimeSnapshot Owns Services

Each `RuntimeSnapshot` (or similar concept) should own its `RequestServices`:

```rust
pub struct RuntimeSnapshot {
    // ... existing fields ...
    services: RequestServices,
}
```

### 3. Thread Services Through Request Path

Avoid massive function signatures by:
- Using `Arc<RequestServices>` where appropriate
- Adding services to existing context structs (e.g., `WafCore::check_request` already has context)
- Cloning `Arc` handles only at snapshot construction, not per-request

### 4. Deprecate Old Accessors

```rust
// src/waf/mod.rs

/// DEPRECATED: Use RuntimeSnapshot.services instead
/// Compatibility accessor - will be removed after full refactoring
pub fn get_threat_intel() -> Option<Arc<ThreatIntelligenceManager>> {
    THREAT_INTEL.get().cloned()
}
```

### 5. Fix UploadValidator YARA Dependency

Currently `UploadValidator::reload_yara_rules_if_needed()` calls `crate::waf::get_yara_rules()` globally. This should be:

```rust
impl UploadValidator {
    pub fn new(config: UploadConfig, yara_rules: Arc<YaraRulesManager>) -> Result<Self, ...> {
        // ... store yara_rules as field ...
    }
}
```

### 6. Profile-Specific Memory Budgets

`GlobalWasmMemoryBudget` and `GlobalPluginManager` should be constructed per-runtime with profile-specific limits, not global.

---

## Test Isolation Requirements

After refactoring, tests should:

1. Construct fresh `RequestServices` per test case
2. Run tests in parallel without singleton contamination
3. Support multiple runtime contexts with different service configurations
4. Allow `threat_intel: None` for core profile without dummy global initialization

---

## Remaining Work (Not Implemented)

This document is **inventory only**. The actual refactoring steps are:

1. Create `RequestServices` context struct
2. Add to `RuntimeSnapshot` or equivalent
3. Thread through request paths (HTTP, WAF core, proxy)
4. Remove global setters/getters progressively
5. Fix `UploadValidator` to accept `YaraRulesManager` at construction
6. Add tests for isolated runtime contexts

---

## References

- Plan: `plans/plan.md` Priority 4 section (lines 2049-2134)
- Related: Priority 4 in upstream TLS client ownership (lines 361, 895)
- Related: Priority 4 in anomaly scoring (lines 1191, 1664)