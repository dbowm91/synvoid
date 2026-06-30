# Plugin Milestone 2 Phase 7: Host API Sub-Capabilities

## Goal

Replace coarse plugin host authority with narrow, auditable, default-deny sub-capabilities. A plugin should receive only the exact host operations it needs: specific mesh read prefixes, event topics, threat-check authority, bounded metrics emission, and future filesystem/network/persistence access under explicit allowlists.

Milestone 1 made plugin authority mandatory. Phase 7 makes that authority granular enough for production defense-in-depth.

## Problem Statement

The current plugin capability model has useful top-level flags such as `Mesh`, `Metrics`, `Persistence`, `FilesystemRead`, `FilesystemWrite`, and `Network`. That is a good base, but coarse capabilities are too broad for production once host APIs become more useful.

Examples:

- `Mesh` may currently cover DHT reads, threat checks, and event emission.
- A plugin that needs `threat_indicator:` lookups should not automatically read `dns_zone:` or emit arbitrary mesh topics.
- A plugin that emits metrics should not create unbounded label cardinality.
- Future filesystem/network/persistence host functions must not be bolted on as broad ambient authority.

This phase introduces scoped sub-capabilities with stable policy enforcement and tests.

## Design Principles

1. Default deny at every host API surface.
2. Capability checks should be semantic, not just boolean.
3. Prefix/topic/host/path allowlists should be normalized before comparison.
4. Production policies should avoid wildcard grants by default.
5. Host API failures should return stable ABI errors and record bounded metrics.
6. Policy should be carried in `EffectivePluginPolicy`, not hidden in global runtime defaults.

## Workstream 1: Split Mesh Authority into Sub-Capabilities

### Target

Replace the coarse `Mesh` host check with scoped mesh permissions.

Suggested policy type:

```rust
#[derive(Debug, Clone, Default)]
pub struct PluginMeshPolicy {
    pub allow_threat_check: bool,
    pub dht_read_prefixes: Vec<String>,
    pub dht_write_prefixes: Vec<String>,
    pub event_emit_topics: Vec<String>,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_event_bytes: usize,
}
```

The existing `PluginCapability::Mesh` can remain as a top-level gate, but it should not grant all mesh operations by itself. It should mean only that mesh sub-policy may be evaluated.

### Implementation Steps

1. Add `PluginMeshPolicy` to manifest/effective policy plumbing.
2. Extend manifest schema with a `[mesh]` section or a nested capabilities section:

```toml
[capabilities]
mesh = true

[mesh]
allow_threat_check = true
dht_read_prefixes = ["threat_indicator:", "ip_reputation:"]
dht_write_prefixes = []
event_emit_topics = ["plugin.audit", "plugin.signal"]
max_key_bytes = 512
max_value_bytes = 8192
max_event_bytes = 4096
```

3. Preserve backwards compatibility carefully:

- If `mesh = false`, all mesh APIs deny.
- If `mesh = true` but no `[mesh]` sub-policy exists, production default should still deny sensitive DHT prefixes and deny arbitrary event emission.
- Development may warn and allow limited behavior only if explicitly configured.

4. Refactor host functions:

- `mesh_query_dht`: require `mesh = true` and key prefix in `dht_read_prefixes`.
- Future `mesh_write_dht`: require `mesh = true` and key prefix in `dht_write_prefixes`.
- `mesh_check_threat`: require `mesh = true` and `allow_threat_check = true`.
- `mesh_emit_event`: require `mesh = true` and topic prefix in `event_emit_topics`.

5. Normalize prefix checks:

- Reject empty prefixes in production.
- Reject `*` wildcard unless explicit unsafe/operator override.
- Use byte-prefix checks over canonical UTF-8 keys if keys are specified as UTF-8.
- Document whether prefixes are case-sensitive.

6. Add `MeshPolicyViolation` error class and metrics.

### Tests

- Plugin with `mesh = false` cannot call any mesh function.
- Plugin with `mesh = true` but no DHT prefix cannot read DHT.
- Plugin with `dht_read_prefixes = ["threat_indicator:"]` can read `threat_indicator:x` but not `dns_zone:x`.
- Plugin with threat check disabled cannot call `mesh_check_threat`.
- Plugin with event topic `plugin.audit` can emit `plugin.audit.blocked` but not `mesh.admin`.
- Empty prefix rejected in production.
- Wildcard prefix rejected unless unsafe override is explicitly set.
- Overlong key/value/event payload rejected before host call.

### Acceptance Criteria

- Mesh authority is operation-scoped.
- Event emission has topic allowlists.
- DHT reads and writes have separate prefix allowlists.
- Threat checks are separately grantable.
- Tests prove a plugin cannot use one mesh grant to access another mesh operation.

## Workstream 2: Filesystem Access Policy for Future Host Functions

### Target

Prepare filesystem policy before adding or expanding filesystem host functions. The model should support safe reads/writes without allowing symlink escapes or ambient access.

### Suggested Policy Type

```rust
#[derive(Debug, Clone, Default)]
pub struct PluginFilesystemPolicy {
    pub read_roots: Vec<PathBuf>,
    pub write_roots: Vec<PathBuf>,
    pub allow_create: bool,
    pub allow_overwrite: bool,
    pub max_read_bytes: usize,
    pub max_write_bytes: usize,
}
```

### Implementation Steps

1. Reuse or harden existing `check_filesystem_access()` logic.
2. For reads:

- canonicalize requested path;
- canonicalize allowed read roots;
- require requested canonical path starts with one allowed root;
- reject symlink escape.

3. For writes:

- canonicalization is harder because the target may not exist;
- canonicalize parent directory;
- ensure parent is inside a write root;
- reject path components containing `..` before canonicalization;
- reject symlink parent escapes;
- enforce create/overwrite policy.

4. Add future host API stubs only if needed. This phase can be policy-only if filesystem APIs are not currently exposed.
5. Add docs explicitly stating filesystem host APIs are absent or default-denied unless implemented.

### Tests

- Read inside allowed root succeeds.
- Read outside root fails.
- Read via symlink escape fails.
- Write new file inside write root succeeds if create allowed.
- Write new file fails if create denied.
- Write outside root fails.
- Write via symlink parent escape fails.
- Absolute paths are rejected unless the allowed root explicitly covers them.

### Acceptance Criteria

- Filesystem policy is ready before filesystem host APIs become broad.
- Write-to-new-file behavior is safe and tested.
- Docs do not imply filesystem access exists unless actually implemented.

## Workstream 3: Network Access Policy for Future Host Functions

### Target

Define network policy with DNS/IP normalization and no unsafe default wildcards.

### Suggested Policy Type

```rust
#[derive(Debug, Clone, Default)]
pub struct PluginNetworkPolicy {
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub allowed_cidrs: Vec<String>,
    pub deny_private_ranges: bool,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub timeout: Duration,
}
```

### Implementation Steps

1. Normalize host names to lowercase IDNA/punycode if external hostnames are supported.
2. Normalize IP literals.
3. Define whether DNS resolution happens once, per request, or through Synvoid's resolver.
4. Prevent DNS rebinding where policy is host-based but connection is IP-based.
5. Reject `*:*` in production unless an unsafe override is set.
6. Deny private/link-local/loopback ranges by default for third-party plugins.
7. Add tests for host/port matching, wildcard rejection, and private IP denial.

### Tests

- Exact host/port allowed.
- Host allowed but wrong port denied.
- Wildcard denied in production.
- Private IP denied by default.
- Hostname normalization avoids case-bypass.
- IP literal normalization avoids textual bypass.

### Acceptance Criteria

- Network policy exists before any generic outbound network plugin API is exposed.
- Production defaults are safe against wildcard and private-network access.

## Workstream 4: Persistence Policy

### Target

If plugins can persist state, persistence must be namespaced, quota-bound, and scoped to plugin/site identity.

### Suggested Policy Type

```rust
#[derive(Debug, Clone, Default)]
pub struct PluginPersistencePolicy {
    pub namespace: String,
    pub max_key_bytes: usize,
    pub max_value_bytes: usize,
    pub max_total_bytes: usize,
    pub allow_delete: bool,
    pub ttl_required: bool,
    pub max_ttl: Duration,
}
```

### Implementation Steps

1. Define storage namespace as `(site_id, plugin_name, plugin_hash)` or a documented variant.
2. Reject cross-plugin namespace access.
3. Enforce key/value/total quotas.
4. Require TTL for untrusted plugins unless operator policy allows durable storage.
5. Add metrics for quota rejections.
6. Add migration story for plugin upgrades if namespace includes binary hash.

### Tests

- Plugin cannot read another plugin's namespace.
- Plugin cannot exceed per-key size.
- Plugin cannot exceed total quota.
- TTL-required policy rejects no-TTL writes.
- Delete denied if `allow_delete = false`.

### Acceptance Criteria

- Persistence is namespaced and quota-bound.
- Plugin upgrades have an explicit namespace/migration policy.
- No unbounded durable writes from untrusted plugins.

## Workstream 5: Metrics Authority and Cardinality Bounds

### Target

Allow useful plugin metrics without unbounded cardinality or sensitive data leakage.

### Suggested Policy Type

```rust
#[derive(Debug, Clone, Default)]
pub struct PluginMetricsPolicy {
    pub allowed_metric_prefixes: Vec<String>,
    pub max_metric_name_bytes: usize,
    pub max_label_count: usize,
    pub max_label_key_bytes: usize,
    pub max_label_value_bytes: usize,
    pub allowed_label_keys: Vec<String>,
    pub denied_label_keys: Vec<String>,
}
```

### Implementation Steps

1. All plugin-emitted metric names must be prefixed, e.g. `plugin.<plugin_name>.` or an allowlisted prefix.
2. Label keys must be allowlisted or bounded to a safe set.
3. Label values must have byte limits and should avoid raw request data.
4. Deny high-cardinality labels such as IP, full URI, user-agent, cookie, authorization, unless explicitly allowed and sampled.
5. Add metrics rejection counters.
6. Update docs with allowed labels.

### Tests

- Metric name outside allowed prefix rejected.
- Too many labels rejected.
- Too-long label key/value rejected.
- Denied label key rejected.
- Raw sensitive label keys rejected by default.
- Valid metric emitted successfully.

### Acceptance Criteria

- Plugin metrics cannot create unbounded cardinality by default.
- Sensitive labels are blocked unless explicitly allowed.
- Metrics policy is documented and tested.

## Workstream 6: Manifest and Effective Policy Integration

### Target

All sub-capability policies should flow through the same authority chain established in Milestone 1.

### Implementation Steps

1. Extend `PluginManifest` with optional sections:

- `[mesh]`
- `[filesystem]`
- `[network]`
- `[persistence]`
- `[metrics]`

2. Extend `EffectivePluginPolicy` to include these policy structs.
3. Ensure missing sections default to deny.
4. Ensure global defaults cannot overgrant a manifest unless a trusted operator override explicitly does so.
5. Add `PluginInfo` / policy introspection summaries.
6. Update signing payload logic so sub-capability sections are covered by manifest hash/signature.
7. Add guardrail test that a signed manifest's sub-capability policy is included in the signing payload.

### Tests

- Missing sub-policy defaults deny.
- Manifest sub-policy grants exactly the expected operation.
- Global defaults cannot grant undeclared sub-policy.
- Signed manifest tampering in sub-policy invalidates signature.
- Policy info exposes sub-capability summaries without secrets.

### Acceptance Criteria

- Sub-capabilities are part of the signed manifest authority model.
- Effective policy includes all sub-capability decisions.
- Runtime host functions consume effective policy only, not raw globals.

## Workstream 7: Observability and Error Taxonomy

### Target

Make host API denial and failure reasons stable, bounded, and visible.

### Implementation Steps

1. Add `HostApiFailureClass`:

```rust
pub enum HostApiFailureClass {
    CapabilityDenied,
    PrefixDenied,
    TopicDenied,
    PathDenied,
    HostDenied,
    QuotaExceeded,
    PayloadTooLarge,
    Timeout,
    InvalidPointer,
    BackendUnavailable,
    InternalError,
}
```

2. Return stable ABI error codes from host functions.
3. Record metrics by plugin, host API, and failure class.
4. Avoid labels containing raw key/topic/path/host unless bounded and explicitly allowed.
5. Add audit logs for denied sensitive operations with redacted/bounded identifiers.

### Tests

- Each denial class maps to a stable ABI code.
- Metrics use bounded labels.
- Audit logs do not include raw secret/header/body values.
- Capability violation can still disable plugin according to failure policy.

### Acceptance Criteria

- Operators can distinguish denied-by-policy from backend failure.
- Metrics remain cardinality-bounded.
- Host API failures integrate with plugin failure state where appropriate.

## Required Validation Commands

```bash
cargo fmt --all -- --check
cargo clippy -p synvoid-plugin-runtime --all-targets -- -D warnings
cargo test -p synvoid-plugin-runtime
cargo test --test plugin_capability_boundary_guard
cargo test --test plugin_signature_policy_guard
cargo test --test manifest_authority_wiring
cargo test --test manifest_authority_load_path_guard
cargo test --test abi_memory_boundary_guard
```

Add new host API policy guard tests to CI.

## Completion Definition

This phase is complete when:

- Mesh access is split into operation-scoped sub-capabilities.
- DHT prefix, event topic, and threat-check permissions are separately enforced.
- Filesystem, network, persistence, and metrics policies are default-deny and ready before broad APIs are exposed.
- Sub-capability policy is part of the effective policy and signed manifest authority chain.
- Host API denials return stable ABI codes and bounded observability signals.
- Tests prove one host authority grant cannot be used to reach another host authority surface.
