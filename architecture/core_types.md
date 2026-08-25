# Core Types (`synvoid-core`)

## 1. Purpose and Responsibility

`crates/synvoid-core` provides **dependency-light shared types** used across multiple SynVoid subsystems. It intentionally avoids heavy dependencies (tokio, hyper, axum, rustls, openraft, wasmtime, yara-x, rusqlite, quinn) so that any crate can depend on it without pulling infrastructure into the request path.

It is the most-depended-on domain crate after `synvoid-config` (13 direct dependents).

## 2. Modules

| Module | Contents |
|--------|----------|
| `admin_mutation` | `AdminMutationResult`, `AdminMutationAuthority` — typed results for all mutating admin endpoints; compat paths use `CompatibilityLegacy` |
| `block_store` | Shared block-store types: `BlockProvenanceKind`, provenance records consumed by `synvoid-block-store` |
| `drain` | Drain-state primitives shared between supervisor and workers |
| `error` | Common error type |
| `ids` | Identifier types (site ID, worker ID) |
| `metrics` | Metric type contracts shared across crates |
| `net` | Network address/parsing helpers |
| `request` | Minimal request-context types for trait signatures |
| `routing` | Routing types shared by proxy/router consumers |
| `streaming_waf` | Types for streaming WAF body scanning contracts |
| `time` | `current_timestamp_secs()`, `current_timestamp_millis()` — canonical u64 Unix time helpers |
| `url` | URL normalization/validation utilities |
| `verdict` | Verdict types shared between WAF decision points |

## 3. Role in the Architecture

- **Trait payload types**: Narrow traits in `synvoid-waf::traits` and composition roots exchange these types across crate boundaries.
- **Admin authority**: `admin_mutation.rs` (~500 lines) is the authority model referenced by the guard-enforced rule "mutating endpoints return typed `AdminMutationResult`" (see [`admin_control_plane_authority.md`](./admin_control_plane_authority.md)).
- **Provenance**: `BlockProvenanceKind` (`LegacyUnknown` only for compat/tests/mocks) lives here so both WAF-side traits and the block store agree on provenance semantics (see [`blocklist_provenance_preservation.md`](./blocklist_provenance_preservation.md)).
- **Time**: All u64 Unix timestamps should come from here or `synvoid_utils::ip_utils` — never hand-rolled `SystemTime` math.

## 4. Boundaries

- Must stay dependency-light; new dependencies require justification (it sits below nearly every other crate).
- Request-path code may use it freely; it contains no I/O, no locks on hot paths, no async runtime coupling.

## 5. Related Docs

- [`request_path_capability_boundary.md`](./request_path_capability_boundary.md)
- [`admin_control_plane_authority.md`](./admin_control_plane_authority.md)
- [`block_store_deep_dive.md`](./block_store_deep_dive.md)
