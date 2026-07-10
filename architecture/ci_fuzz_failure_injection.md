# CI, Fuzzing, and Failure Injection

Architecture doc for Phase 8: profile CI matrix, fuzz target inventory, and failure-injection test seams.

## Fuzz Target Inventory

| Target | Input type | Current status | Runtime bound | Owner crate | Priority |
|--------|------------|----------------|---------------|-------------|----------|
| `fuzz_attack_detection` | `&[u8]` → synthetic HTTP method/path/query | Existing | 1s smoke / manual long | `synvoid` (waf) | High |
| `fuzz_early_parse` | `&[u8]` → raw HTTP request bytes | Existing | 1s smoke / manual long | `synvoid` (http) | High |
| `fuzz_ipc` | `&[u8]` → IPC message postcard bytes | Existing | 1s smoke / manual long | `synvoid` (process) | High |
| `fuzz_serialization` | `&[u8]` → postcard serialized types | Existing | 1s smoke / manual long | `synvoid` (serialization) | Medium |
| `fuzz_serialization_new` | `&[u8]` → postcard serialized types | Existing | 1s smoke / manual long | `synvoid` (serialization) | Medium |
| `fuzz_protocol_proto_decode` | `&[u8]` → protobuf mesh bytes | Existing | 1s smoke / manual long | `synvoid` (mesh) | High |
| `fuzz_raft_commit_notification` | `&[u8]` → protobuf MeshMessage | Existing | 1s smoke / manual long | `synvoid` (mesh) | High |
| `fuzz_raft_response` | `&[u8]` → protobuf MeshMessage | Existing | 1s smoke / manual long | `synvoid` (mesh) | High |
| `dns_message_decode` | `&[u8]` → DNS wire-format bytes | Existing | 1s smoke / manual long | `synvoid` (dns) | High |
| `plugin_manifest` | `&[u8]` → TOML manifest bytes | Existing | 1s smoke / manual long | `synvoid-plugin-runtime` | High |
| `http_path_normalization` | `&[u8]` → URL-encoded path bytes | Existing | 1s smoke / manual long | `synvoid` (utils) | High |
| `blocklist_event_decode` | `&[u8]` → JSON BlocklistEvent | **New** | 1s smoke / manual long | `synvoid-core` | High |
| `blocklist_snapshot_decode` | `&[u8]` → JSON BlocklistSnapshotChunk | **New** | 1s smoke / manual long | `synvoid-core` | High |
| `admin_mutation_result_decode` | `&[u8]` → JSON AdminMutationResult | **New** | 1s smoke / manual long | `synvoid-core` | Medium |
| `http_header_normalization` | `&[u8]` → WAF input normalizer | **New** | 1s smoke / manual long | `synvoid-waf` | High |
| `mesh_protocol_compressed_decode` | `&[u8]` → gzip+protobuf MeshMessage | **New** | 1s smoke / manual long | `synvoid-mesh` | High |

### Tooling Status

- **cargo-fuzz**: Installed (v0.13.2) via `cargo install cargo-fuzz`.
- **Nightly toolchain**: Required for ASAN instrumentation; `nightly-x86_64-unknown-linux-gnu` installed.
- **Compilation**: Fuzz targets require nightly + ASAN; initial compilation is slow for large workspace.
- **CI integration**: Fuzz smoke tests integrated in CI (`fuzz-smoke` job). Dedicated tarpit and mesh test jobs added in Milestone D Phase 4.
- **Smoke command**: `cargo +nightly fuzz run <target> -- -runs=1000` for bounded smoke.

### High-Value Targets Not Yet Implemented

| Target | Input type | Priority | Notes |
|--------|------------|----------|-------|
| Config parse & validate | `&[u8]` → TOML | Medium | Malformed config should fail closed |
| HTTP chunked body framing | `&[u8]` → chunked transfer | High | Request smuggling vector |
| URL/path routing matcher | `&[u8]` → route table input | High | Routing correctness under adversarial paths |

### CI Smoke Commands

```bash
# Existing targets
cargo +nightly fuzz run dns_message_decode -- -runs=1000
cargo +nightly fuzz run plugin_manifest -- -runs=1000
cargo +nightly fuzz run http_path_normalization -- -runs=1000
cargo +nightly fuzz run fuzz_attack_detection -- -runs=1000
cargo +nightly fuzz run fuzz_early_parse -- -runs=1000
cargo +nightly fuzz run fuzz_ipc -- -runs=1000

# New targets (Phase 14)
cargo +nightly fuzz run blocklist_event_decode -- -runs=1000
cargo +nightly fuzz run blocklist_snapshot_decode -- -runs=1000
cargo +nightly fuzz run admin_mutation_result_decode -- -runs=1000
cargo +nightly fuzz run http_header_normalization -- -runs=1000
cargo +nightly fuzz run mesh_protocol_compressed_decode -- -runs=1000
```

Long fuzz runs are manual/nightly only.

## Failure-Injection Test Seams

Target failure cases (Phase F):

1. `UnifiedServer` registered task fails; shutdown report counts critical failure.
2. Supervisor critical task fails; maps to `SupervisorShutdownCause::TaskFailed`.
3. Blocklist catchup cursor points beyond retained history; snapshot fallback requested.
4. Snapshot apply interrupted; cursor not advanced incorrectly.
5. Plugin manifest parse fails; plugin disabled, server continues.
6. Plugin invocation timeout; plugin failure isolated.
7. Mesh peer reconnect with cursor load failure; fallback to full retained catchup or snapshot.
8. Startup resource construction fails after partial resource build; no task leak.
