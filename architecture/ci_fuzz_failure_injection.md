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
| `dns_message_decode` | `&[u8]` → DNS wire-format bytes | **New** | 1s smoke / manual long | `synvoid` (dns) | High |
| `plugin_manifest` | `&[u8]` → TOML manifest bytes | **New** | 1s smoke / manual long | `synvoid-plugin-runtime` | High |
| `http_path_normalization` | `&[u8]` → URL-encoded path bytes | **New** | 1s smoke / manual long | `synvoid` (utils) | High |

### High-Value Targets Not Yet Implemented

| Target | Input type | Priority | Notes |
|--------|------------|----------|-------|
| Mesh protocol full decode | `&[u8]` → protobuf | High | Broader than raft-specific targets |
| Blocklist event decode | `&[u8]` → postcard | High | Critical for block store integrity |
| Blocklist snapshot cursor | `&[u8]` → postcard | High | Cursor corruption could cause infinite catchup |
| Config parse & validate | `&[u8]` → TOML/JSON | Medium | Malformed config should fail closed |
| HTTP chunked body framing | `&[u8]` → chunked transfer | High | Request smuggling vector |
| URL/path routing matcher | `&[u8]` → route table input | High | Routing correctness under adversarial paths |

### CI Smoke Commands

```bash
cargo fuzz run dns_message_decode -- -runs=1000
cargo fuzz run plugin_manifest -- -runs=1000
cargo fuzz run http_path_normalization -- -runs=1000
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
