# Mesh Capability Map — Phase 100

Status: Phase 100 implementation evidence; reviewed against the current `MeshTransport` and `MeshTransportManager` declarations.

This is an ownership and access map, not a runtime redesign. The transport implementation is split across sibling modules (`transport_{connection,dht,dns,global,org,peer,rate_limit,routing,serverless}.rs`) that currently import the complete parent module with `use super::*`. That means readers and writers are distributed across those modules, and most `MeshTransport` fields are `pub(crate)`. The explicit capability boundary is therefore the `MeshTransport` instance plus crate visibility, rather than a narrower capability object. This remains a Phase 100 residual and is an input to Phase 101 extraction qualification.

## MeshTransport field and capability matrix

| Fields / services | Domain | Writers and readers | Hot path | Task crossing | Minimal mesh | Existing seam |
|---|---|---|---|---|---|---|
| `config`, `topology`, `cert_manager`, `runtime`, `running`, `shutdown_tx` | transport / lifecycle | Transport startup, peer and global handlers, shutdown | mixed; topology/session lookups can be hot | shared by accept/session/background tasks | transport config required; runtime optional until start | `MeshTransportTrait`; `MeshLifecycleState` |
| `peer_connections`, `connection_times`, `peer_sessions`, `session_generation` | transport | Connection/session/peer handlers; session reaper and shutdown | yes | yes, per-peer tasks | required for connected peers | `MeshPeerConnection`, session task types |
| `auth_keys`, `auth_failures`, `peer_message_times`, `snapshot_request_times`, `global_rate_limiter`, `revocation_list`, `seen_messages` | identity/security | Peer authentication, replay checks, rate limiting, revocation handlers | yes for auth/message/replay | shared across peer tasks | security core remains required | peer-auth and protocol-signing types; no aggregate seam |
| `pending.{query_dedup, pending_queries, pending_dht_queries, pending_serverless_invocations, pending_consistent_read_responses, pending_snapshot_responses, pending_snapshot_transfers}` (`MeshPendingRequests`) | transport protocol / distributed data / consensus | Request senders and peer response handlers | yes on request/response paths | oneshot senders cross tasks; snapshot transfer crosses peers | basic query maps required; consensus/snapshot maps feature/path dependent | typed request/response state group |
| `record_store`, `routing_manager`, `stake_manager` | DHT/data | DHT and organization handlers; initialization and routing startup | DHT lookups may be hot | maintenance and request tasks | DHT is optional by configuration | `RecordStoreManager`; routing manager concrete |
| `raft_instance`, `pending_membership_changes`, `edge_replica_manager`, `raft_proposal_replay_cache`, `pending_consistent_read_responses`, snapshot fields | consensus | consensus message handlers, state transfer, proposal path, lifecycle initialization | control plane; message dispatch may share event loop | yes, consensus tasks and request handlers | only when canonical/replica mode is active | `CanonicalTrustReader`; consensus transport contract |
| `org_manager`, `org_key_manager`, `tier_key_store`, `tier_key_encryption`, `origin_ed25519_signer`, `mesh_signer`, `mlkem_session_manager` | identity/security | organization, key, handshake, signing and encryption handlers | handshake/session lookups | peer tasks | role/config dependent | signer and session manager types; no single identity capability |
| `application.{threat_intel, yara_rules, backend_pool, serverless_manager}` | application bridges (`MeshApplicationCapabilities`) | peer-message distribution and serverless integration; composition wiring | mostly control plane; event handlers share dispatch | background distribution and peer tasks | optional | `ThreatIntelPolicyContext`; application adapters are partial |
| `dns_resolver`, `dns_registry`, `dns_zones`, `ownership_challenge_store` (`dns`) | DNS bridge | DNS transport handlers and registry/challenge code | query path may be hot | registry verification tasks | feature and config dependent | DNS resolver trait; registry/store concrete |
| `site_config_sync_tx` | application bridge | peer site synchronization sends; receiver owned by composition | control plane | mpsc boundary | optional | typed channel only |
| `verification_manager` | application bridge / lifecycle | verification handlers, scheduled verifier | control plane | background processing | optional | `VerificationTaskManager` |
| `lifecycle.{task_group, lifecycle_state, shutdown_started, mesh_exit_tx, startup_failure_hook, lifecycle_op, id_generator, running_projection, accept_loop_report, failed_startup_residue, auxiliary_tasks, auxiliary_submission_lock, peer_sessions, session_exit_tx, session_reaper_shutdown, auxiliary_exit_tx, aggregate_handler_drained, aggregate_handler_aborted, aggregate_handler_failed, auxiliary_test_hooks, startup_generation, session_generation}` (`MeshTransportLifecycle`) | lifecycle/task ownership | start/rollback/shutdown, task reapers, session exits, tests | atomic checks and exit counters only on steady state; rest control plane | yes, intrinsically | required to preserve start/stop contract | `MeshTaskGroup`, `MeshLifecycleState`, task IDs/reports |

Readers and writers in the table are the modules matching their domain in the sibling module list; the fields' crate-wide visibility means this is a descriptive ownership classification, not enforced access control. Per-field access lists can be generated with `rg` against each field name. The broad `use super::*` in transport extensions prevents a robust narrow list today and is itself the primary decomposition target.

## MeshTransportManager map

| Fields | Domain and access | Hot path / task | Minimal mesh | Existing seam |
|---|---|---|---|---|
| `config`, `topology`, `quic_transport`, `preferred_transport`, `peer_states` | transport selection and peer state; set during setup and read by peer-selection APIs | selection can be hot; no lifecycle task ownership | required for manager | `MeshTransportTrait` |
| `record_store`, `routing_manager`, `verification_manager` | DHT and verification services; setup plus query/verification methods | lookups and scheduled verification | service/config dependent | concrete managers; verification manager getter |
| image/compression/minification/image-rights/proxy-preference caches and matching inflight maps | application bridge cache/stampede protection | request-path hot; shared async callers | only corresponding feature/config path | none; typed caches |
| `*_cache_hits` / `*_cache_misses` atomics | metrics | hot-path increments | corresponding cache path | metrics counters |

## Phase 100 boundary result

- Application consumers now own the narrow YARA snapshot contract and honeypot publisher contract; root adapters bridge those contracts to the mesh managers.
- `MeshTransport` groups application services, lifecycle/task state, and pending request/response rendezvous into named typed aggregates. Constructors and both clone paths retain the prior sharing/reset behavior, including fresh clone-local lifecycle transition locks and the maintenance clone's omitted backend pool.
- These remove production `synvoid-mesh` dependency edges from `synvoid-upload` and `synvoid-honeypot`. Upload's mesh test feature retains the mesh crate only through a dev dependency.
- `MeshTransport` and `MeshTransportManager` remain broad internal aggregates. Splitting the full transport state requires staged receiver migration across the sibling modules and careful preservation of lifecycle semantics. That work is deliberately recorded as remaining extraction risk, rather than claiming the current `pub(crate)` access became capability-safe.
- `MeshProxy` still owns local proxy/cache execution and mesh message handling in one implementation. It depends on canonical `synvoid-proxy` hop-by-hop header logic and `synvoid-proxy-cache`; those semantics must not be copied. The boundary is a candidate for a focused follow-up if Phase 101's dependency audit finds a viable one-way adapter without moving application behavior into mesh.

## Checks to preserve

The capability work must retain the current `MeshTaskGroup` transactional startup, explicit shutdown channels, bounded join/drain, startup rollback residue, generation checks, and required-vs-optional startup decisions. None of the application adapter changes creates tasks or changes those decisions. Existing canonical/advisory authority and freshness behavior remain under `architecture/distributed_state_contract.md` and canonical reader tests.
