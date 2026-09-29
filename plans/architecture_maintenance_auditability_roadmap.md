# Architecture Maintenance and Auditability Roadmap (Phases 96-101)

Status: **CLOSED QUALIFIED — 2026-09-29**; Phases 96–101 implemented and closed.

Registered in: plans/roadmap.md.

Baseline: main at 30e68af8f6e79ce0fe07f0c1871f1d0caa6be6f2.

## Purpose

Reduce avoidable capability reach between SynVoid crates, make dependency direction communicate architectural authority more accurately, and create smaller security/audit units without reducing runtime capability, configuration compatibility, supported feature profiles, or protocol behavior.

This is not a crate-count campaign. Existing useful isolation boundaries remain. A split is justified only when it produces at least one measurable benefit: smaller transitive dependency or unsafe surface, narrower authority, independent protocol/security invariants, cleaner feature/build isolation, or materially easier review.

The completed root-ownership decisions remain authoritative. Root admin, HTTP server composition, WAF composition, plugin lifecycle, server/supervisor/worker orchestration, TLS server integration, TCP, and UDP are not reopened merely to move lines of code.

## Current-head research findings

### 1. Several dependency edges point upward into domain engines for narrow vocabulary

Current manifests and source inspection show:

- synvoid-metrics depends on synvoid-waf only to use AttackType as an in-memory metrics key. The exported IPC/admin payload already carries blocked-by-type data as string keys.
- synvoid-block-store depends on synvoid-waf for MitigationProvider and SizedMitigationProvider even though the contract is generic IP block/unblock enforcement. synvoid-block-store already depends on synvoid-core.
- synvoid-mesh reaches into synvoid-proxy for is_private_ip and hop-by-hop-header classification. The private-address helper is already canonical in synvoid-core::net; the remaining HTTP proxy integration should be narrowed during the mesh phase rather than solved by adding another broad low-level dependency.
- the existing root dependency-entitlement model does not yet express workspace-wide forbidden dependency directions.

These are maintenance/audit problems, not behavior bugs. They should be corrected without changing labels, block/unblock semantics, routing, or mesh traffic behavior.

### 2. The jail wire contract is embedded in a much broader IPC/process crate

synvoid-ipc currently owns supervisor/worker IPC, process management, socket generation, signing, pools, jail binary resolution, jail supervision, and the jail wire protocol.

The child-side synvoid-jail-runtime therefore depends on all of synvoid-ipc even though its actual cross-process contract is the bounded SVJL protocol: version/magic, DTOs, validation, framing, typed errors, digest checks, isolation-policy vocabulary, and constants.

The protocol already has golden-vector tests and a versioned wire contract. This is a clean security boundary suitable for a low-capability leaf crate.

### 3. HTTP/3 transport-specific request flow is owned by synvoid-http

synvoid-http currently declares multiple http3_* modules and directly carries the h3 dependency while synvoid-http3 is the QUIC/H3 server shell and depends on synvoid-http.

The desired direction is already acyclic: protocol-neutral HTTP/request-policy contracts in synvoid-http, HTTP/3 framing/stream/request state machines in synvoid-http3. Moving transport-specific ownership in that direction can reduce audit scope without merging or duplicating the H1/H2/H3 policies.

### 4. Configuration combines high-fanout model ownership with runtime loading and crypto behavior

synvoid-config has roughly half the workspace as reverse consumers. It owns user-facing DTOs/defaults/validation, ConfigManager/file discovery, TOML/file loading, and mesh identity/key derivation behavior.

Current source also shows duplicated or overlapping mesh identity/key realization between synvoid-config mesh types and synvoid-mesh config identity code. A consumer that only needs a SiteConfig or limits DTO should not conceptually acquire configuration mutation/loading and runtime key-materialization authority.

A model/runtime separation is warranted if it preserves existing serialized configuration and materially reduces dependency reach.

### 5. synvoid-mesh is a valid large subsystem but exposes overly broad internal capability

The approximately 100k-LOC mesh crate has independent consensus, DHT, transport, security, lifecycle, distribution, and integration invariants and should not be split for size alone.

The current MeshTransport aggregate, however, owns or can access peer transport, DHT, serverless, canonical reads, snapshots, org/tier keys, threat intelligence, YARA distribution, DNS, site sync, Raft, replica state, lifecycle/task ownership, and application integration. Sibling transport modules commonly rely on broad crate-private access.

The next step is internal capability decomposition and consumer-owned narrow service traits, not an immediate synvoid-mesh-consensus extraction. A later extraction decision should be evidence-driven after the internal graph is cleaner.

## Binding compatibility and capability constraints

1. No supported runtime capability is removed. H1/H2/H3, WAF, proxying, mesh, DNS, jail WASM/YARA execution, admin operations, upload scanning, honeypots, tunnels, and supported feature combinations remain available.
2. Existing default features and the supported --no-default-features profile remain semantically equivalent.
3. Existing persisted TOML/JSON configuration remains readable. No field is silently dropped, reinterpreted, or made inert.
4. Jail protocol version remains v1 unless a wire-semantic change is independently justified. This campaign is expected to keep v1 byte-identical.
5. Distributed-state authority, partition, provenance, replay, and fail-closed rules are unchanged by mesh restructuring.
6. WAF enforcement precedence and observable block/challenge/tarpit semantics are unchanged.
7. Request normalization and security-relevant framing semantics remain canonical; transport ownership movement may not fork policy.
8. No new class-3/public support promise is created. synvoid-rate-limit remains the only externally supported SynVoid crate unless a separate publication plan says otherwise.
9. Internal compatibility re-exports should be retained where they are acyclic and cheap. Where a compatibility re-export would create a cycle, migrate all workspace consumers and document the internal path change rather than adding a cycle.
10. Do not add a low-level dependency solely to relocate a helper. New boundaries must reduce net capability or dependency reach.
11. Do not merge synvoid-filter, app-server/app-handlers, or egress layers solely to lower crate count.
12. Routine CI remains proportionate. Focused guards/tests are added to existing verification rather than spawning a broad permanent matrix.

## Execution order

1. Phase 96 — workspace dependency-direction cleanup and guard baseline.
2. Phase 97 — jail protocol leaf extraction.
3. Phase 98 — HTTP/3 ownership realignment (closed 2026-09-28; see
   `architecture/http3_ownership_phase98_closeout.md`).
4. Phase 99 — configuration model/runtime capability separation (closed
   2026-09-28; see `architecture/config_model_phase99_closeout.md`).
5. Phase 100 — mesh internal capability decomposition and application dependency inversion (closed 2026-09-29; see `architecture/mesh_capability_decomposition_phase100_closeout.md`).
6. Phase 101 — cross-campaign qualification, architecture reconciliation, and future extraction decisions (closed; see `architecture/architecture_maintenance_auditability_closeout.md`).

Phases are ordered to establish low-level dependency rules before adding new boundaries. Phase 100 depends on the earlier HTTP/config cleanup so it does not build new adapters on transitional ownership.

## Detailed plans

- plans/phase_96_workspace_dependency_direction_and_guard_baseline.md
- plans/phase_97_jail_protocol_boundary_extraction.md
- plans/phase_98_http3_ownership_realignment.md
- plans/phase_99_configuration_model_runtime_separation.md
- plans/phase_100_mesh_capability_decomposition.md
- plans/phase_101_architecture_maintenance_qualification_closeout.md

## Campaign acceptance criteria

The campaign can close only when:

- avoidable metrics-to-WAF and block-store-to-WAF edges are removed and guarded against reintroduction;
- low-level/private-address handling no longer requires mesh to reach into proxy for that concern;
- jail child runtime consumes a protocol-only crate rather than the full supervisor/process IPC crate, with byte-identical v1 golden vectors and unchanged dedicated-binary behavior;
- HTTP/3 transport-specific state machines are owned by synvoid-http3 while shared security policy remains canonical and parity-tested;
- configuration model consumers can depend on a lower-capability model boundary without ConfigManager/file-loading/key-realization ownership;
- configuration serialization and runtime behavior remain compatible;
- mesh transport/application integrations consume narrower capability handles/traits and broad friend-style state access is reduced;
- no distributed-state authority semantics change;
- default/minimal/mesh/dns/mesh+dns verification remains green;
- crate-granularity, dependency-ownership, architecture overview, release ordering, and relevant deep dives agree with the final graph;
- dependency/security and performance evidence shows no material unexplained regression.

## Rejection criteria

Reject implementation or closeout that:

- creates crates solely to reduce LOC or crate size;
- removes a feature, backend, route, protocol, config field, or supported deployment mode as a shortcut;
- solves a dependency edge by moving domain-specific types into synvoid-core without proving they are actually domain-neutral;
- duplicates HTTP header/security logic merely to eliminate a dependency;
- changes jail wire bytes while claiming protocol v1 compatibility;
- introduces a synvoid-http <-> synvoid-http3 cycle;
- splits configuration while keeping runtime I/O/key generation in the supposedly low-capability model;
- extracts mesh consensus before the internal capability graph supports a one-way boundary;
- changes Raft/DHT authority or request enforcement semantics incidentally;
- marks skipped native/security evidence as passed;
- reports architectural improvement without recomputing the dependency graph and relevant binary/dependency deltas.
