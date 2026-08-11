# Admin Panel Phase 3 — Frontend/Backend API Contract Reconciliation and Missing Control-Plane Wiring

## Status

**PLANNED**

## Objective

Make every production admin UI request correspond to exactly one real backend operation under the feature profile in which the control is visible. Remove endpoint drift, repair known worker/ICMP/process-management mismatches, complete Mesh initial load/config mutation, wire Tier Keys through existing mesh organization/key authority, and ensure visible controls report real mutation outcomes.

This phase assumes the router and browser security boundary from Phases 1–2 are already stable.

## Scope

Primary files expected to change:

- `admin-ui/src/services/api.rs`
- `admin-ui/src/pages/workers.rs`
- `admin-ui/src/pages/process_management.rs`
- `admin-ui/src/pages/mesh.rs`
- `admin-ui/src/pages/tier_keys.rs`
- `admin-ui/src/pages/icmp.rs`
- other production pages only where contract audit identifies a concrete mismatch
- `src/admin/mod.rs`
- `src/admin/handlers/config.rs`
- `src/admin/handlers/system.rs`
- `src/admin/handlers/mesh_admin.rs` and/or a narrowly scoped tier-key handler module
- `src/admin/state.rs` only if a missing existing manager handle must be exposed narrowly
- `src/admin/handlers/api_discovery.rs` and OpenAPI declarations
- focused contract/mutation tests

Do not expand the admin panel into new product capabilities unrelated to currently shipped controls.

## Baseline mismatches to close

At minimum, this phase must explicitly disposition these known cases:

- frontend worker restart path uses singular `/system/worker/{id}/restart` while backend canonical route is `/system/workers/{id}/restart`
- ICMP config update uses POST while backend canonical route accepts PUT
- Process Management calls `/config/overseer`, which is not registered
- duplicate/ambiguous supervisor status/config concepts exist between frontend and backend
- frontend exposes `/config/mesh`, but the current router does not register it
- Mesh page does not perform an initial fetch and can remain in loading state forever
- Tier Keys frontend calls `/tier-keys`, `/tier-keys/issue`, `/tier-keys/revoke`, and `/tier-keys/unbind`, but those routes are not registered
- Tier Keys mutations discard result/error information
- manual API discovery advertises some absent/stale routes

The implementation must perform a full production-frontend contract audit rather than fixing only these examples.

## Implementation plan

### 1. Build a one-time frontend request inventory

Enumerate every path/method used by production `admin-ui` code, including:

- `ApiService` typed methods
- raw `api.get/post/put/request(...)` calls embedded in pages/components
- WebSocket paths (recorded for contract completeness; Phase 4 owns realtime behavior)

For each request, classify it as:

- canonical and registered
- wrong method
- wrong path
- legacy alias with a canonical replacement
- feature-gated and correctly capability-hidden
- backend operation missing but underlying runtime authority exists
- unsupported/dead UI that should be removed rather than implemented

This inventory can live in the phase implementation notes/test fixture if useful, but do not create a second long-lived manual API specification.

### 2. Select one canonical naming model for supervisor/process controls

Resolve the current `Overseer`/`Supervisor` drift.

The repository has consolidated process terminology under Supervisor. Therefore:

- migrate frontend labels/types/client methods away from legacy `overseer` names where they refer to the same subsystem
- use canonical backend `/config/supervisor` and `/system/supervisor` semantics
- remove `/config/overseer` client calls
- if a compatibility endpoint is necessary for external users, implement it only as an explicit `CompatibilityLegacy` alias and do not use it from the SPA
- avoid keeping two status structs/routes that describe the same thing differently

Preserve distinct process-manager configuration where it is genuinely separate from supervisor configuration.

### 3. Repair worker control paths and responses

Update frontend worker control calls to the registered canonical routes:

- list/status
- count
- scale
- individual restart
- batch restart if exposed

Mutations must consume their typed result/response and refresh state only after a successful operation.

Do not optimistic-update worker state if the backend mutation fails.

### 4. Repair ICMP method and capability boundary

Use canonical `PUT /api/icmp/config` for configuration update if that remains the backend contract.

Ensure:

- ICMP page is shown only when capability indicates support
- update request body matches the server type
- enable/disable mutations report typed outcome or an equivalent truthful status
- failures remain visible to the operator

Do not add a POST compatibility route solely to accommodate the current frontend bug.

### 5. Wire Mesh config read/write canonically

Determine the canonical mesh configuration representation already owned by `ConfigManager`/`synvoid-config`.

Register `/api/config/mesh` GET/PUT only if mesh configuration is intended to be editable at runtime and the existing config manager can safely validate/persist it. Otherwise, replace the current editable UI with a read-only status representation and remove the fake save control. The preferred outcome, given the shipped editor, is to wire the real config mutation if the existing config mutation pattern supports it.

When implementing writable mesh config:

- reuse existing config validation/persistence/versioning semantics
- return `AdminMutationResult` or the established typed config mutation response
- attribute/audit the mutation
- do not directly mutate mesh internals behind `ConfigManager`
- clearly identify fields requiring restart/reload rather than implying immediate live application

### 6. Fix Mesh page lifecycle

Add an initial effect that concurrently or sequentially retrieves:

- mesh runtime status
- canonical mesh config

Required behavior:

- set loading false on both success and failure paths
- show partial availability if one read succeeds and the other fails, where meaningful
- initialize editable fields from fetched config, not `MeshConfig::default()` unless backend data is absent
- save using current edited values
- after success, update state from the mutation response or re-read canonical config
- surface validation/server errors
- disable save when mesh capability is unavailable

Avoid indefinite spinners.

### 7. Wire Tier Keys through existing mesh/org-key authority

The repository already contains mesh tier-key and organization/key-manager functionality. Add the narrow admin adapter necessary for the shipped Tier Keys page rather than duplicating key logic in admin code.

Canonical API shape may remain under `/tier-keys` or be namespaced under `/mesh/tier-keys`; choose one consistent path and migrate the SPA. Prefer the mesh namespace if it better reflects feature ownership, but do not create two permanent aliases absent compatibility need.

Required operations:

- list tier keys visible to the local admin authority
- issue a key for an organization/tier using the existing manager
- revoke a key using existing revocation semantics
- unbind only if the underlying tier-key model supports a safe unbind operation; if not, remove the UI action rather than inventing semantics

Security requirements:

- never return private key material or decrypted secrets beyond what the current operator workflow truly requires
- do not log key secrets
- validate organization ID, key ID, tier range, and authorization invariants server-side
- use existing organization/tier-key manager cryptographic/storage primitives
- audit issue/revoke/unbind mutations
- use `AdminMutationAuthority::AdminManual` for genuine admin mutations and `CompatibilityLegacy` only for actual compatibility paths
- represent mesh propagation truthfully as local/best-effort according to existing control-plane semantics

### 8. Make Tier Keys UI mutation-safe

Replace fire-and-forget mutations with explicit states:

- submitting/disabled while request is in flight
- success feedback including the actual mutation status
- error feedback with bounded server detail
- refresh list after successful mutation
- no silent modal close on failed issue
- no silent revoke/unbind failure

Guard short key IDs before slicing display text; do not assume every returned `key_id` contains at least eight bytes/characters.

### 9. Audit every remaining page for wrong route/method

Perform the same reconciliation for:

- sites/site detail/editor
- upstreams
- logs/request logs/audit logs
- settings/config subsections
- probes
- threat level
- alerts
- DNS
- honeypot
- theme
- system status
- serverless/plugins/spin if surfaced

Do not expand pages that are not currently shipped; simply prove the current production request strings map to registered routes.

### 10. Reduce endpoint-string duplication in the frontend

Without introducing client generation, centralize canonical path construction where it meaningfully reduces drift:

- prefer typed `ApiService` methods for page operations
- remove raw hard-coded path strings from pages when a service method already exists or should exist
- use small path helper functions for parameterized resources if needed

Do not create an elaborate endpoint DSL.

### 11. Reconcile OpenAPI and manual discovery after routes exist

Once actual routes are registered:

- add Mesh config and Tier Key endpoints to OpenAPI if they are implemented
- remove stale/legacy entries
- ensure methods match reality
- avoid duplicate entries
- ensure feature-gated endpoints are described consistently with build capabilities

Manual discovery must never be the only place a route exists.

## Contract regression test

Add one focused table-driven/source-assisted contract test that compares production frontend operations against a canonical backend route/method set.

Acceptable implementation approaches:

- expose a small test-only route manifest while building the router, or
- maintain a compact test fixture generated from the same route-construction helpers, or
- parse a constrained frontend endpoint list in a guard test and compare to the server's known contract

The test must catch the classes of errors observed here: singular/plural path drift, POST-vs-PUT drift, and calls to absent routes.

Do not write a general Rust parser, OpenAPI code generator, or browser crawler for this.

## Acceptance criteria

Phase 3 is complete only when:

- every production `admin-ui` HTTP request path/method has an explicitly identified registered backend route in the feature profile where the control is shown
- no production frontend code calls `/config/overseer`
- frontend terminology and service methods use the canonical Supervisor model where appropriate
- worker restart uses `/system/workers/{worker_id}/restart` and succeeds in focused integration testing
- worker scale/restart UI surfaces backend failure and does not falsely refresh/declare success
- ICMP config mutation uses the backend's canonical method and route and is hidden when ICMP capability is unavailable
- Mesh page performs initial status/config loading and always exits loading state
- Mesh editable state initializes from backend state, not only defaults
- Mesh save either performs a real validated/persisted configuration mutation or the save UI is removed and the page is deliberately read-only; no fake `/config/mesh` call remains
- if Mesh config mutation is implemented, the route is registered, documented, audited, and returns truthful application/restart semantics
- Tier Key list/issue/revoke and any retained unbind action are backed by real existing mesh/key-manager operations
- Tier Key mutations validate IDs/tier values server-side, do not expose/log secret material, emit audit records, and report propagation truthfully
- Tier Key UI never discards mutation errors and refreshes state after success
- unsafe `key_id[..8]` display slicing is removed or guarded
- no compatibility alias is used by the production SPA when a canonical route exists
- OpenAPI/manual discovery matches the final implemented routes and has no duplicate canonical entries
- the focused frontend/backend route-contract test fails when supplied a deliberately wrong path/method fixture and passes on the real source
- no new broad generated-client subsystem or admin-specific CI workflow is added

## Rejection criteria

Reject this phase if it:

- adds missing backend routes as no-op JSON success stubs
- keeps `/config/overseer` as the SPA's primary path
- adds POST support to ICMP merely to preserve a frontend bug
- directly manipulates tier-key cryptographic/storage internals from Yew/frontend code
- bypasses `ConfigManager`/existing admin mutation authority for mesh config edits
- returns private tier-key material unnecessarily
- closes modals or displays success before a mutation response is known
- solves route drift by maintaining two permanent canonical paths for every operation
- leaves any shipped production page knowingly calling a 404/405 route

## Verification commands/evidence

At minimum record focused tests for:

```bash
cargo test --profile ci <admin-route-contract-test>
cargo test --profile ci <admin-worker-control-test>
cargo test --profile ci <admin-mesh-config-test> --features mesh
cargo test --profile ci <admin-tier-key-test> --features mesh
cargo test --profile ci <admin-icmp-test> --features icmp-filter
```

Build the Yew admin UI and manually exercise Worker restart/scale, Process/Supervisor reads, Mesh load/save (if writable), Tier Key list plus one safe test mutation against a test manager, and ICMP config with the relevant feature compiled.
