# Architecture Residuals Roadmap

Status: implementation handoff plan
Baseline reviewed: `main` at `651db50b000c605ff91b832d7ffb47766e4bf1f3` (2026-09-10)

## Purpose

Close the remaining architectural and maintenance residuals identified after the root-module ownership, HTTP/WAF convergence, and admin-panel corrective lines. The repository no longer has broad accidental duplicate implementations; the remaining work is concentrated in a small set of explicit seams where application composition, compatibility facades, feature-gated code, and admin contracts can still drift.

This roadmap is intentionally conservative. It must not trigger another broad crate-extraction campaign. Existing ownership decisions remain authoritative unless a phase below proves that a boundary is wrong.

## Current-state findings driving this roadmap

1. `src/tls/server.rs` still has an HTTPS-specific request flow in `HttpsServer::handle_request_with_cache` rather than composing the canonical `synvoid-http` request stages used by the HTTP server. Framing helpers have already converged; request semantics have not.
2. `src/static_files/mod.rs` is a transitional facade over `synvoid-static-files` but retains a substantial local `file_manager` implementation consumed by root HTTP/WebDAV code. Its periodic YARA refresh API currently succeeds without performing a refresh, so ownership and behavior both need closure.
3. The root crate exposes a large population of `facade_existing_crate` compatibility paths. Most are safe re-exports, but the transition has no explicit retirement policy and therefore risks becoming permanent API duplication.
4. `UnifiedServer`, `WafCore`, and the admin route composition remain large, legitimate composition roots. The problem is internal concentration/change coupling, not incorrect ownership. They should be decomposed into private builders/stages rather than moved to new crates.
5. The admin panel is currently wired correctly, but its ~240-route surface is multiply authored across Axum registration, Utoipa/OpenAPI metadata, API discovery, frontend client calls, and docs. Existing contract tests cover known historical mismatches but are not exhaustive. Optional feature profiles are also verified unevenly.
6. `ApiService::logout()` clears client CSRF state before a non-auth server/network failure is fully interpreted, while root `AuthState` can remain authenticated. This is low severity but should be normalized during admin contract hardening.

## External implementation guidance incorporated

- Cargo features are additive and conditional compilation creates a combinatorial verification problem; common/default/no-default and selected combinations should be deliberately tested rather than assuming default-feature CI is sufficient.
- `cargo-hack` supports `--each-feature` and bounded `--feature-powerset`/`--depth` checks and deduplicates equivalent combinations. Use it only where it reduces maintenance relative to the repository's existing explicit matrix; do not re-expand CI complexity indiscriminately.
- Transport convergence should share policy/semantic stages while preserving transport-specific framing, handshake, flow-control, and listener ownership. The TLS phase therefore targets request-policy parity, not collapsing HTTP and HTTPS listener implementations.

## Phase order

### Phase 01 — TLS request-flow convergence

Plan: `plans/architecture_phase_01_tls_request_flow_convergence.md`

Make HTTP and HTTPS invoke the same canonical request-policy stages and produce equivalent enforcement/accounting semantics. Preserve TLS listener/handshake/certificate ownership in `src/tls`/`synvoid-tls`.

### Phase 02 — Static file-manager ownership and functional closure

Plan: `plans/architecture_phase_02_static_file_manager_closure.md`

Determine the narrow canonical owner for `FileManager`, remove the no-op YARA refresh success path, and converge consumers without weakening traversal/symlink/upload safety.

### Phase 03 — Compatibility-facade retirement policy and first burn-down

Plan: `plans/architecture_phase_03_compatibility_facade_burndown.md`

Classify every `facade_existing_crate` path by actual compatibility requirement, define measurable retirement criteria, remove only zero-value aliases, and leave deliberate stable compatibility paths documented.

### Phase 04 — Composition-root decomposition

Plan: `plans/architecture_phase_04_composition_root_decomposition.md`

Reduce local complexity/change coupling in `UnifiedServer`, `WafCore`, and admin router construction through private builders/stage groupings and explicit dependency bundles. Do not add domain crates and do not move application ownership.

### Phase 05 — Admin contract and feature-profile hardening

Plan: `plans/architecture_phase_05_admin_contract_feature_verification.md`

Make route/capability/frontend drift mechanically detectable, extend feature-profile verification proportionally, and close the logout auth-state residual without reopening the already-completed admin corrective roadmap.

## Global constraints

- No new crate unless a phase demonstrates an unavoidable dependency-cycle or independent reusable domain with at least two real consumers. The default is **no new crate**.
- Preserve public behavior unless a current behavior is explicitly identified as misleading/incorrect (for example, no-op refresh reporting success).
- Preserve feature-gated builds: default, no-default, mesh, dns, icmp-filter, and existing supported combinations.
- Avoid broad formatting/renaming churn while touching request-path or security-sensitive code.
- Any compatibility removal must be preceded by repository-wide consumer search and documented in the root-module/public-surface ledgers.
- Security-sensitive path changes require negative tests, not only happy-path tests.
- Do not reintroduce duplicate parsers, WAF-decision mappings, auth-state stores, or parallel route aliases merely to satisfy tests.

## Completion criteria

The roadmap is complete when all five phases satisfy their acceptance criteria and the architecture documents are updated so that:

1. HTTP and HTTPS share one canonical application request-policy flow with transport-specific differences explicitly enumerated.
2. `FileManager` has one canonical implementation owner and every advertised background refresh operation has real observable semantics or is removed.
3. Every root compatibility facade has an explicit disposition: retained stable compatibility, deprecated with removal target, or removed.
4. Large composition roots retain ownership but are internally decomposed enough that independent subsystem wiring changes do not require editing monolithic functions unnecessarily.
5. Admin frontend calls, Axum routes, capability gates, API discovery/OpenAPI metadata, and selected feature profiles are protected by automated contract checks.
6. The architecture/root-module ledgers and closeout evidence match the implementation rather than aspirational target state.

## Recommended verification envelope

Per phase, run the narrowest relevant unit/integration tests first, then the repository's normal formatting/lint gates. At final closeout, run at minimum:

```text
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh --profile ci
cargo check --no-default-features --features dns --profile ci
cargo check --no-default-features --features icmp-filter --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
cd admin-ui && cargo check
```

If Phase 05 adopts `cargo-hack`, keep it to a bounded, documented feature set/depth and remove redundant hand-written jobs rather than layering it on top of equivalent checks.
