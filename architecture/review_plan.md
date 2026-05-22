# Architecture Review Plan

**Created**: 2026-05-22
**Purpose**: Review SynVoid architecture documentation, verify code claims, identify improvements and bugs.

## Modules

The following discrete modules will be reviewed:

| # | Module | Document(s) | Source Path(s) |
|---|--------|-------------|-----------------|
| 1 | Process Lifecycle | `process_lifecycle.md` | `src/overseer/`, `src/master/`, `src/process/` |
| 2 | Worker Architecture | `worker_architecture.md` | `src/worker/`, `src/server/` |
| 3 | Networking | `networking_deep_dive.md` | `src/listener/`, `src/http/`, `src/http3/` |
| 4 | Routing | `routing_deep_dive.md` | `src/router/`, `src/upstream/` |
| 5 | WAF | `waf_deep_dive.md` | `src/waf/`, `src/filter/`, `src/challenge/` |
| 6 | App Handlers | `app_handlers.md` | `src/static_files/`, `src/php/`, `src/serverless/` |
| 7 | Mesh | `mesh_deep_dive.md` | `src/mesh/` |
| 8 | Layer 3.5 | `layer_3_5_deep_dive.md` | Cross-cutting (PQC, trust models) |
| 9 | Deep Dive Review | `deep_dive_review.md` | Cross-cutting (security analysis) |
| 10 | Overview | `overview.md` | Meta-document |

## Review Workflow

Each subagent will:
1. Read the architecture document(s) for the assigned module
2. Identify claims and architectural assertions
3. Verify claims against actual source code
4. Interrogate code for:
   - Implementation gaps
   - Security vulnerabilities
   - Performance issues
   - Concurrency bugs
   - Missing error handling
   - API/design improvements
5. Write findings to `plans/{module}_review.md`

## Subagent Tasks

### Subagent 1: Process Lifecycle
- **Document**: `architecture/process_lifecycle.md`
- **Output**: `plans/01_process_lifecycle_review.md`
- **Focus**: Overseer/Master/Worker hierarchy, zero-downtime upgrades, IPC security
- **Source paths**: `src/overseer/`, `src/master/`, `src/process/`

### Subagent 2: Worker Architecture
- **Document**: `architecture/worker_architecture.md`
- **Output**: `plans/02_worker_architecture_review.md`
- **Focus**: Unified server, listener pools, request flow
- **Source paths**: `src/worker/`, `src/server/`

### Subagent 3: Networking
- **Document**: `architecture/networking_deep_dive.md`
- **Output**: `plans/03_networking_review.md`
- **Focus**: HTTP/1, HTTP/2, HTTP/3, TLS, QUIC, connection limiting
- **Source paths**: `src/listener/`, `src/http/`, `src/http3/`

### Subagent 4: Routing
- **Document**: `architecture/routing_deep_dive.md`
- **Output**: `plans/04_routing_review.md`
- **Focus**: Router, upstream pools, load balancing, health monitoring
- **Source paths**: `src/router/`, `src/upstream/`

### Subagent 5: WAF
- **Document**: `architecture/waf_deep_dive.md`
- **Output**: `plans/05_waf_review.md`
- **Focus**: WAF pipeline, attack detection, bot mitigation, challenges
- **Source paths**: `src/waf/`, `src/filter/`, `src/challenge/`

### Subagent 6: App Handlers
- **Document**: `architecture/app_handlers.md`
- **Output**: `plans/06_app_handlers_review.md`
- **Focus**: Static files, FastCGI/PHP-FPM, Python (Granian), WASM, Spin
- **Source paths**: `src/static_files/`, `src/php/`, `src/serverless/`, `src/app_server/`

### Subagent 7: Mesh
- **Document**: `architecture/mesh_deep_dive.md`
- **Output**: `plans/07_mesh_review.md`
- **Focus**: DHT, QUIC transport, threat intelligence, P2P networking
- **Source paths**: `src/mesh/`

### Subagent 8: Layer 3.5
- **Document**: `architecture/layer_3_5_deep_dive.md`
- **Output**: `plans/08_layer_3_5_review.md`
- **Focus**: PQC implementation, hybrid signatures, ML-KEM, cross-cutting concerns
- **Source paths**: Cross-cutting (verify in `src/mesh/`, `src/crypto/`)

### Subagent 9: Deep Dive Review
- **Document**: `architecture/deep_dive_review.md`
- **Output**: `plans/09_deep_dive_review.md`
- **Focus**: Security analysis, threat models, cross-cutting architectural concerns
- **Source paths**: Cross-cutting

### Subagent 10: Overview (Meta)
- **Document**: `architecture/overview.md`
- **Output**: `plans/10_overview_review.md`
- **Focus**: Document consistency, cross-references, completeness
- **Source paths**: All modules

## Execution Order

**Wave 1** (Modules 1-7, can run in parallel):
- Subagent 1: Process Lifecycle
- Subagent 2: Worker Architecture
- Subagent 3: Networking
- Subagent 4: Routing
- Subagent 5: WAF
- Subagent 6: App Handlers
- Subagent 7: Mesh

**Wave 2** (Modules 8-10, depends on Wave 1 completion):
- Subagent 8: Layer 3.5
- Subagent 9: Deep Dive Review
- Subagent 10: Overview

## Review Criteria

Each subagent will evaluate:
1. **Accuracy**: Do the documents match the implementation?
2. **Completeness**: Are all features documented?
3. **Correctness**: Are the architectural decisions sound?
4. **Security**: Are there security concerns not addressed?
5. **Performance**: Are there performance implications?
6. **Maintainability**: Is the code well-structured for long-term maintenance?

## Output Format

Each review plan will contain:
- **Verified Claims**: What the documentation says that is confirmed in code
- **Unverified Claims**: Claims that need verification or are uncertain
- **Implementation Gaps**: Features documented but not fully implemented
- **Code Improvements**: Refactoring suggestions
- **Bug Report**: Any bugs discovered
- **Security Concerns**: Potential security issues
- **Missing Documentation**: Important implementation details not documented

## Verification Commands

```bash
# Core profile check
cargo check --no-default-features

# Mesh profile check
cargo check --no-default-features --features mesh

# Full profile check
cargo check --no-default-features --features mesh,dns

# Format and lint
cargo fmt && cargo clippy --lib -- -D warnings

# Run all lib tests (compile check)
cargo test --lib --no-run
```