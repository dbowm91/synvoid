# SynVoid Crate Modularization Refactor Plan

> Status: proposed plan.
> Goal: reduce incremental compile time, reduce dependency fanout, and create subsystem-sized boundaries that smaller coding agents can modify safely.
> Target implementer profile: small subagents such as MiMo 2.5 working one packet at a time with narrow context.

## 0. Current-state diagnosis

SynVoid is already a Cargo workspace, but the root package is still the dominant compilation unit. The root package declares the main library, multiple binaries, and a large dependency set that spans Tokio/Hyper/Axum, TLS, QUIC, DNS, Raft, database, WASM, YARA, OpenAPI, metrics, admin UI support, cryptography, GeoIP, FastCGI, dynamic loading, system APIs, and plugin/serverless runtime concerns.

The existing workspace members are:

```toml
members = [
  ".",
  "pqc",
  "src/wasm_pow",
  "admin-ui",
  "examples/dynamic-plugin-example",
  "examples/embedded-app-example",
  "fuzz",
  "crates/synvoid-utils",
  "crates/synvoid-config",
]
```

The root library exposes roughly seventy public modules through `src/lib.rs`, including WAF, HTTP, HTTP/3, proxy, mesh, DNS, TLS, supervisor, worker, process, admin, plugin, serverless, static files, FastCGI, CGI, upload, router, and many utility surfaces. This is the core reason editing one subsystem can force a broad rebuild surface.

Two internal crates already exist and should be preserved:

- `crates/synvoid-config`: owns strongly typed configuration and currently depends on serde, schemars, utoipa, toml, bytes, http, tracing, anyhow, crypto-related crates, `pqc`, and optional mesh-specific signing support.
- `crates/synvoid-utils`: owns buffer/serialization utilities with a small dependency footprint.

The architecture docs already describe the runtime model as a Supervisor-owned control plane, a latency-sensitive UnifiedServerWorker data plane, and bounded CPU offload workers. The crate refactor should preserve that process model exactly; this is not a runtime architecture rewrite.

## 1. Refactor principles

The refactor should be driven by compile boundaries, not merely folder names.

A module should become a crate when all of these are mostly true:

1. It has expensive dependencies that should not be pulled into unrelated edits.
2. Its API is coherent enough to expose across a crate boundary.
3. It changes less often than its callers, or changes independently from them.
4. It can be tested independently with `cargo test -p <crate>`.
5. It does not require circular references back into the root package.

A module should stay inside the root crate, at least initially, when:

1. Its API is still volatile.
2. Splitting it would require making many internal details public.
3. It has broad access to root internals.
4. It changes together with adjacent code.
5. It is a thin glue layer around process startup or binary orchestration.

The first pass should avoid trying to extract everything. The aim is to move the highest-value, lowest-risk boundaries first, then let dependency graph pressure identify the next crates.

## 2. Target workspace shape

The long-term target should be a workspace with the root package reduced to compatibility facade plus binary composition, while most stable subsystems live in `crates/`.

Proposed final shape:

```text
crates/
  synvoid-core/             # Small common types, verdicts, IDs, request metadata, shared errors.
  synvoid-utils/            # Existing utility crate. Keep lean.
  synvoid-config/           # Existing config crate. Split schema-heavy features later if needed.
  synvoid-waf/              # WAF engine, attack detection, rate limiting, bot classification glue.
  synvoid-challenge/        # CSS/PoW/auth challenge rendering and challenge state.
  synvoid-tarpit/           # Markov tarpit generation and tarpit response primitives.
  synvoid-threat-intel/     # IP feeds, ASN, threat level, violation/probe tracking if separable.
  synvoid-http/             # Hyper/Tower HTTP server pipeline, body handling, streaming WAF bridge.
  synvoid-http-client/      # Existing `src/http_client` pool/client logic.
  synvoid-proxy/            # Reverse proxy, upstream pools, cache, routing integration.
  synvoid-app-handlers/     # Static files, CGI, FastCGI, PHP, MIME, app server dispatch.
  synvoid-tls/              # TLS termination, ACME, cert resolver, mTLS, PQ TLS feature glue.
  synvoid-mesh/             # Mesh transport, DHT, org, reputation, mesh proxy, mesh crypto wrappers.
  synvoid-consensus/        # Raft global control-plane logic extracted from mesh once mesh boundary is stable.
  synvoid-dns/              # DNS server/resolver/DNSSEC logic.
  synvoid-plugin/           # WASM plugin runtime and sandbox integration.
  synvoid-serverless/       # Serverless and Spin runtime integration.
  synvoid-supervisor/       # Supervisor process, drain, lifecycle, control API.
  synvoid-worker/           # UnifiedServerWorker and CPU worker state/lifecycle.
  synvoid-admin/            # Admin API, OpenAPI, dashboard API server.
  synvoid-cli/              # Clap parsing and command dispatch.
  synvoid-testkit/          # Shared test fixtures, mock configs, fake peers, traffic fixtures.
```

This final shape is intentionally more granular than the first implementation wave. Do not create every crate upfront.

## 3. Immediate target shape

The first implementation milestone should create only the crates that are most likely to lower rebuild cost without destabilizing the repo:

```text
crates/
  synvoid-core/
  synvoid-testkit/
  synvoid-challenge/
  synvoid-tarpit/
```

Then, after the first milestone compiles, extract:

```text
crates/
  synvoid-waf/
```

After WAF extraction is stable, extract:

```text
crates/
  synvoid-http-client/
  synvoid-proxy/
```

Only after those compile cleanly should agents attempt mesh/DNS/plugin/serverless extraction.

## 4. Dependency direction rules

These rules are hard constraints. Subagents should stop and report if a task appears to require violating them.

```text
synvoid-core
  depends on: serde, bytes/http only if unavoidable, thiserror optionally
  must not depend on: tokio, hyper, axum, rustls, openraft, wasmtime, yara-x, rusqlite, quinn

synvoid-utils
  depends on: bytes, serde, postcard, rkyv, parking_lot
  must not depend on: root synvoid crate

synvoid-config
  depends on: typed config dependencies only
  must not depend on: root synvoid crate

synvoid-challenge
  depends on: synvoid-core, synvoid-config, rand/base64/sha2/hex as needed
  must not depend on: hyper server, supervisor, worker, mesh

synvoid-tarpit
  depends on: synvoid-core, synvoid-config if defaults are needed
  must not depend on: WAF core, HTTP server, mesh, supervisor

synvoid-waf
  depends on: synvoid-core, synvoid-config, synvoid-utils, synvoid-challenge, synvoid-tarpit
  may depend on: regex, libinjectionrs, dashmap, moka, arc-swap, metrics, isbot, maxminddb if still necessary
  must not depend on: hyper server, supervisor, worker, mesh transport, DNS, admin API

synvoid-http
  depends on: synvoid-core, synvoid-config, synvoid-waf, synvoid-proxy, synvoid-app-handlers
  owns: hyper/tower/tokio HTTP server-specific integration

synvoid-mesh
  depends on: synvoid-core, synvoid-config, synvoid-utils, pqc
  may depend on: quinn, openraft initially
  should later stop owning openraft after synvoid-consensus exists
```

The root `synvoid` package may depend on all extracted crates during the transition. Extracted crates must not depend on the root `synvoid` package.

## 5. Feature-gate policy

The existing root features must keep working during the transition:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

During the transition, root features should forward into member crate features. Example pattern:

```toml
[features]
default = ["socket-handoff", "mesh", "dns", "erased_pool", "swagger-ui"]
dns = ["synvoid-config/dns", "synvoid-dns", "dep:hickory-proto", "dep:hickory-resolver"]
mesh = ["synvoid-config/mesh", "synvoid-mesh", "dep:openraft"]
buffer = ["synvoid-utils/buffer"]
swagger-ui = ["dep:utoipa-swagger-ui"]
```

Avoid creating large feature matrices inside every new crate. Use crate-level optional features only for heavy external dependencies or platform-specific behavior.

## 6. Baseline measurement task

Before moving code, assign a measurement subagent.

### Task CRATE-00: compile-time baseline

Owner: one small subagent.

Files likely touched:

- `scripts/compile-baseline.sh` or `scripts/dev/compile-baseline.sh`
- optionally `plans/crate_modularization_metrics.md`

Commands to run locally:

```bash
cargo clean
cargo build --timings
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Then measure incremental checks after touching representative files:

```bash
touch src/waf/bot.rs && cargo check --lib
touch src/http/server.rs && cargo check --lib
touch src/mesh/dht/mod.rs && cargo check --lib --features mesh
touch crates/synvoid-config/src/lib.rs && cargo check --workspace
```

Deliverable:

- A short metrics file recording clean build wall time, incremental wall time, and top crates from `target/cargo-timings`.
- Do not optimize yet. This is only a baseline.

Acceptance criteria:

- Baseline file committed.
- No source behavior changed.
- Existing profile checks still pass.

## 7. Wave 1: create `synvoid-core`

Purpose: create a dependency-light crate that can receive stable shared types and break root-cycle pressure later.

### Task CRATE-01: scaffold `synvoid-core`

Files touched:

- `Cargo.toml`
- `crates/synvoid-core/Cargo.toml`
- `crates/synvoid-core/src/lib.rs`
- root `src/lib.rs` only if needed for re-export

Initial manifest:

```toml
[package]
name = "synvoid-core"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { workspace = true, features = ["derive"] }
bytes = "1"
http = "1"
thiserror = "2"
```

Keep `bytes` and `http` only if the first moved types require them. Otherwise omit them.

Initial modules:

```text
src/lib.rs
src/error.rs
src/ids.rs
src/time.rs
src/verdict.rs
src/request.rs
```

Acceptance criteria:

```bash
cargo check -p synvoid-core
cargo check --workspace --all-targets
```

### Task CRATE-02: move low-risk shared types into `synvoid-core`

Candidate types/functions:

- simple node/site/request IDs if present and not deeply coupled
- safe timestamp helpers currently re-exported into mesh from `crate::utils`
- WAF verdict/decision-like neutral enums only if they do not require `ChallengeType` from root
- request metadata structs that do not embed `hyper::Request`
- common error wrappers only if they do not pull `anyhow` everywhere

Do not move `WafCore`, `ConfigManager`, `RequestServices`, `ChallengeManager`, or `MeshTransport` in this task.

Refactor pattern:

```rust
// old temporary compatibility re-export in root crate
pub use synvoid_core::{RequestContext, SynvoidError, WafVerdict};
```

Acceptance criteria:

```bash
cargo check -p synvoid-core
cargo check --lib --no-default-features
cargo check --workspace --all-targets
```

Risk notes:

- If moving a type forces `synvoid-core` to depend on `synvoid-config`, stop. Core must remain below config.
- If moving a type requires Hyper, stop unless it is just the `http` crate's header/method/status types.

## 8. Wave 2: create `synvoid-testkit`

Purpose: move test helpers out of root library and give subagents safe fixtures for extracted crates.

### Task CRATE-03: scaffold `synvoid-testkit`

Files touched:

- `Cargo.toml`
- `crates/synvoid-testkit/Cargo.toml`
- `crates/synvoid-testkit/src/lib.rs`

Dependencies:

```toml
[dependencies]
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
tempfile = "3"
serde_json = "1"
```

Move only generic helpers first:

- temp config directory builders
- sample request metadata builders
- deterministic fake IP/domain/site builders
- test fixtures that do not require root `synvoid`

Acceptance criteria:

```bash
cargo check -p synvoid-testkit
cargo test -p synvoid-testkit
cargo test --lib --no-run
```

Do not migrate integration tests wholesale yet.

## 9. Wave 3: extract challenge/tarpit leaves

These are good early extractions because they are leaf-like relative to WAF and HTTP. They also help untangle `WafDecision::Challenge` and `WafCore` from root-local modules.

### Task CRATE-04: scaffold `synvoid-challenge`

Files touched:

- `Cargo.toml`
- `crates/synvoid-challenge/Cargo.toml`
- `crates/synvoid-challenge/src/lib.rs`
- root `src/challenge/` re-export shims

Move candidates from `src/challenge`:

- challenge type enum
- challenge configuration wrappers if not already config-owned
- PoW/CSS challenge rendering and verification primitives
- HTML/static challenge assets only if the path assumptions remain valid

Temporary compatibility pattern:

```rust
// src/challenge/mod.rs
pub use synvoid_challenge::*;
```

Acceptance criteria:

```bash
cargo check -p synvoid-challenge
cargo check --lib --no-default-features
cargo test --lib challenge --no-run
```

### Task CRATE-05: scaffold `synvoid-tarpit`

Files touched:

- `Cargo.toml`
- `crates/synvoid-tarpit/Cargo.toml`
- `crates/synvoid-tarpit/src/lib.rs`
- root `src/tarpit/` re-export shims

Move candidates:

- Markov chain generator
- tarpit profile/default application helpers
- response body generation primitives

Keep HTTP response construction in root/http until `synvoid-http` extraction.

Acceptance criteria:

```bash
cargo check -p synvoid-tarpit
cargo check --lib --no-default-features
cargo test --lib tarpit --no-run
```

## 10. Wave 4: extract WAF engine

This is the first high-value extraction. It should be split into multiple subagent packets, not one large move.

### Task CRATE-06: scaffold `synvoid-waf`

Files touched:

- `Cargo.toml`
- `crates/synvoid-waf/Cargo.toml`
- `crates/synvoid-waf/src/lib.rs`

Initial dependency estimate:

```toml
[dependencies]
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
synvoid-utils = { path = "../synvoid-utils", features = ["buffer"] }
synvoid-challenge = { path = "../synvoid-challenge" }
synvoid-tarpit = { path = "../synvoid-tarpit" }
arc-swap = "1"
dashmap = "7.0.0-rc2"
moka = { version = "0.12", features = ["sync", "future"] }
regex = "1"
aho-corasick = "1.1"
unicode-normalization = "0.1"
libinjectionrs = "0.1"
isbot = "0.1"
metrics = "0.22"
parking_lot = "0.12"
sha2 = "0.10"
hex = "0.4"
subtle = "2"
chrono = { workspace = true }
serde = { workspace = true }
```

Do not include Hyper, Axum, supervisor, worker, DNS, Raft, Quinn, Wasmtime, or YARA unless proven unavoidable.

### Task CRATE-07: move attack detection first

Move from:

```text
src/waf/attack_detection/
```

to:

```text
crates/synvoid-waf/src/attack_detection/
```

Why first:

- It is domain-coherent.
- It has detector-specific tests.
- It should not need process/runtime ownership.
- It removes regex/libinjection-heavy code from the root crate when fully detached.

Required adaptations:

- Replace `crate::config::...` imports with `synvoid_config::...` imports.
- Replace `crate::utils::...` imports with `synvoid_core` or local helpers when feasible.
- Keep a root shim:

```rust
// src/waf/attack_detection/mod.rs or src/waf/mod.rs during transition
pub use synvoid_waf::attack_detection::*;
```

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo test -p synvoid-waf attack_detection --no-run
cargo check --lib --no-default-features
```

### Task CRATE-08: move bot, rate limit, traffic shaping, and endpoint logic

Move these in separate commits if possible:

```text
src/waf/bot.rs
src/waf/ratelimit.rs
src/waf/traffic_shaper/
src/waf/endpoints.rs
src/waf/request_sanitization.rs
src/waf/flood.rs
```

Risk points:

- Rate limiting may touch memory config and mmap/shared-memory details.
- Endpoint error pages may touch theme/static rendering.
- Flood protection may touch system/platform code.

Stop condition:

- If a submodule requires `crate::worker`, `crate::http`, or `crate::supervisor`, leave a trait boundary instead of pulling those dependencies into `synvoid-waf`.

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo test -p synvoid-waf --no-run
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task CRATE-09: move `WafCore` last

Move the orchestration layer only after the leaves compile in `synvoid-waf`.

Expected blockers:

- `WafCoreConfig` currently references root `AuthManager`, `BlockStore`, `GeoIpManager`, `RequestServices`, config defaults, and tarpit generator.
- `WafCore` currently references `crate::worker::context::RequestServices`.
- Mesh-enabled YARA manager is re-exported through WAF.

Resolution strategy:

1. Replace `RequestServices` concrete dependency with a trait or a small adapter type.
2. Move `BlockStore` if it is WAF-specific; otherwise abstract it as a trait.
3. Keep `GeoIpManager` external initially if moving it would create too large a task.
4. Remove direct mesh/YARA re-export from WAF. Mesh or upload should own YARA distribution; WAF can consume a trait.

Suggested trait boundary:

```rust
pub trait WafRequestServices: Send + Sync + 'static {
    fn site_id(&self) -> Option<&str>;
    fn record_security_event(&self, event: SecurityEventRef<'_>);
}
```

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo test -p synvoid-waf --no-run
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

## 11. Wave 5: extract HTTP client and proxy

Only start this wave after `synvoid-waf` has compiled independently.

### Task CRATE-10: extract `synvoid-http-client`

Move from:

```text
src/http_client/
```

to:

```text
crates/synvoid-http-client/src/
```

This crate should own upstream client pools, HTTP/1/HTTP/2 typed/erased client logic, Unix-domain socket client support, and shared upstream request execution helpers.

Expected dependencies:

- hyper
- hyper-util
- hyper-rustls
- tokio
- tower
- http-body
- http-body-util
- bytes
- rustls-native-certs
- hyperlocal

Acceptance criteria:

```bash
cargo check -p synvoid-http-client
cargo check --lib --no-default-features
cargo test --lib http_client --no-run
```

### Task CRATE-11: extract `synvoid-proxy`

Move from:

```text
src/proxy/
src/proxy_cache/
src/upstream/
src/router.rs
src/location_matcher.rs
```

Not all of these must move in one task. Prefer moving cache/location/upstream first, then proxy orchestration.

Dependencies:

- synvoid-core
- synvoid-config
- synvoid-http-client
- synvoid-waf only if proxy needs WAF decisions directly; prefer using core verdicts

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 12. Wave 6: extract mesh gradually

Mesh is large and should not be the first major extraction. The current mesh module includes transport, DHT, Raft, organization management, reputation, behavioral intelligence, PQ crypto wrappers, DNS-related transport extensions, YARA/WASM distribution, and security challenge logic.

### Task CRATE-12: scaffold `synvoid-mesh` without moving Raft out separately

Move the whole `src/mesh/` tree into `crates/synvoid-mesh/src/` only if the earlier crate boundaries have reduced root coupling enough.

Initial approach:

- Keep Raft inside `synvoid-mesh` during the first mesh extraction.
- Preserve feature gates for `mesh` and `dns` transport extensions.
- Keep root `src/mesh/mod.rs` as a compatibility re-export while callers migrate.

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --no-default-features
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
```

### Task CRATE-13: split `synvoid-consensus` from `synvoid-mesh`

Do this only after `synvoid-mesh` builds independently.

Move:

```text
crates/synvoid-mesh/src/raft/
```

to:

```text
crates/synvoid-consensus/src/
```

Goal:

- `synvoid-consensus` owns OpenRaft integration and global registry state machine.
- `synvoid-mesh` owns transport and eventual-consistency DHT.
- Communication between them happens through small traits or explicit adapter structs.

Acceptance criteria:

```bash
cargo check -p synvoid-consensus
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

Stop condition:

If splitting Raft requires broad invasive changes to mesh transport semantics, defer this task and keep Raft inside `synvoid-mesh` for another iteration.

## 13. Wave 7: extract DNS, plugin, serverless, admin, supervisor, worker

These should be later waves because they are more integration-heavy.

### Candidate extraction order

1. `synvoid-dns`: after mesh extraction stabilizes, because DNS has feature interactions with mesh.
2. `synvoid-plugin`: isolate Wasmtime and YARA-related heavy dependencies.
3. `synvoid-serverless`: isolate Spin/serverless runtime dependencies.
4. `synvoid-admin`: isolate Axum/OpenAPI/schema-heavy admin API dependencies.
5. `synvoid-worker`: isolate UnifiedServerWorker and CPU worker lifecycle.
6. `synvoid-supervisor`: isolate supervisor control plane and process lifecycle.
7. `synvoid-cli`: move Clap parsing and command dispatch out of `src/main.rs`.

The most compile-time valuable of these are likely `synvoid-plugin`, `synvoid-serverless`, `synvoid-admin`, and `synvoid-dns`, because they keep heavy dependencies out of common WAF/proxy iteration.

## 14. Root crate transition strategy

During the transition, the root `synvoid` crate should remain the compatibility facade. This minimizes breakage for binaries, examples, tests, and user-facing imports.

Pattern:

```rust
// src/lib.rs
pub use synvoid_core as core;
pub use synvoid_waf as waf;
pub use synvoid_challenge as challenge;
pub use synvoid_tarpit as tarpit;
```

For modules that are moved, prefer re-export shims over immediate global import rewrites. After all tests pass, later cleanup agents can replace `synvoid::waf::...` paths with direct crate imports where beneficial.

Do not delete old module directories until their shims compile and tests pass.

## 15. Subagent execution protocol

Each subagent should receive exactly one task ID and the following constraints:

1. Do not perform opportunistic cleanup outside the task.
2. Do not change runtime behavior unless the task explicitly requires it.
3. Preserve public APIs through root re-export shims where practical.
4. Run the task-specific acceptance commands.
5. Update this plan with status notes only after successful local validation.
6. If an extraction creates circular dependencies, stop and report the cycle instead of adding a reverse dependency.
7. If a new crate needs a heavy dependency, justify it in the task note.

Recommended subagent prompt template:

```text
You are implementing SynVoid crate modularization task CRATE-XX from plans/crate_modularization_refactor.md.
Scope is limited to that task. Preserve behavior. Keep root compatibility re-exports where possible. Do not introduce dependencies from extracted crates back to the root synvoid crate. Run the acceptance commands listed for the task and report failures with exact compiler errors.
```

## 16. Validation matrix

Every completed wave must pass:

```bash
cargo fmt
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

Before merging a major wave, also run:

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

If clippy is noisy because of pre-existing warnings, run the narrower crate-level clippy first and record the broader failure separately.

## 17. Success metrics

The refactor should be considered successful only if it improves at least two of these:

1. Incremental `cargo check` after editing WAF code is materially faster.
2. Incremental `cargo check` after editing challenge/tarpit code avoids rebuilding HTTP/mesh/DNS/plugin-heavy code.
3. `cargo check -p synvoid-waf` works independently.
4. Heavy dependencies move out of root where possible.
5. Agents can modify WAF/challenge/proxy code with narrower context.
6. Feature profile checks remain stable.

Suggested concrete targets:

- `cargo check -p synvoid-waf` under 25-35% of full workspace check time.
- Editing `crates/synvoid-waf/src/attack_detection/*` should not rebuild mesh, DNS, admin UI, plugin, serverless, or supervisor crates once those are extracted.
- Root `Cargo.toml` direct dependency list should shrink over time; dependencies should move to the crate that owns the behavior.

## 18. High-risk areas

### `synvoid-config`

This crate already carries schema/OpenAPI dependencies. That is useful for API generation but may be expensive. Do not split it immediately, but consider a later `synvoid-config-schema` crate if compile timings show `schemars`/`utoipa` dominate builds.

Potential later split:

```text
synvoid-config-core      # config structs + serde/toml validation
synvoid-config-schema    # schemars/utoipa/OpenAPI derives and exports
```

This may require derive-gating and is not a first-wave task.

### WAF/root coupling

`WafCore` currently references root-owned managers such as auth, block store, GeoIP, request services, config defaults, and tarpit. Extract leaves first. Do not start with `WafCore`.

### Mesh/Raft coupling

Mesh currently owns both DHT and Raft. Extract mesh first as one crate if necessary, then split consensus later. Trying to split DHT/Raft before mesh compiles independently is likely to produce high churn.

### Admin/OpenAPI coupling

The main binary directly exports schemas and OpenAPI. Keep this behavior intact while moving code. Do not break `synvoid --export-openapi` or `synvoid --export-api-spec`.

### Feature profiles

The existing developer guide expects these profiles to work:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Every wave must preserve them.

## 19. Recommended branch strategy

Use one branch per wave, not one branch per entire refactor.

```text
refactor/crate-00-baseline
refactor/crate-01-core
refactor/crate-03-testkit
refactor/crate-04-challenge-tarpit
refactor/crate-06-waf
refactor/crate-10-http-proxy
refactor/crate-12-mesh
```

Within each wave, allow small PRs or commits per task ID. Avoid long-running branches that move many modules at once.

## 20. First three concrete tickets

### Ticket 1: CRATE-00 compile baseline

Create compile-time baseline script and metrics file. No behavior changes.

### Ticket 2: CRATE-01 core scaffold

Add `crates/synvoid-core` and workspace membership. No type moves except trivial tests if needed.

### Ticket 3: CRATE-02 core low-risk moves

Move only leaf shared types/functions that do not introduce heavy dependencies. Preserve root re-exports.

These three tickets are deliberately conservative. They will reveal whether the repo has hidden reverse dependencies before any risky subsystem move.
