# SynVoid Continued Crate Modularization Plan

> Status: proposed continuation plan after the initial crate modularization wave.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one task packet at a time.
> Primary goal: turn the root `synvoid` crate into a thin compatibility facade and binary composition crate, while moving remaining high-churn/heavy subsystems into independently checkable crates.

## 0. Context and current state

The first modularization wave has already landed. The workspace now includes extracted subsystem crates such as:

```text
crates/synvoid-core
crates/synvoid-utils
crates/synvoid-config
crates/synvoid-challenge
crates/synvoid-testkit
crates/synvoid-tarpit
crates/synvoid-waf
crates/synvoid-proxy-cache
crates/synvoid-tls
crates/synvoid-plugin-runtime
crates/synvoid-http-client
crates/synvoid-serverless
crates/synvoid-geoip
crates/synvoid-integrity
crates/synvoid-upstream
crates/synvoid-tunnel
```

This is a real improvement over the earlier root-dominant workspace. However, the root `synvoid` package still directly owns many large modules and heavy dependencies. In particular, the root crate still contains or directly exposes:

```text
src/admin
src/app_server
src/auth
src/block_store
src/cgi
src/dns
src/fastcgi
src/http
src/http3
src/mesh
src/plugin
src/process
src/proxy
src/router.rs
src/sandbox
src/server
src/startup
src/static_files
src/streaming
src/supervisor
src/tcp
src/udp
src/upload
src/waf
src/worker
```

The current priority is no longer simply to create more crates. The priority is to evacuate dependencies from the root crate, complete partially extracted subsystem crates, and reduce the amount of root code that must be rechecked during ordinary WAF/proxy/HTTP iteration.

## 1. Refactor thesis

The first refactor wave created subsystem crates. The second wave should make those crates structurally useful.

The root crate should become:

1. a compatibility facade that re-exports stable subsystem crates;
2. a binary composition package for `synvoid`, `synvoid-vpn`, and `server`;
3. a narrow home for temporary integration glue that has not yet been assigned to a subsystem crate.

The root crate should stop being:

1. the owner of full WAF orchestration;
2. the owner of reverse proxy execution;
3. the owner of server-side Hyper/Tower request pipeline;
4. the owner of DNS, mesh, admin API, and app-handler implementation;
5. the direct holder of dependencies already owned by extracted crates.

## 2. Hard constraints for subagents

These constraints are mandatory.

1. Extracted crates must not depend on the root `synvoid` crate.
2. The root `synvoid` crate may depend on extracted crates during transition.
3. Root module shims are allowed and preferred during migration.
4. Do not perform broad cleanup while moving code.
5. Do not change runtime behavior unless a task explicitly requires a behavior-preserving adapter.
6. Preserve existing feature profile checks.
7. Preserve existing binary commands, especially config validation, OpenAPI export, worker modes, supervisor mode, mesh-agent mode, WASM jail mode, and YARA jail mode.
8. When a task would require a circular dependency, stop and report the cycle instead of adding a reverse dependency.
9. When a task would require a new heavy dependency in a low-level crate, stop and report the dependency pressure.
10. Each task should finish with a narrow validation command set.

## 3. Always-run validation profile

At the end of every wave, run:

```bash
cargo fmt
cargo check --workspace --all-targets
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

For smaller task packets, use the task-specific commands first. If those pass, run the wave-level matrix before declaring the wave complete.

If full workspace clippy is too noisy due to unrelated pre-existing issues, run crate-level clippy for the touched crates and record the broader failure separately:

```bash
cargo clippy -p <crate> --all-targets -- -D warnings
```

## 4. Wave A: root dependency evacuation audit

Purpose: identify which dependencies in root `Cargo.toml` are still genuinely root-owned and which should be moved or removed now that subsystem crates exist.

This wave should happen before any further large code movement. It gives later subagents a dependency map and prevents duplicate dependency drift.

### Task CONT-A01: create root dependency ownership matrix

Files touched:

```text
plans/root_dependency_ownership.md
```

Do not change source code in this task.

Create a table with columns:

```text
Dependency | Current root reason | True owner crate | Action | Notes
```

Use these action values:

```text
KEEP_ROOT
MOVE_TO_EXISTING_CRATE
MOVE_TO_NEW_CRATE
REMOVE_FROM_ROOT
FEATURE_FORWARD_ONLY
UNKNOWN_INVESTIGATE
```

At minimum, classify these dependency groups:

```text
Hyper/Tower/Axum stack:
  tokio, hyper, hyper-util, hyper-rustls, tower, tower-http, axum, axum-extra,
  http-body, http-body-util, tokio-util, hyperlocal

TLS/crypto:
  rustls, tokio-rustls, rustls-native-certs, rustls-pki-types,
  rustls-post-quantum, x509-parser, instant-acme, aws-lc-rs,
  rcgen, webpki-roots, subtle, zeroize, ed25519-dalek, x25519-dalek,
  aes-gcm, hkdf, hmac, rsa, pqc

WAF/detection:
  isbot, regex, aho-corasick, unicode-normalization, libinjectionrs,
  bloomfilter, yara-x, stegoeggo

Storage/cache:
  rusqlite, moka, dashmap, parking_lot, memmap2, lru_time_cache,
  linked-hash-map, indexmap, ahash, smallvec

Networking/control plane:
  quinn, h3, h3-quinn, tokio-tungstenite, tonic, tonic-reflection, tonic-prost,
  openraft, socket2, ipnetwork, httparse

App handlers/runtime:
  fastcgi-client, wasmtime, libloading, lightningcss, minify-html,
  minify-js, brotli, flate2, tar, walkdir, infer

Observability/admin/schema:
  metrics, metrics-exporter-prometheus, tracing, tracing-subscriber,
  tracing-appender, log, syslog, sd-notify, schemars, utoipa,
  utoipa-swagger-ui, prost, prost-build

Platform/system:
  nix, libc, windows-sys, sysinfo, notify, daemonize2, dirs, tempfile
```

Acceptance criteria:

```bash
cargo check --workspace --all-targets
```

Expected output:

A dependency ownership document that later subagents can use without rediscovering the graph.

### Task CONT-A02: root dependency pruning pass 1

Depends on: CONT-A01.

Files touched:

```text
Cargo.toml
```

Remove root dependencies that are clearly unused by root code and are already owned by extracted crates.

Candidate removals must be verified with compiler feedback. Do not remove uncertain dependencies in bulk.

Procedure:

1. Pick 3-8 obvious candidates from `plans/root_dependency_ownership.md` marked `REMOVE_FROM_ROOT` or `MOVE_TO_EXISTING_CRATE`.
2. Remove them from root `[dependencies]` only.
3. Run targeted checks.
4. If root code still requires the dependency, revert that dependency removal and mark it `KEEP_ROOT_FOR_NOW` in the matrix.

Acceptance criteria:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
```

Stop condition:

If removing a dependency creates many errors across unrelated modules, revert that specific dependency and leave a note. Do not chase broad code movement in this task.

### Task CONT-A03: root feature forwarding cleanup

Depends on: CONT-A01.

Files touched:

```text
Cargo.toml
```

Goal:

Root features should forward into owning crates when possible instead of directly enabling heavy optional dependencies in root.

Examples of desired direction:

```toml
mesh = ["synvoid-config/mesh", "synvoid-serverless/mesh"]
dns = ["synvoid-config/dns"]
wireguard = ["synvoid-tunnel/wireguard"]
tun-rs = ["synvoid-tunnel/tun-rs"]
origin_key_exchange = ["synvoid-integrity/origin_key_exchange"]
```

Do not force this if the code has not yet moved. This task should only forward features that already have owning crates.

Acceptance criteria:

```bash
cargo check --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

## 5. Wave B: finish WAF extraction

Purpose: make `synvoid-waf` the owner of WAF logic, not merely attack detection/bot/request sanitization.

Current state:

`crates/synvoid-waf` owns:

```text
attack_detection
bot
request_sanitization
```

Root `src/waf` still owns many WAF components:

```text
asn_tracker
endpoints
flood
ip_feed
mitigation
probe_tracker
ratelimit
rule_feed
threat_intel
threat_level
traffic_shaper
violation_tracker
WafCore
WafCoreConfig
WafDecision
TestModeConfig
WafConfig
```

This wave should be broken into multiple small tasks. Do not move `WafCore` first.

### Task CONT-B01: move WAF result/config primitives

Files likely touched:

```text
crates/synvoid-core/src/verdict.rs
crates/synvoid-core/src/lib.rs
crates/synvoid-waf/src/lib.rs
src/waf/mod.rs
```

Move or duplicate-then-reexport low-risk primitives:

```text
WafDecision
TestModeConfig
WafConfig
```

Caveat:

`WafDecision` currently references `ChallengeType`. If `ChallengeType` lives in `synvoid-challenge`, use `synvoid_challenge::ChallengeType`. If root compatibility requires `crate::challenge::ChallengeType`, keep a root re-export shim.

Preferred final direction:

```text
synvoid-challenge owns ChallengeType.
synvoid-waf owns WafDecision/TestModeConfig/WafConfig.
root src/waf/mod.rs re-exports those types.
```

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo test --lib waf --no-run
```

Stop condition:

If moving `WafDecision` forces `synvoid-waf` to depend on root `synvoid`, stop and create a small adapter instead.

### Task CONT-B02: move rate limiting and flood protection

Move:

```text
src/waf/ratelimit.rs
src/waf/flood.rs
```

To:

```text
crates/synvoid-waf/src/ratelimit.rs
crates/synvoid-waf/src/flood.rs
```

Adapt imports from `crate::config` to `synvoid_config` where possible.

Keep root shims:

```rust
// src/waf/ratelimit.rs
pub use synvoid_waf::ratelimit::*;

// src/waf/flood.rs
pub use synvoid_waf::flood::*;
```

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo test --lib ratelimit --no-run
cargo test --lib flood --no-run
```

Stop condition:

If rate limiting depends on shared-memory/platform code that would pull `nix`, `libc`, or root process modules into `synvoid-waf`, isolate that portion behind a trait and leave platform-backed implementation in root for a later task.

### Task CONT-B03: move traffic shaping and connection limiting

Move:

```text
src/waf/traffic_shaper/
```

To:

```text
crates/synvoid-waf/src/traffic_shaper/
```

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo test --lib traffic_shaper --no-run
```

Stop condition:

If this pulls in root metrics/platform/process code, add callback traits or simple metrics adapters instead of pulling root modules into `synvoid-waf`.

### Task CONT-B04: move endpoint blocking and error-page primitives

Move:

```text
src/waf/endpoints.rs
```

To:

```text
crates/synvoid-waf/src/endpoints.rs
```

Caveat:

If endpoint blocking owns static themed HTML generation, split pure decision logic from rendering. `synvoid-waf` should own endpoint decision logic. Root/http/theme can own rendering if needed.

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo test --lib endpoints --no-run
```

### Task CONT-B05: move threat tracking leaves

Move candidates:

```text
src/waf/threat_level.rs
src/waf/violation_tracker.rs
src/waf/probe_tracker.rs
src/waf/asn_tracker.rs
src/waf/ip_feed.rs
src/waf/rule_feed.rs
src/waf/threat_intel.rs
```

Do not move all at once unless imports are trivial. Preferred packet split:

```text
B05a: threat_level + violation_tracker
B05b: probe_tracker + asn_tracker
B05c: ip_feed + rule_feed + threat_intel
```

Potential alternate target:

If these modules are large and conceptually distinct, create:

```text
crates/synvoid-threat-intel
```

Then `synvoid-waf` depends on `synvoid-threat-intel` for tracking and feeds.

Decision rule:

Use `synvoid-threat-intel` if the feed/tracker code needs GeoIP, network fetching, persistence, mesh export, or admin API serialization. Keep it inside `synvoid-waf` if it is pure in-memory WAF state.

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task CONT-B06: introduce WAF service traits for root-owned integrations

Before moving `WafCore`, define traits for dependencies that currently tie WAF to root modules.

Candidate root-owned dependencies:

```text
AuthManager
BlockStore
GeoIpManager
RequestServices
YaraRulesManager
ChallengeManager
```

Create traits in `synvoid-waf`, `synvoid-core`, or `synvoid-threat-intel` depending on domain:

```rust
pub trait BlockListStore: Send + Sync + 'static {
    fn is_blocked(&self, ip: std::net::IpAddr) -> bool;
    fn block(&self, ip: std::net::IpAddr, reason: &str);
}

pub trait GeoIpLookup: Send + Sync + 'static {
    fn lookup_country(&self, ip: std::net::IpAddr) -> Option<String>;
    fn lookup_asn(&self, ip: std::net::IpAddr) -> Option<u32>;
}

pub trait WafRequestServices: Send + Sync + 'static {
    fn site_id(&self) -> Option<&str>;
}
```

Do not overdesign. Start with only methods needed by current `WafCore`.

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo check --lib --no-default-features
```

### Task CONT-B07: move `WafCore` last

Move orchestration after all leaves and traits are stable.

Move:

```text
src/waf/mod.rs WafCore-related implementation
```

To:

```text
crates/synvoid-waf/src/core.rs
```

Root `src/waf/mod.rs` should become mostly re-exports plus any temporary adapters.

Acceptance criteria:

```bash
cargo check -p synvoid-waf
cargo test -p synvoid-waf --no-run
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

## 6. Wave C: extract reverse proxy crate

Purpose: move root `src/proxy` into `crates/synvoid-proxy`, using existing extracted crates.

Current related crates:

```text
synvoid-http-client
synvoid-upstream
synvoid-proxy-cache
synvoid-waf
synvoid-config
```

Current root-owned code:

```text
src/proxy/
src/router.rs
src/location_matcher.rs
```

### Task CONT-C01: scaffold `synvoid-proxy`

Files touched:

```text
Cargo.toml
crates/synvoid-proxy/Cargo.toml
crates/synvoid-proxy/src/lib.rs
```

Initial dependencies:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
synvoid-http-client = { path = "../synvoid-http-client" }
synvoid-upstream = { path = "../synvoid-upstream" }
synvoid-proxy-cache = { path = "../synvoid-proxy-cache" }
synvoid-waf = { path = "../synvoid-waf" }
bytes = "1"
http = "1"
http-body-util = "0.1"
tokio = { version = "1", features = ["rt", "time", "sync", "macros"] }
tracing = "0.1"
metrics = "0.22"
subtle = "2"
```

Avoid depending on root `synvoid`.

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo check --workspace --all-targets
```

### Task CONT-C02: move proxy leaf modules

Move first:

```text
src/proxy/headers.rs
src/proxy/retry.rs
src/proxy/governor.rs
src/location_matcher.rs
```

To:

```text
crates/synvoid-proxy/src/headers.rs
crates/synvoid-proxy/src/retry.rs
crates/synvoid-proxy/src/governor.rs
crates/synvoid-proxy/src/location_matcher.rs
```

Keep root shims.

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo test -p synvoid-proxy --no-run
cargo check --lib --no-default-features
```

### Task CONT-C03: move router and upstream routing glue if clean

Move:

```text
src/router.rs
```

To:

```text
crates/synvoid-proxy/src/router.rs
```

Only do this if it does not pull in app handler implementations directly. If router depends on concrete CGI/FastCGI/static/serverless modules, split routing types from app dispatch.

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
```

### Task CONT-C04: move proxy executor/dispatch

Move:

```text
src/proxy/dispatch.rs
src/proxy/executor.rs
src/proxy/streaming.rs
src/proxy/client_registry.rs
```

To:

```text
crates/synvoid-proxy/src/
```

Do not move `ProxyServer` until leaves compile.

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
```

### Task CONT-C05: move `ProxyServer`

Move the main proxy orchestrator from root `src/proxy/mod.rs` into `crates/synvoid-proxy`.

Root `src/proxy/mod.rs` should become re-exports and temporary adapters.

Acceptance criteria:

```bash
cargo check -p synvoid-proxy
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If `ProxyServer` still requires concrete root `WafCore`, pause until Wave B completes or introduce a small WAF interface trait.

## 7. Wave D: extract server-side HTTP pipeline

Purpose: isolate Hyper/Tower HTTP server code from root and from WAF/proxy logic.

Candidate crate:

```text
crates/synvoid-http
```

Candidate root modules:

```text
src/http
src/streaming
src/listener
```

HTTP/3 should probably be separate:

```text
crates/synvoid-http3
```

because QUIC/H3 dependencies are heavy and relatively specialized.

### Task CONT-D01: scaffold `synvoid-http`

Files touched:

```text
Cargo.toml
crates/synvoid-http/Cargo.toml
crates/synvoid-http/src/lib.rs
```

Initial dependencies:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
synvoid-waf = { path = "../synvoid-waf" }
synvoid-proxy = { path = "../synvoid-proxy" }
bytes = "1"
http = "1"
http-body = "1"
http-body-util = "0.1"
hyper = { version = "1", features = ["http1", "http2", "server"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto", "server-graceful", "http1", "http2"] }
tokio = { version = "1", features = ["rt", "net", "time", "sync", "macros", "io-util"] }
tower = { version = "0.5", features = ["util"] }
tracing = "0.1"
metrics = "0.22"
```

Acceptance criteria:

```bash
cargo check -p synvoid-http
cargo check --workspace --all-targets
```

### Task CONT-D02: move HTTP leaf utilities

Move low-coupling HTTP helpers first:

```text
src/http/body helpers
src/http/header helpers
src/streaming primitives that do not depend on root WafCore
src/listener configuration primitives if not platform-bound
```

Exact files should be discovered by the subagent from `src/http/`.

Acceptance criteria:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
```

### Task CONT-D03: move main HTTP server pipeline

Move the main Hyper request pipeline after WAF/proxy crates are stable.

Requirements:

1. HTTP crate calls into WAF through `synvoid-waf` public API or trait.
2. HTTP crate calls into proxy through `synvoid-proxy` public API.
3. HTTP crate does not depend on root `synvoid`.
4. Root `src/http/mod.rs` becomes a re-export shim.

Acceptance criteria:

```bash
cargo check -p synvoid-http
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

### Task CONT-D04: extract `synvoid-http3`

Only start after `synvoid-http` compiles independently.

Move:

```text
src/http3
```

To:

```text
crates/synvoid-http3/src
```

Dependencies:

```toml
quinn = { version = "0.11", features = ["runtime-tokio"] }
h3 = "0.0.8"
h3-quinn = "0.0.10"
rustls = "0.23"
tokio = { version = "1", features = ["rt", "time", "sync", "macros", "io-util"] }
```

Acceptance criteria:

```bash
cargo check -p synvoid-http3
cargo check --no-default-features --features dns,mesh
```

## 8. Wave E: extract DNS crate

Purpose: isolate Hickory/DNSSEC/DoH/DoT/DoQ code from ordinary WAF/proxy/server builds.

Candidate crate:

```text
crates/synvoid-dns
```

Move:

```text
src/dns
```

### Task CONT-E01: scaffold `synvoid-dns`

Files touched:

```text
Cargo.toml
crates/synvoid-dns/Cargo.toml
crates/synvoid-dns/src/lib.rs
```

Initial dependencies should include only what DNS code needs:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config", features = ["dns"] }
hickory-proto = { version = "0.26", features = ["dnssec-ring"] }
hickory-resolver = { version = "0.26", features = ["system-config", "recursor", "dnssec-ring"] }
tokio = { version = "1", features = ["rt", "net", "time", "sync", "macros"] }
tracing = "0.1"
thiserror = "2"
```

Acceptance criteria:

```bash
cargo check -p synvoid-dns
cargo check --no-default-features --features dns
```

### Task CONT-E02: move DNS module tree

Move:

```text
src/dns/*
```

To:

```text
crates/synvoid-dns/src/*
```

Root `src/dns/mod.rs` should become a feature-gated re-export shim:

```rust
pub use synvoid_dns::*;
```

Acceptance criteria:

```bash
cargo check -p synvoid-dns
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If DNS imports root mesh types directly, introduce a trait or leave mesh-DNS glue in root until `synvoid-mesh` exists.

## 9. Wave F: extract admin API and schema/OpenAPI ownership

Purpose: move Axum/OpenAPI/admin dependencies out of root where possible.

Candidate crate:

```text
crates/synvoid-admin
```

Move:

```text
src/admin
src/auth if tightly admin-specific, or create synvoid-auth separately
```

### Task CONT-F01: decide auth ownership

Do not move code yet. Create a short note in:

```text
plans/auth_admin_boundary.md
```

Answer:

1. Is `src/auth` only admin auth, or does WAF challenge/auth also use it?
2. Should auth become `synvoid-auth`, or stay with `synvoid-admin`?
3. Which crates need to consume auth primitives?

Acceptance criteria:

```bash
cargo check --workspace --all-targets
```

### Task CONT-F02: scaffold `synvoid-admin`

Initial dependencies likely:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
axum = { version = "0.8", features = ["ws", "macros", "json"] }
axum-extra = { version = "0.10", features = ["typed-header"] }
tower-http = { version = "0.6", features = ["cors"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
schemars = "0.8"
utoipa = { version = "5", features = ["axum_extras", "chrono"] }
utoipa-swagger-ui = { version = "9", features = ["axum", "vendored"], optional = true }
```

Acceptance criteria:

```bash
cargo check -p synvoid-admin
cargo check --workspace --all-targets
```

### Task CONT-F03: move OpenAPI/schema export first

Move OpenAPI structs and export helpers first, preserving:

```bash
synvoid --export-openapi
synvoid --export-api-spec
```

Acceptance criteria:

```bash
cargo run -- --export-openapi >/tmp/synvoid-openapi.json
cargo run -- --export-api-spec >/tmp/synvoid-api-spec.json
cargo check -p synvoid-admin
```

### Task CONT-F04: move admin routes and state

Move admin route construction, handlers, WebSocket state, and metrics endpoints.

Stop condition:

If admin state directly owns supervisor internals, define an admin-facing trait instead of depending on root supervisor modules.

Acceptance criteria:

```bash
cargo check -p synvoid-admin
cargo check --workspace --all-targets
```

## 10. Wave G: extract mesh wholesale, then split consensus later

Purpose: isolate mesh/DHT/Raft/PQ/distributed-system code from ordinary root builds.

Candidate crates:

```text
crates/synvoid-mesh
crates/synvoid-consensus later
```

Do not split Raft out first. Move mesh as one crate, stabilize, then split Raft.

### Task CONT-G01: scaffold `synvoid-mesh`

Initial dependencies likely include:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config", features = ["mesh"] }
synvoid-utils = { path = "../synvoid-utils" }
synvoid-integrity = { path = "../synvoid-integrity" }
synvoid-plugin-runtime = { path = "../synvoid-plugin-runtime", optional = true }
pqc = { path = "../../pqc", features = ["async"] }
openraft = "..."
quinn = { version = "0.11", features = ["runtime-tokio"] }
tokio = { version = "1", features = ["rt", "net", "time", "sync", "macros"] }
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }
tracing = "0.1"
thiserror = "2"
```

Use the exact OpenRaft version already in the root lockfile/manifest.

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --no-default-features
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

### Task CONT-G02: move mesh leaf modules first

Move low-coupling leaves before transport:

```text
audit
audit_session
behavioral
behavioral_intel
reputation
network_security
security
security_challenge
verification
crypto_verification
kem
ml_dsa
hybrid_signature
tier_key_encryption
```

Keep root shims under `src/mesh`.

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

### Task CONT-G03: move DHT tree

Move:

```text
src/mesh/dht
```

To:

```text
crates/synvoid-mesh/src/dht
```

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --features mesh
cargo test -p synvoid-mesh dht --no-run
cargo check --no-default-features --features mesh
```

### Task CONT-G04: move organization/cert/protocol/session

Move:

```text
organization
org_key_manager
cert
cert_dist
protocol
session
peer_auth
passover_key_exchange
ml_kem_key_exchange
```

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

### Task CONT-G05: move transport and proxy last

Move:

```text
transport*
transport_core
transport_types
transports
backend
proxy
topology
discovery
hierarchical_routing
wasm_dist
yara_rules
```

Acceptance criteria:

```bash
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If mesh transport depends heavily on root supervisor/worker runtime, leave the process-spawn glue in root and extract only transport library logic.

### Task CONT-G06: split `synvoid-consensus`

Only after `synvoid-mesh` is independently compiling.

Move:

```text
crates/synvoid-mesh/src/raft
```

To:

```text
crates/synvoid-consensus/src
```

Acceptance criteria:

```bash
cargo check -p synvoid-consensus
cargo check -p synvoid-mesh --features mesh
cargo check --no-default-features --features mesh
```

Stop condition:

If the Raft network implementation is still deeply fused to mesh transport, defer this split. A separate consensus crate is desirable, but not at the cost of unstable abstraction gymnastics.

## 11. Wave H: app handlers and runtime glue

Purpose: move application backend handlers out of root and isolate optional runtime dependencies.

Candidate crate:

```text
crates/synvoid-app-handlers
```

Move candidates:

```text
src/static_files
src/cgi
src/fastcgi
src/php
src/mime
src/app_server
src/upload
```

`src/serverless` and `src/plugin` may already be partly backed by `synvoid-serverless` and `synvoid-plugin-runtime`; root shims should be reduced after app-handler extraction.

### Task CONT-H01: scaffold `synvoid-app-handlers`

Initial dependencies likely:

```toml
synvoid-core = { path = "../synvoid-core" }
synvoid-config = { path = "../synvoid-config" }
synvoid-serverless = { path = "../synvoid-serverless" }
synvoid-plugin-runtime = { path = "../synvoid-plugin-runtime" }
synvoid-http-client = { path = "../synvoid-http-client" }
bytes = "1"
http = "1"
http-body-util = "0.1"
tokio = { version = "1", features = ["rt", "fs", "process", "io-util", "time", "macros"] }
tracing = "0.1"
```

Acceptance criteria:

```bash
cargo check -p synvoid-app-handlers
cargo check --workspace --all-targets
```

### Task CONT-H02: move MIME/static file leaves

Move:

```text
src/mime
src/static_files
```

Acceptance criteria:

```bash
cargo check -p synvoid-app-handlers
cargo check --lib --no-default-features
```

### Task CONT-H03: move CGI/FastCGI/PHP handlers

Move:

```text
src/cgi
src/fastcgi
src/php
```

Acceptance criteria:

```bash
cargo check -p synvoid-app-handlers
cargo check --lib --no-default-features
```

### Task CONT-H04: move upload handling if not WAF-owned

Move:

```text
src/upload
```

Decision rule:

If upload handling is mostly malware/YARA/security scanning, it may belong in a future `synvoid-upload` or `synvoid-security-scanner` crate instead of generic app handlers. Prefer a separate crate if it depends on `yara-x`, stegoeggo, quarantine, and scanning policy.

Acceptance criteria:

```bash
cargo check -p synvoid-app-handlers
cargo check --workspace --all-targets
```

## 12. Wave I: supervisor, worker, platform, and CLI cleanup

Purpose: reduce root after data-plane/domain crates are stable.

Candidate crates:

```text
crates/synvoid-supervisor
crates/synvoid-worker
crates/synvoid-platform
crates/synvoid-cli
```

This wave is lower priority for compile wins but important for architecture cleanliness and agent context isolation.

### Task CONT-I01: extract CLI parsing and command dispatch

Move Clap `Args` and top-level command dispatch out of `src/main.rs` into:

```text
crates/synvoid-cli
```

`src/main.rs` should become thin:

```rust
fn main() {
    synvoid_cli::run();
}
```

Acceptance criteria:

```bash
cargo check -p synvoid-cli
cargo run -- --help
cargo run -- --configtest
```

Do not break worker/supervisor modes.

### Task CONT-I02: extract platform/system helpers

Move platform-specific helpers from:

```text
src/platform
src/sandbox if platform-only
src/utils platform-specific pieces
```

To:

```text
crates/synvoid-platform
```

Acceptance criteria:

```bash
cargo check -p synvoid-platform
cargo check --workspace --all-targets
```

### Task CONT-I03: extract worker crate

Move:

```text
src/worker
```

To:

```text
crates/synvoid-worker
```

Only after WAF/proxy/http/app-handler crates expose stable APIs.

Acceptance criteria:

```bash
cargo check -p synvoid-worker
cargo check --workspace --all-targets
cargo run -- --unified-server-worker --help || true
```

### Task CONT-I04: extract supervisor crate

Move:

```text
src/supervisor
src/process
src/drain
src/startup supervisor-specific pieces
```

To:

```text
crates/synvoid-supervisor
```

Acceptance criteria:

```bash
cargo check -p synvoid-supervisor
cargo check --workspace --all-targets
```

## 13. Optional Wave J: split config schema from config core

Only do this if compile timings show `synvoid-config`, `schemars`, or `utoipa` as a persistent bottleneck.

Candidate crates:

```text
crates/synvoid-config-core
crates/synvoid-config-schema
```

Preferred lower-churn alternative:

Keep crate name `synvoid-config`, but gate schema dependencies behind a feature:

```toml
[features]
default = []
schema = ["dep:schemars", "dep:utoipa"]
```

Risk:

Many config structs likely derive `JsonSchema` and `ToSchema`. Feature-gating derives can be noisy.

Task should not be attempted until root dependency evacuation and admin extraction are done.

## 14. Recommended implementation order

Use this order unless compile timings prove a different bottleneck:

```text
A01  root dependency ownership matrix
A02  root dependency pruning pass 1
A03  root feature forwarding cleanup
B01  WAF primitives
B02  WAF rate/flood
B03  WAF traffic shaping
B04  WAF endpoints
B05  WAF threat tracking or synvoid-threat-intel decision
B06  WAF integration traits
B07  WafCore move
C01  synvoid-proxy scaffold
C02  proxy leaf modules
C03  router split
C04  proxy executor/dispatch
C05  ProxyServer move
D01  synvoid-http scaffold
D02  HTTP leaf utilities
D03  HTTP server pipeline
D04  synvoid-http3
E01  synvoid-dns scaffold
E02  DNS move
F01  auth/admin boundary note
F02  synvoid-admin scaffold
F03  OpenAPI/schema export move
F04  admin routes/state move
G01-G05 synvoid-mesh wholesale extraction
G06  synvoid-consensus split if stable
H01-H04 app handlers
I01-I04 CLI/platform/worker/supervisor cleanup
J    config schema split only if timings justify it
```

## 15. Subagent prompt template

Use this for each smaller model assignment:

```text
You are implementing SynVoid continued modularization task CONT-XX from plans/crate_modularization_continuation.md.
Scope is limited to that task. Preserve behavior. Do not introduce dependencies from extracted crates back to the root synvoid crate. Prefer root compatibility re-export shims during migration. Do not perform opportunistic cleanup. Run the task-specific validation commands and report exact failures if any.
```

For a slightly more constrained version:

```text
Implement only CONT-XX. If you encounter a circular dependency or need to pull a heavy runtime dependency into a low-level crate, stop and report the dependency edge. Do not solve it by broadening the crate dependency graph.
```

## 16. Completion criteria for the continuation refactor

This continuation effort is successful when all of the following are true:

1. `cargo check -p synvoid-waf` covers the full WAF engine, not just attack detection/bot/request sanitization.
2. `cargo check -p synvoid-proxy` covers reverse proxy execution and routing.
3. `cargo check -p synvoid-http` covers server-side HTTP/1.1 and HTTP/2 request handling.
4. DNS builds independently under `synvoid-dns`.
5. Mesh builds independently under `synvoid-mesh`, even if Raft remains inside it temporarily.
6. Root `src/lib.rs` is mostly re-exports and compatibility shims.
7. Root `Cargo.toml` no longer directly lists dependencies owned exclusively by extracted crates.
8. Existing feature profile checks still pass.
9. Existing binaries still expose the same user-facing commands.
10. Small subagents can modify WAF/proxy/HTTP/DNS/mesh code without requiring the full root crate context.

## 17. Notes on what not to do

Do not split crates merely because a module exists. Every new crate should reduce rebuild surface, dependency fanout, or agent context size.

Do not split Raft out of mesh until mesh itself builds independently.

Do not split config schema derives unless compile timings justify it.

Do not move supervisor/worker before WAF/proxy/HTTP expose stable APIs; otherwise the task will become a large runtime rewrite.

Do not let `synvoid-core` grow into a junk drawer. It should remain dependency-light and boring.

Do not let `synvoid-waf` depend on Hyper server types. Use `http` crate primitives or SynVoid request metadata types instead.

Do not let `synvoid-proxy` depend on root `WafCore` if a smaller WAF trait or decision API will work.

Do not let root feature flags become stale. Whenever code moves, move or forward the feature ownership deliberately.
