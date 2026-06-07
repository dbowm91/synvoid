# SynVoid Measurement-Driven Modularization Cleanup Plan

> Status: proposed next-pass handoff.
> Target implementer profile: smaller coding agents such as MiMo 2.5, one narrow task at a time.
> Goal: stop broad crate-splitting and switch to evidence-driven cleanup. Measure actual rebuild pain, prune root dependencies where ownership has moved, and only extract remaining modules when compile-time or coupling data justifies it.

## 0. Current state

SynVoid has completed several successful modularization passes.

Major completed boundaries:

```text
synvoid-core              cross-cutting request/routing/metrics/drain primitives
synvoid-config            typed config
synvoid-waf               WAF leaf/mid-level logic and WAF access traits
synvoid-proxy             canonical ProxyServer and proxy data-plane helpers
synvoid-http              reusable HTTP request-flow/dispatch/helper modules
synvoid-http3             HTTP/3 crate exists, server still root-owned
synvoid-static-files      static/minification/image-rights logic
synvoid-ipc               IPC messages and framing
synvoid-dns               DNS subsystem
synvoid-mesh              mesh subsystem, Raft still intentionally inside mesh
synvoid-tls               TLS/ACME/cert logic
synvoid-admin             admin/API pieces
synvoid-upload            upload/security upload pieces
synvoid-plugin-runtime    Wasmtime/plugin runtime
synvoid-serverless        serverless runtime glue
synvoid-platform          platform helpers
synvoid-cli               CLI args and related surface
```

Important consolidation milestones:

```text
root src/proxy/mod.rs is now a compatibility shim.
canonical ProxyServer lives in synvoid-proxy.
image-rights terminology is canonical; poisoning names remain only as compatibility/wire debt.
many root src/http modules are shims over synvoid-http.
```

Remaining broad roots:

```text
root src/http/server.rs remains root-owned.
root src/http3/server.rs remains root-owned.
worker and supervisor remain root-owned orchestration layers.
WafCore remains root-owned and concrete.
mesh/Raft remain together.
root Cargo.toml still has many heavy direct dependencies.
```

This state is acceptable. The next pass should avoid creating more crates by default.

## 1. Refactor thesis

The project has crossed the line from monolith to modular workspace. The next decisions should be driven by measured rebuild cost and concrete dependency ownership, not aesthetic crate count.

Use this rule:

```text
Do not extract another crate or major module unless at least one is true:

1. Compile timing data shows it is on a hot rebuild path.
2. It removes a heavy dependency from root or a high-churn crate.
3. It eliminates a root concrete dependency that blocks HTTP/HTTP3 movement.
4. It lets a small agent work on a subsystem without loading root orchestration context.
```

If none of those are true, leave the code where it is.

## 2. Non-goals

Do not do these in this pass:

```text
Do not create new crates by default.
Do not move worker.
Do not move supervisor.
Do not split Raft from mesh.
Do not move WafCore into synvoid-waf.
Do not move src/http/server.rs without measured justification and a clean dependency inventory.
Do not move src/http3/server.rs unless dependency checks show it is already trait-clean.
Do not remove IPC PoisonImage wire names.
Do not remove image_poisoning compatibility shims.
```

## 3. Validation matrix

For each task, run task-specific checks.

At the end of each wave, run:

```bash
cargo fmt
cargo check -p synvoid-waf
cargo check -p synvoid-proxy
cargo check -p synvoid-http
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo test --lib --no-run
```

At the end of the full pass, run:

```bash
cargo check --workspace --all-targets
```

Optional but preferred if available locally:

```bash
cargo build --timings
```

## 4. Wave M: compile-time measurement baseline

Purpose: establish whether the modularization effort actually improved common iteration paths and identify remaining hot spots.

### Task MDM-M01: create compile timing script

Create:

```text
scripts/measure_compile_paths.sh
```

The script should run representative checks and print wall-clock timings. Use portable shell where practical.

Suggested script body:

```bash
#!/usr/bin/env bash
set -euo pipefail

run() {
  echo "\n== $* =="
  /usr/bin/time -p "$@"
}

run cargo check -p synvoid-core
run cargo check -p synvoid-waf
run cargo check -p synvoid-proxy
run cargo check -p synvoid-http
run cargo check -p synvoid-static-files
run cargo check -p synvoid-ipc
run cargo check --lib --no-default-features
run cargo check --no-default-features --features mesh
run cargo check --no-default-features --features dns
run cargo check --no-default-features --features mesh,dns
run cargo check --workspace --all-targets
```

If `/usr/bin/time` is unavailable on the target platform, use shell `time`.

Acceptance:

```bash
bash scripts/measure_compile_paths.sh
```

If the full script is too slow locally, run at least the individual crate checks and root feature checks.

### Task MDM-M02: record measurement results

Create:

```text
plans/compile_time_measurements.md
```

Record:

```text
Command | Clean/incremental | Wall time | Notes
```

Measure at least:

```text
cargo check -p synvoid-waf
cargo check -p synvoid-proxy
cargo check -p synvoid-http
cargo check -p synvoid-static-files
cargo check --lib --no-default-features
cargo check --workspace --all-targets
```

If possible, also measure incremental edits:

```bash
touch crates/synvoid-waf/src/lib.rs && cargo check -p synvoid-waf
touch crates/synvoid-proxy/src/server.rs && cargo check -p synvoid-proxy
touch crates/synvoid-http/src/lib.rs && cargo check -p synvoid-http
touch crates/synvoid-static-files/src/image_rights.rs && cargo check -p synvoid-static-files
touch src/http/server.rs && cargo check --lib --no-default-features
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

No behavior changes in this task.

### Task MDM-M03: rank remaining compile hot spots

Update:

```text
plans/compile_time_measurements.md
```

Add section:

```text
## Hot spot ranking
```

Rank:

```text
High priority: measured hot and frequent edit path.
Medium priority: measured hot but infrequent edit path.
Low priority: not measured hot or rarely edited.
Defer: orchestration layer where extraction likely increases complexity.
```

Candidate areas:

```text
root src/http/server.rs
root src/http3/server.rs
root WafCore
worker/cpu_task
supervisor/process
admin/OpenAPI export
YARA/upload/security scanner path
rusqlite/block-store/persistence path
mesh/Raft
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 5. Wave R: root dependency ownership and pruning

Purpose: continue dependency evacuation, but only based on current ownership and compiler validation.

### Task MDM-R01: refresh root dependency ownership matrix

Update or create:

```text
plans/root_dependency_ownership.md
```

Classify each root direct dependency with:

```text
Dependency | Current root usage | True owner | Action | Evidence | Notes
```

Action values:

```text
KEEP_ROOT_FOR_NOW
REMOVE_FROM_ROOT
MOVE_TO_EXISTING_CRATE
FEATURE_FORWARD_ONLY
UNKNOWN_INVESTIGATE
```

Focus first on dependencies already known to have moved or likely moved:

```text
isbot
rustls-native-certs
tokio-util
lightningcss
minify-html
minify-js
brotli
maxminddb
wasmtime
hyperlocal
infer
sd-notify
linked-hash-map
instant-acme
rustls-post-quantum
defguard_boringtun
```

Then classify still-heavy root deps:

```text
hyper
hyper-util
hyper-rustls
tower
tower-http
axum
axum-extra
http-body
http-body-util
yara-x
rusqlite
tokio-rustls
rustls
quinn
h3
h3-quinn
libloading
schemars
utoipa
utoipa-swagger-ui
prost
prost-build
openraft
cryptoki
aws-lc-rs
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task MDM-R02: prune root dependencies in tiny batches

Only remove dependencies marked `REMOVE_FROM_ROOT` or convert feature wiring marked `FEATURE_FORWARD_ONLY`.

Rules:

```text
1-5 dependencies per commit.
Do not combine pruning with code movement.
If removal fails, restore and mark KEEP_ROOT_FOR_NOW with the compiler error summary.
Do not prune quinn/h3/h3-quinn while HTTP3 server remains root-owned.
Do not prune hyper/tower/axum while root HTTP server/admin still require them.
Do not prune openraft while root mesh feature still directly enables it.
```

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --workspace --all-targets
cargo check --no-default-features --features mesh,dns
```

### Task MDM-R03: convert dependency comments into ownership notes

Root `Cargo.toml` currently contains helpful comments such as “moved to synvoid-static-files” or “removed from root.” Consolidate durable notes into:

```text
plans/root_dependency_ownership.md
```

Keep `Cargo.toml` comments only where they prevent accidental reintroduction.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 6. Wave H: HTTP server readiness without moving it

Purpose: make main HTTP server movement a future mechanical task, or explicitly decide to keep it as root composition.

### Task MDM-H01: refresh HTTP server dependency inventory

Update:

```text
plans/http_server_dependency_inventory.md
```

Search:

```bash
rg "crate::waf::WafCore|WafCore" src/http/server.rs
rg "crate::router::Router|Router" src/http/server.rs
rg "WorkerMetrics|WorkerDrain|WorkerDrainState|crate::worker" src/http/server.rs
rg "crate::supervisor|crate::server|crate::startup" src/http/server.rs
rg "crate::proxy::ProxyServer|synvoid_proxy::ProxyServer" src/http/server.rs
rg "crate::http::" src/http/server.rs
```

Record:

```text
Concrete dependency | Location | Existing seam | Remaining blocker | Move impact | Notes
```

Acceptance:

```bash
cargo check --lib --no-default-features
```

### Task MDM-H02: replace obvious root HTTP imports with extracted-crate imports

Only replace imports that are already clean and do not require generic rewrites.

Examples:

```text
crate::http::<shim_module> -> synvoid_http::<module>
crate::proxy::ProxyServer -> synvoid_proxy::ProxyServer or root alias if needed
crate::static_files/image_rights -> synvoid_static_files::image_rights
```

Do not move `src/http/server.rs`.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

Stop condition:

If import cleanup requires changing `HttpServer` generics or worker construction flow, stop and document it rather than continuing.

### Task MDM-H03: decide HTTP server ownership policy

Update:

```text
plans/http_server_dependency_inventory.md
```

Add final decision:

```text
KEEP_ROOT_AS_COMPOSITION_LAYER
MOVE_LATER_AFTER_RUNTIME_CONTEXT
MOVE_NOW_NOT_RECOMMENDED
```

Recommended default:

```text
KEEP_ROOT_AS_COMPOSITION_LAYER unless compile timing shows src/http/server.rs is a frequent hot edit path and concrete dependencies are already reduced.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 7. Wave Q: HTTP3 readiness without forcing movement

Purpose: make HTTP3 movement evidence-based.

### Task MDM-Q01: refresh HTTP3 dependency inventory

Update:

```text
plans/http3_server_dependency_inventory.md
```

Search:

```bash
rg "WafCore|Router|WorkerMetrics|WorkerDrainState|UpstreamClientRegistry|HttpClient|FloodProtector|FloodDecision" src/http3/server.rs
rg "crate::" src/http3/server.rs
```

Record whether each dependency is:

```text
already moved to extracted crate
covered by WafProcessor
covered by WafAccess
covered by RouteResolver
covered by MetricsSink/DrainState
still root-only
```

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
```

### Task MDM-Q02: reduce trivial HTTP3 root imports

Only change imports or call signatures that are already covered by existing traits/extracted crates.

Do not move `src/http3/server.rs`.

Acceptance:

```bash
cargo check --no-default-features --features mesh,dns
cargo check -p synvoid-http3
```

Stop condition:

If change requires reworking HTTP3 server ownership/lifetimes, stop and document.

### Task MDM-Q03: decide HTTP3 move readiness

Update:

```text
plans/http3_server_dependency_inventory.md
```

Decision options:

```text
KEEP_ROOT_UNTIL_DRAIN_OR_SOCKET_SEAM
KEEP_ROOT_UNTIL_HTTP_SERVER_CONTEXT_REWORK
MOVE_READY
DEFER_LOW_VALUE
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 8. Wave S: security scanner / YARA / persistence ownership audit

Purpose: identify whether remaining heavy root dependencies `yara-x`, `rusqlite`, and related scanning/persistence crates should move.

### Task MDM-S01: audit YARA/scanning ownership

Create:

```text
plans/security_scanner_ownership.md
```

Search:

```bash
rg "yara|Yara|YARA|yara-x" src crates Cargo.toml
rg "scan_bytes|YaraScan|YaraRules|quarantine|malware" src crates
```

Record:

```text
Module/file | Current crate | Dependencies | Runtime owner | Candidate target | Notes
```

Candidate targets:

```text
synvoid-upload
synvoid-waf
synvoid-static-files
synvoid-plugin-runtime
new synvoid-security-scanner only if strongly justified
root-only for now
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

No source movement in this task.

### Task MDM-S02: audit rusqlite/persistence ownership

Create or update:

```text
plans/persistence_ownership.md
```

Search:

```bash
rg "rusqlite|Connection|backup|sqlite|Sqlite" src crates Cargo.toml
rg "BlockStore|ViolationTracker|Persistence|persist|database" src crates
```

Record:

```text
Module/file | Current crate | Data owned | Candidate target crate | Root dependency removable? | Notes
```

Candidate targets:

```text
synvoid-block-store
synvoid-waf
synvoid-metrics
synvoid-admin
root-only for now
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task MDM-S03: decide scanner/persistence extraction value

Update both inventories with one of:

```text
EXTRACT_NOW_MEASURED_HOT
EXTRACT_LATER_CLEAN_BOUNDARY
KEEP_ROOT_ORCHESTRATION
DEFER_LOW_VALUE
```

Do not extract in this task.

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 9. Wave A: admin/OpenAPI/schema ownership audit

Purpose: determine whether schema/OpenAPI crates should remain root-owned.

### Task MDM-A01: audit OpenAPI/schema ownership

Create:

```text
plans/admin_schema_ownership.md
```

Search:

```bash
rg "utoipa|ToSchema|OpenApi|schemars|JsonSchema|swagger|export-openapi|export-api-spec" src crates Cargo.toml
```

Record:

```text
File | Current crate | Exports user-facing schema? | Root binary dependency? | Candidate target | Notes
```

Candidate targets:

```text
synvoid-admin
synvoid-config
new synvoid-schema only if measured hot
root-only for binary export
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task MDM-A02: decide schema split value

Update:

```text
plans/admin_schema_ownership.md
```

Decision options:

```text
KEEP_ROOT_FOR_BINARY_EXPORT
MOVE_TO_SYNVOID_ADMIN
FEATURE_GATE_SCHEMA_DERIVES
DEFER_LOW_VALUE
```

Default recommendation:

```text
Do not split config/schema derives unless compile timings show schemars/utoipa dominate common checks.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

## 10. Wave W: worker/supervisor containment audit

Purpose: avoid premature extraction while recording actual coupling.

### Task MDM-W01: update worker/supervisor boundary note

Create or update:

```text
plans/worker_supervisor_boundary.md
```

Document:

```text
Which subsystems worker constructs.
Which subsystems supervisor constructs.
Which dependencies are legitimate orchestration dependencies.
Which dependencies are accidental and can be imported from extracted crates.
Whether worker/supervisor are frequent edit paths.
```

Acceptance:

```bash
cargo check --workspace --all-targets
```

### Task MDM-W02: replace accidental root imports only

Only replace imports where the extracted crate already owns the type and no behavior changes are needed.

Do not move worker/supervisor.

Acceptance:

```bash
cargo check --lib --no-default-features
cargo check --no-default-features --features mesh,dns
```

## 11. Recommended task order

Use this exact order:

```text
MDM-M01  create compile timing script
MDM-M02  record measurement results
MDM-M03  rank remaining compile hot spots
MDM-R01  refresh root dependency ownership matrix
MDM-R02  prune root dependencies in tiny batches
MDM-R03  move durable dependency comments into ownership notes
MDM-H01  refresh HTTP server dependency inventory
MDM-H02  replace obvious root HTTP imports with extracted-crate imports
MDM-H03  decide HTTP server ownership policy
MDM-Q01  refresh HTTP3 dependency inventory
MDM-Q02  reduce trivial HTTP3 root imports
MDM-Q03  decide HTTP3 move readiness
MDM-S01  audit YARA/scanning ownership
MDM-S02  audit rusqlite/persistence ownership
MDM-S03  decide scanner/persistence extraction value
MDM-A01  audit OpenAPI/schema ownership
MDM-A02  decide schema split value
MDM-W01  update worker/supervisor boundary note
MDM-W02  replace accidental root imports only
```

## 12. Subagent prompt template

Use this prompt for smaller agents:

```text
You are implementing SynVoid measurement-driven modularization task MDM-XX from plans/measurement_driven_modularization_cleanup.md.
Scope is limited to this task. Preserve behavior. Do not create new crates unless the task explicitly says so. Do not move HTTP server, HTTP3 server, WafCore, worker, supervisor, Raft, or mesh code unless explicitly instructed. Prefer measurement, inventory, root dependency pruning, and import cleanup over broad refactors. Run the task acceptance commands and report exact failures.
```

## 13. Success criteria

This pass is successful when:

```text
1. Compile-time measurements exist for key subsystem crates and root profiles.
2. Remaining hot spots are ranked by measured rebuild cost.
3. Root dependency ownership is current.
4. At least a few clearly obsolete root dependencies are removed or marked KEEP_ROOT_FOR_NOW with evidence.
5. HTTP server and HTTP3 move/defer decisions are evidence-based.
6. YARA/scanning and rusqlite/persistence ownership are audited.
7. Admin/schema split value is assessed rather than assumed.
8. Worker/supervisor remain stable orchestration layers.
9. No new broad crate-splitting occurs without measured justification.
```
