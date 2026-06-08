# Next Modularization Recommendation

## Validation status after workspace-green pass

- Root yara-x removed: YES (moved to `crates/synvoid-upload`)
- Mesh feature now compiles: YES (fixed in SDC-A02)
- Workspace all-targets: **PASSED** — all 4 prior issues resolved in prior work.
- Dead upload duplicates removed: YES (duplicate yara rules, crypto, scanner types consolidated)
- Upload import migration: **COMPLETE** — all 15 upload call sites use `synvoid_upload::` directly; zero `crate::upload::X` submodule refs remain. Root `src/upload/mod.rs` re-export shim retained for broad caller compatibility. No further action needed for upload imports.
- HTTP/3 object-safety: **COMPLETED** — `WafAccess` refactored (associated type removed, `streaming()` returns `Box<dyn StreamingWafScanner>`). Composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` introduced. `Http3Server.waf` is now `Arc<dyn Http3WafBackend>`. See `plans/hwd_h02_deferred.md`.

## Workspace-green results summary

Full 10-command validation matrix (HWD-F01): **ALL PASS**. Includes `cargo fmt`, all 4 profile checks, 3 per-crate checks (`synvoid-http`, `synvoid-http3`, `synvoid-upload`), `--workspace --all-targets`, and `--workspace --no-run`. Warnings only, no errors. The four prior failures (myapp-dynamic E0507, synvoid-ipc sha2, admin-ui errors, synvoid-mesh test errors) were all resolved before this pass.

## Remaining-HTTP-runtime-and-schema-pass results (RHP, 2026-06-08)

After RHP-H301..H306, RHP-S01..S04, RHP-A01..A03, RHP-R01..R02:

- **HTTP/3 root blockers**: ZERO remaining low-effort blockers.
  WafAccess object-safe (RHP-H301). WorkerDrainState removed
  (RHP-H303). bind_udp_reuse re-exported via synvoid-platform
  (RHP-H305). Server stays root-owned for QUIC composition reasons
  (RHP-H306: KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER).
- **Server runtime context**: `HttpServerRuntime` and `HttpAppBackends`
  introduced in `src/http/server.rs` (RHP-S03). `HttpRequestWafBackend`
  trait deferred to RHP-S03b. `ErasedHttpClient` deletion deferred to
  RHP-S03b.
- **Admin/schema ownership**: KEEP_ROOT_FOR_BINARY_EXPORT (RHP-A02).
  No schema imports needed cleanup (RHP-A03). MDM-M02 compile-time
  measurement is the only open follow-up.
- **Root dependency pruning**: 3 deps removed in MDM-R02 batch 2
  (RHP-R02): x509-parser 0.16, openraft-legacy, prost-build.

## HTTP/3 readiness

`Http3RequestWaf` at `crates/synvoid-http/src/http3_request_dispatch.rs:28` is fully object-safe:
- Both methods use `#[async_trait]` or plain signatures
- No generic methods, no `Self` returns, no associated types, no `Sized` bounds

**Strategy A is IMPLEMENTED**: `WafAccess` was refactored to remove the `StreamingScanner` associated type. `streaming()` returns `Option<Box<dyn StreamingWafScanner>>` with a unified trait in `synvoid-core`. A composite trait `Http3WafBackend: Http3RequestWaf + WafAccess` was introduced. `Http3Server.waf` is now `Arc<dyn Http3WafBackend>`.

Remaining root blockers: pre-existing `accept_loop.rs` Send bound errors and `WorkerDrainState` (root-owned, low-impact; resolved by RHP-H302/H303). See "HTTP/3 server move readiness (RHP-H306)" below for the final move-readiness decision.

## Next recommended technical pass

1. **HTTP/3 server** — Move readiness decision recorded as `KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER` (RHP-H306). WafAccess object-safety is completed (`Http3Server.waf` is `Arc<dyn Http3WafBackend>`) and `WorkerDrainState` is resolved (RHP-H302/H303). `bind_udp_reuse` is re-exported via `synvoid-platform` (RHP-H305). Move is gated on three preconditions: `WafCore` extracted to `synvoid-waf`, the dispatch signature changed to take `&dyn Http3RequestWaf`, and the QUIC dep stack unified. See "HTTP/3 server move readiness" section below.
2. **server-runtime context design** — Design complete (RHP-S02). `HttpServerRuntime`, `HttpAppBackends`, and `HttpRequestWafBackend` struct/trait shapes are documented in `plans/server_runtime_context_design.md`. RHP-S03 introduced the structs in root. Future work: RHP-S03b for `HttpRequestWafBackend` trait-object seam and `ErasedHttpClient` deletion.
3. **admin/schema ownership cleanup** — Resolved by RHP-A02 as `KEEP_ROOT_FOR_BINARY_EXPORT`. The spec composer (`src/admin/openapi.rs`, 1611 lines) and the binary-only `--export-openapi` / `--export-api-spec` flags are root-owned by structure. Only follow-up is **MDM-M02** (compile-time measurement to validate the decision).
4. **MDM-M02 measurement** — Open follow-up. Run `cargo build --timings` on `cargo check -p synvoid` and `cargo check --workspace --all-targets`. If `utoipa`/`schemars` macro expansion contributes >20% of root binary compile time, re-open RHP-A02 and re-evaluate `MOVE_TO_SYNVOID_ADMIN`.

---

## HTTP/3 server move readiness (RHP-H306, 2026-06-08)

**Decision**: `KEEP_ROOT_AS_QUIC_COMPOSITION_LAYER`.

`src/http3/server.rs` (300 lines after RHP-H303) **stays in root**. It
is the single composition point for the QUIC endpoint
(`quinn::Endpoint`), the `h3`/`h3-quinn` server builder, the
`synvoid-http` request-dispatch seam, the `synvoid-waf` flood/WAF
layer (`Arc<dyn Http3WafBackend>`), the upstream client registry,
the metrics sink, the root `broadcast::Receiver<()>` shutdown
channel, the `alt_svc_header()` generator for HTTP/1.1's `Alt-Svc`
response, and the platform UDP socket binding (now re-exported from
`synvoid_platform::socket_bind::bind_udp_reuse`). The file is small,
leaf-position in the dependency graph, and tightly coupled to
root-level subsystems. Moving it is not a measurable win on its own.

### Why not `MOVE_READY`

Three independent preconditions must be satisfied, each out of scope
for the current pass:

1. **`bind_udp_reuse` must move or be re-exported via `synvoid-platform`.**
   **RESOLVED in RHP-H305**: function is in
   `synvoid_platform::socket_bind::bind_udp_reuse`. The root
   `crate::platform::socket::bind_udp_reuse` path is preserved via
   `pub use`. ✓
2. **`WafCore` must move to `synvoid-waf`.** `WafCore` is the sole
   `Http3RequestWaf` implementor in the workspace. Even though
   `Http3Server.waf` is `Arc<dyn Http3WafBackend>`, the runtime value
   is constructed in root. Plan section 2 non-goal #4 explicitly says
   "Do not move WafCore into synvoid-waf." Lifting this is a
   separate cross-cutting change.
3. **The `http3_request_dispatch.rs` signature must change to accept
   `&dyn Http3RequestWaf` instead of a generic.** This is a
   `synvoid-http` API change that simplifies the long call site in
   `server.rs:262-285`. Out of scope for the current pass.

Additionally, the QUIC dependency stack (`quinn`, `h3`, `h3-quinn`,
`webpki-roots`, `rustls-pki-types`, `rustls`) is currently declared in
root `Cargo.toml` (lines 156, 171-174) and only partially in
`crates/synvoid-http3/Cargo.toml` (`rustls` and `quinn` only). The
move would require unifying the dependency declarations.

### Why not `KEEP_ROOT_UNTIL_PLATFORM_SOCKET_MOVE`

`bind_udp_reuse` is **resolved** by RHP-H305. The remaining blockers
(WafCore, dispatch signature) are independent and structural.

### Why not `KEEP_ROOT_UNTIL_DRAIN_SEAM`

`WorkerDrainState` was the lowest-effort blocker (one struct field,
stored but never read in any method body). RHP-H302 / RHP-H303
resolved it.

### Why not `DEFER_LOW_VALUE`

`server.rs` is small (~300 lines) but it is the only place where the
`quinn::Endpoint` is constructed, the `h3` server is wired with
`h3_quinn::Connection`, the root shutdown broadcast is consumed,
and the `alt_svc_header()` is generated. These are all
"QUIC composition" responsibilities with no benefit to moving the
file alone. The right label is a specific composition-layer
rationale, not a deferral.

### Re-evaluation preconditions

This decision will be revisited only when **all three** of the
following are completed:

1. `WafCore` is extracted to `synvoid-waf` (requires lifting
   plan section 2 non-goal #4).
2. `handle_http3_request_dispatch` signature changes to accept
   `&dyn Http3RequestWaf` (a `synvoid-http` API change).
3. The QUIC stack dep declarations are unified between root and
   `synvoid-http3`.

Once all three are satisfied, the move is reduced to a
near-mechanical step: `src/http3/server.rs` moves to
`crates/synvoid-http3/src/server.rs`, `synvoid-http3` gains the
QUIC stack dependencies, and the QUIC composition becomes a
self-contained crate. Until then, root-ownership of `server.rs`
is the correct architectural choice.

See `plans/http3_server_dependency_inventory.md` section RHP-H306
for the full decision record.

---

## Schema ownership decision (RHP-A02, 2026-06-08)

The schema/OpenAPI ownership question is **resolved for this pass**:
**KEEP_ROOT_FOR_BINARY_EXPORT**. The root binary legitimately owns
`utoipa` / `schemars` / `utoipa-swagger-ui` because:

- `--export-openapi` and `--export-api-spec` are binary-only CLI flags
  with no runtime consumer (defined in
  `crates/synvoid-cli/src/lib.rs:175,178`, read only in
  `src/main.rs:34,44`).
- The OpenAPI spec composer is root-owned (`src/admin/openapi.rs`,
  1611 lines).
- 19 of the 24 root `utoipa` consumers are admin handler files
  (`src/admin/handlers/*`) that cross subsystem boundaries (mesh, waf,
  config, sites) and are intentionally not in `synvoid-admin` per the
  plan's § 2 non-goal "do not move worker or supervisor".
- `synvoid-admin` already owns its own copies of `utoipa` /
  `schemars` / `utoipa-swagger-ui` for its 6-file partial handler
  set; the question is not capability but scope.

**No code movement in RHP-A02.** The only follow-up is **MDM-M02**
(compile-time measurement) — if profiling shows `utoipa`/`schemars`
dominate `cargo check -p synvoid` or `cargo check --workspace
--all-targets` timings, re-open RHP-A02 and re-evaluate
`MOVE_TO_SYNVOID_ADMIN`. See `plans/admin_schema_ownership.md` §
RHP-A02 for the full decision write-up.

The previous "admin/schema ownership cleanup" item (#3) in the Next
recommended technical pass list is **closed by RHP-A02 (2026-06-08)**.

---

## Server-runtime context design (RHP-S02, RHP-S03, 2026-06-08)

Design complete. See `plans/server_runtime_context_design.md` for
the full design doc. Summary:

- **`HttpServerRuntime`** (root-only, in `src/http/server.rs`):
  re-groups 20+ `HttpServer` data-plane fields (router, WAF, client,
  upstream registry, drain, metrics, IPC, worker_id, mesh cfg-gated
  types, plus the nested `HttpAppBackends`). **INTRODUCED in RHP-S03.**
- **`HttpAppBackends`** (root-only): re-groups serverless / granian /
  plugin_manager. **INTRODUCED in RHP-S03.**
- **`HttpRequestWafBackend`** trait (root-only): combines the 5
  already-implemented WAF bounds (`BufferedRequestWaf` +
  `RequestBodyWaf` + `UploadValidationWaf` + `WafErrorPageRenderer` +
  `WafCoreBackend`); mirrors the existing `Http3WafBackend` pattern.
  **DEFERRED to RHP-S03b** — making `HttpServerRuntime.waf` a trait
  object hit the RHP-S02 §7 stop condition (requires propagating
  `?Sized` bounds into `synvoid-http`).
- **`ErasedHttpClient`**: documented as dead (cloned 4× per request,
  never read in any method body); recommend deletion in RHP-S03b.

Classification: all three structs stay in root because they
reference `WafCore` (via the new trait), `WorkerDrainState`,
`FloodProtector`, and `PluginManager` (via `dyn Any`) — all four are
root-owned. RHP-S02 default rule applies: "Keep root-only composition
structs in root until worker/server boundaries stabilize."

### RHP-S04: server-runtime crate decision

`DEFER_LOW_VALUE`. The structs are root-only and small. Creating
`synvoid-runtime` would gain nothing (would still depend on root
types via traits). The struct decomposition is the right level of
intermediate refactor; a full extraction is premature.

---

## Root dependency pruning (RHP-R02, 2026-06-08)

3 deps removed in MDM-R02 batch 2:

| Dependency | Reason | Owner |
|---|---|---|
| `x509-parser = "0.16"` | 0 root uses; pulled in transitively | `synvoid-tls`, `synvoid-mesh` (0.18.1) |
| `openraft-legacy = "0.10.0-alpha.18"` | 0 uses anywhere; only pinned by root | n/a |
| `prost-build = "0.14"` | 0 uses anywhere; was in wrong section | n/a |

See `plans/root_dependency_ownership.md` MDM-R02 batch 2 for full
details and validation results. No new errors introduced. The 3
pre-existing `accept_loop.rs` Send bound errors are unchanged.

**Deferred**: `prost` removal (0 root uses but consumers in
`synvoid-mesh` only; requires cross-crate change to add it to
`synvoid-mesh`'s Cargo.toml first).
