# Phase 79 Plan: EggServe 0.3.1 H1 Runtime Correctness Corrective

Status: implemented 2026-09-25; local verification matrix green (fmt, clippy, dependency policy, core compile, repo guards, security regression, root guards, core admin tests, admin contract, failure injection — `cargo xtask verify` 10/10). Implementation SHA recorded with the Phase 80 handoff. Corrective follow-up to the Phase 73–78 adoption landed at `2242e1911d2083448371f707392fdb07f83f1bce`.

Registered in: `plans/roadmap.md` and `plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

Depends on: the Phase 73–78 EggServe 0.3.1 adoption implementation. This plan supersedes only the Phase 78 terminal-closure claim; it does not discard the transport-neutral boundary, the exact EggServe pins, or the plaintext/TLS-H1 production architecture unless the corrective work exposes a rollback-class defect.

Dependency-pin note (Finding B): the pins moved to
`eggserve-server = "=0.4.0"` / `eggserve-primitives = "=0.2.2"` under the
"separately justified upstream release" clause below. 0.3.1 cannot satisfy
the Finding B wire requirement at all, so the bump is required, not
optional. Evidence and justification are recorded in
`architecture/eggserve_0_4_0_trailer_head_addendum.md`.

## Purpose

Correct concrete runtime and qualification defects found during post-adoption review before the EggServe H1 migration is treated as production-qualified.

The current production architecture is directionally correct:

- `eggserve-server` / `eggserve-primitives` are exact-pinned (`=0.3.1` / `=0.2.1` at plan time; bumped to `=0.4.0` / `=0.2.2` by Finding B — see the dependency-pin note);
- SynVoid retains bind/accept/flood/TLS/ALPN/PQ/JA4/H2/H3/WAF/routing/backend/policy ownership;
- plaintext H1 and post-Rustls TLS-H1 use the direct EggServe driver;
- H2 remains on Hyper;
- one shared projector externalizes SynVoid-owned deadlines, admission, aggregate-header/body ceilings, and per-response Date/Server authority.

Do not reopen those decisions merely because the Phase 78 closeout was premature. Fix the bounded defects below, prove them, and roll back only if the corrected architecture cannot preserve the required contracts.

Baseline: `2242e1911d2083448371f707392fdb07f83f1bce`.

## Finding A — worker shutdown currently cancels the EggServe connection future

Both plaintext (`src/http/server/accept_loop.rs`) and TLS-H1 (`src/tls/server.rs`) currently race:

1. `serve_http1_connection_with_policy(...)`; and
2. worker/server shutdown.

When shutdown wins, the branch calls `ConnectionShutdown::shutdown()` and then exits the `tokio::select!`. Exiting drops the still-running EggServe connection future. That defeats the purpose of the level-triggered shutdown token and can truncate an active response or tunnel instead of allowing the driver to execute its shutdown/drain path.

### Required correction

- Construct the EggServe connection future once and keep polling that same future after shutdown is signaled.
- On worker/server shutdown, call the existing per-connection `ConnectionShutdown::shutdown()` exactly once/idempotently, then await the connection future to its normal bounded completion.
- Do not create a second independent idle/total/shutdown authority.
- If SynVoid already has an outer hard drain deadline that must abort a stuck connection, reuse that existing policy. Do not invent a new timeout constant merely for EggServe.
- WAF `Drop` continues to signal the same connection token; it must not create a competing close path.
- Prefer one small shared root helper for the plaintext and TLS-H1 drive pattern if that removes duplicated lifecycle logic without moving transport ownership out of the composition root.

### Required tests

Exercise both plaintext and real TLS-H1 production-shaped drivers:

- idle keep-alive receives shutdown and the connection task completes;
- an in-flight streamed response receives shutdown after headers/data begin and is not truncated solely because the outer `select!` dropped the driver future;
- an active WebSocket/tunnel receives shutdown through the EggServe token and terminates/drains according to the existing contract;
- repeated/idempotent shutdown does not panic or leak a task;
- H2 shutdown behavior is unchanged.

Tests must fail against the `2242e191` drive pattern and pass after the correction.

## Finding B — the exact-size buffered response path drops terminal trailers

`src/http/eggserve_h1.rs::convert_response()` currently buffers exact bodies up to the 8 MiB threshold with `BodyExt::collect()` and then converts only the collected DATA to bytes. Terminal trailers retained by the collection are discarded when only `to_bytes()` is used.

The streaming bridge preserves trailers; the buffered fast path does not. `size_hint().exact()` also does not prove that a body has no trailers.

### Required correction

- Preserve terminal trailers for exact/known-length responses at and below the existing buffered threshold.
- Inspect the collected trailer map before consuming DATA bytes.
- If trailers are present, emit an EggServe canonical representation that carries both the known DATA length and trailers (for example, a one-shot known-length canonical stream plus trailer future) rather than degrading to `ResponseBody::Bytes`.
- If trailers are absent, retain the current buffered `Bytes` fast path.
- Do not add whole-body buffering to bodies that are currently streamed.
- Preserve duplicate legal trailer fields as representable by the canonical trailer block.
- HEAD and body-forbidden response semantics must remain non-polling/non-emitting where the existing contract requires that behavior. Do not poll an application body merely to discover impossible/irrelevant trailers for HEAD/1xx/204/304.

### Required tests

Add direct adapter and wire tests for at least:

- exact small DATA + terminal trailers;
- exact zero DATA + terminal trailers on an ordinary body-permitted response;
- exact body without trailers remains `Bytes`/fast-path behavior;
- unknown-length trailers remain preserved through the existing streaming path;
- HEAD and 204/304 do not accidentally poll or emit a body/trailers;
- plaintext and TLS-H1 wire output includes the expected terminal trailer block where HTTP/1 framing permits it.

## Finding C — Phase 78 never exercised the real AppServer WebSocket tunnel path

The Phase 78 closeout explicitly records that app-server tunneled traffic was not looped, while the Phase 78 acceptance criteria require the WebSocket/AppServer tunnel matrix to pass.

The existing EggServe adoption and TLS fixtures set `app_servers: None`; ordinary upstream WebSocket echo therefore does not qualify the AppServer route.

### Required fixture

Do not make CI depend on Python or a real Granian installation.

Use the existing concrete seam:

- construct a `GranianSupervisor` with a `GranianConfig` whose `socket_path` points at a test-owned Unix socket;
- do not call `start()`/spawn a Granian process;
- install that supervisor in the `app_servers` map under the test site id;
- run a minimal test-owned Unix-socket WebSocket/tunnel echo peer at that path;
- route the site as `BackendType::AppServer` so production `maybe_handle_websocket_upgrade` resolves the supervisor socket and invokes the AppServer tunnel callback.

### Required coverage

At minimum prove on plaintext EggServe H1 and real TLS-H1:

- 101 handshake;
- validated `Sec-WebSocket-Accept` and selected subprotocol where configured;
- immediate post-upgrade/read-ahead bytes are delivered exactly once;
- bidirectional tunneled payload reaches the Unix-socket AppServer peer and returns;
- peer close and worker shutdown terminate the tunnel without an owned-task leak.

Reuse the same neutral tunnel assertions across plaintext/TLS where practical.

## Finding D — local endpoint provenance must not fabricate the peer address

Both production H1 paths currently build `ConnectionContext::for_tcp(local_addr.unwrap_or(client_addr), client_addr, ...)`.

If obtaining the local socket address fails, substituting the remote peer address creates false transport provenance.

### Required correction

- Never use the client/remote address as the local endpoint.
- Prefer capturing/validating the local socket address before handing transport ownership to EggServe.
- If EggServe's current context API requires a concrete local address and SynVoid cannot obtain one, fail that connection setup with bounded logging/metrics rather than inventing an endpoint.
- Keep routing behavior unchanged when a truthful local address is available.

Add a narrow helper/unit test that pins this behavior so a future fallback cannot silently reintroduce peer-as-local provenance.

## Implementation notes (recorded during execution)

- **Finding A fixture.** The default proxy body-buffering policy collects an
  upstream response before any byte is written, so a proxy-backed response
  cannot be in flight when shutdown lands. The in-flight tests therefore use
  a streaming-policy site (`body_buffering_policy = streaming`) whose WAF
  tarpit decision is served as a live SynVoid-generated stream
  (`STREAM_PATH`/`STREAM_CHUNKS` in `tests/eggserve_h1_runtime_corrective.rs`).
  First DATA frame → `shutdown()` twice → drain to EOF, asserting every
  chunk arrives. `eggserve_h1::tests::old_select_drop_pattern_cancels_driver_on_shutdown`
  pins that the pre-corrective `select!` drop pattern fails the same drive.
- **Finding B fixture.** A self-contained EggServe service (not the proxy
  path) builds the exact/unknown-length trailer representations directly, so
  the wire assertion is about the adapter + runtime, not upstream routing.

## Non-regression constraints

- No EggServe listener/TLS/H2/H3/static/core adoption.
- No new operator-visible EggServe configuration.
- No change to the exact dependency pins unless a separately justified upstream release is required. **Invoked for Finding B**: 0.3.1 has no code path that can emit an H1 terminal trailer block (see the dependency-pin note).
- No narrowing of SynVoid's valid H1 parser/header configuration range.
- No loss of per-site Date/Server policy.
- No duplicate request-admission or timeout authority.
- No permanent Hyper H1 production fallback.
- Do not fold the pre-existing H2 header-list byte-unit issue, Set-Cookie collapse, or body-limit status relabeling into this runtime corrective; those remain separate follow-up candidates.

## Verification

Run at least:

- `cargo fmt --all -- --check`
- focused adapter unit tests for exact-body trailers
- plaintext adoption loopback suite
- real TLS-H1 convergence suite
- new worker-shutdown/drain tests
- new AppServer tunnel loopback tests
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci`
- `cargo nextest run -p synvoid-config --cargo-profile ci --profile ci`
- `cargo xtask test guards`
- all existing no-default-feature/profile checks used by Phase 78
- `cargo deny check`
- `cargo audit`
- `cargo xtask verify`

Do not mark Phase 79 closed merely because local verification is green. Record the implementation SHA and hand it to Phase 80 for final hosted proof/evidence reconciliation.

## Acceptance criteria

- [x] worker/server shutdown signals `ConnectionShutdown` without dropping the active EggServe driver future (`drive_h1_connection` in both production paths; `old_select_drop_pattern_cancels_driver_on_shutdown` pins the pre-corrective failure);
- [x] active response and tunnel shutdown behavior is directly proven on plaintext and TLS-H1 (`plaintext`/`tls_h1` `inflight_stream_drains_without_truncation`, `websocket_shutdown_terminates_tunnel`, `idle_shutdown_drains_connection_task`);
- [x] exact/known-length small responses preserve terminal trailers (adapter unit tests plus `plaintext_exact_trailer_wire_block` / `tls_h1_exact_trailer_wire_block`);
- [x] ordinary no-trailer exact bodies retain the buffered fast path (`exact_body_without_trailers_keeps_bytes_fast_path`, `exact_empty_without_trailers_stays_empty`);
- [x] real AppServer WebSocket/tunnel dispatch is proven without requiring Python/Granian in CI (`plaintext_appserver_tunnel_loopback`, `tls_h1_appserver_tunnel_loopback`);
- [x] local endpoint provenance never substitutes the remote peer address (`connection_context_never_substitutes_peer_for_local`, `connection_context_preserves_truthful_local`);
- [x] H2/H3 behavior remains unchanged (`tls_h2_stays_hyper_with_header_limit`, H2 branch untouched);
- [x] exact EggServe dependency/ownership model remains intact (ownership profile unchanged; pins moved only under the separately justified upstream-release clause — `architecture/eggserve_0_4_0_trailer_head_addendum.md`);
- [x] focused and full local verification is green (`cargo xtask verify` 10/10, plus feature profiles, `cargo deny check`, `cargo audit`);
- [ ] implementation SHA is recorded for Phase 80 qualification (filled in by the Phase 79 handoff commit).

## Terminal state

Phase 79 is an implementation corrective, not final campaign closure. A green Phase 79 implementation unblocks Phase 80. A rollback-class failure must be recorded explicitly rather than hidden behind a partial migration.