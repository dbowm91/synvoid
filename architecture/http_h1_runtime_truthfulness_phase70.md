# HTTP/1 Runtime Truthfulness Corrective (Phase 70)

Status: **closed**. Phases 70–71 implementation/closeout head:
`92ddc25d62e5b28e345ba660bf0a2504a6fa32f2`; Phase 72 evidence
reconciliation lands on top with no runtime change.

Baseline reviewed: `main` at `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c`
(2026-09-24) — preserved as the pre-fix baseline.
Proof-bearing Phase 70/71 closeout head:
`92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` (implementation plus the routine
verification recorded in that closeout commit).

Verification cited below is locally recorded verification. Remote CI
observed for the proof-bearing SHA: the push workflow run for that SHA
(`36029889970`) completed cancelled (superseded by a follow-up push), so
no green remote CI outcome is claimed for it. Remote green was observed
for the Phase 72 reconciliation instead — see
`architecture/http_truthfulness_phase72_closeout.md`.

Plan: `plans/phase_70_http_h1_runtime_truthfulness_corrective.md`.
Evidence reconciliation: `plans/phase_72_http_truthfulness_corrective_closeout.md`
(Phase 72 closeout: `architecture/http_truthfulness_phase72_closeout.md`).

## Builder behavior before

- Plaintext (`src/http/server/accept_loop.rs`): Hyper H1 builder set
  `.header_read_timeout(10s)`, `.max_headers(128)`,
  `.max_buf_size(max_request_size)` — but **no `.timer(..)`**. Per the
  resolved `hyper 1.10.1` source (`src/server/conn/http1.rs`,
  `src/common/time.rs`), `header_read_timeout` stores `Dur::Configured` and
  `serve_connection` calls `Time::check`, which **panics** when a timeout is
  configured with `Time::Empty`. The plaintext timeout was therefore not
  "merely unproven" — every H1 connection task would panic at
  `serve_connection` time instead of enforcing the timeout.
- TLS (`src/tls/server.rs`): computed `_header_read_timeout`,
  `max_headers`, `_max_buf_size` but the H1 builder called only
  `.keep_alive(true)` before `serve_connection(..).with_upgrades()`. TLS-H1
  had no header timeout, no header-count ceiling, and Hyper's default
  (~400 KiB) parser buffer regardless of configuration. `max_headers` only
  reached the H2 builder as `max_header_list_size`.
- Startup log: plaintext advertised `(HTTP/1.1 + HTTP/2)` while constructing
  only `hyper::server::conn::http1::Builder` (no cleartext H2/h2c).

## Behavior after

- New single owner `src/http/h1_policy.rs`:
  - `PLAINTEXT_PROTOCOL_LABEL = "HTTP/1.1"` +
    `plaintext_startup_message()` — the plaintext log now reads
    `HTTP server listening on ... (HTTP/1.1) [SO_REUSEPORT]`.
  - `configure_h1_builder(&mut Builder, &HttpConfig)` — sets
    `.timer(TokioTimer::new())`, `.header_read_timeout(..)`,
    `.max_headers(..)`, `.max_buf_size(..)`.
- Plaintext accept loop and TLS-H1 path both call the helper; underscore
  dead locals removed; `.with_upgrades()` retained on both; TLS H2 builder
  (`max_header_list_size(max_headers as u32)`) unchanged.

## Timer requirement/result

Resolved `hyper 1.10.1` requires an explicit `Timer` whenever
`header_read_timeout` is configured; otherwise `serve_connection` panics
(`Time::check` → `panic!("timeout ... set, but no timer set")`). The
canonical adapter in the current graph is `hyper_util::rt::TokioTimer`
(root already depends on `hyper-util` with the `tokio` feature). Both H1
paths now set it through the helper. No dependency/feature/lockfile change
was needed, so no `cargo deny`/`cargo audit` delta.

## Protocol startup-message correction

- `src/http/server/accept_loop.rs`: H1-only message via the helper.
- `src/tls/server.rs`: keeps `(HTTP/1.1 + HTTP/2)` — ALPN routing actually
  serves both.
- `architecture/http_server.md`, `.opencode/skills/httpserver/SKILL.md`,
  `tests/http_tls_parity.rs` vocabulary comments corrected; no plaintext
  H2/h2c was added.

## Tests

`tests/http_h1_parser_parity.rs` (ownership: composition;
`tests/OWNERSHIP.toml` entry) drives a plaintext loopback H1 server built by
the production helper, plus an identical-values repeat run proving the shared
mapping is repeatable (plain TCP in both runs — the repeat run is NOT a TLS
handshake), plus source guards:

| Case | Plaintext | Shared-policy repeat (plain TCP) |
| --- | --- | --- |
| max headers (8; 4 ok / 20 rejected) | ✅ | ✅ |
| parser buffer (8192; small ok / 16 KiB header rejected) | ✅ | ✅ |
| slow headers (1s timeout; partial held → terminated ≤15s; fast control 200) | ✅ | ✅ |
| WebSocket upgrade → 101 reaches dispatch | ✅ | ✅ |

Real TLS-H1 transport evidence (Phase 72):
`tests/http_h1_tls_transport.rs` (ownership: composition;
`tests/OWNERSHIP.toml` entry) performs a real Rustls handshake — `rcgen`
self-signed leaf for `localhost`, client trusts only that certificate, ALPN
`http/1.1` asserted on both client and server ends — then serves Hyper H1
over the server `TlsStream` through the production `configure_h1_builder`
mapping with `.with_upgrades()` retained. No builder settings are copied
into the test. Cases: control 200, max-headers fit/reject, parser-buffer
fit/reject, 1s header-read timeout with a post-handshake stall terminated
within 15s, WebSocket upgrade reaching 101.

Scope truth: the TLS fixture tests the post-handshake `TlsStream` seam, not
the full `HttpsServer` (no WAF/router/backend construction). The source
guard below links that seam to the production `src/tls/server.rs` H1 call
site; together they prove the intended transport mapping.

Source guards in `tests/http_h1_parser_parity.rs` pin: plaintext log has no
`HTTP/2` claim; both H1 paths call `configure_h1_builder`; both retain
`.with_upgrades()`; no `_header_read_timeout`/`_max_buf_size` dead locals
remain; the H2 `max_header_list_size(max_headers as u32)` line is unchanged.
A unit test in `h1_policy.rs` proves building a connection with a configured
timeout no longer panics.

Reconciled 2026-09-25 (Phase 80): the "both H1 paths call
`configure_h1_builder`" and "both retain `.with_upgrades()`" clauses
described the Phase 70 Hyper-only wiring. The Phase 73–78 adoption
(`2242e191`) replaced both production H1 paths with the EggServe runtime
while `h1_policy::configure_h1_builder` stayed as the Hyper mapping for the
test lanes — so those two clauses went red at the adoption but this file
kept reporting 10/10. The guard now asserts the current wiring truth
(shared `project_eggserve_h1`, shared `h1_connection_context` /
`drive_h1_connection` / `EggserveH1Service`, parser controls still consumed,
H2 `max_header_list_size` unchanged, and `configure_h1_builder` remaining
the single Hyper mapping authority) and is green again. The behavioral
cases in this document are unchanged.

No private Hyper error strings are asserted (status classes only).

## Commands/results (locally recorded)

At Phase 70/71 closeout (`92ddc25d`):

- `cargo test --test http_h1_parser_parity --profile ci` — 10/10 pass.
- `cargo fmt --all -- --check` — green.
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci` — green.
- `cargo xtask test guards` — green.
- Feature-profile `cargo check` matrix — green.
- `cargo xtask verify` — recorded in the closeout commit message.

After Phase 72 evidence reconciliation (no runtime change; repeat-run
labels renamed, `tests/http_h1_tls_transport.rs` added):

- `cargo test --test http_h1_parser_parity --profile ci` — 10/10 pass.
- `cargo test --test http_h1_tls_transport --profile ci` — 5/5 pass.
- `cargo test --test http_tls_parity --profile ci` — pass.

After Phase 79/80 (EggServe 0.4.0 pins, source-guard rebasing; no
behavioral change to the parser controls):

- `cargo test --test http_h1_parser_parity --profile ci` — 10/10 pass.
- `cargo test --test http_h1_tls_transport --profile ci` — 5/5 pass.
- `cargo test --test http_config_runtime_semantics --profile ci` — pass.
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci` — green.
- `cargo nextest run -p synvoid-config --cargo-profile ci --profile ci` — green.
- `cargo xtask test guards` — green.
- Feature-profile `cargo check` matrix — green.
- `cargo xtask verify` — green (recorded in the Phase 72 closeout commit).

No dependency manifest/feature changed in Phase 72 beyond test-only
`[dev-dependencies]` (`rustls`, `rustls-pki-types`, `rcgen` reusing locked
versions), so no new `cargo deny`/`cargo audit` delta is manufactured here;
the Phase 70 statement (no dependency/feature/lockfile change, hence no
deny/audit delta) stands for the runtime baseline.

## Residual delegated to Phase 71

- `max_request_size` naming/docs imply a request-body limit; runtime use is
  the Hyper parser-buffer ceiling. Phase 71 owns the full `HttpConfig`
  semantics matrix and doc/admin-UI reconciliation.
- Keep-alive idle timeout, pipeline depth, request-line/header-size fields
  have no demonstrated H1 builder consumer; Phase 71 classifies them.
- `max_connections` permit scope (per-request admission) wording; Phase 71.
