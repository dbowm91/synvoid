# HTTP/1 Runtime Truthfulness Corrective (Phase 70)

Status: **implemented**; closeout pending routine verification.

Baseline reviewed: `main` at `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c` (2026-09-24).
Implementation head: recorded at closeout commit.

Plan: `plans/phase_70_http_h1_runtime_truthfulness_corrective.md`.

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

New `tests/http_h1_parser_parity.rs` (ownership: composition;
`tests/OWNERSHIP.toml` entry added) drives loopback H1 servers built by the
production helper with identical values for both labels:

| Case | Plaintext | TLS-H1 (post-handshake equivalent) |
| --- | --- | --- |
| max headers (8; 4 ok / 20 rejected) | ✅ | ✅ |
| parser buffer (8192; small ok / 16 KiB header rejected) | ✅ | ✅ |
| slow headers (1s timeout; partial held → terminated ≤15s; fast control 200) | ✅ | ✅ |
| WebSocket upgrade → 101 reaches dispatch | ✅ | ✅ |

Source guards in the same file pin: plaintext log has no `HTTP/2` claim;
both H1 paths call `configure_h1_builder`; both retain `.with_upgrades()`;
no `_header_read_timeout`/`_max_buf_size` dead locals remain; the H2
`max_header_list_size(max_headers as u32)` line is unchanged. A unit test in
`h1_policy.rs` proves building a connection with a configured timeout no
longer panics.

No private Hyper error strings are asserted (status classes only).

## Commands/results (recorded at closeout)

- `cargo test --test http_h1_parser_parity --profile ci` — 10/10 pass.
- `cargo fmt --all -- --check` — green.
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci` — green.
- `cargo xtask test guards` — green.
- Feature-profile `cargo check` matrix — green.
- `cargo xtask verify` — recorded in the closeout commit message.

## Residual delegated to Phase 71

- `max_request_size` naming/docs imply a request-body limit; runtime use is
  the Hyper parser-buffer ceiling. Phase 71 owns the full `HttpConfig`
  semantics matrix and doc/admin-UI reconciliation.
- Keep-alive idle timeout, pipeline depth, request-line/header-size fields
  have no demonstrated H1 builder consumer; Phase 71 classifies them.
- `max_connections` permit scope (per-request admission) wording; Phase 71.
