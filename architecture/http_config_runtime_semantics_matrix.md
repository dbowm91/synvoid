# HTTP Configuration Runtime-Semantics Matrix (Phase 71)

Status: **implemented**; closeout pending routine verification.

Baseline reviewed: `main` at `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c` plus the
Phase 70 implementation head. Re-verified against the implementation head:
every consumer cited below was confirmed by executable search/test, not copied
from the planning review.

Plan: `plans/phase_71_http_config_runtime_semantics_truthfulness.md`.

Disposition vocabulary: `ACTIVE_EXACT` (runtime matches docs),
`ACTIVE_NARROWER_THAN_DOCS` (real consumer, narrower scope than described),
`INERT` (no consumer, still admitted), `DUPLICATE_POLICY` (alias of another
control), `DEPRECATED_COMPAT` (parseable compat key, explicitly not enforced).

Byte accounting for the ingress bound: sums of parsed header-name bytes plus
header-value bytes (`request_headers_ingress_size`). Separator (`: `), CRLF,
and request-line bytes are NOT counted. This is a post-parse count, not a
pre-parse wire-byte ceiling; the transport parser's own memory ceiling
(`max_buf_size`) still applies underneath. Docs must not claim otherwise.

## Field matrix

### `header_read_timeout_secs` — ACTIVE_EXACT

- Default 10; validation rejects 0.
- Docs: seconds to wait for complete headers before closing.
- Consumers: plaintext H1 and TLS-H1 through `src/http/h1_policy.rs`
  (`header_read_timeout` + explicit `TokioTimer`; Hyper panics without one).
- Scope: plaintext H1 / TLS-H1. Enforcement phase: parser. Failure: idle
  header connection terminated.
- Proof: `tests/http_h1_parser_parity.rs` slow-header cases on both paths.

### `keep_alive_timeout_secs` — DEPRECATED_COMPAT

- Default 60; no validation (no consumer to bound).
- Docs previously described an idle persistent-connection timeout. No
  demonstrated Hyper H1 runtime consumer: both H1 builders set only
  `keep_alive(true)`.
- Decision: truthfully deprecated, not implemented. Wrapping
  `serve_connection` in `tokio::time::timeout` would impose a wrong
  total-connection lifetime (kills active long requests/bodies/responses,
  races WebSocket upgrades). A true activity-aware idle timeout needs
  connection-activity instrumentation — registered as a separate follow-up,
  not smuggled into this phase.
- Action: docs/admin-UI mark "not enforced"; key remains parseable.

### `max_headers` — ACTIVE_EXACT

- Default 128; validation rejects 0 and values above `u32::MAX` (the TLS H2
  path casts to `u32` for `max_header_list_size`; fail closed instead of
  truncating).
- Consumers: plaintext H1 + TLS-H1 (shared helper) + TLS H2 header-list size.
- Scope: plaintext H1 / TLS-H1 / H2. Enforcement phase: parser. Failure: H1
  transport rejection; H2 stream error.
- Proof: `tests/http_h1_parser_parity.rs` max-headers cases on both H1 paths;
  H2 line pinned unchanged by the same file's source guard.

### `max_request_line_size` — DEPRECATED_COMPAT

- Default 8192; no consumer found in executable code.
- Docs described the full H1 request line (method + URI + version). Hyper
  exposes parsed components to the application, not the exact original wire
  line; approximating the wire line post-parse would be inexact by
  construction. A true wire limit needs transport-boundary machinery (a
  separate plan), and silently redefining the key as a request-target limit
  would be an incompatible semantic rename (also a separate decision).
- Action: docs/admin-UI mark "not enforced"; key remains parseable.

### `max_header_size_ingress` — ACTIVE_EXACT (H1/H2; H3 follow-up residual)

- Default 4096; validation rejects 0 (zero would 431 every request).
- Docs: maximum total size of all request headers from clients. Now exact
  for the transports below.
- Consumers: canonical `prepare_request_preflight`
  (`crates/synvoid-http/src/request_preparation.rs`) via
  `request_headers_ingress_size`, before trust-token bypass, routing, WAF,
  and backend work.
- Scope: plaintext H1 / TLS-H1 / H2 (all share the canonical flow).
  Enforcement phase: post-parse admission. Failure: deterministic 431
  (`Request Header Fields Too Large`) + `synvoid.http.header_size_rejected`.
- H3 residual: the QUIC dispatch chain (`prepare_http3_request_prelude` and
  downstream dispatch) does not thread `HttpConfig`, and its terminal maps a
  bare `Respond` without a precise status. Threading the limit plus a 431
  terminal mapping is a small explicit follow-up, deliberately not folded in
  here to avoid H3 dispatch surgery inside a truthfulness closeout.
- Proof: unit tests on the helper plus live-preflight
  `tests/http_config_runtime_semantics.rs` (431 above limit, 404 routing for
  fitting headers through the same boundary).

### `max_header_size_egress` — DEPRECATED_COMPAT

- Default 16384; no consumer. No truncation exists anywhere on the response
  path, and inventing truncation would risk corrupting `Set-Cookie`,
  security headers, signatures, or application values. Fail-closed
  replacement (swap uncommitted over-limit responses for an error) needs
  provenance-safe response-commitment work — a separate plan if ever wanted.
- Action: docs/admin-UI mark "not enforced (responses are never truncated)";
  key remains parseable.

### `max_request_size` — ACTIVE_NARROWER_THAN_DOCS

- Default 1048576; validation now rejects values below Hyper's H1
  parser-buffer minimum 8192 (`MIN_H1_PARSER_BUFFER_SIZE`; the builder
  panics below it).
- Docs previously read as a request-body limit. Runtime reality: Hyper H1
  `max_buf_size` parser-buffer ceiling on plaintext H1 + TLS-H1 (Phase 70
  helper). Body limits live elsewhere (`max_streaming_body_size`, per-route
  upload policy, H3's own `Http3Config::max_request_size`).
- Action: docs/admin-UI state the parser-buffer scope; no behavior change.

### `pipeline_limit` — DEPRECATED_COMPAT

- Default 32; no consumer. Hyper's server does not expose an H1
  pipeline-depth control to map this onto, and mapping it onto global
  concurrency, `max_connections`, H2 streams, or backend concurrency would
  be a different limit wearing this key's name.
- Action: docs/admin-UI mark "not enforced"; key remains parseable.

### `waf_stall_timeout_secs` — ACTIVE_EXACT

- Default 5. Consumers: H1/common WAF decision
  (`crates/synvoid-http/src/waf_decision.rs`), streaming WAF decision, and
  the H3 WAF dispatch paths. Enforcement phase: WAF decision. Failure: stall
  sleep then 408 under the concurrency cap. No change.

### `max_stalled_requests` — ACTIVE_EXACT

- Default 100. Consumers: same stall-permit sites as above
  (`StallPermit::try_new`). No change.

### `max_connections` — ACTIVE_NARROWER_THAN_DOCS

- Default 10000; validation rejects 0.
- Docs previously read as a TCP-connection cap. Runtime reality: sizes the
  root request-admission semaphore (`HttpServer::new`, mirrored by the TLS
  server's shared semaphore); the permit is acquired per request in
  `handle_request` / `handle_request_with_cache` and held for request
  lifetime — i.e. concurrent HTTP request admission, not accepted TCP
  connections. A true per-connection accept-loop cap (permit per accepted
  socket through close, flood/worker/WebSocket interaction) is a distinct
  subsystem and a separate plan if wanted.
- Action: docs/admin-UI say "concurrent request admission"; no behavior
  change; key compatibility preserved.

### `strict_protocol_validation` — ACTIVE_EXACT

- Default false. Consumers: plaintext accept-loop sniff
  (`is_tls_client_hello` / `is_valid_http_request_start`) and the TLS-port
  HTTP peek. Enforcement phase: pre-parse. Failure: connection skipped
  before handshake/dispatch with `synvoid.http.*` counters. No change.

### `max_streaming_body_size` — ACTIVE_EXACT

- Default 10485760 (10 MiB). Consumers: request preparation / body policy
  (`collect_and_scan_request_body` bound on the H1 canonical flow).
  Enforcement phase: body. Failure: 413 fail-closed. No change.

## Validation deltas (Phase 71)

`HttpConfig::validate()` now additionally rejects, each naming its field:

- `http.max_request_size` below 8192 (Hyper H1 parser-buffer floor);
- `http.max_headers` above `u32::MAX` (H2 header-list cast);
- `http.max_header_size_ingress` equal to 0 (would 431 all traffic).

No arbitrary upper bounds were added; EggServe bounds were not used as
justification (EggServe is not the production runtime).

## Operator-surface reconciliation

- `docs/CONFIGURATION.md`: deprecated keys marked "not enforced" with the
  reason; `max_request_size` states the parser-buffer scope;
  `max_connections` states concurrent-request admission;
  `max_header_size_ingress` states post-parse name+value accounting and the
  431 behavior.
- `docs/TROUBLESHOOTING.md`: 431 row for oversized aggregate headers.
- `architecture/config.md`: validation bounds recorded.
- `architecture/http_server.md`: H1 parser policy + admission-semaphore
  scope notes.
- `admin-ui/src/config_docs.rs`: descriptions no longer present deprecated
  keys as active controls; narrower scopes stated.
- Example/generated config comments (`config/main.toml`,
  `src/supervisor/cli_commands.rs`, `src/commands/one_shot.rs`): wording
  aligned where semantics are described.
- `.opencode/skills/httpserver/SKILL.md`: H1 policy + config-semantics
  pointer.

## Guard

`tests/http_config_runtime_semantics.rs` (ownership: composition):

- serializes `HttpConfig::default()` and requires the exact 13-field set —
  a new field fails until the matrix and this table are extended;
- requires every matrix entry to use the allowed disposition vocabulary;
- spot-checks ACTIVE consumers exist in executable code;
- requires deprecated keys to keep parseable docs/UI entries carrying
  not-enforced markers;
- requires narrower-scope wording for `max_request_size`/`max_connections`.

## Residuals / follow-ups (registered, not blocking)

1. H3 ingress enforcement: thread the limit through the QUIC dispatch chain
   with a 431 terminal mapping. Blocker: H3 prelude/dispatch signatures and
   terminal status mapping. Owner: future H3 policy pass.
2. True idle keep-alive timeout: needs connection-activity instrumentation
   that does not impose total-lifetime semantics. Owner: future connection
   lifecycle pass.
3. True TCP-connection cap vs request admission: needs accept-loop permit
   ownership with flood/worker/WebSocket interaction design. Owner: future
   admission-control pass.
4. Egress header policy: needs provenance-safe commit design. Owner: future
   response-policy pass.
5. Request-line wire limit or deliberate target-limit rename: needs
   transport-boundary mechanism or compat-version decision. Owner: future
   parsing-policy pass.
