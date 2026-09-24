# Phase 71 Plan: HTTP Configuration Runtime-Semantics Truthfulness Closure

Status: implemented/closed. Evidence: `architecture/http_config_runtime_semantics_matrix.md`; enforcement + guard tests `tests/http_config_runtime_semantics.rs` (6/6), helper unit tests in `crates/synvoid-http`, validation unit tests in `crates/synvoid-config`; routine verification recorded in the closeout commit.

Registered in: `plans/roadmap.md`.

Baseline reviewed: `main` at `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c` plus the Phase 70 planning registration.

Depends on: Phase 70 for final H1 parser/runtime ownership.

## Primary goal

Make every field in `synvoid_config::HttpConfig` truthful: each documented operator control must either have an executable runtime consumer with precisely documented scope, or be explicitly classified/deprecated rather than presented as an active security/performance control.

The EggServe Phase 65 qualification exposed several fields whose names/docs imply stronger runtime behavior than current code search demonstrates. This phase closes that configuration-surface debt without changing unrelated WAF/routing/backend policy.

## Required inventory

The canonical set to classify is:

- `header_read_timeout_secs`;
- `keep_alive_timeout_secs`;
- `max_headers`;
- `max_request_line_size`;
- `max_header_size_ingress`;
- `max_header_size_egress`;
- `max_request_size`;
- `pipeline_limit`;
- `waf_stall_timeout_secs`;
- `max_stalled_requests`;
- `max_connections`;
- `strict_protocol_validation`;
- `max_streaming_body_size`.

Create:

`architecture/http_config_runtime_semantics_matrix.md`

For every field record:

- config default and validation;
- documented meaning in `docs/CONFIGURATION.md`;
- admin-UI description;
- exact runtime consumer(s);
- transport scope: plaintext H1 / TLS-H1 / H2 / H3 / common policy;
- enforcement phase: pre-parse / parser / post-parse / body / response / request admission;
- failure behavior/status/connection close;
- whether the current implementation matches the advertised meaning;
- disposition: `ACTIVE_EXACT`, `ACTIVE_NARROWER_THAN_DOCS`, `INERT`, `DUPLICATE_POLICY`, or `DEPRECATED_COMPAT`;
- implementation/doc/test action.

Do not infer activity from a config field being copied through structs. A field is active only when executable runtime behavior consumes it.

## Current evidence that must be resolved

The planning review already established these facts; implementation must verify them against the then-current head rather than blindly accepting them:

- `header_read_timeout_secs`: consumed by plaintext H1; Phase 70 should make TLS-H1 equivalent.
- `max_headers`: plaintext H1 and TLS H2 have consumers; TLS-H1 parity is Phase 70.
- `max_request_size`: used as plaintext H1 Hyper `max_buf_size`, which is a parser-buffer control, not a request-body-size limit; TLS-H1 parity is Phase 70.
- `waf_stall_timeout_secs` and `max_stalled_requests`: actively consumed by H1/common WAF and H3 WAF paths.
- `max_connections`: used to size the root request semaphore in `HttpServer`; this appears to bound concurrent request handling/admission rather than literal accepted TCP connections, so documentation/name scope must be reconciled.
- `strict_protocol_validation`: actively controls pre-parser protocol sniff/probe behavior.
- `max_streaming_body_size`: actively consumed by request preparation/body-policy logic.
- repository search did not demonstrate runtime consumers for `keep_alive_timeout_secs`, `pipeline_limit`, `max_request_line_size`, or `max_header_size_egress`;
- `max_header_size_ingress` is documented as an aggregate request-header bound, but a canonical runtime consumer was not demonstrated by the review.

These are investigation starting points, not permission to write the matrix without executable confirmation.

## Workstream A — Classify before implementing

First land tests/evidence that demonstrate each field's current behavior.

For an apparently inert field, write a focused test that changes only that config value and proves no runtime behavior changes where the docs claim it should.

Do not permanently keep "tests that prove broken behavior" after remediation if they are misleading; convert them to positive contract tests or preserve the before-state in the evidence report.

## Workstream B — Low-risk exact runtime controls

Where the documented contract is clear and implementation can be added without inventing policy, make the control real.

### Request header aggregate size

If `max_header_size_ingress` is intended as total parsed request-header bytes:

- define the byte accounting precisely (header-name bytes + value bytes; state whether separator/CRLF overhead counts);
- enforce it in one canonical request-frontdoor/preflight location shared by plaintext H1, TLS-H1, H2, and H3 where message semantics permit;
- reject before routing/WAF/backend work;
- use a deterministic client error such as 431 if consistent with existing response policy;
- note that post-parse enforcement does not replace the transport parser's own memory ceiling; docs must not claim otherwise.

If the intended security contract requires a true pre-parse wire-byte ceiling, do not pretend a post-parse count is equivalent. Record the blocker and either add a transport-level solution in a separate plan or narrow the docs.

### Egress header aggregate size

Before implementing `max_header_size_egress`, choose and document failure semantics.

Do not truncate arbitrary response headers: truncating `Set-Cookie`, security headers, signatures, or application values can create incorrect/security-sensitive responses.

Preferred fail-closed policy if adopted:

- measure final headers after SynVoid response transforms;
- if over limit, replace an uncommitted response with a deterministic internal/upstream error according to provenance;
- never attempt a second response after streaming commitment.

If exact provenance-safe behavior cannot be implemented narrowly, mark the field deprecated/inert and correct docs/UI instead of inventing truncation.

## Workstream C — Request-line/target semantics decision

`max_request_line_size` is documented as the full H1 request line (method + URI + version), but Hyper exposes parsed request components rather than the exact original wire line to the application.

Choose one explicit contract:

1. **wire request-line limit** — implement at the H1 transport boundary before/while parsing using a bounded mechanism that sees the raw request line, without duplicating the whole HTTP parser; or
2. **request-target limit** — intentionally redefine the field in a backwards-compatible/deprecation path, with a new truthful name if needed and docs explaining the old key's compatibility mapping.

Do not approximate the full wire line after parsing and call it exact.

H2/H3 do not have an H1 request line; if the setting is H1-only, document that. If the desired policy is target-length across protocols, introduce/rename semantics deliberately and test all transports.

## Workstream D — Keep-alive timeout decision

`keep_alive_timeout_secs` currently appears documented as an idle persistent-connection timeout without a demonstrated Hyper H1 runtime consumer.

Determine whether the existing Hyper stack can enforce per-connection idle keep-alive timeout cleanly without:

- imposing a hard total connection lifetime;
- killing an active long request/body/response;
- racing WebSocket upgrades;
- duplicating worker shutdown logic.

If yes, implement a connection-activity-aware timeout and test idle vs active behavior for plaintext and TLS-H1.

If not, do not wrap the whole `serve_connection` future in `tokio::time::timeout`; that would implement the wrong total-lifetime semantic. Mark/deprecate the key truthfully and remove claims that it currently bounds idle sockets.

## Workstream E — Pipeline-limit decision

The docs currently describe `pipeline_limit` as limiting concurrent pipelined requests per connection. Prove whether the Hyper server actually exposes/needs such a bound under the current service model.

Do not map this field to:

- global request concurrency;
- `http.max_connections`;
- HTTP/2 stream concurrency;
- backend concurrency;

merely because all are semaphores/limits.

If exact H1 pipeline-depth control is not available or materially useful, classify the field as compatibility/deprecated and correct docs/UI. A no-op security knob is worse than an explicitly unsupported/deprecated knob.

## Workstream F — Reconcile max_connections semantics

Trace the `HttpServer::new` semaphore and the TLS server's corresponding shared semaphore to determine exact scope.

If it is held per request, documentation must say "concurrent HTTP request admission" rather than "TCP connections."

If the project intends a TCP connection cap, that is a distinct accept-loop resource policy and must not be silently substituted for the current request semaphore. Implementing a true connection cap requires:

- permit acquisition per accepted connection;
- permit lifetime through connection close;
- plaintext/TLS parity;
- interaction with flood protection and worker scaling;
- WebSocket/tunnel lifetime semantics.

Make that a separate plan if needed rather than changing the meaning of `http.max_connections` invisibly.

Preserve public config compatibility.

## Workstream G — Validation bounds

After final semantics are known, extend `HttpConfig::validate()` for fields whose runtime/library APIs have hard valid ranges.

Examples:

- parser buffer minimums/maximums required by Hyper;
- header counts that overflow H2's `u32` conversion;
- zero values that would disable a required security control unexpectedly.

Do not add arbitrary upper bounds solely because EggServe had different bounds; EggServe is not the production runtime.

Validation errors must name the exact field and reason.

## Workstream H — Documentation/admin UI reconciliation

Update all operator surfaces from the matrix, including:

- `docs/CONFIGURATION.md`;
- `docs/TROUBLESHOOTING.md`;
- `architecture/config.md`;
- `architecture/http_server.md`;
- `admin-ui/src/config_docs.rs`;
- generated/example config comments where semantics are described;
- `.opencode/skills/httpserver/SKILL.md`.

Rules:

- no active-sounding description for an inert field;
- no "connection" wording for a request semaphore unless that is truly the runtime scope;
- no "truncates" wording for egress headers unless runtime actually truncates and that behavior is intentionally accepted;
- protocol-specific scope must be explicit.

Keep deprecated keys parseable unless a separate compatibility/version decision authorizes removal.

## Workstream I — Truthfulness guard

Add a focused repository guard/test that enumerates the canonical `HttpConfig` fields and requires each to appear in the runtime-semantics matrix with one allowed disposition.

For fields classified `ACTIVE_EXACT`, add behavior tests at the owning runtime boundary.

For `DEPRECATED_COMPAT`, add a config parse test and documentation marker but do not require a fake runtime consumer.

The guard should prevent future config fields from being added to `HttpConfig` and the admin UI without a runtime-semantics disposition.

## Verification

Focused:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-config --cargo-profile ci --profile ci
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo xtask test guards
```

Run root/TLS/H3 suites for every field whose scope crosses those transports.

Profiles:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Broader:

```bash
cargo xtask verify
```

If runtime behavior or public configuration semantics materially change, run the repository's current full/release verification gates and record them in the closeout evidence.

## Acceptance criteria

Phase 71 is complete only when:

- every `HttpConfig` field has one documented runtime-semantics disposition;
- no field is described as an active protection/tuning knob without an executable consumer;
- fields with straightforward exact semantics are enforced consistently across their intended transports;
- request-line vs request-target semantics are explicit rather than approximated;
- keep-alive is either a true idle timeout or truthfully deprecated/inert, never a total-lifetime timeout disguised as idle;
- pipeline limit is either genuinely enforced at H1 pipeline scope or truthfully deprecated;
- `max_connections` documentation matches the actual permit lifetime/scope;
- ingress/egress header size semantics are exact and fail safely;
- configuration validation matches library/runtime valid ranges;
- docs, admin UI, examples, architecture, and runtime agree;
- a guard prevents new undocumented/no-op `HttpConfig` fields;
- routine verification passes.

## Stop/split conditions

Split a new implementation plan instead of broadening Phase 71 if truthful enforcement requires:

- a custom/raw H1 parser;
- a new TCP connection-admission subsystem;
- invasive connection-activity instrumentation for idle keep-alive;
- response buffering solely to calculate egress headers;
- public config key removal or incompatible semantic rename.

In those cases, close the affected field as `DEPRECATED_COMPAT` or precisely documented residual for this phase, and register the separate follow-up with a concrete blocker/owner.
