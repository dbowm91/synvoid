# EggServe 0.2.2-Line H1 Compatibility Qualification

Status: **RETAIN_CURRENT_H1** at Phase 65. No production route or manifest dependency changed.

## Baseline and upstream artifacts

- Repository baseline: `79379d555ca4a8b6359760af2052a6e8228c3cfd` (`main`, 2026-09-24). The handoff plan names `11a1fb2844cd648418eefd72801f1aee2090d140`; that is not the checked-out baseline used here.
- Rust toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`.
- Registry artifacts, downloaded from crates.io:

| Crate | Version | SHA-256 |
| --- | --- | --- |
| `eggserve-server` | `0.2.1` | `255c1e95d0e6c6f7db8c26ea128267b3a1851dafe0f13a8229cdbec38a630feb` |
| `eggserve-primitives` | `0.2.0` | `8732e77fae06b395f992cb1dd163ca30750e2f44d1fed3824eb8fc4650dafc03` |
| `eggserve-core` | `0.2.2` | `d7ad027bf61c2f505c5a591348d03ab7d92cf1849af45e8d804e5593eb13bb54` |

All three require Rust 1.89, below the checked-out toolchain. Both the direct leaf and core packages resolve with default features disabled. The direct leaf uses the existing SynVoid HTTP/Tokio foundation (`hyper`, `hyper-util`, `http`, `http-body`, `bytes`, `tokio`) and adds no TLS/H2/H3/static ownership. Core adds the static-serving composition and its supporting filesystem/template dependencies (including `eggserve-static`, `rustix`, and `phf`); it is not justified for the intended adapter. If adoption is reconsidered, the only candidate is `eggserve-server = 0.2.1` plus `eggserve-primitives = 0.2.0`.

## Current ownership and coupling inventory

| SynVoid location | Current role / coupling | Required disposition if reconsidered | Phase 69 candidate deletion |
| --- | --- | --- | --- |
| `src/http/server/accept_loop.rs` | Socket accept, flood check, protocol sniff/prefix, Hyper H1 builder and connection task | Keep all listener/security work; substitute only H1 driver | Hyper H1 builder and driver |
| `src/http/server/connection_types.rs` | Connection stream/prefix lifecycle and connection drop signalling | Preserve sniffed bytes exactly once; prove whether lifecycle wrapper remains needed | Only dead generic H1 plumbing |
| `src/http/server.rs` | Root composition and request entry; Hyper request/body boundary | Keep composition; adapt transport request into neutral envelope | No blanket Hyper removal |
| `src/tls/server.rs` | TLS accept, flood/probe, Rustls, ALPN, H1/H2 routing and Hyper request/body boundary | Keep TLS and H2; hand only ALPN H1 stream to shared H1 driver | TLS H1 builder/closure only after parity |
| `crates/synvoid-http/src/request_frontdoor.rs` | Canonical policy flow; currently Hyper request types | SynVoid-owned request/body/tunnel envelope | Hyper type imports that are only for H1 policy |
| `request_preparation.rs` | Routing/preflight and Hyper upgrade capture | Move upgrade capture to transport adapter; retain one canonical validation authority | Hyper upgrade coupling |
| `http_request_flow.rs` | Canonical staged request flow with Hyper request/body types | Consume neutral envelope | Hyper request/body signatures |
| `body_policy.rs`, `shared_handler.rs`, streaming helpers | Body collection/WAF thresholds, concrete `Incoming` body polling | Incremental generic `http_body::Body` adapter, preserving errors/drop/trailers semantics | Hyper body-specific helpers only |
| Internal/special endpoint dispatch | Canonical dispatch and pass-through body ownership | Neutral request/body | Hyper body signatures |
| WebSocket upgrade/dispatch | Canonical validation plus Hyper `OnUpgrade` and upgraded IO | SynVoid one-shot capability with `AsyncRead + AsyncWrite`; transport adapter owns conversion | Hyper-only capability adapter if unused by H2 |
| Response construction/streaming | SynVoid response body streams through Hyper response aliases | Frame-preserving conversion to EggServe canonical response stream | H1-only response adapters |
| Drain/connection accounting | Worker drain flags, connection/request semaphores, metrics, task/drop signaling | One shutdown/admission owner; preserve existing worker contract | Superseded H1-only lifecycle code |

Hyper remains required by H2, HTTP/3 integrations, Axum/Tonic, and outbound/client paths. This campaign would not remove Hyper from the workspace.

## Configuration projection inventory

| SynVoid value | Candidate EggServe value | Assessment |
| --- | --- | --- |
| `header_read_timeout_secs` | `header_read_timeout` | Direct seconds mapping (current default 10s). |
| `keep_alive_timeout_secs` | `keep_alive_idle_timeout` | Direct seconds mapping (current default 60s). |
| `max_headers` | `max_headers` | Direct for the current default 128; EggServe accepts 1–10,000 while SynVoid currently has no corresponding upper validation. |
| `max_request_line_size` | `max_request_target_bytes` | Related but not identical: request line includes method/version; EggServe bounds target length separately (128 bytes–64 KiB). SynVoid currently has no matching upper validation. |
| `max_header_size_ingress` | `max_header_bytes` | Aggregate name+value byte policy; current default 4096 is within EggServe's 1 KiB–1 MiB range. |
| `max_request_size` | `max_buf_size` | Current plaintext Hyper parser buffer; current default 1 MiB is within EggServe's 8 KiB–4 MiB range. Do not use it as a body limit. |
| `max_streaming_body_size` | `max_request_body_bytes` | Not exact: SynVoid's body policy has distinct fixed-small-body, streaming-WAF, and post-collection paths. EggServe's global hard ceiling rejects before service invocation. Current default 10 MiB is supported; unbounded SynVoid config values above EggServe's 1 GiB ceiling are not. |
| `pipeline_limit`, `max_connections`, request semaphore | EggServe connection/in-flight admission | No direct same-scope mapping is proven; setting parallel EggServe semaphores risks changed queue/503 and double-limit semantics. |
| No hard connection lifetime | `connection_total_timeout` | Can be disabled with `Duration::ZERO`. |
| No generic handler, total body-read, or no-progress response-write deadline | Required nonzero `handler_timeout`, `body_read_timeout`, `response_write_timeout` | **Blocking mismatch.** EggServe validation rejects zero; each finite timeout can preempt a SynVoid request/body/response path currently allowed to continue. There is no equal-scope SynVoid setting from which to derive it. |
| Existing request/tunnel admission | `max_active_tunnels` | EggServe requires a separate nonzero tunnel semaphore. Equality to connection admission may avoid a lower numeric ceiling but still adds a second authority and needs lifecycle/admission proof. |

No production projection helper was added because the mandatory timeout semantics have no non-interfering value. Setting a very long finite deadline would only defer the changed behavior, not prove parity. An arbitrary timeout or silently bounded config would violate the plan's mandatory-control rule.

## Runtime/body/tunnel/stream feasibility

- `eggserve-server 0.2.1` exposes `serve_http1_connection` over caller-owned Tokio `AsyncRead + AsyncWrite + Unpin + Send` streams. Its public connection context represents local/remote socket addresses and HTTP/HTTPS scheme; TLS is not performed by the driver. Source inspection confirms a TCP or completed `tokio-rustls::TlsStream<TcpStream>` can be handed in without EggServe binding or terminating TLS.
- The leaf H1 runtime itself still uses Hyper internally (`Incoming`, `OnUpgrade`) and converts into EggServe's canonical request/body types. This does not force Hyper into SynVoid's canonical policy API: a root adapter can bridge standard HTTP heads and frame streams to a SynVoid-owned envelope. EggServe's response model supports bytes and pull-driven streams, so a no-full-buffering adapter is structurally feasible, but this phase did not add or claim a tested adapter.
- The leaf runtime offers one-shot `TunnelCapability::accept` with validated tunnel intent, ordered bounded handshake headers, a bounded `TunnelIo`, and transport-owned framing. SynVoid can represent this behind its own one-shot capability alongside Hyper `OnUpgrade`; duplicate/opaque header, cancellation, and read-ahead parity still require executable adapter tests before adoption.
- Hyper body and response adapters can preserve DATA frames and trailers with standard `http-body` frame polling. This was not implemented or claimed as proven because the Phase 65 configuration gate already fails.

## Decision and blocker

**Decision: `RETAIN_CURRENT_H1`.** Keep production on the current Hyper plaintext and TLS-H1 paths. Do not start Phase 66–69 on this baseline.

Blocking contract: EggServe 0.2.1 requires nonzero handler, body-read, and response-write timeouts. SynVoid has no equivalent total deadlines for these scopes; body policies and WAF stall timeouts do not cover the same work. No finite timeout is provably non-interfering with SynVoid's currently supported slow body, long-running handler, or backpressured response paths. The same runtime also requires finite maxima for request target, parser buffer, header count/bytes, and a 1 GiB hard request-body ceiling where SynVoid has no matching upper config validation. Production adoption would therefore silently narrow existing configuration/runtime behavior, or require a separate policy decision/upstream API change.

The blocker is EggServe runtime contract/configuration, not missing listener/TLS ownership. A generally useful upstream change would provide explicit disabled semantics for handler/body/write deadlines and permit service-owned or disabled global body ceilings, plus limits whose upper bounds can be projected without narrowing caller config. After such a published artifact exists, repeat qualification with executable body/tunnel parity tests before deciding whether Phase 66 may start.

The known plaintext startup log still says HTTP/1.1 + HTTP/2 although the shown driver is H1-only; it remains a pre-existing truthfulness issue and was not changed because no runtime migration landed. TLS H1 parser settings also remain as before. README behavior/dependency claims remain accurate and need no update.

## Qualification commands and evidence scope

Executed `cargo info` for each pinned registry artifact; inspected the direct-leaf `RuntimeConfig`, validation kernel, connection driver, request conversion, tunnel API, and caller-owned TCP example. Compared isolated feature trees for direct leaf versus core with defaults disabled. Registry checksums above are SHA-256 of the downloaded `.crate` archives.

The adapter-specific body/tunnel, adversarial-wire, and performance matrices were not run because this decision stops before implementation and leaves the worktree's production code unchanged. The retained branch does not claim those parity results; they belong to a future requalification after the upstream contract changes.

Local repository verification on the docs-only closeout:

- `cargo xtask verify` — passed all 10 steps (fmt, clippy, dependency policy, core compile, repo guards, security regression, root guards, core admin tests, admin contract, failure injection).
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci` — 87 passed.
- `cargo nextest run -p synvoid-config --cargo-profile ci --profile ci` — 89 passed.
- `cargo check --no-default-features` — passed as the `core-compile` step in `cargo xtask verify`.
- `cargo check --no-default-features --features post-quantum` — passed.
- `cargo check --no-default-features --features mesh` — passed.
- `cargo check --no-default-features --features dns` — passed.
- `cargo check --no-default-features --features mesh,dns` — passed.
- `cargo deny check` — passed as the `dependency-policy` step in `cargo xtask verify`.
- `cargo audit` — passed with six existing allowed unmaintained-crate advisories (atomic-polyfill, bincode 1/2, fxhash, proc-macro-error, proc-macro-error2); no vulnerable crate failure.

The full/release closeout commands were not run: Phase 69 was not entered and no EggServe runtime was adopted or benchmarked.
