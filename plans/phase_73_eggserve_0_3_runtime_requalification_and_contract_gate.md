# Phase 73 Plan: EggServe 0.3 Runtime Requalification and Contract Gate

Status: **closed — `RETAIN_PENDING_UPSTREAM` on 0.3.0; re-run 2026-09-25
reached `GO_DIRECT_0_3` against the pinned `eggserve-server = "=0.3.1"` /
`eggserve-primitives = "=0.2.1"` artifacts** (evidence:
`architecture/eggserve_0_3_1_h1_requalification_addendum.md`,
`crates/synvoid-http/tests/eggserve_0_3_1_qualification.rs`). The production
status recorded at Phase 73 was accurate only at that decision point.
Phases 74–78 subsequently implemented adoption at
`2242e1911d2083448371f707392fdb07f83f1bce`, and
corrective Phases 79–80 closed the current production disposition as
`ADOPTED` on EggServe 0.4.0 / primitives 0.2.2. The 0.3.0 compatibility
result remains historical and unchanged. Evidence:
`architecture/eggserve_0_3_h1_compatibility_matrix.md`.

Registered in: `plans/roadmap.md`.

Parent campaign:
`plans/eggserve_0_3_h1_requalification_and_adoption_roadmap.md`.

Planning baseline:
`dd1ff0fcfe4ce11da0036adbf39c2d595e9a2246`.

## Purpose

Repeat the historical Phase 65 direct-H1 qualification against the materially
different published EggServe 0.3 runtime and decide whether SynVoid may begin a
new production-adoption sequence.

This phase must not route production traffic through EggServe.

The only valid terminal decisions are:

- `GO_DIRECT_0_3` — every required SynVoid contract is representable on the
  exact published artifact;
- `RETAIN_PENDING_UPSTREAM` — the direct architecture is otherwise viable,
  but one or more generally useful upstream contracts are still missing;
- `RETAIN_CURRENT_H1` — a deeper correctness/security/maintenance mismatch
  makes adoption unattractive.

## Exact upstream artifacts

Begin by querying crates.io again. At planning time the qualified publication
is:

- `eggserve-primitives = "=0.2.1"`
  - checksum
    `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101`;
- `eggserve-server = "=0.3.0"`
  - checksum
    `b26bcaeb357dfafeb780649c789765c7b6545d85388ecdbb446a47ff78aac082`.

Upstream source proof:
`c62faf59b19913eb49b97d371435122c5a8fb6ac`.

Upstream publication closeout:
`15a9f4b2d98152c9dcfb630a8fd57e9357610e3e`.

If a newer release exists at execution time, do not silently substitute it.
Record both the latest registry state and the exact candidate being qualified.
A later release may be selected only if the evidence explains which blocker it
changes and pins its checksum.

## Workstream A — dependency/profile truth

Capture before/after direct-leaf graphs without adding EggServe core/static:

```bash
cargo tree -i hyper
cargo tree -i hyper-util
cargo tree -i http
cargo tree -i http-body
cargo tree -i bytes
cargo tree -i tokio
```

Qualify the direct profile only:

```toml
eggserve-server = { version = "=0.3.0", default-features = false }
eggserve-primitives = { version = "=0.2.1", default-features = false }
```

Do not enable Tower unless a test proves the native service interface cannot
represent a required boundary. The expected production shape is the native
direct service contract.

Prefer a standalone qualification fixture or test-only dependency placement.
Do not add a production EggServe dependency until this phase reaches GO.

Record:

- resolved versions/checksums;
- no-dev package count;
- whether direct EggServe adds core/static/PHF ancestry;
- duplicate Hyper/Tokio/http-body versions;
- MSRV compatibility with SynVoid.

## Workstream B — reclassify every Phase 65 runtime control

Build a new evidence file:

`architecture/eggserve_0_3_h1_compatibility_matrix.md`.

Do not edit the historical 0.2.2 matrix into a new conclusion.

Required mapping:

| SynVoid contract | EggServe 0.3 candidate | Required disposition |
| --- | --- | --- |
| H1 header timeout | `header_read_timeout` | exact projection |
| H1 parser buffer | `max_buf_size` | exact only if full valid range fits |
| H1 header count | `max_headers` | exact only if full valid range fits |
| canonical ingress header bytes | EggServe `max_header_bytes` + SynVoid preflight | avoid an earlier narrower ceiling |
| deprecated request-line key | semantic target ceiling | keep EggServe target ceiling External |
| streaming/body WAF policy | service `RequestBodyPolicy` | SynVoid must remain size/WAF authority |
| generic handler timeout | `PolicyOwner::External` | no EggServe deadline |
| generic body deadline | `PolicyOwner::External` | no EggServe total body deadline |
| keep-alive idle timeout | `PolicyOwner::External` | current SynVoid key is not enforced |
| write no-progress timeout | `PolicyOwner::External` | no new deadline |
| hard total connection lifetime | zero/disabled | preserve current no-total-lifetime behavior |
| request admission semaphore | `AdmissionOwner::External` | preserve SynVoid queueing/metrics |
| tunnel admission | `AdmissionOwner::External` | do not add a new tunnel cap |
| response error representation | presenter/service responses | prove status/body/header parity |
| per-site Date/Server behavior | EggServe final response policy | **hard gate** |
| connection drop request | `ConnectionShutdown` | prove response-then-close parity |

The candidate production ownership profile, if GO, should be explicit:

```text
H1PolicyOwnership:
  handler_deadline = External
  request_body_deadline = External
  keep_alive_idle_deadline = External
  response_write_progress_deadline = External
  global_request_body_ceiling = External
  request_target_ceiling = External

AdmissionOwnership:
  service_calls = External
  tunnels = External

connection_total_timeout = disabled
http1_request_target_mode = OriginOnly
```

Other scalar fields still require valid EggServe values even when their
execution policy is External. Record every placeholder and why it cannot affect
runtime behavior.

## Workstream C — mandatory range compatibility

This is a hard compatibility gate, not a documentation note.

At planning time:

- SynVoid `http.max_request_size` accepts any value >= 8192;
  EggServe `max_buf_size` caps at 4 MiB.
- SynVoid `http.max_headers` accepts through `u32::MAX`;
  EggServe caps at 10,000.
- SynVoid `http.max_header_size_ingress` accepts any nonzero `usize`;
  EggServe `max_header_bytes` caps at 1 MiB.

Default values fit. That is insufficient.

Required proof:

1. enumerate the full SynVoid validation range;
2. compare it to the exact candidate validation kernel;
3. construct boundary fixtures at, below, and above EggServe maxima;
4. demonstrate there is no hidden alternate public
   `H1ConnectionPolicy` constructor that bypasses validated parser policy;
5. reject clamping or per-config silent fallback as the default solution.

A GO is allowed only if:

- the exact upstream candidate supports SynVoid's currently valid range; or
- a separate explicit SynVoid compatibility plan has already changed that
  public config contract.

Do not add new upper bounds inside Phase 73.

## Workstream D — per-site response metadata authority

This is the second hard gate.

SynVoid currently permits per-site:

- `SiteSecurityHeadersConfig.date_header`;
- `date_jitter_seconds`;
- `server_token`.

Exercise at least two sites on one runtime with intentionally different
settings.

Prove the exact EggServe final response boundary can preserve:

- Date enabled on one site and disabled on another;
- different Date jitter policy;
- different Server token values;
- existing security headers;
- `Set-Cookie`, CSP, cache, and Alt-Svc values;
- duplicate legal application headers.

At planning time, EggServe 0.3.0 removes service `Date`/`Server` and
re-applies one runtime-level `ResponsePolicy`; that is not sufficient.

A GO requires a published generic upstream preservation/external-ownership
contract or a separately approved SynVoid compatibility change.

Do not use task-local/global side channels to smuggle per-request policy into a
global Date provider.

## Workstream E — body adaptation executable prototype

Even if Workstreams C/D currently block GO, retain a bounded prototype so no
second hidden blocker is deferred.

Using tests/fixture code only, convert:

```text
EggServe RequestBody
  -> candidate SynVoid neutral body stream
  -> current body/WAF machinery
```

Cover:

- empty body;
- fixed Content-Length;
- multi-frame body;
- chunked/unknown-length body;
- trailers;
- body transport error;
- early drop/cancellation;
- body above `max_streaming_body_size`;
- WAF block while streaming.

The intended final ownership is that SynVoid remains the body-size/WAF policy
authority. Prefer an EggServe service `RequestBodyPolicy::Stream` whose limit
does not preempt the SynVoid limit, combined with
`global_request_body_ceiling = External`.

Do not accept a change where EggServe returns 413 before SynVoid accounting/WAF
when current SynVoid behavior requires the request to reach canonical policy
first, unless differential evidence proves the externally visible contract is
equivalent and metrics/accounting remain correct.

## Workstream F — tunnel/WebSocket prototype

Prototype one neutral one-shot upgrade capability representing:

- current Hyper `OnUpgrade`;
- EggServe `TunnelCapability`.

Required behavior:

- WebSocket request validation remains SynVoid-owned;
- one-shot accept;
- `Sec-WebSocket-Accept` and negotiated protocol preserved;
- no application control over forbidden framing;
- immediate post-upgrade read-ahead delivered exactly once;
- handler receives only Tokio `AsyncRead + AsyncWrite`;
- disconnect/cancellation closes both directions;
- app-server WebSocket path and upstream WebSocket path both work;
- declined capability stays ordinary HTTP.

The prototype must not expose EggServe types from the canonical
`synvoid-http` API.

## Workstream G — connection-drop/shutdown prototype

Current WAF `Drop` calls a request-drop callback tied to the H1 connection.

Prove a cloned EggServe `ConnectionShutdown` can represent this contract:

1. service selects the same terminal response currently produced;
2. drop callback signals graceful connection shutdown;
3. response bytes are committed as today;
4. keep-alive does not accept another request afterward;
5. shutdown cannot truncate the selected response unexpectedly;
6. worker/global drain remains separately observable.

If semantics differ, classify the mismatch. Do not change WAF Drop behavior
inside qualification.

## Workstream H — response-stream prototype

Convert the existing:

`http::Response<BoxBody<Bytes, Infallible>>`

to EggServe canonical response types without full buffering.

Cover:

- empty;
- fixed bytes;
- unknown-length stream;
- known-length stream where represented;
- trailers;
- tarpit/slow stream;
- upstream body early termination;
- HEAD;
- 204/205/304;
- duplicate headers;
- current security/Alt-Svc/cookie metadata.

The EggServe runtime remains final framing authority. SynVoid remains
application/security metadata authority subject to the response-metadata hard
gate above.

## Workstream I — decision evidence

The new matrix must state:

- exact SynVoid baseline;
- exact crates.io versions/checksums;
- exact upstream source/CI evidence;
- dependency graph delta;
- all config/range mappings;
- response metadata result;
- body/response prototype result;
- tunnel result;
- connection-drop result;
- remaining blocker list;
- terminal decision.

### GO criteria

`GO_DIRECT_0_3` requires all of:

- full valid SynVoid H1 parser/header config range preserved;
- per-site Date/Server behavior preserved;
- no duplicate deadline/admission authority;
- body/WAF semantics preserved;
- WebSocket/app-server tunnel parity proven;
- response streaming preserved;
- request-drop/drain behavior preserved;
- caller-owned TCP/prefixed/TLS streams proven;
- no core/static/TLS/H2/H3 migration required;
- security/dependency gates green.

### Retain criteria

If either mandatory range compatibility or per-site response metadata remains
unrepresentable, close `RETAIN_PENDING_UPSTREAM`; do not begin Phase 74.

## Verification

At minimum, using the repository's current commands at execution time:

```bash
cargo fmt --all -- --check
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-config --cargo-profile ci --profile ci
cargo xtask test guards
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
cargo deny check
cargo audit
cargo xtask verify
```

Add focused standalone/adapter tests for the exact EggServe artifact. No
production route changes.

## Acceptance criteria

- [ ] exact published EggServe candidate and checksums recorded;
- [ ] Phase 65 blocker table re-evaluated rather than copied;
- [ ] every EggServe runtime control has an explicit SynVoid ownership
      disposition;
- [ ] full valid SynVoid parser/header config space is compared;
- [ ] per-site Date/Server behavior is executable-tested;
- [ ] body and response stream adapters are executable-tested;
- [ ] Hyper and EggServe tunnel capabilities are both represented by the
      proposed neutral contract;
- [ ] WAF request-drop mapping is executable-tested;
- [ ] caller-owned plaintext/prefixed/TLS transport seam remains viable;
- [ ] dependency/security/profile gates pass;
- [ ] explicit GO/RETAIN decision recorded;
- [ ] production remains Hyper H1 throughout Phase 73.

## Non-goals

- No Phase 74 neutral-boundary implementation.
- No production EggServe dependency.
- No plaintext/TLS route migration.
- No config range narrowing.
- No removal of per-site response policy.
- No H2/H3 change.
