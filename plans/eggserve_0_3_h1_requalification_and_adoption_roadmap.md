# EggServe 0.3 Direct H1 Requalification and Adoption Roadmap

Status: planned. Phase 73 is qualification-ready. Phases 74–78 are gated on an
explicit Phase 73 GO decision against an exact published EggServe artifact.

Planning baseline: `dd1ff0fcfe4ce11da0036adbf39c2d595e9a2246`
(Phase 72 HTTP truthfulness closeout metadata head).

Historical context:

- the EggServe 0.2.2-line campaign closed `RETAIN_CURRENT_H1` at Phase 65;
- historical Phases 66–69 were never started and remain historical, not an
  implementation queue;
- Phases 70–72 corrected the retained Hyper H1 runtime/config truthfulness and
  are closed;
- upstream EggServe subsequently implemented and published a materially new
  direct-H1 embedding contract.

## Upstream baseline motivating requalification

Published artifacts qualified upstream under EggServe Plan 286:

- `eggserve-primitives 0.2.1`, checksum
  `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101`;
- `eggserve-server 0.3.0`, checksum
  `b26bcaeb357dfafeb780649c789765c7b6545d85388ecdbb446a47ff78aac082`.

Upstream proof-bearing source:
`c62faf59b19913eb49b97d371435122c5a8fb6ac`, CI run
`36067050590` (success). Published-artifact closeout head:
`15a9f4b2d98152c9dcfb630a8fd57e9357610e3e`, CI run
`36071193286` (success).

The new direct runtime materially resolves the Phase 65 blockers:

- `H1PolicyOwnership` supports explicit External ownership for handler,
  request-body, idle, response-write, global-body-ceiling, and semantic
  request-target policy;
- `AdmissionOwnership` supports External service/tunnel admission;
- total connection lifetime can be disabled;
- `RuntimeConfig::h1_connection_policy()` projects a narrow
  `H1ConnectionPolicy`;
- `serve_http1_connection_with_policy` accepts caller-owned established byte
  streams, including completed Rustls streams;
- `RuntimeRejectionPresenter` provides a bounded typed error-presentation
  seam;
- the H1 tunnel path now hands an opaque direct `TunnelIo` to the service;
- the direct server graph remains independent of EggServe core/static/PHF.

Those changes justify requalification. They do **not** by themselves authorize
production adoption.

## Current SynVoid-side findings

Repository review at the planning baseline found two remaining exact-artifact
compatibility blockers plus one required internal refactor.

### Blocker A — final response metadata authority

SynVoid owns per-site response metadata through
`SiteSecurityHeadersConfig`, including:

- `date_header`;
- `date_jitter_seconds`;
- `server_token`.

The current EggServe 0.3.0 final response boundary removes service-provided
`Date` and `Server`, then applies one runtime-level `ResponsePolicy`.
That cannot represent different Date enable/jitter or Server token settings for
different sites sharing one runtime.

`RuntimeRejectionPresenter` does not solve this: it applies only to
runtime-generated rejection presentation, not ordinary service responses.

Therefore current 0.3.0 cannot replace production H1 without either:

1. a generally useful upstream response-metadata ownership/preserve mode that
   keeps canonical framing authority while allowing validated service-owned
   `Date`/`Server`; or
2. an explicit SynVoid product/config compatibility decision removing or
   changing the per-site behavior.

No plan in this program may silently choose option 2.

### Blocker B — mandatory parser/header scalar ranges

SynVoid currently admits valid configurations beyond EggServe 0.3.0's
mandatory validation maxima.

Relevant EggServe bounds:

- `max_buf_size <= 4 MiB`;
- `max_headers <= 10_000`;
- `max_header_bytes <= 1 MiB`.

Relevant SynVoid behavior:

- `http.max_request_size` is the H1 parser-buffer ceiling, validated only
  with a lower bound of 8192;
- `http.max_headers` is valid through `u32::MAX`;
- `http.max_header_size_ingress` is valid for any nonzero `usize` and is
  enforced canonically after parsing.

For ordinary/default SynVoid values the ranges overlap, but adoption must
preserve the currently valid config surface. A runtime that refuses a
previously valid larger value is a compatibility regression.

Phase 73 must either prove a later published EggServe artifact removes/extends
these bounds sufficiently, or explicitly retain Hyper. Do not clamp.

### Required SynVoid refactor — Hyper types cross the policy boundary

The canonical `synvoid-http` H1/H2 pipeline still carries
`hyper::body::Incoming` through request frontdoor, preparation, body policy,
streaming, internal endpoints, and backend dispatch. It also carries
`hyper::upgrade::OnUpgrade` through request preparation and WebSocket
dispatch.

EggServe's canonical `RequestBody` and `TunnelCapability` cannot be
converted back into those concrete Hyper types. If Phase 73 reaches GO,
SynVoid must first introduce a transport-neutral inbound body/request/upgrade
boundary while leaving current Hyper transports in production.

The response side is less invasive: SynVoid already uses standard
`http::Response<BoxBody<Bytes, Infallible>>`. Phase 75 should adapt that
response at the root EggServe service boundary rather than redesigning every
backend response type.

## Target ownership after successful adoption

```text
SynVoid
  bind / accept / flood / protocol sniff
  TLS / SNI / PQ / JA4 / ALPN
  H2 + H3 transport
  per-request admission + site traffic policy
  WAF / routing / backend policy
  per-site response metadata/security policy
  worker drain/shutdown policy
       |
       | caller-owned H1 stream
       v
EggServe direct H1
  H1 parser/framing
  canonical body/tunnel transport mechanics
  connection driver + graceful close
  canonical response framing
       |
       v
SynVoidEggserveService
  neutral request/body/upgrade adapter
       |
       v
existing synvoid-http policy/backend pipeline
```

No EggServe listener, TLS termination, H2/H3, static-serving, CLI, or Python
ownership enters SynVoid.

## Execution sequence

```text
73  exact EggServe 0.3.x requalification + remaining-contract gate
 |
 | GO only
 v
74  transport-neutral SynVoid inbound body/request/upgrade boundary
 |
75  EggServe service/config/response/tunnel adapter + differential qualification
 |
76  plaintext H1 production adoption
 |
77  TLS-ALPN H1 convergence (H2 unchanged)
 |
78  adversarial/performance/release closeout + legacy H1 retirement
```

Detailed plans:

- `plans/phase_73_eggserve_0_3_runtime_requalification_and_contract_gate.md`
- `plans/phase_74_http_transport_neutral_inbound_and_upgrade_boundary.md`
- `plans/phase_75_eggserve_0_3_adapter_and_differential_qualification.md`
- `plans/phase_76_eggserve_plaintext_h1_production_adoption.md`
- `plans/phase_77_eggserve_tls_h1_runtime_convergence.md`
- `plans/phase_78_eggserve_h1_adversarial_performance_closeout.md`

## Program invariants

- no valid SynVoid config is silently clamped or rejected because of an
  EggServe implementation maximum;
- no per-site Date/server-token behavior is silently converted into one global
  runtime policy;
- no default EggServe deadline/admission policy becomes an accidental second
  authority;
- no request/response buffering is introduced solely for adaptation;
- no WebSocket capability loss;
- no listener/TLS/H2/H3/static-policy migration;
- no permanent dual production H1 runtime;
- no raw EggServe type becomes a canonical `synvoid-http` domain type;
- Hyper remains in the workspace for H2 and other existing consumers even if
  production H1 moves;
- performance/footprint claims require measured evidence.

## Stop rule

Phase 73 may close `RETAIN_PENDING_UPSTREAM` or `RETAIN_CURRENT_H1`. That is
a valid result.

Phases 74–78 must not begin merely because most Phase 65 blockers disappeared.
They require an exact published artifact that preserves SynVoid response-policy
and valid-config semantics, or a separately approved SynVoid compatibility
change with its own plan.

If a later EggServe release supplies the missing generic contracts, rerun Phase
73 against that exact registry artifact and only then open Phase 74.
