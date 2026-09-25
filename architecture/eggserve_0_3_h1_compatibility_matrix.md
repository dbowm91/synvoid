# EggServe 0.3 H1 Compatibility Qualification

Status: **RETAIN_PENDING_UPSTREAM**. Production remains on Hyper H1. Phases
74–78 are not authorized by this result and remain gated.

## Candidate and baseline

- SynVoid baseline: `33f5de72` (Phase 73 plan registration; working tree was
  clean before qualification).
- Registry query date: 2026-09-25 (`cargo info` against crates.io).
- Latest published candidates remain `eggserve-server 0.3.0` and
  `eggserve-primitives 0.2.1`; no newer release was substituted.
- Exact archive SHA-256 values, verified from Cargo's downloaded registry
  archives:

| Crate | Version | SHA-256 | Rust requirement |
| --- | --- | --- | --- |
| `eggserve-server` | `0.3.0` | `b26bcaeb357dfafeb780649c789765c7b6545d85388ecdbb446a47ff78aac082` | 1.89 |
| `eggserve-primitives` | `0.2.1` | `ba5372af39cb279fab9cc672608fe83c3ac5ca16d8f8ce058c2400626ef3a101` | 1.89 |

Both support the repository's current Rust toolchain. The selected profile
would disable default features and use only the direct server and primitives
crates; no production dependency was added. Registry sources were inspected
from Cargo's unpacked archives. The direct H1 driver accepts caller-owned
Tokio streams and has a narrow `H1ConnectionPolicy`; construction is only
through `RuntimeConfig::h1_connection_policy()` (policy fields are private).

## Runtime-control disposition

| SynVoid contract | EggServe 0.3 candidate | Disposition |
| --- | --- | --- |
| H1 header timeout | `header_read_timeout` | Exact projection is representable. |
| H1 parser buffer | `max_buf_size` | **Incompatible range:** EggServe caps at 4 MiB; SynVoid has no upper bound. |
| H1 header count | `max_headers` | **Incompatible range:** EggServe caps at 10,000; SynVoid permits through `u32::MAX`. |
| Canonical aggregate ingress header bytes | `max_header_bytes` plus SynVoid preflight | **Incompatible range:** EggServe requires 1 KiB–1 MiB; SynVoid permits every nonzero `usize`. An EggServe value below SynVoid's configured ceiling can reject first. |
| Deprecated request-line key | `max_request_target_bytes` | Not semantically equivalent; SynVoid's deprecated key is not an enforced target ceiling. No safe projection. |
| Request body size and WAF | `RequestBodyPolicy` and `global_request_body_ceiling` | External ownership is available; SynVoid can remain policy owner in principle. No SynVoid adapter prototype was completed in this gate. |
| Handler/body/idle/write deadlines | `H1PolicyOwnership::External` | External ownership is available; no EggServe deadline should be activated. |
| Keep-alive idle timeout | External ownership | Current SynVoid key is not enforced; must not acquire new semantics. |
| Hard total connection lifetime | `connection_total_timeout = 0` | Disabled behavior is representable. |
| Request/tunnel admission | `AdmissionOwnership::External` | External ownership is representable. |
| Response error representation | Service response / runtime presenter | A bounded presenter exists for EggServe pre-service failures; it does not solve ordinary response metadata. |
| Per-site Date and Server behavior | Runtime `ResponsePolicy` | **Hard blocker:** one runtime-level policy cannot preserve per-site Date enabled/suppressed, jitter, and distinct Server token settings. The final boundary removes service `Date`/`Server` and applies this global policy. |
| Connection drop request | `ConnectionShutdown` | Candidate has a shutdown capability; behavior parity was not prototyped in SynVoid. |

The production ownership shape otherwise remains as proposed in Phase 73:
external handler/body/idle/write deadlines and body ceiling; external service
and tunnel admission; disabled total connection lifetime; and origin-form-only
request targets. That does not cure the mandatory parser range or response
metadata failures.

## Mandatory config range comparison

SynVoid validation in `crates/synvoid-config/src/http.rs` accepts:

- `http.max_request_size >= 8192`, with no upper bound;
- `1 <= http.max_headers <= u32::MAX`;
- `http.max_header_size_ingress >= 1`, with no upper bound.

EggServe 0.3.0's published `runtime_limits` validation accepts:

- `8192 <= max_buf_size <= 4 MiB`;
- `1 <= max_headers <= 10,000`;
- `1 KiB <= max_header_bytes <= 1 MiB`.

Boundary construction from these validation predicates establishes the
mismatch without relying on defaults:

| Setting | Within EggServe maximum | First value above EggServe maximum | SynVoid accepts above-max value? |
| --- | ---: | ---: | --- |
| Parser buffer | 4 MiB | 4 MiB + 1 | Yes |
| Header count | 10,000 | 10,001 | Yes |
| Aggregate ingress header bytes | 1 MiB | 1 MiB + 1 | Yes |

Each above-maximum value is rejected by EggServe validation and accepted by
SynVoid validation. The low aggregate-header values from 1 through 1023 are
also valid in SynVoid but rejected by EggServe's minimum. Clamping, silent
fallback, or narrowing SynVoid validation is disallowed by the plan. This
alone prevents `GO_DIRECT_0_3`.

## Response metadata gate

SynVoid site config carries `date_header`, `date_jitter_seconds`, and
`server_token` (`crates/synvoid-config/src/site/security.rs`). EggServe's
`ResponsePolicy` carries one runtime-level `DatePolicy` and one
`server_identification`; finalization explicitly strips application `Date`
and subordinates application `Server`. A shared runtime therefore cannot
represent two sites with distinct values. No generic preservation or
per-response external-ownership mode exists in this artifact. Task-local or
global per-request side channels are not an acceptable adapter.

This independently prevents `GO_DIRECT_0_3`.

## Qualification limits and next gate

The artifact and source contracts were rechecked, but this phase did not add a
production dependency or route traffic through EggServe. No SynVoid executable
body/response/tunnel adapter prototype, differential harness, full dependency
graph comparison, or benchmark was completed. These are not represented as
passed. They must be addressed only after a later exact published artifact
removes both hard blockers, and Phase 73 is rerun. Until then, Phase 74's
transport-neutral refactor and Phases 75–78 remain unopened by the campaign
stop rule.

Local repository verification after recording this decision:

- `cargo xtask verify` — passed all 10 steps (fmt, clippy, dependency policy,
  core compile, repo guards, security regression, root guards, core admin
  tests, admin contract, and failure injection).
- The verification reported pre-existing warnings in the vendored
  `third-party/minify-html-compat` and `third-party/yara-x-compat` sources;
  no step failed.

**Decision: `RETAIN_PENDING_UPSTREAM`.** Required upstream changes are:

1. Parser/header controls must accept SynVoid's complete existing valid range,
   or provide a generally useful mode that prevents an earlier narrower
   ceiling without changing canonical SynVoid enforcement.
2. The final response boundary must preserve validated service-owned
   per-response `Date` and `Server` metadata while retaining EggServe's
   framing authority.

No README, runtime, config contract, or subsystem skill was changed because
production ownership and operator-visible behavior remain unchanged.
