# Phase 72 Plan: HTTP Truthfulness Corrective Closeout and Evidence Reconciliation

Status: implementation handoff plan.

Registered in: `plans/roadmap.md`.

Baseline reviewed: `main` at `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` (2026-09-24).

Depends on:

- Phase 70 implemented/closed;
- Phase 71 implemented/closed;
- EggServe Phase 65 remains `RETAIN_CURRENT_H1`; Phases 66–69 remain gated/not started.

## Primary goal

Close the remaining evidence and planning-truth gaps left after Phases 70–71 without changing HTTP policy, reopening EggServe adoption, or opportunistically implementing deferred configuration features.

The implementation at `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` is treated as the runtime baseline. Phase 72 exists because the closeout artifacts and tests do not yet line up perfectly with what the implementation and roadmap claim.

This phase owns exactly three corrective areas:

1. **evidence-status reconciliation** — Phase 70/71 architecture evidence still says "closeout pending routine verification" even though the plans/roadmap are closed and the closeout commit records successful routine verification;
2. **real TLS-H1 transport evidence** — `tests/http_h1_parser_parity.rs` labels several cases "TLS-H1 (post-handshake equivalent)" but actually runs the shared H1 builder over ordinary TCP twice, relying on source guards for the TLS call site;
3. **residual-registration truthfulness** — the Phase 71 matrix/roadmap says five residual follow-ups are "registered", but no corresponding focused plan files are registered in the numbered roadmap.

No production behavior change is required unless the real TLS-H1 test exposes a defect.

## Non-goals

- Do not implement EggServe or reopen Phases 66–69.
- Do not change the H1 parser policy established in Phase 70 unless the new end-to-end TLS evidence proves it wrong.
- Do not implement H3 ingress-header enforcement in this closeout.
- Do not implement a keep-alive idle timeout.
- Do not add a new TCP connection-admission subsystem.
- Do not implement egress header limiting/truncation.
- Do not implement a raw H1 request-line parser or rename public config keys.
- Do not remove `DEPRECATED_COMPAT` keys.
- Do not claim remote GitHub Actions evidence unless an actual workflow run/status for the proof-bearing SHA is observed.

## Workstream A — Reconcile Phase 70 evidence authority

Update `architecture/http_h1_runtime_truthfulness_phase70.md` so its top-level state matches the repository's actual closeout.

Required changes:

- change `Status: implemented; closeout pending routine verification` to an explicit closed status;
- record the proof-bearing Phase 70/71 closeout SHA `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` as the closeout implementation/evidence head;
- preserve the original pre-fix baseline `beff97a8c5e53e0b9c64cea691bc76f0bee8fd2c`;
- distinguish local recorded verification from remote CI status;
- after Workstream C lands, replace the "TLS-H1 post-handshake equivalent" wording with an exact description of the new real TLS test.

The document must not retroactively claim a remote CI run if none was observed.

## Workstream B — Reconcile Phase 71 evidence authority

Update `architecture/http_config_runtime_semantics_matrix.md` so it is a final evidence authority rather than a pre-closeout draft.

Required changes:

- top-level status must say implemented/closed;
- record `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` as the proof-bearing closeout baseline before Phase 72 corrections;
- preserve the field dispositions already established at Phase 71;
- update verification wording to the actual recorded commands/results;
- replace any inaccurate use of "registered" for the five deferred items.

The five items are currently **catalogued residual opportunities**, not registered numbered implementation plans:

1. H3 `max_header_size_ingress` threading + 431 terminal mapping;
2. activity-aware idle keep-alive timeout;
3. true TCP accepted-connection admission versus per-request admission;
4. provenance-safe egress-header limit policy;
5. raw H1 request-line limit or explicit request-target compatibility redesign.

Use one of two truthful outcomes:

- **default closeout outcome:** call them "catalogued residuals / future plan candidates" and state that none is active/registered; or
- if implementation deliberately creates separate focused plans in the same pass, list their exact plan paths and roadmap entries.

Do not call a prose bullet "registered" merely because it appears in an evidence document.

## Workstream C — Add real TLS-H1 transport/parity evidence

The current Phase 70 tests prove the shared H1 policy twice over plaintext TCP and use source guards to pin the TLS call site. That is useful structural evidence, but it does not execute a TLS handshake.

Add a focused integration fixture that performs a real TLS handshake and then drives Hyper H1 over the resulting `tokio_rustls::server::TlsStream`.

### Required fixture properties

Use repository/test dependencies already available where possible:

- generate or load a deterministic/self-signed test certificate using the repository's established TLS test convention;
- server side uses Rustls/`tokio-rustls`;
- client side trusts only the test certificate/root;
- negotiate ALPN `http/1.1`;
- assert the negotiated protocol is `http/1.1`;
- after successful handshake, drive the H1 server with the production `h1_policy::configure_h1_builder`;
- retain `.with_upgrades()`;
- do not copy the Phase 70 builder settings into the test.

If testing through the full `HttpsServer` is practical without constructing unrelated WAF/router/backend infrastructure, prefer that. Otherwise, the accepted narrow seam is:

```text
TCP
 -> real rustls server/client handshake
 -> negotiated ALPN http/1.1
 -> server TlsStream
 -> production configure_h1_builder
 -> Hyper H1 serve_connection(...).with_upgrades()
```

The existing source guard must continue to prove that the production `src/tls/server.rs` H1 branch invokes the same helper. Together, the real TlsStream test plus call-site guard prove the intended transport mapping without duplicating the root server.

### Required TLS-H1 cases

At minimum execute over the actual TLS stream:

1. **normal request control**
   - valid H1 request gets a 200-class response from the test service;

2. **header-read timeout**
   - configure a short timeout;
   - complete TLS handshake first;
   - send a partial H1 request header and stall;
   - connection must terminate/reject within a generous bounded tolerance;

3. **max headers**
   - configured small header count;
   - fitting request succeeds;
   - over-limit request is rejected;

4. **parser-buffer ceiling**
   - valid minimum/small parser buffer;
   - fitting request succeeds;
   - oversized header/request input is rejected;

5. **WebSocket upgrade**
   - an upgrade request reaches a 101 response over TLS-H1;
   - `.with_upgrades()` remains exercised, not only source-searched.

Do not assert private Hyper error strings.

### H2 regression truth

Do not turn this closeout into a new H2 test framework.

Retain the existing source/behavior evidence that:

- TLS ALPN still branches on `h2`;
- H2 builder remains separate;
- `max_header_list_size(max_headers as u32)` remains unchanged.

If an existing runnable ALPN-H2 integration fixture can be reused cheaply, run it. Otherwise record the exact existing test/guard that owns H2 and do not claim new end-to-end H2 evidence.

## Workstream D — Tighten test naming and claims

After the real TLS fixture exists, remove misleading test names/comments that imply a TLS handshake where none occurs.

Options:

- keep shared-helper plaintext loopback tests and rename the second label to something like `shared_policy_repeatability`; or
- consolidate duplicate helper-only cases and let the real TLS fixture own all `tls_h1_*` names.

Preferred end state:

- helper tests prove the policy function itself;
- plaintext integration proves plaintext wiring;
- real TLS-H1 integration proves TLS stream compatibility;
- source guards prove both production call sites use the same helper.

No test should be named `tls_*` if it never establishes TLS.

Update `tests/OWNERSHIP.toml` for any new integration test file.

## Workstream E — Roadmap and plan-status closeout truth

Update `plans/roadmap.md` after implementation so:

- Phases 70–71 remain closed;
- Phase 72 is marked closed only after the evidence changes and real TLS-H1 fixture pass;
- the five Phase 71 residuals are described as catalogued/non-active unless actual plans were created;
- EggServe remains retained at Phase 65 with 66–69 gated;
- no wording implies the deprecated compatibility fields are scheduled for implementation.

Update Phase 70/71 plan status only if needed to point to Phase 72 as the final evidence correction. Do not rewrite their historical bodies.

Create a short closeout record if useful:

`architecture/http_truthfulness_phase72_closeout.md`

It should summarize only:

- why Phase 72 existed;
- exact evidence corrections;
- real TLS-H1 test coverage;
- final residual-plan disposition;
- exact verification commands/results;
- final proof-bearing SHA placeholder to be filled by the implementation closeout.

Avoid duplicating the full Phase 70/71 matrices.

## Workstream F — Verification and evidence discipline

Focused commands:

```bash
cargo fmt --all -- --check
cargo test --test http_h1_parser_parity --profile ci
cargo test --test <new-real-tls-h1-test> --profile ci
cargo test --test http_config_runtime_semantics --profile ci
cargo nextest run -p synvoid-http --cargo-profile ci --profile ci
cargo nextest run -p synvoid-config --cargo-profile ci --profile ci
cargo xtask test guards
```

Run the repository's existing TLS/request-parity test as part of the focused gate:

```bash
cargo test --test http_tls_parity --profile ci
```

Feature-profile checks:

```bash
cargo check --no-default-features
cargo check --no-default-features --features post-quantum
cargo check --no-default-features --features mesh
cargo check --no-default-features --features dns
cargo check --no-default-features --features mesh,dns
```

Routine gate:

```bash
cargo xtask verify
```

If the implementation changes only tests/docs and no dependency manifests/features:

- `cargo deny check` / `cargo audit` may be referenced from the Phase 70/71 closeout if still applicable;
- do not manufacture a new dependency-security claim.

If a manifest/lockfile changes, run both explicitly.

### Remote CI truth rule

At final closeout, inspect the proof-bearing commit's GitHub status/workflow evidence if available.

Record exactly one of:

- remote CI observed green, with run/check identity;
- remote CI observed failing/pending, with state;
- no remote status/run observed through the available repository interface.

Never turn absence of a reported run into "CI passed."

## Acceptance criteria

Phase 72 is complete only when:

- Phase 70 architecture evidence says closed and names the proof-bearing closeout SHA;
- Phase 71 matrix says closed and no longer calls unplanned residual bullets "registered";
- a real TLS handshake with ALPN `http/1.1` is executed in test;
- the resulting TLS stream exercises the production H1 policy helper;
- TLS-H1 timeout, header-count, parser-buffer, and WebSocket-upgrade behavior have executable coverage;
- tests no longer use `tls_h1` naming for a plain-TCP-only fixture;
- production TLS H1 remains source-guarded to the shared helper;
- existing TLS H2 branch remains unchanged;
- roadmap/plan/evidence states agree;
- no EggServe dependency or Phase 66–69 implementation appears;
- no deferred Phase 71 feature is accidentally implemented as part of closeout;
- focused tests, feature checks, and `cargo xtask verify` pass;
- remote CI status is described only to the extent actually observed.

## Rejection criteria

Reject the closeout if it:

- changes runtime policy merely to make a test easier;
- duplicates H1 parser settings in test code instead of calling the production helper;
- calls a plain TCP connection "TLS-H1";
- claims end-to-end `HttpsServer` coverage when only a post-handshake `TlsStream` seam was tested;
- says residual work is registered without concrete plan/roadmap entries;
- creates five speculative implementation plans just to justify the word "registered";
- reopens EggServe adoption;
- claims remote CI green without an observed run/check.

## Final terminal state

The intended terminal state is:

**HTTP truthfulness campaign closed with evidence aligned to runtime.**

At that point:

- Phases 70–72 are historical/closed;
- EggServe 65 remains retained;
- 66–69 remain gated;
- the five Phase 71 residuals remain explicit non-blocking future candidates unless separately promoted into plans;
- further HTTP work requires a new focused plan with its own baseline and acceptance criteria.
