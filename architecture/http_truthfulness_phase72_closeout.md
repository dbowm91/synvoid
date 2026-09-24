# HTTP Truthfulness Corrective Closeout (Phase 72)

Status: **closed**. No production behavior change.

Plan: `plans/phase_72_http_truthfulness_corrective_closeout.md`.
Roadmap: `plans/roadmap.md` ("Phase 72" section).

Baseline: `92ddc25d62e5b28e345ba660bf0a2504a6fa32f2` (Phases 70–71
implementation/closeout head; treated as the runtime baseline throughout).
Proof-bearing Phase 72 closeout SHA:
`1c215fa8d6df94cba3c7bed2d462221b8cf0ad18` (recorded in the follow-up
SHA-record commit, per repo convention).

Remote CI status for the proof-bearing SHA: observed green. GitHub Actions
run `36035559122` on `main` for `1c215fa8` completed `success`: job `ci`
(`cargo xtask verify`, 26m28s) and job `dependency-security`
(`cargo deny check` + `cargo audit`, 42s) both green. Only annotation is a
generic Node.js 20 deprecation notice on `actions/checkout`, unrelated to
this change.

## Why Phase 72 existed

The implementation at the baseline was accepted as the runtime baseline.
Phase 72 existed because closeout artifacts and tests did not line up with
what the implementation and roadmap claimed:

1. Phase 70/71 architecture evidence still said "closeout pending routine
   verification" while plans/roadmap were closed and the closeout commit
   recorded successful routine verification;
2. `tests/http_h1_parser_parity.rs` labeled cases "TLS-H1 (post-handshake
   equivalent)" but ran the shared H1 builder over ordinary TCP twice,
   relying on source guards for the TLS call site;
3. the Phase 71 matrix/roadmap called five residual follow-ups
   "registered" with no corresponding focused plan files in the numbered
   roadmap.

## Exact evidence corrections

- `architecture/http_h1_runtime_truthfulness_phase70.md`: status is now
  closed; pre-fix baseline `beff97a8…` preserved; proof-bearing closeout
  head `92ddc25d…` recorded; local verification distinguished from remote
  CI (no remote outcome claimed without an observed run); the
  "post-handshake equivalent" table/wording replaced with the exact
  plaintext + shared-policy-repeat + real-TLS split below.
- `architecture/http_config_runtime_semantics_matrix.md`: status is now
  closed; same baseline/SHA/CI treatment; field dispositions unchanged
  (all 13 entries keep their Phase 71 disposition); proof citations updated
  to the exact test binaries; "registered" replaced with "catalogued
  future plan candidates (no numbered plans registered)".
- `tests/http_h1_parser_parity.rs`: the four `*_tls_h1_post_handshake`
  cases renamed to `*_shared_policy_repeat` with header docs stating they
  are plain-TCP repeat runs, not handshakes; source guards unchanged.
- `plans/roadmap.md`: top status and Phase 70–72 sections say closed;
  residuals described as catalogued/non-active; EggServe stays retained at
  Phase 65 with 66–69 gated; deprecated compatibility fields not scheduled
  for implementation.
- `tests/OWNERSHIP.toml`: entry added for `http_h1_tls_transport`
  (composition); `http_h1_parser_parity` reason updated to point at the new
  file for TLS-stream evidence.
- `.opencode/skills/httpserver/SKILL.md`, `architecture/http_server.md`:
  parity pointers updated to both test files plus these evidence docs.
  README.md / AGENTS.md carry no Phase 70–72 claims; nothing to prune
  there.

## Real TLS-H1 test coverage

New `tests/http_h1_tls_transport.rs` (5/5 pass). Narrow seam:

```text
TCP
 -> real rustls server/client handshake
 -> negotiated ALPN http/1.1 (asserted on both ends)
 -> server TlsStream
 -> production configure_h1_builder (no copied settings)
 -> Hyper H1 serve_connection(...).with_upgrades()
```

Certificate convention follows the repository's established test pattern
(`crates/synvoid-http-client/tests/egress_parity.rs`): `rcgen`
self-signed leaf for `localhost`, DER handed directly to both peers,
client trusts only that certificate. Test-only `[dev-dependencies]`
(`rustls`, `rustls-pki-types`, `rcgen`) reuse locked versions — no new
supply-chain surface; plain `rustls` keeps the single aws-lc-rs process
provider.

Cases over the actual TLS stream: control 200 + server-observed ALPN
(`tls_h1_real_alpn_negotiates_http11_and_serves_control`), max-headers
fit/reject, parser-buffer fit/reject, 1s header-read timeout with a
post-handshake stall terminated within 15s, WebSocket upgrade reaching
101. No private Hyper error strings asserted.

Scope truth: this is the post-handshake `TlsStream` seam, NOT full
`HttpsServer` coverage (no WAF/router/backend construction). The
production TLS-H1 call site stays pinned to the helper by the source
guard in `tests/http_h1_parser_parity.rs`. TLS H2 behavior is unchanged
and remains owned by that guard
(`max_header_list_size(max_headers as u32)`); no new H2 framework is
claimed.

## Final residual-plan disposition

The five Phase 71 items remain catalogued future plan candidates —
H3 `max_header_size_ingress` threading + 431 mapping, activity-aware idle
keep-alive timeout, true TCP accepted-connection admission, egress-header
commit policy, raw H1 request-line limit / target-limit rename. None is
active or registered; promoting any of them requires a new focused plan
with its own baseline and acceptance criteria. No EggServe/Phase 66–69
work appears in this closeout.

## Verification commands/results (locally recorded, `--profile ci`)

- `cargo fmt --all -- --check` — green.
- `cargo test --test http_h1_parser_parity --profile ci` — 10/10 pass.
- `cargo test --test http_h1_tls_transport --profile ci` — 5/5 pass.
- `cargo test --test http_config_runtime_semantics --profile ci` — 6/6 pass.
- `cargo test --test http_tls_parity --profile ci` — 8/8 pass.
- `cargo nextest run -p synvoid-http --cargo-profile ci --profile ci` — 91/91 pass.
- `cargo nextest run -p synvoid-config --cargo-profile ci --profile ci` — 93/93 pass.
- `cargo xtask test guards` — 3 steps pass (includes ownership/guard suites;
  `root_test_ownership_guard` 2/2 pass for the new test entry).
- Feature-profile `cargo check` matrix (`--no-default-features`, plus
  `post-quantum`, `mesh`, `dns`, `mesh,dns`) — green; both H1 test targets
  also compile under `--no-default-features`.
- `cargo deny check` — green (advisories/bans/licenses/sources ok).
- `cargo audit` — 6 allowed warnings, identical before/after this change
  (pre-existing; test-only dev-deps reuse locked crates, no new surface).
- `cargo xtask verify` — green (recorded in the closeout commit message).
