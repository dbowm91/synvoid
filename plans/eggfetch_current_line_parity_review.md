# Eggfetch Current-Line Parity Review (follow-up decision gate)

Status: open follow-up plan (not part of the Phase 41–47 campaign).

Context: Phase 47 deferred a public `synvoid-http-client` support decision until a newer eggfetch line could be evaluated, deciding against the then-current 0.1.4-era baseline. That threshold has since been crossed outside SynVoid. The Phase 34 / Phase 47 0.1.4-era matrix is dated decision history and must not be used as current evidence. `synvoid-http-client` remains internal until this review completes.

Baseline: current `main` at review start (record the commit when work begins).

## Goal

Decide, on current evidence only: adopt eggfetch (or successor) behind a narrow SynVoid adapter, or document why `synvoid-http-client` remains necessary. No new generic HTTP crate without explicit gap evidence. Do not migrate as a side effect of bookkeeping — this is a decision gate with its own acceptance criteria.

## Scope (evaluate at least)

- TLS backend/provider parity, including SynVoid's aws-lc/PQ requirements
- HTTP/1.1 and HTTP/2 behavior used by SynVoid
- Streaming/open request-body requirements (WAF mid-stream scan, erased bodies)
- Direct Unix-domain-socket routing
- Connection pooling and resolved-target reuse
- Timeout semantics across headers/body/redirects/retries
- Certificate-chain versus hostname-verification control
- Size/error/response-body limits
- Dependency footprint and duplicate Hyper/Rustls stack impact
- API maturity/MSRV/support burden
- Whether SynVoid can become a thin adapter instead of owning a second generic client

## Method

1. Re-run the Phase 34 capability matrix against the current eggfetch line (record exact version, date, download/dependent counts at review time — not from memory).
2. Add black-box parity tests before any migration step; migration, if chosen, is incremental.
3. Record the decision and evidence in `architecture/egress_client_decision_*` (new dated record; do not rewrite the Phase 34 history).

## Acceptance

- Current-line matrix re-run with recorded versions/dates.
- Parity/security/dependency evidence for either branch (adopt with adapter, or retain with documented gaps).
- No second public generic HTTP client without justified burden.
- `synvoid-http-client` disposition updated in exactly one place per doc layer (no stale version claims reintroduced).

## Non-goals

- No migration in Phase 48; no publication of `synvoid-http-client`; no SynVoid-specific demands placed on eggfetch (forbidden branch stays forbidden).
