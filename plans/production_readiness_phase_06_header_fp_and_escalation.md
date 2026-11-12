# Phase 06 Plan: Header False Positives and Ban Escalation

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: Phase 05 owns the resolved per-site policy seam.

## The finding

`AttackDetector::check_sqli_internal` and `check_xss_internal` scan the
normalized and raw value of every request header except the current
content-negotiation skip list. The recent commit `d507fefa` stopped scanning
`Accept`, `Accept-Encoding`, `Accept-Language` and `Accept-Charset`, because
libinjection classified Firefox's media `Accept` as SQL injection with
fingerprint `X`. That fixed the observed video 403, but the design remains
high-risk:

- Browser metadata headers (`Sec-Fetch-*`, `Priority`, `Upgrade-*`, `Range`,
  `If-*`, `Cache-Control`, `Pragma`, `DNT`, `TE`, `Connection`) are not
  payload sinks and are not safe to run through libinjection.
- `Referer`/`Origin` contain URLs and are already exempted from the bare-IP
  SSRF/RFI heuristics, but SQLi/XSS scanning still applies to them.
- `User-Agent` is skipped only for allowlisted bots; arbitrary browser/API
  user agents are still scanned.
- `Authorization` is a credential, not a query/template sink; JWT detection
  is the appropriate detector.
- A single libinjection match records a violation, and
  `config/main.toml` uses `violations_before_block = 3` in a 300-second
  window with a 1-hour level-1 ban. A benign header repeated by page assets
  can therefore ban a real user.

This is a false-positive amplification problem, not only a detection-tuning
problem.

## Work items

### 06.1 Define a header scan policy

Add a single policy in `synvoid-waf` (near
`attack_detection/detector_common.rs`) that classifies headers:

- **Skip for SQLi/XSS payload detection**: content negotiation, browser
  metadata, framing, cache validators, `Host`, `Authorization`,
  `Content-Type`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  `TE`, `Upgrade`, `Sec-*`, `Priority`, `Range`, `If-*`, `Cache-Control`,
  `Pragma`, `DNT`, `Accept-*`.
- **Scan with URL-aware rules**: `Referer`, `Origin`; keep the existing
  same-origin/bare-IP exemptions and inspect anchored inclusion patterns.
- **Scan as user-controlled values**: `Cookie` (the primary SQLi/XSS sink),
  and any explicitly configured custom headers.
- **Detector-specific**: `Authorization` goes to the JWT detector, not
  libinjection. `User-Agent` goes to bot/ fingerprint detection; do not run
  the SQLi/XSS payload detectors on it.
- **HeaderValidator** continues to run on every header for length, CRLF,
  invalid characters and known malicious framing patterns. This is a
  structural validator, not libinjection.

Expose the policy as a static safe default plus a small
`[attack_detection.headers]` (or equivalent) allow/deny extension if operators
need to scan an application-specific header. Do not make the default “scan
everything, tune later.”

### 06.2 Calibrate escalation

- Add a confidence/weight input to `AttackDetectionResult` or to the
  violation-recording call. Structural, high-confidence classes (request
  smuggling, CRLF/header injection, command injection, path traversal with
  sensitive targets) keep a high weight; ambiguous libinjection-only header
  or generic URL matches get a lower weight or do not count toward an IP ban.
- Do not record a violation for a detection that is allowed by the resolved
  `log` action. `log` must be observation, not escalation.
- Keep per-path log-only behavior; ensure it also suppresses violation
  recording.
- Make the ban window/thresholds configurable (they already are in
  `[threat_level]`) and document the default. Add an operator note for the
  existing admin unban endpoint.
- Add metrics labeled by detector and input location (bounded labels, no
  IP/URL/UA values) so false positives are visible before a ban.

### 06.3 Regression corpus

- Add a browser/API header corpus in `synvoid-waf` tests:
  - Firefox/Chrome/Safari navigation, asset, video, font and fetch requests;
  - curl/wget, Python requests/httpx/aiohttp, Go net/http, Java/OkHttp,
    Node fetch/axios, Postman;
  - common CDN/proxy headers, trace headers and JWT bearer tokens.
- Assert no SQLi/XSS detection for the corpus and that the `Accept` + `Referer`
  video request remains 206 through the live WAF.
- Keep the cookie/custom-header attack tests positive: a real SQLi in a
  cookie or a configured header must still block.
- Add a test that three benign header variants do not produce an escalation
  ban.

### 06.4 Documentation

- Update `docs/ATTACK_DETECTION.md` (header detection scope),
  `docs/SECURITY.md` (ban/escalation), `docs/THREAT_LEVEL.md` and the
  configuration reference.
- State that header scanning is not “all headers” and name the scanned set.

## Non-goals

- Removing libinjection from query/body/cookie detection.
- A machine-learning classifier or a new external rule corpus.
- Changing the bot/tarpit policy beyond the `User-Agent` detector separation.
- Adding a new root test without `tests/OWNERSHIP.toml`.

## Verification

```bash
cargo test -p synvoid-waf --profile ci
cargo test --test security_regression --profile ci -- --test-threads=1
cargo test --test integration_test --profile ci
cargo xtask verify
```

Live: the exact Firefox media request with `Referer` returns 206; a cookie
SQLi returns 403; a benign browser session across the site loads assets and
video without a threat-level escalation; the unban path works after a
deliberate ban.

## Risks

- Narrowing header scanning could create a false negative for an
  application that reflects an unusual header into SQL/HTML. Mitigate with the
  configurable custom-header scan list and keep structural header validation.
- Escalation weights are security policy. Keep the defaults conservative and
  document them; do not silently make every libinjection hit a ban.

## Exit criteria

- The browser/API corpus produces no SQLi/XSS header detections.
- Real cookie/custom-header payloads still block.
- A benign request cannot reach a ban through header-only libinjection hits.
- The docs describe the scanned header set and the escalation policy.

## Completion evidence

Implemented 2026-11-11. `HeaderScanPolicy` skips browser metadata, framing,
cache, `Host`, `Authorization`, `Content-*`, `Transfer-Encoding` and unknown
headers by default; `Cookie`, `Referer`/`Origin` and configured custom headers
are scanned, with `Authorization` handled by JWT detection and `User-Agent` by
bot detection. Structural `HeaderValidator` still runs on every header.
Attack confidence now separates structural/pattern hits from libinjection-only
header/URL hits; log policy and per-path log rules suppress violation escalation.
The browser/API header corpus, positive Cookie/custom-header tests and the
three-variant no-escalation test pass, and the full workspace suite is green.

