# Phase 01 Plan: RFI/SSRF `Referer` Same-Origin Exemption

Status: **IMPLEMENTED** (branch `plans/waf-admin-deployment-truthfulness`; shared `is_referer_or_origin` in `detector_common.rs`, gates in `rfi.rs`/`ssrf.rs`/`open_redirect.rs`, unit tests, docs paragraph).

> Scope note (found during deployment verification): the first cut covered
> RFI/SSRF only, but the same browser `Referer` was still blocked by the
> open-redirect detector, whose Aho list matches any absolute URL (`://`,
> `http://`, ...) via a branch that ignores redirect-param context. Phase 01
> therefore also gates that branch for `referer`/`origin` values that carry
> no redirect parameter (`?next=` etc. smuggled payloads still fire).
>
> Enabling SSRF by default (Phase 02 follow-up) then exposed the same class
> in the `Host` header: every request on IP-literal hosting carries a
> private-IP `Host`, tripping the SSRF private-IP heuristic. The `Host`
> header names the already-reached server the router matched — not a
> server-side fetch target — so it is exempt from that heuristic too
> (`is_host` in `detector_common.rs`); the Aho branch stays active.

Registered in: `plans/roadmap.md`.

Campaign: `plans/waf_admin_deployment_truthfulness_roadmap.md`.
Predecessor: none (first phase).

## The finding

Legitimate browser subresource loads are blocked as RFI. `curl` without
`Referer` returns 200; a browser-like request with
`Referer: http://192.168.182.143:8082/` returns `403 Attack Detected`, log:

```text
Attack detected from 192.168.182.143: Rfi (score: 100) at header:referer
```

Two detectors fire on the same header (score 50 + 50 = 100, threshold 100):

- `RfiDetector` (`crates/synvoid-waf/src/attack_detection/rfi.rs:12-24`):
  `IP_REGEX_PATTERN = r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"`.
  `detect_with_url_decode` (`rfi.rs:43-94`) lowercases, URL-decodes, runs the
  Aho patterns, then **unconditionally** runs `IP_REGEX`. The Aho lists
  (`patterns.rs:554-597` `rfi()` / `rfi_high()`) are all anchored
  (`=http://`, `?file=http://`, `?page=`, …) and would not match a bare
  `Referer: http://IP/` value — only the IP regex does. Paranoia does not
  gate the regex branch. The existing unit test pins this behavior for query
  strings (`rfi.rs:127-134` `test_rfi_ip_address` asserts
  `"http://192.168.1.1/malicious.txt" @ QueryString` is RFI) but no test
  covers `Header("referer")`.
- `SsrfDetector` overlaps on the same private-IP URL
  (`ssrf.rs:278-309` `contains_private_ip_or_localhost`, `block_private_ips`
  default true). Priority (`mod.rs:603-620`, `Rfi(9) < Ssrf(10)`) reports
  `Rfi`; with anomaly scoring both contribute. Fixing RFI alone still blocks
  via SSRF — both need the exemption.

Header iteration is the all-headers loop:
`AttackDetector::check_rfi_internal` (`mod.rs:837-860`) and
`check_ssrf_internal` (`mod.rs:862-885`) iterate **every** normalized header
(`inputs.headers`), including `referer`/`origin`. The `SECURITY_HEADERS`
allowlist (`detector_common.rs:152-164`, includes `referer`/`origin`) is not
used on this path — `check_request_sync` (`mod.rs:272-565`) calls the
`check_*_internal` helpers directly, never `check_inputs`. There is no
same-origin (`Host` vs `Referer`/`Origin`) logic anywhere in
`attack_detection/`; `open_redirect.rs:379-426` narrows its own
`detect_in_headers` to redirect headers, but `check_open_redirect_internal`
(`mod.rs:974-1003`) bypasses it the same way.

IP-based testing (no domain, per operator constraint) always triggers this:
every browser subresource carries a same-site IP `Referer`.

## Goal

Same-site `Referer`/`Origin` headers stop scoring RFI/SSRF IP hits, while
genuine smuggled-URL payloads in headers still fire.

## Recommended disposition

Skip the **bare-IP-regex** branch for `Header(referer|origin)`; keep the Aho
pattern branch active in headers (a smuggled `?file=http://evil/` inside a
header still matches `=http://` context and still blocks).

Concretely, in `RfiDetector::detect_with_url_decode`, when
`location.header_name()` is `referer` or `origin` (case-insensitive,
`InputLocation::header_name` at `config.rs:328-334`), skip the `IP_REGEX`
block and return the Aho result only. Mirror the same guard in
`SsrfDetector` around the `contains_private_ip_or_localhost` branch only
(keep SSRF Aho indicators such as `169.254.169.254` active in headers).
Do not touch `check_*_internal` header iteration, `SECURITY_HEADERS`, or
scoring — minimal diff, no plumbing changes.

Out of scope (explicitly not this phase): wiring site `rfi.enabled`
(Phase 02), mounting admin (Phase 03), same-origin `Host` comparison
(larger plumbing — deferred unless review demands it), changing the query/
body IP behavior (pinned by existing tests).

## Workstreams

- **A — detector change** (`crates/synvoid-waf/src/attack_detection/` only):
  `rfi.rs` header-name gate + `ssrf.rs` private-IP branch gate. No new
  crate, no composition-root change, no config schema change.
- **B — regression tests** (in `crates/synvoid-waf/tests/`, not root
  `tests/`): benign `Header("referer")` with IP URL → `None` for both
  detectors; malicious header (`Referer: x?file=http://evil/shell.txt`) →
  still `Some`; existing `QueryString` IP tests unchanged. Follows
  `test_rfi_ip_address` precedent; add the SSRF mirror.
- **C — docs**: one paragraph in `docs/ATTACK_DETECTION.md` noting the
  `referer`/`origin` same-site exemption and that query/body IP detection
  is unchanged.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --profile ci --all-targets -- -D warnings
cargo test -p synvoid-waf --profile ci
cargo test -p synvoid-waf --test wave10_test --profile ci
cargo nextest run -p synvoid-waf --cargo-profile ci --profile ci
cargo check --no-default-features --profile ci
cargo check --no-default-features --features mesh,dns --profile ci
```

Manual (test deployment, not committed): browser-like
`curl -H 'Referer: http://<ip>:8082/' <asset>` → 200; `?id=1' OR '1'='1`
and `?<script>` → still 403.

Rollback: revert the two gate hunks; behavior returns to current FP.
