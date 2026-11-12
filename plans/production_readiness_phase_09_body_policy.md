# Phase 09 Plan: Body Policy and Upload Limits

Status: **COMPLETE** (implemented 2026-11-11; evidence below).
Campaign: `plans/production_readiness_remediation_roadmap.md`.
Predecessor: Phase 05 for per-site policy plumbing.

## The finding

There are three different body-size concepts, and they do not agree:

- `http.max_request_size` is the H1 parser-buffer ceiling, not a body limit
  (`crates/synvoid-config/src/http.rs`, `docs/CONFIGURATION.md`).
- `http.max_streaming_body_size` defaults to 10 MiB
  (`default_max_streaming_body_size`).
- `AttackDetectionConfig.max_request_body_size` defaults to 10 MiB
  (`default_max_body_size`), and the detector returns an `AttackType::Other`
  result with fingerprint `body_size` when the body exceeds it. That result is
  rendered as a 403 “Attack Detected”, not a 413.
- `defaults.upload.max_size` advertises 100 MiB, and `docs/UPLOADS.md`
  describes large uploads; a direct body above the WAF cap cannot reach the
  upload path.

`BodyBufferingPolicy` defaults to `Buffered`. The streaming fast path is only
used when the site opts into `body_buffering_policy = "streaming"`, the backend
is `Upstream` or `Serverless`, and no body transform is active
(`crates/synvoid-http/src/streaming_request_fast_path.rs`). The
`streaming_threshold_bytes` field is accepted but ignored by
`SiteProxyConfig::should_stream` and `BodyBufferingPolicy::should_stream`.
Consequently:

- small/medium bodies are buffered, fine for a 1 MiB request and dangerous for
  many concurrent 10 MiB bodies;
- direct uploads above 10 MiB are rejected even though the upload docs say
  100 MiB;
- the rejection is a 403 attack block, which is the wrong status and misleading
  in logs;
- the chunked-upload path works only because each chunk is below the cap.

## Work items

### 09.1 Define one body-size policy

- Add a per-site body limit, for example `SiteProxyConfig.max_request_body_size`
  (and, if needed, `max_streaming_body_size`), with a global default in
  `HttpConfig`.
- Decide precedence explicitly: site override > global `http` value > built-in
  default. Do not keep both `http.max_streaming_body_size` and a WAF
  `max_request_body_size` with different meanings.
- Keep `http.max_request_size` documented as the H1 parser-buffer ceiling.
- Enforce the resolved limit in:
  - `collect_and_scan_request_body` / `collect_body_with_chunk_waf`;
  - `StreamingWafCore::new`/`streaming_for_path` so the streaming scanner uses
    the same limit;
  - the buffered full-body WAF path, so the detector and body policy agree.
- Return `413 Request Body Too Large` for the body-limit breach, not a 403
  attack detection. Either remove the detector's internal
  `max_request_body_size` block or map its `body_size` fingerprint to 413.
  Add a typed `WafDecision`/`BodyPolicyError` path so the dispatch layer does
  not have to string-match the fingerprint.

### 09.2 Make streaming policy truthful

- Implement `streaming_threshold_bytes`: `should_stream` should return true
  when the known content length exceeds the threshold (or when the site
  explicitly selects `Streaming`). For chunked bodies with no content length,
  document whether the site's explicit `Streaming` policy is required.
- Remove the field if it is not going to be implemented; accepting a no-op
  config is not acceptable.
- Keep the existing restriction that body transforms (plugins, minification,
  image rights, compression) disable the streaming path; document it.
- Consider making `Streaming` the default for Upstream/Serverless only after
  a benchmark and compatibility pass. This phase can document the default and
  leave the default change to a separate decision.

### 09.3 Upload path

- Document the supported large-upload mode: the chunked/resumable upload
  protocol keeps each request below the WAF body cap. If the application does
  not use chunked uploads, the operator must raise the per-site cap.
- If an application needs a 100 MiB direct body, expose a per-route/per-site
  cap that can be set high for that route only; do not raise the global cap.
- Ensure the upload scanner/archive inspection uses the same limit and that a
  body over the cap does not reach YARA or the sandbox with a misleading
  verdict.
- Add an operator-facing note to `docs/UPLOADS.md` and
  `docs/CONFIGURATION.md` with the effective defaults and the chunked-upload
  workaround.

### 09.4 Tests

- Body sizes just below/above the global and per-site cap, with
  `Content-Length` and chunked transfer.
- A body above the cap returns 413 and increments a body-limit metric, not a
  403 attack counter.
- Streaming policy: `Buffered` buffers; `Streaming` streams; a threshold value
  changes the path for a known content length; transforms force the buffered
  path.
- The streaming scanner's byte limit and the buffered detector's limit agree.
- Chunked upload: a sequence of sub-cap chunks succeeds while a single
  over-cap chunk is rejected with 413.
- Memory regression test or benchmark with concurrent 10 MiB bodies; record
  RSS and event-loop behavior.

## Non-goals

- Rewriting the chunked upload protocol.
- Raising the global ceiling for all sites.
- A new body-storage backend.
- Removing the WAF body scan for large bodies.

## Risks

- A 413 instead of 403 changes client-visible behavior and some clients may
  retry; document it.
- A per-site limit can be abused by a tenant to bypass a global protection
  budget; cap the maximum allowed per-site value.
- Streaming changes the point at which a block can be returned; the response
  may already have started. Keep the existing mid-body block semantics and
  test them.

## Exit criteria

- One documented body-size policy governs buffering, WAF scanning and uploads.
- A body over the resolved cap returns 413.
- The streaming threshold either works or is removed from the schema.
- The direct-upload limit and the chunked-upload path are documented with the
  actual defaults.

## Completion evidence

Implemented 2026-11-11. `[proxy] max_request_body_size` overrides the global
`[http] max_streaming_body_size`; the same resolved cap is used by the bounded
collector, the streaming scanner and the HTTP/3 body path. Declared-length and
chunked bodies above the cap return `413` (with
`synvoid.http.body_too_large`), not a 403 attack verdict. `streaming_threshold_bytes`
now switches a buffered site to streaming above the known size; explicit
`streaming` remains required for unknown-length bodies. Body-policy, WAF,
HTTP/3, TLS and the full workspace suites pass. The chunked-upload benchmark
workload still reports 415 because the separate upload policy rejects its MIME
type; the body cap itself is enforced as 413.

