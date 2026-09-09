# Phase 20 Plan: HTTP Normalization, Dispatch, and Ownership Convergence

Status: complete — implemented; evidence in `architecture/http_ownership_convergence.md` (matrix, pipeline, H3/WS mapping, residual blockers) and `architecture/root_module_burndown_report.md` (Phase 20 closure).

Roadmap position: Track 3, Phase 20 of `plans/roadmap.md`.

Primary goal: make HTTP parsing, normalization, body policy, response transformation, and reusable dispatch logic have exactly one canonical implementation, while leaving only application/runtime composition in root `src/http`.

## Context

`src/http/mod.rs` currently exports more than forty submodules. Many have corresponding implementations in `crates/synvoid-http/src/`, while several root files remain substantial application handlers or composition layers. The root module ledger therefore still classifies `http` as `split_required`.

This is a security-sensitive boundary. Divergent handling of request targets, headers, transfer/content encoding, body limits, forwarding metadata, challenge paths, or WAF response mapping can create request-smuggling or policy-bypass behavior even when both implementations appear individually correct.

This phase follows the WAF convergence phase so HTTP consumes the settled enforcement contract rather than preserving adapter duplication.

## Constraints

- Preserve the current HTTP/1.x, HTTP/2, HTTP/3, WebSocket, upstream, static-file, CGI/FastCGI/PHP, serverless, WASM/Spin, upload, and mesh dispatch behavior for supported feature profiles.
- Do not rewrite the HTTP server wholesale.
- Do not create a second parser/normalizer during migration.
- Root may retain socket/server lifecycle, application-specific handler wiring, and runtime service bundles.
- Shared parsing/normalization/response policy belongs in `synvoid-http` unless a concrete dependency blocker is documented.
- Avoid new allocations/copies on the common request path.
- Preserve request-path/WAF capability guards.

## Step 1: Build a root-to-crate ownership map

Create `architecture/http_ownership_convergence.md` with a file-level matrix for every module exported by `src/http/mod.rs`.

Classify each root module as:

- thin facade over `synvoid-http`
- root adapter to a crate-owned operation
- duplicate implementation
- reusable HTTP domain logic that should move
- application-specific handler/backend composition that should remain root-owned
- stale/dead module

Pay particular attention to similarly named modules already present in both trees, including:

- `app_server_backend_dispatch`
- `axum_dynamic_dispatch`
- `body_policy`
- `buffered_request_waf_dispatch`
- `cgi_backend_dispatch`
- `challenge_paths`
- `early_parse`
- `fastcgi_php_backend_dispatch`
- `headers`
- request parsing
- response building/transformation
- streaming/WAF dispatch
- upstream dispatch

Do not infer equivalence solely from filenames. Confirm actual responsibility, callers, and dependency direction.

## Step 2: Establish one canonical normalization pipeline

Document and enforce one sequence for incoming HTTP data before security policy evaluates it.

The canonical path must cover, as applicable:

1. request-line / pseudo-header parsing
2. request-target and path normalization
3. authority/host validation
4. header canonicalization and duplicate handling
5. trusted forwarding metadata interpretation
6. transfer framing and content-length policy
7. content-encoding/decompression limits
8. body-size policy
9. query/path decoding rules used by WAF/routing
10. WAF/request-policy evaluation
11. backend routing and upstream request construction

Every protocol frontend that ultimately evaluates equivalent HTTP semantics should either call the same canonical helpers or have explicit differential tests proving equivalent policy.

Do not normalize a path differently for routing and WAF unless the distinction is intentional, documented, and tested against traversal/bypass cases.

## Step 3: Remove root duplicate parser/policy implementations

Move reusable code into `synvoid-http` and replace root copies with re-exports/adapters.

High-value candidates include:

- header helpers
- early parsing
- body policy
- challenge/special-path classification
- request parsing DTO conversion
- WAF decision-to-response mapping
- response helper/transform utilities
- reusable backend dispatch planners

Keep application-specific managers (for example root-owned server lifecycle or UI/file-manager application handlers) in root when moving them would force unrelated root services into `synvoid-http`.

When a root wrapper is only a call-through to the crate, prefer a direct re-export or direct canonical import over maintaining another module layer unless compatibility requires the path.

## Step 4: Make framing ambiguity fail closed

Add focused tests for HTTP/1.x ambiguity and normalization, including:

- duplicate/conflicting `Content-Length`
- `Transfer-Encoding` plus `Content-Length`
- unsupported transfer codings
- malformed chunk sizes and chunk terminators
- header whitespace/obs-fold policy
- duplicate `Host`/authority conflicts
- absolute-form vs origin-form request targets
- percent-encoded path separators/dot segments
- invalid UTF-8 where bytes are permitted vs text-required paths
- compressed-body expansion bounds
- oversized header/body paths

The canonical parser/policy must either reject ambiguous input or normalize it exactly once before both routing and WAF evaluation.

## Step 5: Reconcile HTTP/3 and WebSocket adapters

HTTP/3 already uses dedicated crate paths and WAF adapters. Verify that it maps into the same enforcement semantics and normalization policy where protocol semantics overlap.

For WebSocket upgrade and frame-level WAF handling:

- handshake HTTP policy should share the canonical HTTP path
- frame-level policy may remain protocol-specific
- mappings to enforcement outcomes must be exhaustive and tested

Do not force frame semantics into an HTTP request parser merely to reduce module count.

## Step 6: Clarify root `HttpServer` ownership

Audit `src/http/server.rs` and related shared handler/service bundles.

The expected root ownership is:

- listener/socket lifecycle
- application runtime handles
- composition of WAF/router/upstream/static/plugin/admin capabilities
- request task ownership/drain interaction

Reusable HTTP state machines and transformations should live in `synvoid-http`.

If `HttpServer` remains root-owned, document it as application composition and make the root `http` module eligible for `keep_app_root`. If it can be moved without importing application services, move it; do not force this outcome.

## Step 7: Close adjacent `tls` and `http_client` split state

After HTTP boundaries are stable, disposition the two adjacent mixed modules.

### TLS

- Keep certificate parsing/config/reload primitives in `synvoid-tls`.
- Keep only listener/server integration in root if it depends on root `HttpServer`/runtime composition.
- Replace duplicate TLS config/build logic with crate APIs.
- Reclassify root `tls` to `keep_app_root` or `facade_existing_crate` with precise rationale.

### HTTP client

- Keep reusable client/pool/URL/proxy/encoding behavior in `synvoid-http-client`.
- Keep only root QUIC/tunnel dispatch adapters that genuinely require root tunnel services.
- Move `streaming_waf_body` into the appropriate canonical crate if it is reusable HTTP/WAF logic rather than root composition.
- Reclassify `http_client` once only the adapter remains.

## Step 8: Add source and behavior guards

Update guards to prevent:

- new parser/normalization implementations under root when canonical crate helpers exist
- domain crates importing root HTTP compatibility paths
- duplicate WAF-decision mapping tables
- facade-classified modules accumulating logic

Prefer simple path/import/source guards plus focused behavioral tests over generated architecture tooling.

## Documentation updates

Update:

- `architecture/http_server.md`
- `architecture/http_ownership_convergence.md`
- `architecture/root_module_ledger.md`
- `architecture/root_module_burndown_report.md`
- `architecture/root_dependency_ownership.md`
- `architecture/final_surface_audit.md`
- HTTP/WAF boundary docs and `AGENTS.override.md` where paths change

## Acceptance criteria

Phase 20 is complete when:

- every `src/http` submodule has a documented canonical owner
- parsing/header/framing/body/normalization security logic has one canonical implementation
- WAF and routing see the same canonical request representation for security-relevant fields unless an explicit tested difference is documented
- duplicate root implementations of crate-owned HTTP helpers are removed
- HTTP/3 and WebSocket handshake paths map correctly into the canonical enforcement contract
- root `HttpServer` contains application composition rather than avoidable shared HTTP algorithms
- `http`, `tls`, and `http_client` are each reclassified from `split_required` or have a narrowly documented residual blocker
- request-smuggling/framing ambiguity tests cover the listed high-risk cases
- no domain crate imports root HTTP compatibility modules
- relevant HTTP/WAF benchmarks show no material unexplained regression

## Rejection criteria

Reject an implementation that:

- creates a new parser alongside the existing crate parser without deleting/replacing the old path
- changes normalization order without differential/security tests
- lets WAF inspect a materially different path/authority/body representation than routing uses
- moves application runtime handles into `synvoid-http`
- duplicates TLS certificate/reload policy in root
- preserves call-through root modules with nontrivial logic merely for organizational symmetry
- performs a broad server rewrite unrelated to ownership convergence

## Verification

At minimum run:

```bash
cargo fmt --all -- --check
cargo check
cargo check --no-default-features
cargo test -p synvoid-http
cargo test -p synvoid-http-client
cargo test -p synvoid-tls
cargo test -p synvoid-http3
cargo test -p synvoid-proxy
cargo test --test request_path_capability_boundary_guard
cargo test --test root_facade_boundary_guard
cargo test --test root_module_ledger_guard
cargo test --test root_dependency_ownership_guard
```

Run focused malformed-framing/normalization tests and the existing normalization/proxy-header/request-path benchmarks. Any new fuzz targets belong in Phase 24 rather than expanding this phase into a verification-infrastructure project.
