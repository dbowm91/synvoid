# Admin Panel Phase 5 — Alerting Delivery and Outbound-Request Hardening

## Status

**IMPLEMENTED**

## Objective

Make alerting behavior exposed through the admin panel operationally truthful and safe. Remove the current false-success email stub, ensure webhook test/results reflect actual delivery, and harden outbound webhook destination policy against private/link-local/loopback targets after DNS resolution and redirects.

This phase is intentionally limited to the alerting functionality already represented by the admin API/configuration/UI. It does not create a general notification platform.

## Scope

Primary files expected to change:

- `src/admin/alerting/mod.rs`
- `src/admin/handlers/alerting.rs`
- `admin-ui/src/pages/alerts.rs`
- `admin-ui/src/services/api.rs`
- configuration/schema types directly owning alert settings
- shared HTTP-client helpers only if a narrow redirect/destination-policy hook is required
- focused alert delivery/security tests and admin documentation

Do not redesign unrelated outbound HTTP behavior or introduce a general job queue.

## Baseline problems

### Email delivery is a success-returning stub

`send_email_internal()` validates that several SMTP fields are configured, logs a message, and returns `Ok(())` without creating an SMTP connection or transmitting mail. Any UI/configuration claim that email alerting works is therefore false.

### Webhook aggregate status is inaccurate

The webhook helper records success/failure counters but returns `Ok(())` even if all configured destinations failed. `POST /api/alerts/test-webhook` can therefore return an applied/success message while zero endpoints received the test event.

### Webhook SSRF validation is textual rather than network-authoritative

The current configuration check rejects selected textual prefixes such as localhost/private IPv4 strings. It does not robustly cover:

- IPv6 loopback/private/link-local/unspecified addresses
- IPv4 link-local and other non-routable classes
- hostnames resolving to disallowed addresses
- hostnames with explicit ports
- redirects from an allowed initial URL to a disallowed destination
- DNS answers that change between validation and connection

The admin endpoint is authenticated, but SynVoid is a privileged network appliance and outbound destinations configured through its control plane should still obey a deliberate egress policy.

## Binding decisions

### Email support disposition

This phase must choose one of two complete outcomes, not remain in between:

**Preferred outcome: implement SMTP email delivery** because the configuration surface already advertises it.

If a maintained dependency with acceptable size/security footprint can provide SMTP+TLS without disproportionate complexity, implement the actual send path.

**Fallback outcome: remove unsupported email delivery claims** if implementing SMTP would materially violate the project's dependency/runtime scope. In that case remove or deprecate `email_enabled`, SMTP credential UI/schema/docs, and ensure no handler reports that email was sent.

The implementer must record which outcome was selected and why. A logging stub returning `Ok` is not acceptable under either outcome.

### Webhook success semantics

Define aggregate result explicitly:

- `Success`: all required configured destinations delivered successfully
- `PartialFailure`: at least one delivery succeeded and at least one failed
- `Failure`: no configured destination succeeded

A single test-webhook operation should expose enough bounded detail to tell the operator whether it succeeded, partially succeeded, or failed without returning secrets or excessive response bodies.

## Implementation plan

### 1. Introduce a typed alert delivery result

Replace the current helper behavior that collapses all webhook outcomes into `Result<(), String>`.

Use a compact result type containing at least:

- attempted destination count
- succeeded count
- failed count
- bounded per-destination status/error category if appropriate

Do not include credential material or complete arbitrary remote response bodies.

Map this result into admin mutation/status semantics truthfully.

### 2. Make webhook HTTP success criteria explicit

Treat only expected successful HTTP response classes as delivery success. At minimum:

- connection/DNS/TLS failures are failures
- timeout is failure
- non-2xx HTTP status is failure unless a specific documented webhook contract says otherwise

Bound response body reading or avoid it entirely for delivery success.

Use explicit connect/request timeout values suitable for an admin alert path so a slow destination cannot stall indefinitely.

### 3. Correct `/alerts/test-webhook`

The endpoint must:

- return a no-op/not-configured result when webhooks are disabled or empty
- return applied/success only when the defined success condition is met
- return a distinct partial-failure result/status/message when some destinations fail
- return failure/appropriate HTTP status when no destination succeeds
- emit an audit event containing outcome counts/categories, not secret URLs if URL disclosure is considered sensitive in audit policy
- update delivery success/failure metrics consistently with the actual result

Do not return "Test webhook sent" after total failure.

### 4. Implement authoritative destination classification

Create a small outbound destination policy helper used both when validating configuration and immediately before connection.

For each destination URL:

- parse with the canonical URL parser
- allow only `http`/`https` if plaintext HTTP remains intentionally permitted; prefer/document HTTPS for remote webhooks
- extract hostname correctly when a port is present
- resolve DNS names
- classify every candidate IP
- reject if any selected connection candidate is disallowed according to policy

Disallow at minimum:

- IPv4 loopback `127.0.0.0/8`
- RFC1918 private ranges
- IPv4 link-local `169.254.0.0/16`
- unspecified `0.0.0.0/8`/unspecified address semantics
- multicast/reserved/non-global ranges where outbound webhook use is not meaningful
- IPv6 loopback `::1`
- IPv6 unspecified `::`
- IPv6 unique-local `fc00::/7`
- IPv6 link-local `fe80::/10`
- IPv6 multicast
- IPv4-mapped IPv6 forms resolving to a disallowed IPv4 address

Use standard library/address classification where precise enough; avoid hand-rolled string matching.

### 5. Close DNS/redirect policy gaps

Configuration-time DNS validation alone is insufficient. Enforce destination policy at request time as close as practical to connection establishment.

For redirects:

- either disable redirects for webhook delivery, which is the preferred simplest behavior, or
- revalidate every redirect target before following it

Do not automatically follow an allowed public URL into a private address.

If the current shared HTTP client automatically follows redirects, configure a webhook-specific client/request path with redirects disabled rather than changing global behavior for unrelated systems.

### 6. Handle DNS rebinding pragmatically

Do not build a custom DNS stack. The goal is to avoid obvious validate-then-connect gaps.

Preferred small approaches:

- resolve and connect through an HTTP client mechanism that pins/uses the validated resolved address while preserving the original Host/SNI, or
- use a client-level DNS resolver hook/policy that validates each resolution immediately before connection

If the current client abstraction cannot support this without broad architectural work, document the residual and at minimum combine request-time resolution validation with redirects disabled. Do not claim complete rebinding resistance without connection-time enforcement.

### 7. Implement SMTP delivery if retained

If email support remains advertised:

- use a maintained SMTP library rather than implementing SMTP manually
- support authenticated STARTTLS/TLS according to configuration
- validate sender/from requirements explicitly; add the smallest missing config field if necessary
- bound connect/send timeouts
- avoid logging username/password
- treat authentication/TLS/recipient/server-status failures as delivery failures
- escape/format subject/body safely using the library's message builder
- send one message to configured recipients or a bounded strategy consistent with library semantics

Prefer a local fake SMTP server/test transport for verification. Do not require external production credentials in tests.

### 8. Protect SMTP secrets in configuration/API responses

Review whether `GET /alerts/config` currently returns `email_password` in cleartext to the browser.

Preferred admin-secret semantics:

- write-only password/secret input
- read response reports `password_configured: true/false` rather than returning the secret
- an omitted password in update means "preserve existing secret" unless an explicit clear operation is requested

Apply the same pattern to any alert webhook secret/header configuration if such fields exist or are added.

Do not expose stored SMTP passwords merely because the caller is admin; browser compromise impact should still be minimized.

### 9. Improve Alerts UI truthfulness

The page should present:

- enabled/disabled state
- validation errors from backend
- webhook test success/partial/failure counts
- email test/delivery capability only if genuinely supported
- credential fields as password inputs and never pre-populated with returned plaintext passwords

Disable test controls while a test is in flight.

Do not show a green success toast from a generic HTTP 200 if the returned typed result says partial/no delivery.

### 10. Preserve alert cooldown and metrics behavior

Do not regress existing alert rule/cooldown logic while changing delivery internals.

Ensure:

- failed deliveries do not suppress future alert evaluation beyond the intended rule cooldown unless that behavior is explicitly desired
- delivery metrics distinguish success and failure accurately
- spawned delivery tasks are bounded/owned sufficiently for current admin runtime; do not add an unbounded retry queue

Retries, if any, should be small and explicit. A durable delivery queue is out of scope.

## Focused tests

### Destination-policy unit tests

Cover representative URLs/addresses:

- public IPv4 allowed
- `127.0.0.1` rejected
- `10.x`, `172.16/12`, `192.168.x` rejected
- `169.254.x` rejected
- `localhost:port` rejected after parsing/resolution
- `::1`, `fe80::`, `fc00::`, multicast rejected
- IPv4-mapped private IPv6 rejected
- hostname resolving to private address rejected

Use deterministic resolver injection/fakes where possible; do not depend on public DNS in tests.

### Redirect tests

Using a local test HTTP server:

- public/allowed-like test destination success path works under injected policy/test environment
- redirect behavior is disabled or revalidated
- a redirect toward a blocked target is rejected

### Webhook outcome tests

Cover:

- one destination success -> success
- all fail -> failure
- one succeeds/one fails -> partial failure
- timeout -> failure
- non-2xx -> failure

### Email tests if SMTP retained

Using local fake SMTP/test transport:

- valid configuration produces one accepted message
- auth/TLS/server failure is reported as failure
- missing required configuration fails validation
- API readback does not expose stored password

## Acceptance criteria

Phase 5 is complete only when:

- no alert email helper returns success without transmitting a message
- if SMTP remains advertised, an actual SMTP/TLS send path exists and passes local deterministic delivery tests
- if SMTP is removed instead, the admin UI/schema/docs no longer claim working email delivery and stale stub code is deleted
- `GET /alerts/config` does not return stored SMTP passwords or equivalent secrets in plaintext
- webhook delivery result records attempted/succeeded/failed counts
- webhook test endpoint reports total failure as failure rather than success
- partial webhook delivery is distinguishable from complete success
- non-2xx responses, connection errors, TLS errors, and timeouts are counted as failures
- destination validation uses parsed/resolved IP classification rather than hostname string-prefix checks
- loopback/private/link-local/unspecified/multicast IPv4 and IPv6 destinations are rejected according to documented policy
- explicit ports do not bypass localhost/private checks
- redirects are disabled or every redirect target is revalidated; a redirect cannot reach a blocked private target
- request-time validation occurs close enough to connection establishment that configuration-time-only DNS checking is not the sole defense
- outbound operations have bounded timeouts and do not create an unbounded retry queue
- alert UI displays real success/partial/failure state and does not expose saved credential values
- focused webhook/SSRF/email tests pass

## Rejection criteria

Reject this phase if it:

- leaves the SMTP logging stub in place while continuing to expose `email_enabled`
- treats any completed HTTP request as webhook success regardless of status
- filters SSRF destinations only with lowercase/string-prefix checks
- validates hostnames only when configuration is saved but not when requests are made
- follows redirects without revalidating them
- returns SMTP password values in API responses
- adds a durable notification queue, message broker, or general outbound policy framework unrelated to this admin correction
- changes the entire shared HTTP client redirect policy for unrelated subsystems when a webhook-specific client would suffice

## Verification commands/evidence

Record focused tests, for example:

```bash
cargo test --profile ci <admin-alert-webhook-test-target>
cargo test --profile ci <admin-alert-destination-policy-test-target>
cargo test --profile ci <admin-alert-email-test-target>   # only if SMTP retained
```

Also perform one local Alerts page check showing a successful webhook test, a deliberately failing destination, and a blocked private/link-local destination. If email support remains, prove delivery to a local fake SMTP server without external credentials.
