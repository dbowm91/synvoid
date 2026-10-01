# Honeypot standalone qualification — Phase 107

Status: **CLOSED DEFER** at the tested package derived from Phase 106 commit
`a87d0b0c` (current qualification head includes Phase 106 closeout `340c13fb`).

## Evidence

- `cargo package -p synvoid-honeypot` and
  `cargo publish -p synvoid-honeypot --dry-run` passed. The packaged source
  compiled with no SynVoid workspace dependency.
- A temporary consumer outside the workspace used the extracted `.crate`,
  bound a loopback TCP listener, wrote and read back an interaction through the
  bounded writer, invoked a fake `HoneypotThreatPublisher`, used a template
  responder, and shut down listener/writer cleanly. The consumer test passed.
- The library has zero normal SynVoid dependency edges. `cargo tree -p
  synvoid-honeypot -e normal` contains the Rust/Tokio/SQLite/serde/metrics/
  tracing/regex/crypto support graph only.
- `cargo test -p synvoid-honeypot --profile ci`: 207 tests passed.
- `cargo deny check` passed. `cargo audit` found no vulnerable advisory; the
  repository's six allowed unmaintained-crate warnings remain (see Phase 106
  closeout).
- SynVoid-wide `cargo xtask verify` and `verify-full` passed on Phase 106
  implementation SHA `a87d0b0c`; exact totals are recorded in
  `plans/phase_106_honeypot_application_neutral_boundary.md`.

## API and support classification

| Surface | Classification now | Compatibility rule if independently supported |
| --- | --- | --- |
| `PortHoneypotConfig` and nested runtime config | Experimental consumer contract | Field/default/serde changes require migration notes; persisted SynVoid DTO is owned by SynVoid and translated by root adapter. |
| Runner, listener, controller lifecycle | Experimental consumer contract | Start/stop and terminal one-runner/one-lifecycle behavior must remain explicit; shutdown must drain writer. |
| `HoneypotResponder` and built-in responders | Experimental extension contract | Trait method/behavior changes require a semver review; templates and protocol behavior need fixtures. |
| `AiProviderTransport` and provider responders | Experimental extension contract | Embedding owns TLS, proxy and streaming byte enforcement. Secret-safe typed errors and explicit budgets are required. |
| Storage APIs and `HoneypotRecord` schema | Implementation detail with currently public escape hatches | No stable schema promise is made. Any future persistence compatibility requires versioned schema migrations and explicit record/API policy. |
| Indicator types, scoring, and `HoneypotThreatPublisher` | Experimental advisory extension contract | Indicators remain advisory. Enforcement is solely the embedding application's decision. |
| Metrics and tracing | Implementation detail | No exporter is required; names and event fields are not a stable API. Payloads and provider secrets must never enter logs. |

The crate has no independent semver policy today. Its package version is `0.1.0`;
this does not constitute an announced support guarantee.

## Threat model and current controls

The runtime intentionally accepts connections from hostile peers. Embedders
must isolate it like an exposed service and must not present production
credentials, real internal services, or privileged network access. Built-in
responders simulate services; they do not provide a safe general sandbox for
arbitrary responder implementations.

- Payload intake and protocol recognition operate on attacker-controlled bytes.
  Listener config provides payload, connection and per-IP limits and operation
  timeouts. Phase 106 preserves these settings. Parser-specific fuzz/property
  coverage and a standalone hostile-input campaign were not demonstrated in
  this qualification.
- Retention defaults to the first 256 bytes plus the digest of the full payload
  and original byte length. Hash-only/none omit payload content; full retention
  stores it. Credentials in captured traffic are not independently redacted.
- Writer enqueue has a nonblocking bounded `try_write_record` path and counts
  dropped records; async writes can wait for queue capacity. Defaults exist for
  queue, batch and payload sizes, but public config accepts larger values with
  no crate-level hard maxima. SQLite errors do not retry failed batches.
- Database permissions follow OS defaults/umask, parent-directory creation
  errors are ignored before open, data is not encrypted, and SQLite has no
  custom busy timeout. Operators must protect the database path and backups.
- AI is disabled by default. If enabled, prompt/response, generation duration,
  concurrency, turns and provider-failure budgets are bounded. Prompt injection
  remains possible; the model is not trusted and must have no production tools
  or secrets. External provider requests disclose attacker-controlled context
  and can incur cost. Embedding transport must enforce TLS identity, outbound
  destination policy, request deadlines and streaming response caps.
- Runtime AI API keys are skipped by serialization and redacted in `Debug`;
  embedders must still secure configuration ingress and their transport logs.
- Threat publication is an injected advisory callback. The library does not
  block, ban or otherwise enforce its observations.
- The current runner supports TCP listeners only; UDP-only config fails closed.
  No non-macOS native listener/storage qualification or supported-target matrix
  was produced here.

## Decision: DEFER independent repository extraction

The clean application boundary and tarball consumer proof satisfy the
architectural preconditions, but not independent release/support readiness.
The exact remaining blockers are:

1. no explicit `rust-version`, tested MSRV, README quickstart, crate-level
   rustdoc guide, runnable packaged example, changelog, or semver/support policy;
2. public config and persistence schema are not classified as stable, and
   `HoneypotRecord`/SQLite have no versioned consumer migration contract;
3. queue, batch and full-payload config lack enforced hard ceilings; database
   file mode/encryption and failure policy need deliberate standalone choices;
4. hostile parser fuzz/property coverage and a non-macOS target qualification
   are absent;
5. no second independent production consumer or measured maintenance benefit
   justifies the continuing release and support burden;
6. the three provider responders require embedding-owned transport, and no
   production SynVoid call site currently constructs them.

Disposition: **DEFER**. Keep the crate in the SynVoid workspace and preserve the
current boundary. Do not create a repository, publish, or add a long-lived git
dependency. Reopen only with an owner for the support surface and a follow-up
plan that closes these exact release/security gaps; Phase 112 records this
decision in the campaign gate refresh.
