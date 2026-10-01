# Honeypot application-neutral boundary

Phase 106 keeps `synvoid-honeypot` in this workspace while defining ownership
for its reusable runtime API. The crate owns its runtime configuration,
listeners, responders, retention policy, bounded SQLite writer and threat
indicators. The root application owns persisted-config translation, admin
mutation and mesh publication; each embedding supplies the concrete HTTP
transport for AI responders. Threat publication stays injected through
`HoneypotThreatPublisher`; the library does not perform mesh enforcement.

## Configuration compatibility

`synvoid-config-model::honeypot_port::HoneypotPortConfig` remains the persisted
DTO used by TOML, admin JSON and schema generation. The root adapter
`runtime_config_from_persisted` translates all its fields to runtime settings:
`enabled` and `site_scope` copy directly; `ports` selects the runtime min/max
range and count (an empty list keeps runtime defaults); `protocols` maps to
the runtime transport list (an empty list uses TCP). The current runner rejects
configs without TCP because UDP listeners are not implemented. Other
runtime-only controls keep their documented runtime defaults. Serialized DTO
names and defaults remain covered by config-model golden assertions and root
adapter tests.

The legacy runtime uses a range plus count for port rotation and cannot
represent arbitrary sparse port lists exactly. The persisted contract is
preserved as supplied; runtime selection remains bounded by its existing
rotation model. Changing this model requires an explicit persisted-schema
migration and is outside this phase.

| Surface | Persisted/default behavior | Runtime/embedding behavior |
| --- | --- | --- |
| Enabled | DTO defaults enabled; explicit values round-trip | runtime type defaults disabled; root adapter copies persisted value |
| Ports | DTO defaults `[8080, 8443, 9090]` | adapter maps min/max/count into existing rotating-range model |
| Protocols | DTO defaults `tcp`, `udp` | adapter preserves the list; TCP is currently the only supported listener |
| Scope | DTO defaults `global` | adapter copies `site_scope` |
| AI mode | runtime defaults `Disabled`; `TemplateOnly`, `LocalModelOnly`, and opt-in `ExternalProvider` remain distinct | app supplies provider transport; no provider is contacted without explicit responder construction |
| Retention | runtime default `Truncated`, 256 bytes + digest | writer applies selected mode before enqueueing |
| Mesh intel | disabled by default | injected publisher is an advisory output only; enforcement remains app-owned |
| Admin mutation | DTO is saved to `main.toml`, audit logged, and reload broadcast | controller updates its runtime config snapshot; running listener lifecycle changes follow worker config reload/restart |

The persisted DTO's protocol list may request UDP, but the runner rejects
UDP-only settings rather than silently binding TCP. Empty protocol lists retain
the prior app behavior of serving TCP. Arbitrary sparse port lists remain a
known limitation of the existing runtime range model.

`PortHoneypotController::from_runner` snapshots the configuration that created
the runner, so controller reads do not revert to runtime defaults.

## Data retention and saturation

The default is `Truncated`: the record keeps at most 256 payload bytes and 512
hex characters and records SHA-256 of the complete original payload plus its
original byte length. `HashOnly` and `None` store no payload bytes or hex text;
both retain the digest and length. `Full` stores the complete payload and hex
representation plus digest/length, so operators must opt into the associated
privacy and disk risks. Credentials in attacker payloads are not separately
redacted and may be persisted according to the selected mode.

The default writer queue holds 4096 records, batches up to 64, flushes at least
once per second, and uses one blocking SQLite flush at a time on Tokio's
blocking pool. `try_write_record` never waits: a full or closed queue returns an
error and the caller records a drop metric. Async writes may wait for bounded
queue capacity. SQLite failures are counted and logged without payload content;
failed batches are not retried. Retention cleanup deletes records older than
`retention_days` and trims to `max_records`. The legacy
`StorageConfig.flush_interval_secs` and `StorageWriterConfig.write_timeout_ms`
fields are currently not consumed; the active flush interval is
`StorageWriterConfig.flush_interval_ms`, and SQLite uses its default busy
timeout. They remain visible for compatibility and should not be represented
as operational controls until a separately reviewed migration defines their
meaning.

SQLite opens the configured path with WAL journaling, `synchronous=NORMAL`, a
64 MiB page cache, memory-backed temp storage and a 256 MiB mmap hint. The
storage constructor attempts to create the parent directory, ignores that
directory-creation error, and then propagates SQLite open/schema errors. It
does not set an explicit database file mode, encrypt the database, or set a
custom SQLite busy timeout; filesystem permissions follow the OS and umask.
Queue, batch and full-retention payload sizes are operator-configurable and
have defaults but no crate-level hard maximum. This is a documented resource
and at-rest privacy limit for any future standalone support claim.

## AI transport

AI responders depend on `AiProviderTransport`, an async JSON POST capability
that receives deadline, maximum response bytes and headers, and returns a
status plus body or a secret-safe typed error. The embedding
application owns TLS verification, proxy policy and actual bounded body
collection. Implementations must cap bytes while streaming, return typed-safe
errors without echoing request headers, and never log provided headers or body.
The responder also caps serialized request bodies at twice the prompt budget
plus 4096 bytes, bounds model names to 256 bytes and provider URLs to 2048
bytes, and rejects over-budget provider responses. It still applies generation
deadlines, concurrency/circuit budgets, prompt/response truncation and provider
secret headers. AI mode stays
disabled by default. API keys are omitted from serialized runtime config and
provider config structs do not implement `Debug`. Metrics and tracing are facade dependencies; exporters
are not required by consumers and payloads/API keys are not tracing fields.

No production SynVoid call site currently constructs one of these three AI
provider responders, so this phase establishes and tests the extension point;
it does not switch an active SynVoid provider integration to a new transport.
