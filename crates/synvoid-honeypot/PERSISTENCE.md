# Honeypot persistence contract

Status: internal SQLite representation; **not** a stable database interchange
format or external schema promise.

## Schema and migration

The runtime uses SQLite tables `honeypot_connections`, `honeypot_metadata`, and
`honeypot_announced_indicators`. The connection table stores timestamps, source
and local endpoints, service/protocol labels, confidence, retained payload fields,
and detection metadata. Schema generation is recorded in SQLite
`PRAGMA user_version` (`1` in the current implementation).

Opening an older database applies idempotent column migrations inside a SQLite
transaction, then records the schema version. A database with a newer schema
version, malformed SQLite content, failed migration, or failed permission
hardening fails startup. Migrations are additive. No guarantee is made that a
future SynVoid version preserves this internal schema; export records through
the runtime-facing APIs if a durable interchange format is needed.

## Filesystem permissions

On Unix, a parent directory created for the database is set to mode `0700`, and
the database file is set to `0600` before schema/data writes. A symlink at the
database path is rejected; SQLite is also opened with its no-follow flag.
Permissions of an existing parent directory are left as configured by the
operator. The process user must own or otherwise be able to protect that
directory. SQLite WAL sidecar files are managed by SQLite in the same directory.

On Windows, the database inherits the directory ACL. The crate does not set or
verify Windows DACLs and makes no equivalent `0700`/`0600` claim.

## Failure, locking, and backups

Directory creation, database open, schema discovery, and migration errors are
returned. Runtime inserts/queries return SQLite errors; the bounded writer
records queue saturation/write failures as operational drops rather than
blocking an attacker-facing connection indefinitely. No custom SQLite busy
retry policy is promised; callers should treat a busy/locked result as a failed
operation and observe the writer's drop/error counters.

The library does not provide a backup/export lifecycle contract. For a consistent
backup while running, use SQLite's online backup mechanism. Copying only the main
database file while WAL mode is active is not a supported backup procedure.
Applications own retention, encryption-at-rest, restore drills, and backup
access control. Encryption at rest is not implemented.
