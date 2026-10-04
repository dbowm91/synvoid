# synvoid-honeypot

TCP honeypot runtime primitives for embedding applications. The crate owns
connection admission, bounded hostile-input capture, protocol detection,
SQLite persistence, responder contracts, shutdown/drain, and advisory threat
signals. It does not own application firewall policy or automatically block
hosts.

## Minimal embedding

```rust,no_run
use synvoid_honeypot::{PortHoneypotConfig, PortHoneypotRunner};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
    let mut config = PortHoneypotConfig::default();
    config.enabled = true;
    config.storage.database_path = "./data/honeypot.db".into();
    let runner = PortHoneypotRunner::new(config)?;
    let running = runner.clone();
    let task = tokio::spawn(async move { running.run().await });

    // Application-owned shutdown signal goes here.
    runner.stop();
    task.await?;
    Ok(())
    })
}
```

`PortHoneypotConfig::default()` leaves serving disabled. The runtime currently
supports TCP only; UDP/QUIC entries in `transport_protocols` do not start those
transports. Runtime config and extension traits are experimental class-2
consumer surfaces. No external support or compatibility promise is made.

## Storage and payload handling

See [`PERSISTENCE.md`](PERSISTENCE.md) for the SQLite schema, migration,
permission, corruption, locking, and backup contract. Payload retention defaults
to truncated data with a digest; applications should keep `PayloadRetentionMode`
at `Truncated`, `HashOnly`, or `None` unless full payload retention has a
documented operational need. Configured payloads and service responses are
bounded by hard maxima and over-limit settings are rejected.

## AI responder transport

AI is disabled by default. `AiProviderTransport` is supplied by the embedding
application and is responsible for TLS identity verification, endpoint
allowlists/egress policy, deadlines, streaming response limits, cancellation,
retry/cost limits, and secret-safe diagnostics. Do not put provider credentials
in logs. The crate does not add a provider SDK or grant a responder host tools.

Threat indicators are advisory data. Publishing an indicator never implies a
block, ban, or enforcement action; the receiving application applies its own
provenance and policy gates.

## Security scope

The crate assumes the host process, OS account, and configured database path are
trusted. It is not a network sandbox or a replacement for firewall isolation.
Attacker-controlled bytes are processed within the configured hard caps, but
detectors are heuristics and do not guarantee protocol correctness. AI-generated
content is untrusted. Encryption at rest is not provided.

On Unix, a newly created database parent directory is restricted to `0700` and
the database file to `0600`; symlink database paths are rejected. Existing
parent-directory permissions are not changed. On Windows, permissions follow the
inherited filesystem ACL; this crate does not modify or verify DACLs.

## Verification state

Standalone MSRV evidence: Rust 1.85.0 packaged-tarball build and consumer test
passed outside the workspace with network access disabled. This is class-2
toolchain evidence only. It is not a class-3 support commitment or a publication
signal.
