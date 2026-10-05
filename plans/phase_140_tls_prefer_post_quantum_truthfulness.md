# Phase 140 Plan: `prefer_post_quantum` Truthfulness

Status: **REGISTERED** (2026-10-05). Not started.

Campaign: `plans/dns_encrypted_transport_truthfulness_roadmap.md`.
Predecessor: Phase 139.
Registered in: `plans/roadmap.md`.

Source residual: Phase 133 **F-7** (severity low), recorded not changed in
`architecture/dns_provider_inversion_phase133_closeout.md` and carried in
`architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` §
"Residual work this campaign deliberately left" item 4.

## The finding

`prefer_post_quantum` is a documented TLS setting that selects nothing.

- Definition: `crates/synvoid-config/src/tls.rs:21-22`
  (`#[serde(default = "default_prefer_post_quantum")]`, default `true` at
  `:48`, default fn at `:69-71`); mirrored at
  `crates/synvoid-tls/src/config.rs:9,50,69,88`.
- **Sole read site:** `crates/synvoid-tls/src/cert_resolver.rs:269-272` — a
  `tracing::debug!` and `counter!("synvoid.tls.post_quantum")`. Nothing else.
- The rest of `build_server_config` (`:264-335`) never re-reads it. Key-exchange
  groups come from `default_provider()` (`:267`), fixed by the compiled-in
  `prefer-post-quantum` rustls cargo feature (`architecture/pqc.md:21`,
  `architecture/networking_deep_dive.md:68`).
- Absent from every shipped TOML.

Pinned by `prefer_post_quantum_does_not_gate_the_hybrid_key_exchange`: a client
offering **only** `X25519MLKEM768` completes a handshake against a server built
with the flag off. Availability is governed by the compiled-in feature, not this
setting.

The Phase 133 closeout notes Phase 134 must not describe its trait as
"honouring a post-quantum preference" — there is no preference to honour. The
Phase 134 closeout and its trait do satisfy that. This phase addresses the
residual itself.

## Options and their costs

| Option | Cost | Assessment |
|---|---|---|
| **(a) remove the setting** | `TlsConfig` has **no** `deny_unknown_fields`, so leftover operator TOML keys still parse. But it is a field on a published class-3 type (`crates/synvoid-tls/Cargo.toml:3` = `0.1.0`); `architecture/public_crate_release_policy.md:25-27` bars silent documented-behavior change in a minor bump, and `:37` files serialized data under its own rule → requires **≥ 0.2.0**. | semver + migration work |
| **(b) rename to reflect telemetry** | same semver cost, plus a serde `alias` for the old key; also lands in the policy's "Behavior: never" bucket (`:38`). | semver work for a cosmetic gain |
| **(c) make it actually gate** | needs a second `CryptoProvider` with filtered kx groups — groups are provider-scoped, not `ServerConfig`-scoped — which breaks the deliberate single-provider invariant documented at `Cargo.toml:142-144`. | a crypto phase, worst cost/benefit here |
| **(d) document it as telemetry** | one matrix/closeout correction plus a rustdoc sentence. | **convention-consistent** |

## Recommended disposition: (d), optionally bundling (b)

The repo already has a precedent for a documented-but-inert field: `doh.path` /
`doh.json_path` were reclassified from `implemented` to `PERSISTURE` with a
matrix entry (`architecture/dns_config_runtime_matrix.md:1212-1215`) rather than
rejected or removed.

Phase 41's reduced-feature rejection concerns capability-bearing **sections**
under reduced builds, not inert booleans in a full build. A `validate()`
rejection here would break every default-true config, since the field defaults
to `true`. So rejection is not available, and (a) is disproportionate to a
low-severity truthfulness gap.

## Goal

Make the setting's inertness explicit and correctly named, so no future reader
or doc claims a post-quantum preference that does not exist.

## Workstream A — decide (d) vs (b)

- **(d)** document as telemetry: lowest risk, no semver cost, keeps the field
  parseable and stable.
- **(b)** additionally rename with a serde `alias`: clearer, but costs a minor
  version bump on a published class-3 crate and needs a migration note.
- Record the choice and the reason.

## Workstream B — documentation

- `crates/synvoid-tls/src/config.rs:9` — a rustdoc sentence stating that the
  field is **telemetry only** and that availability comes from the compiled-in
  `prefer-post-quantum` rustls feature;
- `architecture/dns_config_runtime_matrix.md` — a `PERSISTURE`-style entry
  following the `doh.path` precedent;
- correct the F-7 rows in
  `architecture/dns_startup_truthfulness_and_provider_inversion_closeout.md` and
  `architecture/dns_provider_inversion_phase133_closeout.md` **by pointer**;
- `architecture/pqc.md` and `architecture/networking_deep_dive.md` if either
  implies the setting gates anything;
- `docs/CONFIGURATION.md` if it documents the field as functional.

## Workstream C — evidence

Keep `prefer_post_quantum_does_not_gate_the_hybrid_key_exchange` green and
unmodified. If the field is renamed, add a test asserting the serde `alias`
still parses the old key.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --profile ci --all-targets -- -D warnings
cargo test -p synvoid-tls --profile ci
cargo test -p synvoid-config --profile ci
cargo test -p synvoid-repo-guards --profile ci
cargo deny check
cargo audit
cargo xtask verify
```

## Acceptance criteria

- the setting's inertness is documented at its definition and in the runtime
  matrix;
- the existing pin is unmodified and green;
- no doc claims a post-quantum preference is honored by this setting;
- if renamed, a serde `alias` test proves old configs still parse.

## Rejection criteria

Reject a closeout that:

- introduces a second `CryptoProvider` to make the field gate (option c) without
  a separate registered crypto phase;
- removes the field without recording the `≥ 0.2.0` semver consequence;
- adds a `validate()` rejection that would fail default-true configs;
- modifies or deletes the existing pin.

## Closeout

`architecture/dns_provider_inversion_phase140_closeout.md`.
