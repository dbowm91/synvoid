# DNS Provider Inversion — Phase 140 Closeout: `prefer_post_quantum` Truthfulness

**Status: CLOSED QUALIFIED** (2026-10-05)
**Branch:** `phase-125-dns-runtime-dto-contract`
**Disposition: (d) document as telemetry** — the setting is kept, not renamed or removed
**Qualification: unchanged — no crate class, support bar, or semver statement is affected.**

---

## 1. Disposition

The user chose option **(d)**: document the setting as telemetry, keep its name, keep it
parsing. Options (b) rename and (c) make-it-gate were rejected; (c) is additionally barred
by the plan's own rejection criteria without a separately registered crypto phase.

The deciding factor was not cost but blast radius. The phase found the gap was **not** a
rustdoc nit confined to the TLS crate — it was operator-facing guidance in five documents
telling administrators to tune a knob connected to nothing.

---

## 2. The finding was larger than the plan recorded

The Phase 140 plan described `prefer_post_quantum` as having "sole read site"
`crates/synvoid-tls/src/cert_resolver.rs:269-272` and framed the fix as "one matrix/closeout
correction plus a rustdoc sentence". Both statements understate the problem. Measured on the
Phase 140 head:

### 2.1 Two read sites, one of them operator-facing

| Site | Use | Verdict |
|------|-----|---------|
| `crates/synvoid-tls/src/cert_resolver.rs:269` | `tracing::debug!` + `counter!("synvoid.tls.post_quantum")` | inert, harmless |
| `src/tls/server.rs:251` | the HTTPS startup banner interpolated `"with"` / `"without"` PQC | **operator-facing over-claim** |

The banner sat **directly beneath** a truthful pair of lines:

```rust
#[cfg(feature = "post-quantum")]
tracing::info!("Post-quantum cryptography: ENABLED");
```

So at startup the process said PQ was enabled, and then one line later printed a PQC status
derived from a field that controls nothing. Two adjacent log lines, one truthful, one lying.

**A second defect in the same line, not in the plan at all:** the banner hardcoded
`"TLS 1.3"` regardless of `tls_1_3_only` / `enable_tls_12_fallback`. An operator running with
TLS 1.2 fallback was told "TLS 1.3". This was fixed under the same decision.

### 2.2 The plan's semver premise was wrong

The plan sized options (a)/(b) by asserting the field is "on a published class-3 type" and
concluding a rename "requires **≥ 0.2.0**", citing `architecture/public_crate_release_policy.md`.

**`synvoid-tls` is not class 3.** `architecture/public_crate_release_readiness_phase47.md` §1
records that exactly one crate was promoted — `synvoid-rate-limit` — and
`public_crate_release_policy.md` is explicitly "binding for any crate promoted to externally
supported (class 3)". `synvoid-tls` is class 2, so that binding policy does not apply to it.

The practical consequence: a rename would have cost source-level churn across `src/tls/`,
tests, and any external consumer, but **not** a promised semver consequence. This made (b)
cheaper than the plan assumed. It did not change the decision — see §1 — and it is recorded
because a plan that mis-sizes an option cannot be trusted to have sized it honestly.

### 2.3 Five documents carried functional claims

| Document | Claim |
|----------|-------|
| `docs/CONFIGURATION.md:298-307` | "Use hybrid PQ KEX"; "protects against future quantum computers"; "Only disable if you encounter interoperability issues with legacy clients"; and "requires a `--features post-quantum` build to take effect" |
| `docs/HTTP3.md:40,58` | "Enable post-quantum key exchange"; "**Recommended**: Enable for long-term security" — and listed the **default as `false`**, which is wrong (`synvoid-config` defaults it `true`) |
| `architecture/tls.md:87,114,403` | "Post-quantum hybrid KEM **if `prefer_post_quantum` is set**" — the single clearest functional claim |
| `architecture/config.md:497` | `// Use hybrid post-quantum KEX` |
| `.opencode/skills/tls_termination/SKILL.md:26,35` | "honors `prefer_post_quantum`"; "only takes effect in `--features post-quantum` builds" |

**The feature-gating claim was itself wrong**, and that is worth separating from the rest. It
appears in `CONFIGURATION.md`, the skill, and `architecture/agent_knowledge_maintenance.md:211`.
It says PQ needs a `--features post-quantum` build. `architecture/networking_deep_dive.md:68`
states the opposite for inbound TLS: `synvoid-tls` and `synvoid-http-client`
*unconditionally* enable rustls `prefer-post-quantum` + `aws-lc-rs`, and the root
`post-quantum` feature is a **marker** wiring http-client and admin *egress* only.

So the documentation was wrong twice over: it claimed an inert setting was functional, **and**
it claimed a build feature gates inbound TLS when it does not.

---

## 3. What changed

### 3.1 Documentation (Workstream B)

- `crates/synvoid-tls/src/config.rs:9` — rustdoc: telemetry only; availability comes from the
  compiled-in rustls `prefer-post-quantum` feature; the field is read in exactly one place.
- `crates/synvoid-config/src/tls.rs:21` — rustdoc on the **persisted** schema, which is where
  an operator's editor resolves the key. Explicitly warns against adding a `validate()`
  rejection, since the field defaults to `true`.
- `architecture/dns_config_runtime_matrix.md` — a **`PERSISTURE`** entry following the
  `doh.path` / `doh.json_path` precedent (F-2), with the inertness evidence, both read sites,
  and the corrected class-2 semver analysis.
- The five documents in §2.3, corrected.
- `architecture/dns_provider_inversion_phase133_closeout.md`,
  `…_phase136_closeout.md`, and `…_startup_truthfulness_and_provider_inversion_closeout.md` —
  corrected **by pointer**, never rewritten.

`architecture/pqc.md:21` and `architecture/networking_deep_dive.md:68` were checked and needed
**no** change: both were already accurate, and the latter is the source that disproves the
feature-gating claim.

### 3.2 The startup banner

Replaced the interpolated claim with `tls_profile_description`, which derives the protocol
range from `tls_1_3_only` / `enable_tls_12_fallback` and names the PQ status from the
compile-time state. Both original over-claims are gone.

### 3.3 Classification

`tls.prefer_post_quantum` is **`PERSISTURE`** — parses, defaults `true`, gates nothing.
Removed from the closure of this campaign.

---

## 4. Evidence

### 4.1 The behavioural pin is untouched

`prefer_post_quantum_does_not_gate_the_hybrid_key_exchange`
(`crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs:713`) — a real handshake where a
client offering **only** `X25519MLKEM768` connects to a server built with the flag off. Not
modified, not deleted, still green. The plan's rejection criteria required this.

### 4.2 New guard suite — `tools/synvoid-repo-guards/tests/tls_post_quantum_truthfulness.rs`

A behavioural pin cannot catch wording, and wording is what misleads. Four gates:

| Guard | Pins |
|-------|------|
| `no_in_scope_document_claims_the_setting_is_functional` | the acceptance criterion *"no doc claims a post-quantum preference is honored by this setting"*, mechanically |
| `the_startup_banner_does_not_read_the_inert_field` | the banner cannot be reintroduced |
| `both_definitions_document_the_setting_as_telemetry` | telemetry wording survives at both definitions |
| `the_handshake_pin_still_exists_and_is_unmodified_in_spirit` | the behavioural proof cannot be quietly weakened or deleted |

**5 mutations, all fired:** functional claim restored in `tls.md`; banner reintroduced in the
multi-line rustfmt shape; banner reintroduced in the single-line shape; telemetry doc stripped
from `synvoid-tls`; handshake pin weakened.

### 4.3 A guard bug the mutation testing caught

The banner guard was **line-scoped** on the first attempt and **passed the exact regression it
was written to catch**. rustfmt breaks `tracing::info!` across lines, so the macro name and the
interpolated field sit on different lines. The guard was rewritten to scan each `tracing::`
statement as a whole span, and it now fails on both the multi-line and single-line shapes.

This is recorded rather than quietly fixed: a guard that passes a reintroduced defect is worse
than no guard, because it converts a known risk into a believed-closed one. It was only visible
because the mutation was run.

Two further precision fixes came from the same exercise: the prose gate was narrowed to lines
that actually mention the setting (otherwise a correct sentence elsewhere in a document reads
as a violation), and `docs/HTTP3.md` was reworded rather than the gate weakened when it quoted
the bad phrasing in order to disown it.

---

## 5. Verification

| Lane | Result |
|------|--------|
| `cargo xtask verify` | **10 steps, 10 passed** (513.9s) — fmt → clippy → deny → core-compile → repo-guards → security-regression → root-guards → core-admin-tests → admin-contract → failure-injection |
| `cargo test -p synvoid-tls --profile ci` | **23 passed** (3 + 20 + 0), 0 failed |
| `cargo test -p synvoid-tls --profile ci --test cert_resolver_provider_evidence prefer_post_quantum` | **1 passed** — the pin |
| `cargo test -p synvoid-repo-guards --profile ci --test tls_post_quantum_truthfulness` | **4 passed** |
| `cargo test -p synvoid-repo-guards --profile ci` | **160 passed** (156 pre-existing + 4 new) |
| `cargo test -p synvoid-config --profile ci` | green |
| `cargo fmt --all -- --check`, `cargo clippy --profile ci --all-targets -- -D warnings` | clean |

**No persisted configuration changed.** The field, its key, its default, and its serde
attributes are untouched; only documentation was added around them. Existing operator TOML is
byte-identical in effect.

**Not run, recorded as not-run:** `cargo xtask verify-full`, `verify-release`, `cargo audit`
(the separate CI `dependency-security` job; `cargo deny check` runs inside `verify` and the
manifest is unchanged), and the extended-timeout suites — none of which this change touches.

---

## 6. What this phase did **not** do

| Not done | Why |
|----------|-----|
| Rename the field (b) | User chose (d). Re-deciding needs a separate phase and the user's call. |
| Make it gate (c) | Barred by the plan's rejection criteria: kx groups are provider-scoped, so it needs a second `CryptoProvider` and breaks the deliberate single-provider invariant (`crates/synvoid-tls/Cargo.toml`). |
| Remove the field (a) | Disproportionate to a low-severity truthfulness gap, and removal is a public API change on a published crate. |
| Add a `validate()` rejection | The field defaults to `true`, so a rejection fails every default-true config. Phase 41's reduced-feature rejection concerns capability-bearing **sections**, not an inert boolean. |
| Touch `architecture/pqc.md` / `networking_deep_dive.md` | Both were already accurate. Changing correct documentation to look busy is its own defect. |
| Change `synvoid-dns`'s class | Unaffected — this phase touched no DNS capability. |

---

## 7. Closure

This is the **last registered phase** of `plans/dns_residual_truthfulness_roadmap.md`
(Phases 137–140). All four are now CLOSED QUALIFIED:

| Phase | Scope | Closeout |
|-------|-------|----------|
| 137 | ALPN for DoT/DoH | `…_phase137_closeout.md` |
| 138 | GeoIP composition wiring | `…_phase138_closeout.md` |
| 139 | Mesh coupling disposition and inversion | `…_phase139_closeout.md` |
| 140 | `prefer_post_quantum` truthfulness | this document |

Two residuals remain registered and deliberately unclosed, both recorded rather than
silently absorbed:

1. **`synvoid-mesh`'s `dns = []` feature** — 20 compile errors, unfixable without a dependency
   cycle. Carried from Phase 139.
2. **The anycast broadcast cluster** — `crates/synvoid-dns/src/anycast_sync.rs`, coupled and
   dead, pinned as the named residual by
   `mesh_anycast_cluster_remains_the_only_named_residual`.

Plus one item that was unrelated to the campaign and was **fixed separately after it
closed**: the pre-existing `metrics_wiring.rs` parallel-execution race. All four tests
shared one `static COUNTER_STORE` and each called `reset_counters()`, so a concurrent
test's reset could delete the counter another was about to assert on. Re-measured on the
pre-fix tree at **3 failures in 120 runs (2.5%)**, against **0 in 210** after giving each
`TestRecorder` its own store. It never showed up in CI because `nextest` gives each test
its own process.