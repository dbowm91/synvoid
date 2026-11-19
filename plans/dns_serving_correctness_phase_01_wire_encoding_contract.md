# Phase 01 Plan: Wire Encoding Contract

Status: **IMPLEMENTED** (2026-11-19; `dns_wire_contract`, 9 tests).
Audit: `plans/dns_capability_audit.md` (D1, D2).
Registered in: `plans/roadmap.md`.
Campaign: `plans/dns_serving_correctness_roadmap.md`.
Predecessor: none.
Depends on: nothing. Every later phase depends on this one.

## The finding

**D1 (Critical, confirmed by execution).** Zone records are stored under
origin-relative names (`"@"`, `"www"`, `"a.b"`) by
`normalize_record_name` (`crates/synvoid-dns/src/server/zone.rs:28-56`), and
`encode_rr` (`crates/synvoid-dns/src/server/response_encoder.rs:116-129`)
writes `record.name` verbatim, substituting the question name only when the
record name is `"@"` or empty:

```rust
let record_name = if record.name == "@" || record.name.is_empty() {
    qname
} else {
    &record.name
};
```

An in-process probe against `DnsServer::handle_query` for `www.test.local/A`
decoded the answer owner as `"www"`. Every non-apex answer is therefore
out-of-zone; resolvers discard it.

**D2 (Critical).** The recursive listener takes
`question.name().to_string()` (dotted presentation form) and appends its ASCII
bytes as the wire name in both the question and every answer
(`crates/synvoid-dns/src/recursive.rs:739-740`, `:492-493`, `:1149-1186`).
`"example.com."` is emitted as the literal bytes `65 78 61 6d ...`, so a parser
reads `0x65` as a label length. No recursive response is parseable. The unit
tests assert only that the section is non-empty (`:1560-1585`).

## Root cause

There is no owner-name encoder. Each path builds names itself:

- the authoritative path stores relative names and encodes them as-is, relying
  on `"@"` to mean "the question";
- the recursive path has `String` names and writes the string;
- `wire::encode_name` exists but silently drops labels longer than 63 bytes and
  empty labels (`wire.rs:352-380`), so it is not a safe primitive either.

The tests never decode an owner name, so both mistakes pass.

## Fix scope

### R1 — One owner encoder

Replace `wire::encode_name` with a total function:

```rust
pub fn encode_owner(relative: &str, origin: &str) -> Result<Vec<u8>, NameError>;
```

Rules, in order:

- `"@"` or empty → `origin`;
- a name already equal to `origin` (case-insensitive, trailing dot ignored) →
  `origin`;
- a relative name → `format!("{relative}.{origin}")`;
- `origin` empty → the name is treated as absolute (root zone);
- every label is length-checked (1..=63), the total is checked (<= 255 octets),
  and empty labels (`a..b`) are rejected rather than skipped.

Keep a thin `encode_name(name) -> Vec<u8>` wrapper only for absolute names
(question section, RDATA targets), implemented as `encode_owner(name, "")`,
and make it return `Result` so callers cannot ignore a malformed name.

### R2 — `encode_rr` takes the origin

Change the signature to
`encode_rr(record, origin, qname_compression)`; build the owner with R1 and use
the compression pointer only when the encoded owner equals the question name.
`build_response` and every other `encode_rr` caller already receive
`signer_name`/`origin` and must pass it.

### R3 — Recursive path uses the encoder

- `build_question_section` and `build_answer_record` take the origin (or a
  pre-encoded owner) and call R1; never append a `String`.
- The question echo is copied from the request bytes (the parsed question
  section) rather than rebuilt from `Name::to_string()`, so case and unusual
  labels survive.
- `CachedRecord.name` becomes a full FQDN or `(relative, origin)`; the cache
  already stores byte names, so store the encoded wire name and reuse it.

### R4 — Echo the original question section

`assemble_packet` rebuilds the question with `build_question(qname, qtype, 1)`
(`response_encoder.rs:367`), which re-splits a textual name and cannot represent
a label containing a dot. Pass the original question bytes from the parsed
query and append them verbatim, adjusting only the counts. This also removes the
case-mismatch class (a resolver that verifies 0x20 case would otherwise discard
the answer).

### R5 — Regression tests that decode like a client

Extend `crates/synvoid-dns/tests/support/response.rs` with:

- `answer_owner(resp, index) -> String` (handles compression pointers);
- `question_name(resp) -> String`.

New suite `crates/synvoid-dns/tests/dns_wire_contract.rs`:

1. apex `A` answer owner == `example.com`;
2. `www` `A` answer owner == `www.example.com`;
3. multi-label `a.b` owner;
4. `CNAME` target RDATA parses as a name;
5. question echo preserves the client's mixed case;
6. authoritative NXDOMAIN echoes the question and its QDCOUNT is 1;
7. recursive `build_question_section` output is byte-identical to
   `wire::encode_owner(relative, origin)` (unit test in `recursive.rs`);
8. `encode_owner` rejects a 64-byte label, an empty label, and a >255-octet
   name.

### R6 — CI gate

Add a `dns-wire` step to `tools/xtask/src/verify.rs` running the new suite, and
a shell guard that fails when the suite reports fewer than 8 tests. Steps are
`(name, shell)` pairs appended to `verify_steps()` (`verify.rs:131`; the routine
lane CI actually runs) — copy the `mesh-contract` / `mesh-contract-guard` pair
added in `ea638ff9` (`verify.rs:154-164`). `cargo xtask verify` has no
per-step selection (`main.rs:23-29` ignores extra positionals), so the step is
selected by running the whole lane locally or by invoking the `cargo test`
command the step prints with `--dry-run --json`.

## Out of scope

- RRSIG data (phase 04) — it will consume the same encoder, but signing is not
  changed here.
- EDNS/OPT layout (phase 02).
- Wildcards and referrals (phase 09) — they also need the origin-aware encoder,
  but their lookup semantics are separate.

## Verification

```bash
cargo test -p synvoid-dns --test dns_wire_contract --profile ci
cargo test -p synvoid-dns --test dns_interop_authoritative --profile ci
cargo test -p synvoid-dns --profile ci
cargo xtask verify          # the new dns-wire step runs inside the routine lane
```

Note: no DNS suite is currently registered in `.github/workflows/ci.yml`; the
only CI test step is `cargo xtask verify`. A suite that is not in
`verify_steps()` is invisible to CI, which is why R6 is part of this phase and
not phase 10.

Acceptance:

- the probe that produced `"www"` now returns `www.test.local`;
- no `encode_name(` call remains outside `wire.rs` except the absolute wrapper;
- `rg 'record\.name' crates/synvoid-dns/src/server/response_encoder.rs` shows no
  direct encoding;
- full DNS suite green, and the new suite fails if `encode_rr` is reverted to
  ignore the origin.
