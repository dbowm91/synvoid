# DNSSEC Trust Anchors in SynVoid

> **Related Documentation:** [DNS & DNSSEC Architecture](dns-dnssec-architecture.md) | [DNS Architecture](../architecture/dns.md) | [Troubleshooting](TROUBLESHOOTING.md)

## Summary

SynVoid uses **static DNSSEC trust anchors**: a file is read once at startup and
is the only anchor source. There is no automated anchor management.

**RFC 5011 automated trust-anchor management is not implemented.** It was
designed and partially built (`TrustAnchorManager` with `Seen → Pending → Valid`
promotion, a CDS-driven `trust_anchor_check`, a `[dns.trust_anchors]` lifecycle
configuration, and a background update task), then removed by decision **T5**
because nothing ever fed the state machine and nothing ever consumed its output:

- `start_rfc5011_updates` had no caller, so the manager never observed the root
  DNSKEY RRset.
- The recursor's anchors were a startup snapshot, so a promotion or a revocation
  never reached validation.
- The state machine accepted a self-referential CDS as proof that a new key was
  trusted, and honoured the REVOKE bit from an observation whose
  `authentic_data` flag was captured but never consulted.

Carrying a state machine that cannot change a single validation decision is
worse than not having one: an operator would believe anchor rollover was
automatic. The code was deleted rather than left as a warning-shaped feature.

## Configuring anchors

```toml
[dns.recursive]
enabled = true
upstream_provider = "recursive"     # local validation
root_hints_path = "/var/lib/synvoid/dns/root.hints"
trust_anchor_path = "/var/lib/synvoid/dns/trusted-key.key"
dnssec_validation = true
```

`dns.recursive.trust_anchor_path` is the **only** supported anchor source. The
file uses the zone-file form, one record per line:

```text
; root KSK
. 86400 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3...R1AkUTV74bU=
```

The parenthesised multi-line form is not folded by the parser; keep the record
on one line.

Notes:

- A missing or unparseable file is logged and the built-in defaults are used.
  Check the startup log (`Loaded N static DNSSEC trust anchors from ...`) to
  confirm which anchors are active.
- The anchors are a **startup snapshot**. Replacing the file takes effect on the
  next process start. There is no reload signal, no database, and no polling.
- Rolling the root KSK is therefore a **manual operation**: update the file,
  restart the resolver.

## `[dns.trust_anchors]` is parseable but rejected

The section is retained so an existing configuration file still loads, but
activating it returns a typed `Unsupported` error naming
`dns.recursive.trust_anchor_path` as the only source:

```toml
[dns.trust_anchors]
enabled = true    # rejected: RFC 5011 trust-anchor management is not implemented
```

`db_path`, `refresh_interval_secs`, `pending_observation_days`,
`revocation_grace_days`, `extended_removal_days`,
`trust_anchor_retention_days`, and `allow_key_rotation` describe a lifecycle
that has no runtime consumer. They parse and are ignored.

## Relationship to validation

Local validation happens only in `upstream_provider = "recursive"`, where
hickory's recursor validates every answer against the static anchors and reports
the result honestly (`SERVFAIL` for bogus data, never a cached empty answer).

Forwarders (`system`, `google`, `cloudflare`, `custom`, `globalnodes`) do **not**
validate locally. `dnssec_validation = true` with one of those is a startup
error unless the operator accepts delegated validation:

```toml
[dns.recursive]
upstream_provider = "cloudflare"
dnssec_validation = true
allow_unvalidated_forwarding = true   # explicit: the upstream validates
```

In that mode `/health` reports `dnssec_state.validation = "delegated"`, not
`"enabled"`.

## See also

- `architecture/dns.md` — resolver structure and the removed RFC 5011 types.
- `docs/dns-dnssec-architecture.md` — signing and validation architecture.
- RFC 5011 §2-§4 (the specification this deployment deliberately does not
  implement), RFC 4034 §2 (DNSKEY RDATA), RFC 2308 §3 (negative TTL).
