# SynVoid Image Rights Terminology Inventory

> Generated as part of [`image_rights_final_cleanup.md`](image_rights_final_cleanup.md).
>
> Scope: every remaining `poison|poisoning|Poison|POISON|perturb|perturbation|Perturb|PERTURB`
> match in `src/`, `crates/`, `plans/`, `README.md`, `docs/`, `architecture/`,
> `examples/`, `tests/`, and `Cargo.toml` is classified here.
>
> Classifications:
>
> ```text
> MUST_RENAME            - Stale user-facing text or live canonical name that should change.
> COMPAT_ALIAS_OK        - Deprecated compatibility alias or shim. Retain until next refactor cycle.
> IPC_WIRE_COMPAT_OK     - Wire-visible IPC enum/field. Retain until protocol-v2 rename.
> HISTORICAL_NOTE_OK     - Historical plan/architecture note. Acceptable.
> UNRELATED_CONCEPT_OK   - Unrelated security concept (e.g. DNS cache poisoning, mutex poisoning).
> ```

## Must rename now

| Term | File | Context | Classification | Action | Notes |
|------|------|---------|----------------|--------|-------|
| ~~`image poisoning`~~ | ~~`README.md:16`~~ | ~~User-facing description of CPU worker transforms~~ | MUST_RENAME (resolved) | Replaced with "image rights marking (steganographic / metadata signaling)" | ~~Top-level user-facing statement~~ **Resolved in this pass.** |
| ~~`Image Poisoning` section header~~ | ~~`architecture/http_server.md:328`~~ | ~~Architecture section header for image rights path~~ | MUST_RENAME (resolved) | Renamed to "Image Rights Marking" with note clarifying the steganographic (not adversarial) intent | **Resolved in this pass.** |
| ~~`Image Poison Cache` section header~~ | ~~`architecture/http_server.md:377`~~ | ~~Architecture section header for image rights cache~~ | MUST_RENAME (resolved) | Renamed to "Image Rights Cache" | **Resolved in this pass.** |
| ~~`SiteImagePoison` tree listing~~ | ~~`architecture/config.md:721`~~ | ~~Architecture tree listing~~ | MUST_RENAME (resolved) | Updated to `SiteImageRightsConfig` with compat alias noted | **Resolved in this pass.** |

## Compatibility aliases retained

| Term | File | Context | Classification | Action | Notes |
|------|------|---------|----------------|--------|-------|
| `pub mod image_poisoning` | `crates/synvoid-static-files/src/lib.rs:3` | Compatibility shim module declaration | COMPAT_ALIAS_OK | Retain | Re-exports `image_rights::*` |
| `pub mod image_poisoning` | `src/http/mod.rs:13` | Compatibility shim module declaration | COMPAT_ALIAS_OK | Retain | Re-exports `image_rights::*` |
| `pub use ... as apply_image_poisoning` | `crates/synvoid-static-files/src/image_poisoning.rs:4` | Deprecated function alias | COMPAT_ALIAS_OK | Retain | Re-export only |
| `pub use ... as invalidate_image_poison_cache_for_site` | `crates/synvoid-static-files/src/image_poisoning.rs:5` | Deprecated function alias | COMPAT_ALIAS_OK | Retain | Re-export only |
| `pub use ... as apply_image_poisoning` | `src/http/image_poisoning.rs:4` | Root-level deprecated function alias | COMPAT_ALIAS_OK | Retain | Re-export only |
| `pub use ... as invalidate_image_poison_cache_for_site` | `src/http/image_poisoning.rs:5` | Root-level deprecated function alias | COMPAT_ALIAS_OK | Retain | Re-export only |
| `pub type SiteImagePoisonConfig = SiteImageRightsConfig` | `crates/synvoid-config/src/site/misc.rs:40-41` | Deprecated type alias for config | COMPAT_ALIAS_OK | Retain | Documented as deprecated |
| `pub SiteImagePoisonConfig` re-export | `crates/synvoid-config/src/site/mod.rs:47` | Re-exports the deprecated alias | COMPAT_ALIAS_OK | Retain | Needed for back-compat |
| `alias = "image_poison"` | `crates/synvoid-config/src/site/mod.rs:126` | Serde alias on `image_rights` field | COMPAT_ALIAS_OK | Retain | Preserves old `image_poison` config key |
| `SiteImagePoisonConfig` (mesh cache LRU value type) | `crates/synvoid-mesh/src/mesh/transports/manager.rs:91` | LRU cache value type | COMPAT_ALIAS_OK | Retain | Uses compat type alias |

## IPC wire compatibility retained

These names are serialized on the wire (postcard over the supervisor<->worker
control socket or DHT overlay). They are retained as compatibility debt until an
explicit protocol version bump.

| Term | File | Context | Classification | Action | Notes |
|------|------|---------|----------------|--------|-------|
| `CpuTaskKind::PoisonImage` | `crates/synvoid-ipc/src/ipc.rs:120` | Enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Serialized across worker boundaries |
| `CpuTaskPayload::PoisonImage` | `crates/synvoid-ipc/src/ipc.rs:154-163` | Enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Serialized across worker boundaries |
| `CpuTaskResult::PoisonImage` | `crates/synvoid-ipc/src/ipc.rs:219-221` | Enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Serialized across worker boundaries |
| `poisoned_body: Vec<u8>` | `crates/synvoid-ipc/src/ipc.rs:220` | Struct field name on the wire | IPC_WIRE_COMPAT_OK | Retain | Serialized field name |
| `Message::PoisonImageRequest` | `crates/synvoid-ipc/src/ipc.rs:684-694` | Message enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Postcard-serialized over IPC |
| `Message::PoisonImageResponse` | `crates/synvoid-ipc/src/ipc.rs:695-698` | Message enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Postcard-serialized over IPC |
| `poisoned_body: Vec<u8>` | `crates/synvoid-ipc/src/ipc.rs:697` | Message field name on the wire | IPC_WIRE_COMPAT_OK | Retain | Serialized field name |
| `Message::PoisonImageError` | `crates/synvoid-ipc/src/ipc.rs:699-702` | Message enum variant on the wire | IPC_WIRE_COMPAT_OK | Retain | Postcard-serialized over IPC |
| `CpuTaskKind::PoisonImage` payload match | `crates/synvoid-ipc/src/ipc.rs:197,242` | Wire variant matches in router | IPC_WIRE_COMPAT_OK | Retain | Branch on wire variant |
| `CpuTaskPayload::PoisonImage` match | `crates/synvoid-ipc/src/ipc.rs:1413,1595,2195` | Wire variant matches | IPC_WIRE_COMPAT_OK | Retain | Branch on wire variant |
| `Message::PoisonImageRequest/Response/Error` doc comment | `crates/synvoid-ipc/src/ipc.rs:443,451` | Doc comments listing wire messages | IPC_WIRE_COMPAT_OK | Retain | Names match wire variants |
| `Message::PoisonImageResponse` match arms | `crates/synvoid-ipc/src/ipc.rs:1140,1921-1923` | Match arm on wire variant | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variants |
| `Message::PoisonImageRequest/Error` validation strings | `crates/synvoid-ipc/src/ipc.rs:1324-1337` | Internal validation error labels | IPC_WIRE_COMPAT_OK | Retain | Labels refer to wire variant names |
| `Message::PoisonImageRequest` CPU task routing | `crates/synvoid-ipc/src/ipc.rs:2121,2207` | Legacy CPU task routing branches | IPC_WIRE_COMPAT_OK | Retain | Routes to CpuTask handler |
| `PoisonImageResponse` construction | `crates/synvoid-ipc/src/ipc.rs:2196-2198` | Builds wire response | IPC_WIRE_COMPAT_OK | Retain | Constructs wire variant |
| `task_kind: CpuTaskKind::PoisonImage` tests | `crates/synvoid-ipc/src/ipc.rs:2916,2923,2946,2953,3000,3053` | Test fixtures for wire format | IPC_WIRE_COMPAT_OK | Retain | Test wire variants |
| `Message::PoisonImageRequest/Response/Error` match arms (client) | `crates/synvoid-static-files/src/client.rs:542-548` | Match arms on wire variants | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variants |
| `synvoid_ipc::Message::PoisonImageResponse/Error` | `crates/synvoid-static-files/src/client.rs:1651,1662,1668` | Constructs wire response | IPC_WIRE_COMPAT_OK | Retain | Constructs wire variant |
| `poisoned_body` field accesses | `crates/synvoid-static-files/src/client.rs:1653,1656,1665` | Accesses wire field | IPC_WIRE_COMPAT_OK | Retain | Field name on the wire |
| `CpuTaskPayload::PoisonImage` dispatch | `src/worker/cpu_task/payload.rs:75,87,91,120,160,180,252,284,294,310,325,349` | Wire variant handling in worker | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variant |
| `CpuTaskResult::PoisonImage { poisoned_body }` | `src/worker/cpu_task/payload.rs:252` | Wire variant match | IPC_WIRE_COMPAT_OK | Retain | Field name on the wire |
| `Message::PoisonImageResponse { poisoned_body }` | `src/worker/cpu_task/mod.rs:372-374` | Constructs wire response | IPC_WIRE_COMPAT_OK | Retain | Wire variant and field name |
| `CpuTaskPayload::PoisonImage` legacy routing | `src/worker/cpu_task/mod.rs:350-385` | Legacy CPU task routing | IPC_WIRE_COMPAT_OK | Retain | Routes legacy wire variant |
| `CpuTaskPayload::PoisonImage` | `src/worker/cpu_task/dispatch.rs:249-289` | Generic CpuTask dispatch branch | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variant |
| `poisoned_body` local var | `src/worker/cpu_task/dispatch.rs:259,273` | Local var carries wire field | IPC_WIRE_COMPAT_OK | Retain | Name mirrors wire field |
| `Message::PoisonImageRequest/Response/Error` (tests) | `tests/ipc_test.rs:1031,1046,1048,1054` | Test fixtures for wire format | IPC_WIRE_COMPAT_OK | Retain | Verifies wire variants |
| `cpu_offload_queued_poison_image` (admin JSON) | `crates/synvoid-admin/src/handlers/stats.rs:266,342` | Admin API JSON field name | IPC_WIRE_COMPAT_OK | Retain | External admin API field |
| `cpu_offload_active_poison_image` (admin JSON) | `crates/synvoid-admin/src/handlers/stats.rs:270,346` | Admin API JSON field name | IPC_WIRE_COMPAT_OK | Retain | External admin API field |
| `cpu_offload_completed_poison_image` (admin JSON) | `crates/synvoid-admin/src/handlers/stats.rs:274,350` | Admin API JSON field name | IPC_WIRE_COMPAT_OK | Retain | External admin API field |
| `queued_poison_image` / `active_poison_image` / `completed_poison_image` | `crates/synvoid-ipc/src/ipc.rs:255,261,267` | IPC stat field names | IPC_WIRE_COMPAT_OK | Retain | Serialized via admin API |
| `CpuTaskKind::PoisonImage` branches in metrics | `src/worker/cpu_task/metrics.rs:84,113,150,179,216,235,307-308` | CPU task metrics dispatch | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variant |
| `cpu_task_kind_label(CpuTaskKind::PoisonImage)` | `src/worker/cpu_task/metrics.rs:307-308` | Metrics label map | IPC_WIRE_COMPAT_OK | Retain | Returns "image_rights" label (canonical name in metrics, not in IPC) |
| `DhtKey::SiteImagePoisonConfig(String)` | `crates/synvoid-mesh/src/mesh/dht/keys.rs:42` | DHT key variant | IPC_WIRE_COMPAT_OK | Retain | String-form key: "site_image_poison_config:<id>" |
| `DhtKey::PoisonedImage { site_id, original_hash }` | `crates/synvoid-mesh/src/mesh/dht/keys.rs:49` | DHT key variant | IPC_WIRE_COMPAT_OK | Retain | String-form key: "poisoned_image:<site>:<hash>" |
| `DhtKey::site_image_poison_config(...)` | `crates/synvoid-mesh/src/mesh/dht/keys.rs:250-251` | DHT key constructor | IPC_WIRE_COMPAT_OK | Retain | Constructs wire variant |
| `DhtKey::poisoned_image(...)` | `crates/synvoid-mesh/src/mesh/dht/keys.rs:258-259` | DHT key constructor | IPC_WIRE_COMPAT_OK | Retain | Constructs wire variant |
| `DhtKey::SiteImagePoisonConfig` to_string branch | `crates/synvoid-mesh/src/mesh/dht/keys.rs:415-416` | Wire serialization | IPC_WIRE_COMPAT_OK | Retain | "site_image_poison_config:..." |
| `DhtKey::PoisonedImage` to_string branch | `crates/synvoid-mesh/src/mesh/dht/keys.rs:431-435` | Wire serialization | IPC_WIRE_COMPAT_OK | Retain | "poisoned_image:..." |
| `site_image_poison_config` parser branch | `crates/synvoid-mesh/src/mesh/dht/keys.rs:583-584` | Wire deserialization | IPC_WIRE_COMPAT_OK | Retain | Parses wire string key |
| `poisoned_image` parser branch | `crates/synvoid-mesh/src/mesh/dht/keys.rs:594` | Wire deserialization | IPC_WIRE_COMPAT_OK | Retain | Parses wire string key |
| `DhtKey::PoisonedImage / SiteImagePoisonConfig` | `crates/synvoid-mesh/src/mesh/dht/keys.rs:709-710,778,797,848,851,904,907,959,961` | Various DHT key matches/queries | IPC_WIRE_COMPAT_OK | Retain | Branches on wire variants |
| `SignedRecordType::SiteImagePoisonConfig` | `crates/synvoid-mesh/src/mesh/dht/signed.rs:570,615,662,860,1384` | DHT signed record type | IPC_WIRE_COMPAT_OK | Retain | Serialized over mesh |
| `SiteImagePoisonConfig` (DHT signed record lookup) | `crates/synvoid-mesh/src/mesh/dht/signed.rs:570` | DHT signed record type reference | IPC_WIRE_COMPAT_OK | Retain | Reads wire field |
| `SiteImagePoisonConfig` (mesh cache LRU value type) | `crates/synvoid-mesh/src/mesh/transports/manager.rs:91` | LRU cache value type | COMPAT_ALIAS_OK | Retain | Uses compat type alias |
| `crate::dht::keys::DhtKey::poisoned_image(...)` | `crates/synvoid-mesh/src/mesh/proxy.rs:1856,1890` | DHT key construction in mesh proxy | IPC_WIRE_COMPAT_OK | Retain | Wire-keyed |
| `PoisonImageRequest/Response` listed in IPC tables | `architecture/platform_deep_dive.md:106`, `architecture/ipc_process.md:98` | Architecture documentation tables | HISTORICAL_NOTE_OK | Retain | Documents wire variants |
| `SiteImagePoison, SiteLogging, SiteWorkerPool configs` | `architecture/config.md:721` | Architecture tree listing | HISTORICAL_NOTE_OK | Retain | Documents compat alias |

## Historical plan notes retained

These are intentionally left in place to record the rename pass history.

| Term | File | Context | Classification | Action | Notes |
|------|------|---------|----------------|--------|-------|
| Image-rights rename pass description | `plans/image_rights_terminology_rename_pass.md` | Original rename plan | HISTORICAL_NOTE_OK | Retain | Source of truth for the rename pass |
| Final cleanup plan | `plans/image_rights_final_cleanup.md` | This cleanup plan | HISTORICAL_NOTE_OK | Retain | Source of truth for this pass |
| `image poisoning` in `plans/polish.md:71,148` | Polish backlog notes | Backlog item | HISTORICAL_NOTE_OK | Retain | Historical note |
| `image poisoning` in `plans/http_*.md` | HTTP consolidation plans | Historical handoff docs | HISTORICAL_NOTE_OK | Retain | Documents the historical extract path |
| `image_poisoning` in `plans/root_dependency_ownership.md:70-72` | Dependency ownership doc | Historical extract note | HISTORICAL_NOTE_OK | Retain | Documents the extract path |
| `PoisonImageRequest/Response` | `architecture/platform_deep_dive.md:106`, `architecture/ipc_process.md:98` | Architecture documentation | HISTORICAL_NOTE_OK | Retain | Documents wire variants |
| `Image Poisoning` / `Image Poison Cache` | ~~`architecture/http_server.md:328,377`~~ | ~~Architecture section headers~~ | HISTORICAL_NOTE_OK (resolved) | Renamed to "Image Rights Marking" / "Image Rights Cache" | **Resolved in this pass.** The poison-name historical note no longer applies. |

## Unrelated concepts (not image rights)

These refer to security concepts unrelated to the image protection path. They
are not part of this cleanup pass.

| Term | File | Context | Classification | Action | Notes |
|------|------|---------|----------------|--------|-------|
| `CachePoisoningError`, `PotentialPoisoning` | `src/dns/cache.rs:165-528`, `src/dns/sharded_cache.rs:15`, `crates/synvoid-dns/src/cache.rs`, `crates/synvoid-dns/src/sharded_cache.rs` | DNS response cache poisoning detection | UNRELATED_CONCEPT_OK | Retain | Different concept (DNS cache integrity) |
| `CachePoisoningAttempt` | `src/dns/metrics.rs:434` | DNS cache attack metric | UNRELATED_CONCEPT_OK | Retain | DNS-specific metric |
| `SlashReason::DhtPoisoning` | `crates/synvoid-mesh/src/mesh/dht/stake.rs:160,174,604` | DHT mesh security slashing reason | UNRELATED_CONCEPT_OK | Retain | Mesh security concept |
| `DhtPoisoning` references | `architecture/layer_3_5_deep_dive.md:126`, `tests/dht_integration_test.rs:344` | DHT mesh security concept | UNRELATED_CONCEPT_OK | Retain | DHT integrity protection |
| `Response queue poisoning` | `docs/ATTACK_DETECTION.md:245`, `docs/REQUEST_SANITIZATION.md:168` | WAF attack detection concept | UNRELATED_CONCEPT_OK | Retain | WAF signal |
| `Cache lock poisoned` / `Config lock poisoned` / `cpu task pending lock poisoned` / `CPU task limiter lock poisoned` / `env lock poisoned` | `src/worker/response_builder.rs:22,34,181,278,297,526`, `src/worker/cpu_task/state.rs:120`, plus many lock-poisoned panic sites | Standard Rust mutex `PoisonError` handling | UNRELATED_CONCEPT_OK | Retain | Standard library term |
| `Err(poisoned) => poisoned.into_inner()` | `src/upload/config.rs:214`, `crates/synvoid-upload/src/config.rs:214` | Mutex `PoisonError` recovery | UNRELATED_CONCEPT_OK | Retain | Standard library term |
| `pool to prevent poisoning` | `crates/synvoid-mesh/src/mesh/transport.rs:1750` | Connection pool reuse safety | UNRELATED_CONCEPT_OK | Retain | Describes connection pool safety, unrelated to image rights |
| `adversarial perturbation`, `Nightshade-style`, `model poisoning` | `plans/image_rights_terminology_rename_pass.md` | Background context for the rename decision | HISTORICAL_NOTE_OK | Retain | Records the rationale |

## Unknown / needs investigation

None. All matches are classified above.

## Summary

```text
MUST_RENAME           : 0   (all resolved in this pass)
COMPAT_ALIAS_OK       : 9   (compat modules, type aliases, serde alias)
IPC_WIRE_COMPAT_OK    : 38  (IPC enum variants, fields, DHT keys, admin API fields)
HISTORICAL_NOTE_OK    : 6   (plan/architecture files)
UNRELATED_CONCEPT_OK  : 7   (DNS cache, DHT mesh, mutex poisoning, WAF signal)
```

All `MUST_RENAME` items in the original inventory have been resolved. Internal
worker code now uses canonical `image_rights::` names (the worker sub-module was
renamed from `image_poisoning` to `image_rights` in this pass; see
`git log --diff-filter=R src/worker/`). The remaining matches are either
wire-compatibility debt, deprecation shims, historical documentation, or
unrelated security concepts.

## Protocol classification (Task IRC-03)

The IPC names are explicitly classified here.

| Question | Answer |
|----------|--------|
| Are these names serialized or wire-visible? | **Yes.** The supervisor<->worker control channel and the DHT overlay both use postcard-serialized enums/structs. The admin API surface also serializes `cpu_offload_*_poison_image` field names as JSON. |
| Are they part of an external/stable protocol? | The supervisor<->worker channel is **internal** to a single SynVoid deployment. The DHT wire format is shared across mesh peers and may be replicated across deployments. The admin API JSON shape is consumed by dashboards, monitoring, and external scripts. |
| Can they be renamed now with serde aliases? | postcard does not honor serde tag aliases in the same way JSON does. Adding `#[serde(alias = ...)]` to enum variants does not retag existing serialized bytes. A protocol migration would require either (a) a new variant paired with an explicit converter, or (b) a bumped protocol version with parallel variants. |
| Should they remain as compatibility debt until a protocol version bump? | **Yes.** Renaming silently would break supervisor<->worker compatibility, mesh replication compatibility, and any external dashboard consuming the admin API. |

### Recommended decision

```text
Keep the following names on the wire as-is for at least one more refactor cycle:

- CpuTaskKind::PoisonImage
- CpuTaskPayload::PoisonImage
- CpuTaskResult::PoisonImage
- Message::PoisonImageRequest
- Message::PoisonImageResponse
- Message::PoisonImageError
- poisoned_body (field name)
- queued_poison_image / active_poison_image / completed_poison_image (admin/stats fields)
- DhtKey::SiteImagePoisonConfig
- DhtKey::PoisonedImage
- site_image_poison_config (DHT string key)
- poisoned_image (DHT string key)
- SignedRecordType::SiteImagePoisonConfig

Use rights-marking names only in:

- Rust wrapper APIs and types that are not on the wire.
- User-facing logs and error messages.
- Documentation, README, and architecture deep dives.
- New internal call sites (cpu_task dispatch, worker modules, response builders).

A future IPC protocol-v2 rename should introduce ImageRightsMarkRequest/Response
and a new CpuTaskKind::ImageRightsMark variant, then deprecate the PoisonImage
variants after one full deprecation cycle. Until then, treat the wire names
as documented compatibility debt.
```

## Compatibility removal policy (Task IRC-07)

```text
Keep `image_poisoning` compatibility modules and `SiteImagePoisonConfig` alias
for at least one more refactor cycle.

Keep IPC `PoisonImage` wire names until an explicit IPC protocol version bump
or alias-based migration is implemented.

Remove compatibility shims only after all internal call sites and docs use
image-rights names and no external examples reference old names.

If SynVoid has no external users yet, the compatibility removal can be done
earlier, but only in a dedicated cleanup commit with full grep validation.
```
