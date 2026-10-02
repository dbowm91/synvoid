# Phase 111: Tunnel Convergence Evidence

Status: **CLOSED DEFER** (2026-10-02).

## Decision and evidence boundary

No tunnel adoption or upstream change is qualified. The plan names
`eggstack/eggtunnel`, but no Eggtunnel checkout is present under
`/Users/davidbowman/projects`, and its repository source, release contract, wire
vectors, lifecycle tests, and security guarantees could not be inspected. The
available `/Users/davidbowman/projects/eggress` checkout is clean at its local
`main` tracking `origin/main`; it provides generic stream relay
(`eggress-relay`) and optional QUIC transport (`eggress-transport-quic`), as
well as proxy outbound UDP association. These do not by themselves prove
compatibility with an authenticated tunnel/session protocol. No cross-repo
source or release was changed.

## Capability disposition

| Capability | SynVoid owner | Eggress evidence | Disposition |
|---|---|---|---|
| Frame header/versioning and messages | `synvoid-tunnel::quic::{framing,messages,validation}` | No corresponding authenticated tunnel wire protocol established | RETAIN; no wire reinterpretation |
| Authentication and session identity | Tunnel client/server + SynVoid peer/mesh identity | Generic proxy connector/relay is not a drop-in identity/session contract | RETAIN; parity unavailable |
| Registration, mapping, connection IDs | `quic::{registry,server,client}` and `TunnelManager` | No equivalent service registration contract established | RETAIN |
| Reconnect/backoff and ping/pong/health | `quic::{client,health}` | Eggress relay lifecycle differs; no tunnel session parity evidence | RETAIN pending comparison |
| Graceful drain/cancel | runtime/session lifecycle | Eggress generic relay supports half-close and drain patterns, but call-site lifecycle equivalence is unproven | DEFER adoption |
| QUIC endpoint/connection/stream setup | `quic::runtime`; consumed by `synvoid-mesh` | Optional `eggress-transport-quic` provides proxy/H3 transport, not a generic authenticated tunnel runtime | RETAIN; candidate only after Eggtunnel contract review |
| Generic TCP byte relay/backpressure | Tunnel stream handlers | `eggress-relay` is generic and half-close-aware | Candidate UPSTREAM/ADOPT only after semantic parity tests; no safe replacement established |
| TLS policy | Tunnel QUIC/TLS and mesh peer policy | Eggress transport TLS is proxy/H3-scoped | RETAIN identity and route policy |
| Proxy traversal | SynVoid proxy/route integrations | Eggress has mature outbound chaining/relay mechanisms | Potential future integration, no tunnel-specific parity proof |
| UDP/datagram | `quic::messages`, runtime/session datagram capabilities; UDP manager | Eggress outbound UDP association is proxy semantics, not negotiated authenticated tunnel datagrams | RETAIN; never model as TCP half-close |
| TUN and WireGuard | `tun.rs`, `wireguard/**`, VPN client | No relevant Eggress TUN/WireGuard contract established | RETAIN as VPN product behavior |
| Upstream URL/route resolution | `upstream.rs`, SynVoid config | Eggress route/outbound config is a separate proxy contract | RETAIN SynVoid config adapter |
| Mesh QUIC reuse | `synvoid-mesh` consumes `QuicRuntime`/connection types | No generic mesh peer-auth boundary in Eggress | RETAIN; do not make Eggtunnel depend on mesh |
| Metrics/diagnostics | SynVoid tunnel/mesh metrics | Eggress has its own diagnostics/metrics | Keep SynVoid labels and policy at adapter |

## Maintenance evidence and next gate

SynVoid tunnel dependencies include Quinn, rustls, framing/session logic,
upstream/config integrations, metrics, and optional WireGuard. `synvoid-vpn-client`
and `synvoid-mesh` are active internal consumers, so no standalone move or
wire replacement is justified. Eggress's relay primitive is the strongest
concrete overlap, but wrapper adoption alone would not prove removed maintenance
surface. Reopen only with Eggtunnel source/API and versions available; compare
wire and lifecycle semantics, then demonstrate reduced code/dependencies with
mixed-version, VPN, mesh, backpressure, cancellation/drain, and datagram tests.
If generic authenticated datagrams are proposed, first register an independent
Eggtunnel plan specifying negotiated capability IDs, bounds, replay, and
saturation behavior. This phase did not establish that requirement.
