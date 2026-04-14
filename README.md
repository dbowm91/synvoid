# MaluWAF

A high-performance Web Application Firewall (WAF) and reverse proxy written in Rust. MaluWAF provides comprehensive protection for multiple websites with advanced attack detection, flood mitigation, and bot blocking capabilities. For certain tech stacks MaluWAF provides a full rust alternative to traditional methods from application to client. It also provides for an experimental P2P CDN architecture using a mesh network.

## Worker Design

The goal is to separate processes in case of a crash, making sure the master worker is rock solid (which is in turn watched by the overseer process) and allows for zero-downtime updates.

It uses an overseer --> master --> worker model. The overseer is a process thats primary purpose is to make sure the master process is working and to handle updates without stopping. The master process spawns the workers, which there are primarily two: the minifier and unifiedrequest workers. The minifier workers job is to periodically minify html/css/js, compress, and cache as needed. Since tokio runtime can scale vertically very well, utilizing all cores if allowed, all requests are handled in the unifiedrequest worker. The one downside to this approach is that we can't so easily adjust the number of threads without restarting the loop, so for now this requires restarting that worker. This is different than how NGINX does this, but effectively tokio is doing a similar thing.

## Better results on linux

Best support and performance will be seen on linux. It's more suited to networking that I know of at many levels. The underlying async architecture for things like EPOL are more heavily optimized in linux, windows equivalent for unix sockets is less performative, and I know we can run wireguard relying on kernel instead of userspace in linux. I can be completely wrong on some things, i'm not really an expert on any of this and even less on windows.

Inter Process Comunications (IPCs) are different and that's a major thing. Since the master and worker processes must communicate with eachother, in POSIX systems we're using unix sockets to communicate in IPCs. This avoids some overhead of running through local loopback for SYN/ACK. Passing sockets and windows equivalent is used as a fallback and the whole IPC itself is abstracted over, but I think there's a performance penalty for this on the windows side. I don't know.

For the mesh WAF-WAF communication protocol, we can offload wireguard to the kernel. WAF-WAF messaging is intended to be a backhaul method connecting the WAF node operating at the edge to an origin server, as well as for doing inter-WAF messaging for things like threat intelligence sharing, origin lookups, and health checks.

## Transport protocols: Wireguard and QUIC

The primary intention was twofold with the transports. First, I wanted to expose a website hosted at home or remote server through a VPS. That way you could push an origin server with decent specs through a comparatively minimal VPS, or just make it easier to deploy a remote origin server in various places. Secondly, since a lot of the logic and dependencies were already in place, why not allow the WAF to act as a VPN? 

## Mesh Network

Once the transport protocols were in place for the intended server-WAF and user VPN-WAF, I started looking at the mesh network. This is completely opt-in, it will work (as it was originally intended) as a single instance. The mesh network gives us a couple of new capabilities that could allow the WAF to be more full featured in its original mission: to protect the underlying origin server.

The biggest single weakness of a one-off WAF instance is that it's susceptible to DDOS attacks. Even with the layers of protections that are build into the WAF at the end of the day the way major CDNs are able to withstand these attacks really is about having a lot of PoPs (points of presence) and distributing the load of a DDOS over many of them. The other side of the coin concerns DNS, which is more or less out of scope for this project (major CDNs use anycast and sophisticated routing techniques to balance load), but what i figured could be done was try to lay the groundwork for a sort of P2P approach to this. Like a collaborative DDOS defense system.

For now, assume we have a properly setup DNS that allows Geodns, so the DNS conects us to the closest WAF edge node. The edge node does a lookup for origin server if it doesn't know it, and passes the origin server through the mesh network through a wireguard tunnel. There are still some issues with this, but it's a starting point. Each edge node is monitoring paths and each WAF that has an upstream is monitoring health of the origin server. This gives us flexibility in how we can chose routes. The mesh network assumes there can be multiple WAFS carrying the same origin server, which allows the edge WAF processing the client request to connect to the best performing WAF that has the origin server.

With this design, we can shield the identity of the origin server from the edge. WAFS can work as both an edge and an upstream provider. One origin server can broadcast to several remote WAFs in different locals. So there are a lot of options for how this can be setup as a load balancer and providing PoPs in various geographic areas.

The mesh network will allow for WAF instances to share intelligence in the form of blocked attacks. This will require some level of finnesse to make sure a mesh network doesn't flood itself or lead to unintended amplification effects, but if implemented correctly should let the mesh network respond rapidly to an emerging threat.

### TCP Proxying Through the Mesh

TCP services (HTTP, HTTPS, etc.) can be proxied through the mesh without port conflicts. Each WAF node uses QUIC streams to connect to upstream WAFs. Since QUIC provides native stream multiplexing:
- WAF B can simultaneously proxy example1.com from WAF F and example2.com from WAF G
- Each connection uses independent QUIC streams
- No port allocation conflicts between different upstream WAFs

### UDP Limitations

UDP services (DNS, VoIP, gaming protocols, etc.) **cannot be proxied through the mesh network**. This is a fundamental limitation due to:

1. **Port Conflicts**: Unlike TCP with QUIC streams, UDP requires each node to bind to specific ports. Multiple WAFs cannot share the same UDP port, making mesh-level routing impractical.

2. **Stateful Connections**: UDP is connectionless - there's no built-in way to maintain session state across mesh hops.

3. **No Stream Multiplexing**: UDP lacks QUIC's stream abstraction that makes TCP mesh proxying work cleanly.

**However**, UDP services can still be protected by individual WAF nodes for their local upstreams. Each WAF can:
- Accept UDP traffic from clients
- Apply WAF protections (flood detection, protocol filtering)
- Forward to local or configured upstreams

The existing UDP listener infrastructure (`UdpListenerPool`) handles this use case with full WAF protections including per-IP rate limiting, protocol detection, and amplification attack mitigation.

Last main benefit is that this can function as a VPN using other WAF instances that allow for it in a network.

## Control of the mesh network

The mesh network follows a structure influenced by Tor, in that there are a small and limited number of "global peers" that work as control nodes, sort of like directory authority nodes. For clarity, that's where the similarities end, as the goal of this project is nearly the opposite (expose websites or other servers to the public internet). These global nodes are entirely arbitrary, allowing users to start their own CDN networks. These nodes maintain a full peer list and database of WAFs that have origin servers. The global peers also work as a single source of truth for the network, allowing for a mesh network to work as a private CDN, approve or reject peers, and approve or reject websites from running through the network. This could be loosely organized by hobbyists as a form of crowdsourced CDN.

My personal preference would be a more unified network over many fragmented ones, since large ones would allow for more DDOS mitigation capability. There's also merits for running your own white lable mesh network: you can ensure total control, privacy, focus on a specific geographic area, and have more uniform server performance. 

## Purpose

This started as a project to learn rust, I wanted to do something similar to what nginx is doing. Thankfully tokio/hyper exist, so the groundwork for this isn't terribly difficult. Later it branched into learning about WAFs and the problems people are facing with scraper bots, especially AI scrapers. So MaluWAF is most mature at the reverse proxy and WAF layers.



## Quick Start

```bash
# Clone and build
git clone https://github.com/maluwaf/maluwaf.git
cd maluwaf
cargo build --release

# Run with default configuration
./target/release/maluwaf
```

The WAF starts on:
- Main HTTP server: http://localhost:8080
- Admin API: http://localhost:8081
- Prometheus metrics: http://localhost:9090

## Key Features

- **Attack Detection**: Blocks common web attacks including SQL injection, XSS, SSRF, path traversal, and command injection using pattern matching and libinjection. Useful for protecting applications from automated attacks and exploit attempts.

- **Flood Protection**: Defends against volumetric attacks (SYN floods, UDP floods) and connection exhaustion through rate limiting. Operates at both per-IP and global levels to prevent service degradation.

- **Bot Mitigation**: Identifies and challenges automated traffic including AI crawlers, scrapers, and suspicious bots. Uses CSS honeypots, JavaScript challenges, and behavioral analysis to separate legitimate users from bots.

- **Multi-Site Support**: Run protection for unlimited websites from a single WAF instance. Each site can have independent configuration for upstream servers, protection rules, and rate limits.

- **HTTP/3 & QUIC**: Modern protocol support with lower latency through 0-RTT connections and improved performance on lossy networks. Provides better mobile user experience.

- **WAF Clustering**: Connect multiple WAF instances in a peer-to-peer mesh network to share threat intelligence, distribute DDoS load, and coordinate protection across geographic regions.

- **Observability**: Monitor WAF health through Prometheus metrics, structured JSON logging, and real-time WebSocket feeds for live traffic monitoring and debugging.

- **Security**: Automatic header sanitization removes sensitive information from responses, silent stalling wastes attacker time without revealing the server exists, and no version disclosure prevents information leakage.

## Documentation

See the [docs directory](docs/) for comprehensive documentation:

| Guide | Description |
|-------|-------------|
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Quick start guide with CLI options |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment guide |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture overview |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Complete configuration reference |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | Admin API documentation |
| [ATTACK_DETECTION.md](docs/ATTACK_DETECTION.md) | Attack detection details |
| [FLOOD_PROTECTION.md](docs/FLOOD_PROTECTION.md) | Flood protection details |
| [REQUEST_SANITIZATION.md](docs/REQUEST_SANITIZATION.md) | Request sanitization and header handling |
| [UPSTREAM_HEALTH.md](docs/UPSTREAM_HEALTH.md) | Upstream health checking |
| [STATIC_FILES.md](docs/STATIC_FILES.md) | Static file serving and optimization |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |

## Configuration

Configuration is in `config/main.toml`. See [CONFIGURATION.md](docs/CONFIGURATION.md) for details.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MALU_CONFIG_DIR` | `./config` | Configuration directory |
| `RUST_LOG` | `info` | Log level |
| `MALU_ADMIN_TOKEN` | - | Admin API token |

## License

MIT License - see [LICENSE](LICENSE) file for details.
