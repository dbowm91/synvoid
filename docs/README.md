# SynVoid Documentation

Use these guides to install SynVoid, configure a site, and operate the service. For a first deployment, follow the guides in order:

1. [Getting Started](GETTING_STARTED.md) builds SynVoid and proxies one site.
2. [Configuration](CONFIGURATION.md) explains the available settings.
3. [Deployment](DEPLOYMENT.md) covers production hardening and service installation.

## Core guides

| Guide | Purpose |
|---|---|
| [README](../README.md) | Project overview and quick start |
| [Getting Started](GETTING_STARTED.md) | Build, configure, and test a local proxy |
| [Configuration](CONFIGURATION.md) | Main and site configuration reference |
| [Deployment](DEPLOYMENT.md) | Production deployment and hardening |
| [Admin UI](ADMIN_UI.md) | Browser-based administration |
| [API Reference](API_REFERENCE.md) | Admin API endpoints |
| [Troubleshooting](TROUBLESHOOTING.md) | Diagnose common problems |
| [FAQ](FAQ.md) | Frequently asked questions |
| [Feature Status](FEATURE_STATUS.md) | Current capability status and limitations |
| [Security](SECURITY.md) | Security guidance and threat model |

## WAF and traffic management

| Guide | Purpose |
|---|---|
| [Attack Detection](ATTACK_DETECTION.md) | WAF detection coverage and policy |
| [Bot Protection](BOT_PROTECTION.md) | Bot detection and crawler controls |
| [Rate Limiting](RATE_LIMITING.md) | Request rate limits |
| [Flood Protection](FLOOD_PROTECTION.md) | Network flood protection status and configuration |
| [Request Sanitization](REQUEST_SANITIZATION.md) | Request normalization and header handling |
| [Threat Intelligence](THREAT_INTEL.md) | Threat feeds and enforcement |
| [Threat Level](THREAT_LEVEL.md) | Adaptive threat-level behavior |
| [Signed Rule Feed](SIGNED_RULE_FEED.md) | Signed WAF rule distribution |
| [Tarpit](TARPIT.md) | Anti-scraping behavior |
| [Traffic Shaping](TRAFFIC_SHAPING.md) | Bandwidth and connection shaping |

## Proxy and application features

| Guide | Purpose |
|---|---|
| [Upstream Health](UPSTREAM_HEALTH.md) | Upstream health checks |
| [Proxy Cache](PROXY_CACHE.md) | Response caching |
| [Static Files](STATIC_FILES.md) | Static file serving |
| [FastCGI](FASTCGI.md) | FastCGI and PHP-FPM integration |
| [HTTP/3](HTTP3.md) | HTTP/3 support and configuration |
| [Tunnels](TUNNELS.md) | QUIC and site-to-site tunnels |
| [Serverless](SERVERLESS.md) | WASM serverless functions |
| [Uploads](UPLOADS.md) | Upload validation and malware scanning |
| [Honeypot](HONEYPOT.md) | Deception listeners and storage |

## Optional services and integrations

| Guide | Purpose |
|---|---|
| [WAF Mesh](WAF_MESH.md) | Mesh networking and distributed coordination |
| [DNS and DNSSEC](dns-dnssec-architecture.md) | DNS and DNSSEC design and operation |
| [DNS Mesh Integration](dns-mesh-integration.md) | DNS integration with mesh services |
| [RFC 5011 Trust Anchors](RFC5011_TRUST_ANCHOR.md) | Automated DNSSEC trust-anchor updates |
| [Global Node CA](global-node-ca.md) | Global node certificate authority |
| [Plugins](PLUGINS.md) | WASM plugins and extensions |
| [Plugin Configuration](PLUGIN_CONFIG_REFERENCE.md) | Plugin settings reference |
| [Plugin Operations](PLUGIN_OPERATOR_RUNBOOK.md) | Plugin operations and troubleshooting |
| [WASM ABI](WASM-ABI.md) | Plugin ABI specification |
| [Sandboxing](SANDBOXING.md) | Platform sandbox support and limits |
| [Platform Support](PLATFORM_SUPPORT.md) | Operating system support details |
| [Process Management](PROCESS_MANAGEMENT.md) | Supervisor and worker lifecycle |

## Operations and maintenance

| Guide | Purpose |
|---|---|
| [Upgrade](UPGRADE.md) | Upgrade steps and compatibility notes |
| [Release](RELEASE.md) | Release lifecycle and versioning |
| [Release Checklist](RELEASE_CHECKLIST.md) | Release qualification checklist |
| [Performance](PERFORMANCE.md) | Measurement and performance tuning |
| [Contributing](../CONTRIBUTING.md) | Contribution guidelines |
| [Changelog](../CHANGELOG.md) | Version history |

## Developer references

- [Architecture](ARCHITECTURE.md) describes the system design.
- [Developer Guide](DEVELOPER.md) covers local development and verification.
- [Architecture overview](../architecture/overview.md) indexes binding design documents. The `plans/` directory retains phase handoff history.
- [Testing contracts](testing/verification-contract.md) and [test ownership rules](testing/root-test-ownership.md) describe repository verification requirements.
- [Architecture decision records](adr/) preserve historical design rationale. They are not a statement of current behavior.

The source repository is available at [github.com/dbowm91/synvoid](https://github.com/dbowm91/synvoid).
