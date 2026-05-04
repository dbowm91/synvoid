# Worker Extension Runtime

This skill documents the extension runtime pattern for managing worker lifecycle extensions.

## Overview

`ExtensionRuntime` provides a unified interface for managing lifecycle extensions in the worker process. This replaces scattered startup/shutdown code with a consistent registry pattern.

## Core Trait

```rust
#[async_trait]
pub trait ExtensionRuntime: Send + Sync {
    fn name(&self) -> &'static str;
    async fn start(&self) -> Result<(), Error>;
    async fn stop(&self) -> Result<(), Error>;
    fn health_check(&self) -> HealthStatus;
}
```

## Failure Policies

| Policy | Behavior | Use Case |
|--------|----------|----------|
| `FailClosed` | Stop processing if extension fails | Mesh, DNS (critical infrastructure) |
| `FailOpen` | Log warning, continue without | Serverless, Honeypot (optional features) |

## ExtensionRegistry

**Location**: `src/worker/extension.rs`

```rust
pub struct ExtensionRegistry {
    extensions: Vec<ExtensionInfo>,
}

impl ExtensionRegistry {
    pub fn register(&mut self, runtime: Arc<dyn ExtensionRuntime>, policy: ExtensionFailurePolicy);
    pub async fn start_all(&self) -> Result<(), Error>;
    pub async fn stop_all(&self) -> Result<(), Error>;
    pub fn refresh_health(&self);
    pub fn get_health_statuses(&self) -> Vec<ExtensionHealth>;
}
```

## Wrapped Runtimes

| Runtime | Policy | Feature Gate |
|---------|--------|-------------|
| `MeshExtensionRuntime` | FailClosed | `mesh` |
| `DnsExtensionRuntime` | FailClosed | `dns` |
| `ServerlessExtensionRuntime` | FailOpen | (none) |
| `HoneypotExtensionRuntime` | FailOpen | (none) |

## Health API

Extension health is exposed via Admin API `/health/extensions` which returns:
- Extension name
- Failure policy
- Current health status
- Last refresh timestamp

## Usage

```rust
let mut registry = ExtensionRegistry::new();
registry.register(
    Arc::new(mesh_runtime),
    ExtensionFailurePolicy::FailClosed,
);
registry.start_all().await?;
```