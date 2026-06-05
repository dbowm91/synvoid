//! Serverless WASM function management.

pub mod async_compilation;
pub mod instance_pool;
pub mod manager;
#[cfg(feature = "mesh")]
pub mod mesh_integration;
pub mod registry;
pub mod routing;
pub mod scheduler;

pub use async_compilation::{AsyncCompilationHandle, AsyncCompilationManager, CompilationState};
pub use instance_pool::{
    InstancePool, InstancePoolConfig, InstancePoolError, InstancePoolMode, InstanceState,
    PoolHealth, PoolMetrics, ServerlessInstance,
};
pub use manager::{get_global_serverless_manager, set_global_serverless_manager};
#[cfg(feature = "mesh")]
pub use manager::{
    handle_serverless_function, CallerContext, ServerlessError, ServerlessFunction,
    ServerlessManager,
};
#[cfg(not(feature = "mesh"))]
pub use manager::{CallerContext, ServerlessError, ServerlessFunction, ServerlessManager};
pub use registry::{
    get_global_serverless_registry, FunctionMetadata, FunctionStats, ServerlessRegistry,
};
pub use routing::{MethodMatch, RouteMatch, ServerlessRoute};
pub use scheduler::{ServerlessScheduler, TimerEntry, TimerPayload};

#[cfg(feature = "mesh")]
pub use mesh_integration::{
    set_mesh_dht, set_mesh_transport, MeshDhtProvider, MeshOrganizationProvider,
    MeshRoutingProvider, MeshTransportProvider, MeshWasmDistProvider,
};
