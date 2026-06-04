// Submodule: CPU affinity, shared-connection-table heartbeat, and IPC
// stream setup. These live in `state.rs`; this file is kept for the
// architecture outline and re-exports the relevant helpers.

pub use super::state::{
    apply_cpu_affinity, setup_unified_server_panic_handler, setup_worker_ipc,
    start_shared_connection_heartbeat,
};
