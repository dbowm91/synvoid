//! Master process management.
//!
//! Implements the parent (master) process that spawns and communicates
//! with worker processes via IPC. Provides CLI command handlers
//! (status, stop, rehash, token generation) and platform-specific
//! IPC accept loops (Unix domain sockets, Windows named pipes).

pub mod commands;
pub mod ipc;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use windows::{windows_ipc_accept_loop, windows_command_pipe_listener};

pub use commands::{
    handle_configtest, handle_generatenewtoken, handle_generatetoken, handle_rehash, handle_status,
    handle_stop,
};
pub use ipc::handle_worker_connection;
