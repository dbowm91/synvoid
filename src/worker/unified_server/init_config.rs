// Submodule: Config loading, bandwidth-config extraction, and pre-bind port
// checks. These live in `state.rs`; this file is kept for the architecture
// outline and re-exports the relevant helpers.

pub use super::state::{
    extract_bandwidth_config, setup_config, should_skip_prebind_port_check,
    validate_ports_or_skip_for_shared_port,
};
