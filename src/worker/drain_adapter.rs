use std::sync::Arc;

use synvoid_core::drain::DrainState;

use super::drain_state::WorkerDrainState;

#[derive(Clone)]
pub struct WorkerDrainStateAdapter {
    inner: Arc<WorkerDrainState>,
}

impl WorkerDrainStateAdapter {
    pub fn new(inner: Arc<WorkerDrainState>) -> Self {
        Self { inner }
    }
}

impl DrainState for WorkerDrainStateAdapter {
    fn is_draining(&self) -> bool {
        self.inner.is_draining()
    }

    fn should_accept_new_connection(&self) -> bool {
        !self.inner.is_stopped_accepting()
    }
}
