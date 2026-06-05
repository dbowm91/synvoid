pub trait DrainState: Send + Sync + 'static {
    fn is_draining(&self) -> bool;
    fn should_accept_new_connection(&self) -> bool {
        !self.is_draining()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AlwaysAcceptDrainState;

impl DrainState for AlwaysAcceptDrainState {
    fn is_draining(&self) -> bool {
        false
    }
}
