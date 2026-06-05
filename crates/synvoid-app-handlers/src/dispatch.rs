use synvoid_core::routing::RouteTarget;

pub trait AppBackendDispatcher: Send + Sync + 'static {
    type Request;
    type Response;
    type Error: std::error::Error + Send + Sync + 'static;

    fn dispatch(
        &self,
        target: &RouteTarget,
        request: Self::Request,
    ) -> Result<Self::Response, Self::Error>;
}
