use thiserror::Error;

#[derive(Debug, Error)]
pub enum SynvoidError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),
}
