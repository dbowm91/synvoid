use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock as TokioRwLock;

use crate::admin::verify_admin_token;
use crate::config::ConfigManager;
use crate::static_files::file_manager::FileManager;

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct FileManagerQuery {
    pub path: Option<String>,
    pub recursive: Option<bool>,
    pub query: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateDirectoryRequest {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RenameRequest {
    pub old_path: String,
    pub new_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SetPermissionsRequest {
    pub path: String,
    pub mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExtractArchiveRequest {
    pub archive_path: String,
    pub dest_path: String,
}

#[derive(Clone)]
struct FileManagerState {
    config: Arc<TokioRwLock<ConfigManager>>,
    file_manager: Arc<FileManager>,
    admin_token_hash: String,
}

unsafe impl Send for FileManagerState {}
unsafe impl Sync for FileManagerState {}

fn get_admin_auth(req: &axum::extract::Request) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .map(|t| t.to_string())
}

fn require_auth(state: &FileManagerState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !verify_admin_token(token, &state.admin_token_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(())
}

async fn list_handler(
    State(state): State<Arc<FileManagerState>>,
    Query(params): Query<FileManagerQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = params.path.unwrap_or_else(|| "/".to_string());

    let result = state
        .file_manager
        .list_directory(&path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(result)))
}

async fn read_handler(
    State(state): State<Arc<FileManagerState>>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = format!("/{}", path);
    let data = state.file_manager.read_file(&path).await.map_err(|e| {
        http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
    })?;

    let ext = std::path::Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");

    let mime = crate::mime::MIME_REGISTRY
        .read()
        .get_mime_for_extension(ext)
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok((StatusCode::OK, [("Content-Type", mime)], data))
}

async fn write_handler(
    State(state): State<Arc<FileManagerState>>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = format!("/{}", path);

    state
        .file_manager
        .write_file(&path, body.to_vec())
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({ "path": path }),
    )))
}

async fn delete_handler(
    State(state): State<Arc<FileManagerState>>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = format!("/{}", path);

    state.file_manager.delete(&path).await.map_err(|e| {
        http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
    })?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({ "deleted": path }),
    )))
}

async fn mkdir_handler(
    State(state): State<Arc<FileManagerState>>,
    Json(payload): Json<CreateDirectoryRequest>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    state
        .file_manager
        .create_directory(&payload.path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({ "created": payload.path }),
    )))
}

async fn rename_handler(
    State(state): State<Arc<FileManagerState>>,
    Json(payload): Json<RenameRequest>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    state
        .file_manager
        .rename(&payload.old_path, &payload.new_path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "old_path": payload.old_path,
        "new_path": payload.new_path
    }))))
}

async fn get_permissions_handler(
    State(state): State<Arc<FileManagerState>>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let path = format!("/{}", path);

    let permissions = state
        .file_manager
        .get_permissions(&path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(permissions)))
}

async fn set_permissions_handler(
    State(state): State<Arc<FileManagerState>>,
    Json(payload): Json<SetPermissionsRequest>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    state
        .file_manager
        .set_permissions(&payload.path, payload.mode)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(
        serde_json::json!({ "path": payload.path, "mode": payload.mode }),
    )))
}

async fn search_handler(
    State(state): State<Arc<FileManagerState>>,
    Query(params): Query<FileManagerQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let query = params.query.ok_or(StatusCode::BAD_REQUEST)?;
    let path = params.path.unwrap_or_else(|| "/".to_string());

    let result = state
        .file_manager
        .search(&query, &path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(result)))
}

async fn upload_handler(
    State(state): State<Arc<FileManagerState>>,
    Query(params): Query<FileManagerQuery>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let filename = headers
        .get("X-Filename")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let dest_path = params.path.unwrap_or_else(|| "/".to_string());

    let entry = state
        .file_manager
        .upload_file(&dest_path, filename, body.to_vec())
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(entry)))
}

async fn extract_handler(
    State(state): State<Arc<FileManagerState>>,
    Json(payload): Json<ExtractArchiveRequest>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    require_auth(&state, &headers)?;

    let extracted = state
        .file_manager
        .extract_archive(&payload.archive_path, &payload.dest_path)
        .await
        .map_err(|e| {
            http::StatusCode::from_u16(e.status_code()).expect("valid HTTP status code")
        })?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "extracted": extracted.len(),
        "files": extracted
    }))))
}

pub fn create_file_manager_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    file_manager: Arc<FileManager>,
    admin_token_hash: String,
) -> Router {
    let state = FileManagerState {
        config,
        file_manager,
        admin_token_hash,
    };

    Router::new()
        .route("/list", get(list_handler))
        .route("/read/*path", get(read_handler))
        .route("/write/*path", put(write_handler))
        .route("/delete/*path", delete(delete_handler))
        // TODO: Re-enable once axum version conflict is resolved
        // .route("/mkdir", post(mkdir_handler))
        // .route("/rename", post(rename_handler))
        // .route("/permissions/*path", get(get_permissions_handler))
        // .route("/permissions", put(set_permissions_handler))
        .route("/search", get(search_handler))
        .route("/upload", post(upload_handler))
        // TODO: Re-enable once axum version conflict is resolved
        // .route("/extract", post(extract_handler))
        .with_state(Arc::new(state))
}

pub async fn file_manager_handler(
    req: axum::extract::Request,
) -> Result<impl IntoResponse, StatusCode> {
    let _path = req.uri().path().to_string();

    Err::<(), _>(StatusCode::NOT_FOUND)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_files::file_manager::FileManagerConfig;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_file_manager_creation() {
        let config = FileManagerConfig {
            enabled: true,
            root_path: PathBuf::from("/tmp"),
            max_file_size: 1024 * 1024,
            blocked_extensions: vec!["exe".to_string()],
            allowed_extensions: vec![],
            allow_hidden_files: false,
            allow_symlinks: false,
        };

        let fm = FileManager::new(config);
        assert!(fm.config().enabled);
    }
}
