//! WebDAV support for SynVoid
//!
//! This module implements WebDAV (Web-based Distributed Authoring and Versioning) protocol
//! support using Axum. WebDAV extends HTTP with methods for collaborative file management.
//!
//! Supported methods:
//! - PROPFIND: List properties of a resource (directory listing)
//! - MKCOL: Create a collection (directory)
//! - MOVE: Move a resource
//! - COPY: Copy a resource
//! - GET, PUT, DELETE: Standard HTTP file operations

use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::any,
    Router,
};
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock as TokioRwLock;

use crate::admin::verify_admin_token;
use crate::config::ConfigManager;
use crate::static_files::file_manager::FileManager;

/// WebDAV configuration
#[derive(Debug, Clone)]
pub struct WebDavConfig {
    /// Enable WebDAV support
    pub enabled: bool,
    /// Root path for WebDAV operations
    pub root_path: String,
    /// Require authentication for WebDAV operations
    pub require_auth: bool,
}

impl Default for WebDavConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root_path: String::new(),
            require_auth: true,
        }
    }
}

/// State for WebDAV handler
#[derive(Clone)]
struct WebDavState {
    // SAFETY_REASON: Debugging - stored for introspection
    #[allow(dead_code)]
    config: Arc<TokioRwLock<ConfigManager>>,
    file_manager: Arc<FileManager>,
    admin_token_hash: String,
    webdav_config: WebDavConfig,
}

unsafe impl Send for WebDavState {}
unsafe impl Sync for WebDavState {}

/// Verify authentication from request headers
fn require_auth(state: &WebDavState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if !state.webdav_config.require_auth {
        return Ok(());
    }

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

/// Normalize path to ensure it starts with /
fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    if !path.starts_with('/') {
        return format!("/{}", path);
    }
    path.to_string()
}

/// Extract destination header for MOVE/COPY operations
fn get_destination_header(headers: &HeaderMap) -> Result<String, StatusCode> {
    headers
        .get("Destination")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            tracing::warn!("WebDAV: Missing Destination header");
            StatusCode::BAD_REQUEST
        })
        .map(|s| s.to_string())
}

/// Extract Depth header (default is infinity for WebDAV)
fn get_depth_header(headers: &HeaderMap) -> String {
    headers
        .get("Depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("infinity")
        .to_string()
}

/// Check if Overwrite header is set to T
fn get_overwrite_header(headers: &HeaderMap) -> bool {
    headers
        .get("Overwrite")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("T"))
        .unwrap_or(true)
}

// ============================================================================
// PROPFIND Handler - List directory properties
// ============================================================================

/// Handle PROPFIND requests - list properties of a resource
async fn propfind_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let path = normalize_path(path);
    let depth = get_depth_header(headers);

    tracing::debug!("WebDAV PROPFIND: path={}, depth={}", path, depth);

    // Get directory listing
    let listing = state
        .file_manager
        .list_directory(&path)
        .await
        .map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV PROPFIND list_directory error: {:?}", e);
            status
        })?;

    // Generate WebDAV XML response
    let xml = generate_propfind_response(&path, &listing);

    Ok(Response::builder()
        .status(StatusCode::MULTI_STATUS)
        .header("Content-Type", "application/xml; charset=utf-8")
        .header("DAV", "1, 2")
        .body(axum::body::Body::from(xml))
        .unwrap())
}

/// Generate PROPFIND XML response
fn generate_propfind_response(
    path: &str,
    listing: &crate::static_files::file_manager::DirectoryListing,
) -> String {
    let mut xml = String::new();
    xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    xml.push_str(r#"<D:multistatus xmlns:D="DAV:">"#);

    // Response for the requested resource itself
    xml.push_str(&format!(
        r#"<D:response><D:href>{}</D:href><D:propstat><D:prop>
        <D:displayname>{}</D:displayname>
        <D:getlastmodified>Thu, 01 Jan 1970 00:00:00 GMT</D:getlastmodified>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:supportedlock/>
        </D:prop></D:propstat></D:response>"#,
        escape_xml(path),
        escape_xml(path.trim_end_matches('/'))
    ));

    // Responses for each entry in the directory
    for entry in &listing.entries {
        let href = &entry.path;
        let display_name = &entry.name;
        let is_dir = entry.is_directory;
        let size = entry.size;
        let modified = entry
            .modified
            .map(|t| {
                std::time::UNIX_EPOCH
                    .checked_add(std::time::Duration::from_secs(t))
                    .map(|st| {
                        let datetime: chrono::DateTime<chrono::Utc> = st.into();
                        datetime.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
                    })
                    .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string())
            })
            .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());

        xml.push_str(r#"<D:response><D:href>"#);
        xml.push_str(&escape_xml(href));
        xml.push_str(r#"</D:href><D:propstat><D:prop>"#);
        xml.push_str(&format!(
            r#"<D:displayname>{}</D:displayname>
            <D:getlastmodified>{}</D:getlastmodified>"#,
            escape_xml(display_name),
            modified
        ));

        if is_dir {
            xml.push_str(r#"<D:resourcetype><D:collection/></D:resourcetype>"#);
        } else {
            xml.push_str(&format!(
                r#"<D:resourcetype><D:file/></D:resourcetype>
            <D:getcontentlength>{}</D:getcontentlength>"#,
                size
            ));
        }

        xml.push_str(
            r#"<D:supportedlock/>
        </D:prop></D:propstat></D:response>"#,
        );
    }

    xml.push_str(r#"</D:multistatus>"#);
    xml
}

/// Escape special XML characters
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ============================================================================
// MKCOL Handler - Create collection (directory)
// ============================================================================

/// Handle MKCOL requests - create a new collection (directory)
async fn mkcol_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let path = normalize_path(path);

    tracing::debug!("WebDAV MKCOL: path={}", path);

    // MKCOL does not accept a request body
    if !body.is_empty() {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    // Check if path already exists
    let listing = state.file_manager.list_directory(&path).await;
    if listing.is_ok() {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }

    // Try to read file at path - if it succeeds, path exists as a file
    if state.file_manager.read_file(&path).await.is_ok() {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }

    // Create the directory
    state
        .file_manager
        .create_directory(&path)
        .await
        .map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV MKCOL create_directory error: {:?}", e);
            status
        })?;

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header("Location", path.as_str())
        .body(axum::body::Body::empty())
        .unwrap())
}

// ============================================================================
// MOVE Handler - Move/rename a resource
// ============================================================================

/// Handle MOVE requests - move a resource to a new location
async fn move_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let source = normalize_path(path);
    let destination = get_destination_header(headers)?;
    let overwrite = get_overwrite_header(headers);

    tracing::debug!(
        "WebDAV MOVE: {} -> {} (overwrite={})",
        source,
        destination,
        overwrite
    );

    // Parse destination to get just the path
    let dest_path = if destination.starts_with("http://") || destination.starts_with("https://") {
        // Full URL - extract path
        url::Url::parse(&destination)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| destination.clone())
    } else {
        destination.clone()
    };

    let dest_path = normalize_path(&dest_path);

    // Check if destination exists
    let dest_exists = state.file_manager.list_directory(&dest_path).await.is_ok()
        || state.file_manager.read_file(&dest_path).await.is_ok();

    if dest_exists && !overwrite {
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    // Delete destination if it exists and overwrite is true
    if dest_exists && overwrite {
        state.file_manager.delete(&dest_path).await.map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV MOVE delete error: {:?}", e);
            status
        })?;
    }

    // Perform the rename/move
    state
        .file_manager
        .rename(&source, &dest_path)
        .await
        .map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV MOVE rename error: {:?}", e);
            status
        })?;

    if dest_exists && overwrite {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", dest_path.as_str())
            .body(axum::body::Body::empty())
            .unwrap())
    }
}

// ============================================================================
// COPY Handler - Copy a resource
// ============================================================================

/// Handle COPY requests - copy a resource to a new location
async fn copy_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let source = normalize_path(path);
    let destination = get_destination_header(headers)?;
    let overwrite = get_overwrite_header(headers);

    tracing::debug!(
        "WebDAV COPY: {} -> {} (overwrite={})",
        source,
        destination,
        overwrite
    );

    // Parse destination to get just the path
    let dest_path = if destination.starts_with("http://") || destination.starts_with("https://") {
        url::Url::parse(&destination)
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| destination.clone())
    } else {
        destination.clone()
    };

    let dest_path = normalize_path(&dest_path);

    // Check if source exists
    let source_is_dir = state.file_manager.list_directory(&source).await.is_ok();
    let source_is_file = state.file_manager.read_file(&source).await.is_ok();

    if !source_is_dir && !source_is_file {
        return Err(StatusCode::NOT_FOUND);
    }

    // Check if destination exists
    let dest_exists = state.file_manager.list_directory(&dest_path).await.is_ok()
        || state.file_manager.read_file(&dest_path).await.is_ok();

    if dest_exists && !overwrite {
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    // Delete destination if it exists and overwrite is true
    if dest_exists && overwrite {
        state.file_manager.delete(&dest_path).await.map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV COPY delete error: {:?}", e);
            status
        })?;
    }

    if source_is_dir {
        // Copy directory recursively using a stack-based approach
        copy_directory_recursive(state, &source, &dest_path).await?;
    } else {
        // Copy file
        let data = state.file_manager.read_file(&source).await.map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV COPY read_file error: {:?}", e);
            status
        })?;

        state
            .file_manager
            .write_file(&dest_path, data)
            .await
            .map_err(|e| {
                let status = StatusCode::from_u16(e.status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                tracing::warn!("WebDAV COPY write_file error: {:?}", e);
                status
            })?;
    }

    if dest_exists && overwrite {
        Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::CREATED)
            .header("Location", dest_path.as_str())
            .body(axum::body::Body::empty())
            .unwrap())
    }
}

/// Recursively copy a directory using a stack-based approach
async fn copy_directory_recursive(
    state: &WebDavState,
    source: &str,
    dest: &str,
) -> Result<(), StatusCode> {
    // Use a stack for iterative traversal instead of recursion
    let mut stack: Vec<(String, String)> = vec![(source.to_string(), dest.to_string())];

    while let Some((src_path, dest_path)) = stack.pop() {
        // Create destination directory
        state
            .file_manager
            .create_directory(&dest_path)
            .await
            .map_err(|e| {
                let status = StatusCode::from_u16(e.status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                tracing::warn!("WebDAV COPY create_directory error: {:?}", e);
                status
            })?;

        // List source directory
        let listing = state
            .file_manager
            .list_directory(&src_path)
            .await
            .map_err(|e| {
                let status = StatusCode::from_u16(e.status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                tracing::warn!("WebDAV COPY list_directory error: {:?}", e);
                status
            })?;

        // Add subdirectories and files to the stack
        for entry in listing.entries {
            let new_src_path = entry.path.clone();
            let new_dest_path = if dest_path.ends_with('/') {
                format!("{}{}", dest_path, entry.name)
            } else {
                format!("{}/{}", dest_path, entry.name)
            };

            if entry.is_directory {
                // Add directory to stack to process later
                stack.push((new_src_path, new_dest_path));
            } else {
                // Copy file directly
                let data = state
                    .file_manager
                    .read_file(&new_src_path)
                    .await
                    .map_err(|e| {
                        let status = StatusCode::from_u16(e.status_code())
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                        tracing::warn!("WebDAV COPY read_file error: {:?}", e);
                        status
                    })?;

                state
                    .file_manager
                    .write_file(&new_dest_path, data)
                    .await
                    .map_err(|e| {
                        let status = StatusCode::from_u16(e.status_code())
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                        tracing::warn!("WebDAV COPY write_file error: {:?}", e);
                        status
                    })?;
            }
        }
    }

    Ok(())
}

// ============================================================================
// Standard HTTP Handlers (GET, PUT, DELETE)
// ============================================================================

/// Handle GET requests - retrieve a file
async fn get_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let path = normalize_path(path);

    tracing::debug!("WebDAV GET: path={}", path);

    // Check if it's a directory
    if state.file_manager.list_directory(&path).await.is_ok() {
        // Return PROPFIND-like response for directories
        let listing = state
            .file_manager
            .list_directory(&path)
            .await
            .map_err(|e| {
                let status = StatusCode::from_u16(e.status_code())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                tracing::warn!("WebDAV GET list_directory error: {:?}", e);
                status
            })?;

        let xml = generate_propfind_response(&path, &listing);
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(axum::body::Body::from(xml))
            .unwrap());
    }

    // It's a file
    let data = state.file_manager.read_file(&path).await.map_err(|e| {
        let status =
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        tracing::warn!("WebDAV GET read_file error: {:?}", e);
        status
    })?;

    let ext = Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");

    let mime = crate::mime::MIME_REGISTRY
        .read()
        .get_mime_for_extension(ext)
        .unwrap_or_else(|| "application/octet-stream".to_string());

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime.as_str())
        .body(axum::body::Body::from(data))
        .unwrap())
}

/// Handle PUT requests - create or update a file
async fn put_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let path = normalize_path(path);

    tracing::debug!("WebDAV PUT: path={}, size={}", path, body.len());

    // Check if it's a directory
    if state.file_manager.list_directory(&path).await.is_ok() {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }

    state
        .file_manager
        .write_file(&path, body.to_vec())
        .await
        .map_err(|e| {
            let status =
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            tracing::warn!("WebDAV PUT write_file error: {:?}", e);
            status
        })?;

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(axum::body::Body::empty())
        .unwrap())
}

/// Handle DELETE requests - delete a file or directory
async fn delete_handler(
    state: &WebDavState,
    path: &str,
    headers: &HeaderMap,
) -> Result<Response, StatusCode> {
    require_auth(state, headers)?;

    let path = normalize_path(path);

    tracing::debug!("WebDAV DELETE: path={}", path);

    state.file_manager.delete(&path).await.map_err(|e| {
        let status =
            StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        tracing::warn!("WebDAV DELETE error: {:?}", e);
        status
    })?;

    Ok(Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(axum::body::Body::empty())
        .unwrap())
}

/// Handle OPTIONS requests - return WebDAV support information
async fn options_handler(_state: &WebDavState) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header("DAV", "1, 2")
        .header(
            "Allow",
            "OPTIONS, GET, HEAD, POST, PUT, DELETE, MOVE, COPY, PROPFIND, MKCOL, PROPPATCH",
        )
        .header("MS-Author-Via", "DAV")
        .body(axum::body::Body::empty())
        .unwrap()
}

// ============================================================================
// Router Creation
// ============================================================================

// SAFETY_REASON: Future use - WebDAV router creation
#[allow(dead_code)]
pub fn create_webdav_router(
    config: Arc<TokioRwLock<ConfigManager>>,
    file_manager: Arc<FileManager>,
    admin_token_hash: String,
    webdav_config: WebDavConfig,
) -> Router {
    let state = WebDavState {
        config,
        file_manager,
        admin_token_hash,
        webdav_config,
    };

    Router::new()
        // Use any() to catch all methods and dispatch in the handler
        .route("/", any(webdav_handler))
        .route("/*path", any(webdav_handler))
        .with_state(Arc::new(state))
}

/// Combined WebDAV handler that dispatches based on HTTP method
async fn webdav_handler(
    State(state): State<Arc<WebDavState>>,
    AxumPath(path): AxumPath<String>,
    headers: HeaderMap,
    req: axum::extract::Request,
) -> Result<Response, StatusCode> {
    let method = req.method().clone();
    let state = state.as_ref();

    // Dispatch based on method
    match method.as_str() {
        "GET" | "HEAD" => get_handler(state, &path, &headers).await,
        "PUT" => {
            let body = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            put_handler(state, &path, &headers, body).await
        }
        "DELETE" => delete_handler(state, &path, &headers).await,
        "OPTIONS" => Ok(options_handler(state).await),
        "PROPFIND" => propfind_handler(state, &path, &headers).await,
        "MKCOL" => {
            let body = axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024)
                .await
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            mkcol_handler(state, &path, &headers, body).await
        }
        "MOVE" => move_handler(state, &path, &headers).await,
        "COPY" => copy_handler(state, &path, &headers).await,
        _ => {
            tracing::warn!("WebDAV: Unsupported method: {:?}", method);
            Err(StatusCode::METHOD_NOT_ALLOWED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/foo"), "/foo");
        assert_eq!(normalize_path("foo"), "/foo");
        assert_eq!(normalize_path("/foo/"), "/foo/");
    }

    #[test]
    fn test_escape_xml() {
        assert_eq!(escape_xml("hello"), "hello");
        assert_eq!(escape_xml("a & b"), "a &amp; b");
        assert_eq!(escape_xml("<tag>"), "&lt;tag&gt;");
        assert_eq!(escape_xml("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_webdav_config_default() {
        let config = WebDavConfig::default();
        assert!(!config.enabled);
        assert!(config.require_auth);
        assert_eq!(config.root_path, "");
    }
}
