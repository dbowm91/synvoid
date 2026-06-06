use bytes::Bytes;
use http::{HeaderMap, Method, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;

use crate::spin::runtime::SpinRuntime;

#[derive(Debug, Clone)]
pub struct SpinRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    pub env: HashMap<String, String>,
}

impl SpinRequest {
    pub fn new(method: Method, path: String) -> Self {
        Self {
            method,
            path,
            headers: HeaderMap::new(),
            body: None,
            env: HashMap::new(),
        }
    }

    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }

    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    pub fn method_str(&self) -> &str {
        self.method.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct SpinResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl SpinResponse {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        }
    }

    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = body;
        self
    }

    pub fn with_header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: TryInto<http::header::HeaderName>,
        V: TryInto<http::header::HeaderValue>,
    {
        if let (Ok(key), Ok(value)) = (key.try_into(), value.try_into()) {
            self.headers.insert(key, value);
        }
        self
    }

    pub fn to_response(self) -> Response<Bytes> {
        Response::builder()
            .status(self.status)
            .body(self.body)
            .unwrap_or_else(|_| Response::builder().status(500).body(Bytes::new()).unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct SpinHandlerConfig {
    pub app_name: String,
    pub manifest_path: std::path::PathBuf,
    pub timeout_seconds: u64,
    pub max_instances: usize,
}

impl Default for SpinHandlerConfig {
    fn default() -> Self {
        Self {
            app_name: String::new(),
            manifest_path: std::path::PathBuf::new(),
            timeout_seconds: 30,
            max_instances: 10,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SpinHandlerError {
    #[error("Invalid method: {0}")]
    InvalidMethod(String),
    #[error("Handler error: {0}")]
    HandlerError(String),
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

pub struct SpinHttpHandler {
    runtime: Arc<SpinRuntime>,
}

impl SpinHttpHandler {
    pub fn new(runtime: Arc<SpinRuntime>) -> Self {
        Self { runtime }
    }

    pub async fn handle_request(
        &self,
        request: SpinRequest,
    ) -> Result<SpinResponse, SpinHandlerError> {
        let method = request.method_str().to_string();
        let path = request.path.clone();
        let headers = request.headers.clone();
        let body = request.body.clone();
        let env = request.env.clone();

        tracing::debug!("Spin HTTP handler processing {} {}", method, path);

        let response = self
            .runtime
            .handle_http_request(&method, &path, &headers, body, env)
            .map_err(|e| SpinHandlerError::RuntimeError(e.to_string()))?;

        let (parts, body) = response.into_parts();
        Ok(SpinResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    pub fn handle_request_sync(
        &self,
        request: SpinRequest,
    ) -> Result<SpinResponse, SpinHandlerError> {
        let method = request.method_str().to_string();
        let path = request.path.clone();
        let headers = request.headers.clone();
        let body = request.body.clone();
        let env = request.env.clone();

        tracing::debug!("Spin HTTP handler processing {} {}", method, path);

        let response = self
            .runtime
            .handle_http_request(&method, &path, &headers, body, env)
            .map_err(|e| SpinHandlerError::RuntimeError(e.to_string()))?;

        let (parts, body) = response.into_parts();
        Ok(SpinResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

pub struct SpinAppsManager {
    apps: std::sync::Arc<parking_lot::RwLock<std::collections::HashMap<String, Arc<SpinRuntime>>>>,
}

impl SpinAppsManager {
    pub fn new() -> Self {
        Self {
            apps: std::sync::Arc::new(parking_lot::RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn register(&self, name: &str, runtime: Arc<SpinRuntime>) -> Result<(), SpinHandlerError> {
        let mut apps = self.apps.write();
        if apps.contains_key(name) {
            return Err(SpinHandlerError::HandlerError(format!(
                "Spin app '{}' already registered",
                name
            )));
        }
        apps.insert(name.to_string(), runtime);
        tracing::info!("Registered Spin app '{}'", name);
        Ok(())
    }

    pub fn unregister(&self, name: &str) -> bool {
        let mut apps = self.apps.write();
        if let Some(runtime) = apps.remove(name) {
            runtime.shutdown();
            tracing::info!("Unregistered Spin app '{}'", name);
            true
        } else {
            false
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<SpinRuntime>> {
        self.apps.read().get(name).cloned()
    }

    pub fn list_apps(&self) -> Vec<String> {
        self.apps.read().keys().cloned().collect()
    }

    pub fn shutdown_all(&self) {
        let apps: std::collections::HashMap<String, Arc<SpinRuntime>> =
            std::mem::take(&mut *self.apps.write());
        for (_, runtime) in apps {
            runtime.shutdown();
        }
        tracing::info!("All Spin apps shutdown");
    }
}

impl Default for SpinAppsManager {
    fn default() -> Self {
        Self::new()
    }
}

static SPIN_APPS_MANAGER: std::sync::LazyLock<std::sync::Arc<SpinAppsManager>> =
    std::sync::LazyLock::new(|| std::sync::Arc::new(SpinAppsManager::new()));

pub fn get_global_spin_apps_manager() -> Arc<SpinAppsManager> {
    SPIN_APPS_MANAGER.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spin_request_new() {
        let request = SpinRequest::new(Method::GET, "/hello".to_string());
        assert_eq!(request.method_str(), "GET");
        assert_eq!(request.path, "/hello");
    }

    #[test]
    fn test_spin_response_new() {
        let response = SpinResponse::new(StatusCode::OK);
        assert_eq!(response.status, StatusCode::OK);
    }

    #[test]
    fn test_spin_apps_manager() {
        let manager = SpinAppsManager::new();
        assert!(manager.list_apps().is_empty());
    }
}
