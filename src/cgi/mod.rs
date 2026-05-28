use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::Command;

use bytes::Bytes;
use http::{header::HeaderName, HeaderMap, HeaderValue, Method, StatusCode, Uri};

use crate::config::site::CgiConfig;

fn sanitize_cgi_path(path: &str) -> String {
    let mut result = String::new();
    let mut skip_slash = false;

    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            continue;
        }
        if !skip_slash {
            result.push('/');
        }
        result.push_str(component);
        skip_slash = false;
    }

    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &["server", "x-powered-by", "connection", "keep-alive"];

pub struct CgiHandler {
    root: PathBuf,
    index: String,
    pass_variables: bool,
    timeout: u64,
    allowed_extensions: Vec<String>,
}

impl CgiHandler {
    pub fn new(config: &CgiConfig) -> Result<Self, String> {
        let root = config
            .root
            .as_ref()
            .map(PathBuf::from)
            .ok_or("CGI root directory is required")?;

        if !root.exists() || !root.is_dir() {
            return Err(format!(
                "CGI root does not exist or is not a directory: {:?}",
                root
            ));
        }

        let index = config
            .index
            .clone()
            .unwrap_or_else(|| "index.cgi".to_string());
        let pass_variables = config.pass_variables.unwrap_or(true);
        let timeout = config.timeout.unwrap_or(30);

        let allowed_extensions = vec![
            "cgi".to_string(),
            "pl".to_string(),
            "py".to_string(),
            "sh".to_string(),
            "rb".to_string(),
            "php".to_string(),
            "lua".to_string(),
            "exe".to_string(),
        ];

        Ok(CgiHandler {
            root,
            index,
            pass_variables,
            timeout,
            allowed_extensions,
        })
    }

    pub async fn execute(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        client_ip: Option<std::net::IpAddr>,
    ) -> Result<CgiResponse, CgiError> {
        let path = uri.path();

        let script_path = self.resolve_script(path)?;

        let env = self.build_env(method, uri, headers, client_ip);

        self.spawn_script(&script_path, method, headers, body, env)
            .await
    }

    fn resolve_script(&self, path: &str) -> Result<PathBuf, CgiError> {
        let path = path.trim_start_matches('/');

        if path.is_empty() || path.ends_with('/') {
            let index_path = self.root.join(path).join(&self.index);
            if index_path.exists() && index_path.is_file() {
                return self.validate_script_path(&index_path);
            }
        }

        let full_path = self.root.join(path);

        let canonical = std::fs::canonicalize(&full_path)
            .or_else(|_| {
                std::fs::metadata(&full_path).map(|m| {
                    if m.is_symlink() {
                        std::fs::read_link(&full_path)
                            .map(|p| full_path.join(p))
                            .unwrap_or_else(|_| full_path.clone())
                    } else {
                        full_path.clone()
                    }
                })
            })
            .map_err(|_| CgiError::NotFound(format!("Path not found: {}", path)))?;

        if !canonical.starts_with(&self.root) {
            tracing::warn!(
                "CGI path traversal attempt: {} -> {}",
                path,
                canonical.display()
            );
            return Err(CgiError::Forbidden("Path traversal denied".to_string()));
        }

        if canonical.is_dir() {
            let index_path = canonical.join(&self.index);
            if index_path.exists() && index_path.is_file() {
                return self.validate_script_path(&index_path);
            }
            return Err(CgiError::NotFound("Directory index not found".to_string()));
        }

        self.validate_script_path(&canonical)
    }

    fn validate_script_path(&self, path: &PathBuf) -> Result<PathBuf, CgiError> {
        if !path.exists() {
            return Err(CgiError::NotFound(format!("Script not found: {:?}", path)));
        }

        if !path.is_file() {
            return Err(CgiError::Forbidden("Not a file".to_string()));
        }

        if let Some(ext) = path.extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if !self.allowed_extensions.contains(&ext_str) {
                tracing::warn!("CGI script with disallowed extension: {:?}", path);
                return Err(CgiError::Forbidden(
                    "Script extension not allowed".to_string(),
                ));
            }
        } else {
            return Err(CgiError::Forbidden("Script has no extension".to_string()));
        }

        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|e| {
            tracing::warn!("Failed to get CGI script metadata: {}", e);
            CgiError::NotFound(format!("Cannot access script: {}", e))
        })?;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(CgiError::Forbidden("Script not executable".to_string()));
        }

        Ok(path.clone())
    }

    fn build_env(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        client_ip: Option<std::net::IpAddr>,
    ) -> HashMap<String, String> {
        let mut env = HashMap::new();

        env.insert("REQUEST_METHOD".to_string(), method.as_str().to_string());

        let path = uri.path();
        env.insert("SCRIPT_NAME".to_string(), path.to_string());

        let safe_path = sanitize_cgi_path(path);
        let script_filename = self.root.join(safe_path.trim_start_matches('/'));
        env.insert(
            "SCRIPT_FILENAME".to_string(),
            script_filename.to_string_lossy().to_string(),
        );

        let request_uri = if let Some(query) = uri.query() {
            format!("{}?{}", path, query)
        } else {
            path.to_string()
        };
        env.insert("REQUEST_URI".to_string(), request_uri);

        if let Some(query) = uri.query() {
            env.insert("QUERY_STRING".to_string(), query.to_string());
        } else {
            env.insert("QUERY_STRING".to_string(), String::new());
        }

        env.insert("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string());
        env.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        env.insert("SERVER_SOFTWARE".to_string(), "SynVoid".to_string());

        if let Some(addr) = client_ip {
            env.insert("REMOTE_ADDR".to_string(), addr.to_string());
        }

        if let Some(host) = headers.get("host") {
            if let Ok(h) = host.to_str() {
                env.insert("HTTP_HOST".to_string(), h.to_string());
                if let Some(port_pos) = h.find(':') {
                    env.insert("SERVER_NAME".to_string(), h[..port_pos].to_string());
                    if let Ok(port) = h[port_pos + 1..].parse::<u16>() {
                        env.insert("SERVER_PORT".to_string(), port.to_string());
                    }
                } else {
                    env.insert("SERVER_NAME".to_string(), h.to_string());
                    env.insert("SERVER_PORT".to_string(), "80".to_string());
                }
            }
        } else {
            env.insert("SERVER_NAME".to_string(), "localhost".to_string());
            env.insert("SERVER_PORT".to_string(), "80".to_string());
        }

        if let Some(accept) = headers.get("accept") {
            if let Ok(a) = accept.to_str() {
                env.insert("HTTP_ACCEPT".to_string(), a.to_string());
            }
        }

        if let Some(accept_lang) = headers.get("accept-language") {
            if let Ok(lang) = accept_lang.to_str() {
                env.insert("HTTP_ACCEPT_LANGUAGE".to_string(), lang.to_string());
            }
        }

        if let Some(accept_enc) = headers.get("accept-encoding") {
            if let Ok(enc) = accept_enc.to_str() {
                env.insert("HTTP_ACCEPT_ENCODING".to_string(), enc.to_string());
            }
        }

        if let Some(user_agent) = headers.get("user-agent") {
            if let Ok(ua) = user_agent.to_str() {
                env.insert("HTTP_USER_AGENT".to_string(), ua.to_string());
            }
        }

        if let Some(content_type) = headers.get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                env.insert("CONTENT_TYPE".to_string(), ct.to_string());
            }
        }

        if let Some(content_length) = headers.get("content-length") {
            if let Ok(cl) = content_length.to_str() {
                env.insert("CONTENT_LENGTH".to_string(), cl.to_string());
            }
        }

        if let Some(authorization) = headers.get("authorization") {
            if let Ok(auth) = authorization.to_str() {
                env.insert("HTTP_AUTHORIZATION".to_string(), auth.to_string());
            }
        }

        if self.pass_variables {
            env.insert("REDIRECT_STATUS".to_string(), "200".to_string());
        }

        env
    }

    async fn spawn_script(
        &self,
        script_path: &PathBuf,
        method: &Method,
        headers: &HeaderMap,
        body: Bytes,
        env: HashMap<String, String>,
    ) -> Result<CgiResponse, CgiError> {
        let timeout = self.timeout;

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout),
            self.execute_script(script_path, method, headers, body, env),
        )
        .await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                tracing::warn!("CGI script timed out after {}s: {:?}", timeout, script_path);
                Err(CgiError::Timeout)
            }
        }
    }

    async fn execute_script(
        &self,
        script_path: &PathBuf,
        method: &Method,
        _headers: &HeaderMap,
        body: Bytes,
        env: HashMap<String, String>,
    ) -> Result<CgiResponse, CgiError> {
        let mut cmd = Command::new(script_path);

        cmd.env_clear();
        for (key, value) in env {
            cmd.env(key, value);
        }

        if method != Method::GET && method != Method::HEAD {
            cmd.stdin(Stdio::piped());
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| CgiError::ExecutionFailed(e.to_string()))?;

        if !body.is_empty() {
            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                let _ = stdin.write_all(&body).await;
            }
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| CgiError::ExecutionFailed(e.to_string()))?;

        let stdout = output.stdout;
        let stderr = output.stderr;

        if !stderr.is_empty() {
            if let Ok(stderr_str) = String::from_utf8(stderr.clone()) {
                if !stderr_str.trim().is_empty() {
                    tracing::debug!("CGI stderr: {}", stderr_str);
                }
            }
        }

        Self::parse_response(stdout)
    }

    fn parse_response(stdout: Vec<u8>) -> Result<CgiResponse, CgiError> {
        if let Some(pos) = Self::find_header_body_separator(&stdout) {
            let header_bytes = &stdout[..pos];
            let body_bytes = &stdout[pos + 4..];

            let status = Self::parse_status(header_bytes);
            let headers = Self::parse_headers(header_bytes);

            Ok(CgiResponse {
                status,
                headers,
                body: Bytes::from(body_bytes.to_vec()),
            })
        } else {
            Ok(CgiResponse {
                status: StatusCode::OK,
                headers: HashMap::new(),
                body: Bytes::from(stdout),
            })
        }
    }

    fn find_header_body_separator(data: &[u8]) -> Option<usize> {
        data.windows(4).position(|w| w == b"\r\n\r\n")
    }

    fn parse_status(header_bytes: &[u8]) -> StatusCode {
        if let Ok(header_str) = String::from_utf8(header_bytes.to_vec()) {
            for line in header_str.lines() {
                let line_lower = line.to_lowercase();
                if line_lower.starts_with("status:") {
                    let status_str = line_lower.trim_start_matches("status:").trim();
                    if let Some(code) = status_str.split_whitespace().next() {
                        if let Ok(code) = code.parse::<u16>() {
                            return StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
                        }
                    }
                }
            }
        }
        StatusCode::OK
    }

    fn parse_headers(header_bytes: &[u8]) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        if let Ok(header_str) = String::from_utf8(header_bytes.to_vec()) {
            for line in header_str.lines() {
                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim().to_lowercase();
                    let value = line[colon_pos + 1..].trim().to_string();

                    if !name.is_empty() && name != "status" {
                        headers.insert(name, value);
                    }
                }
            }
        }

        headers
    }
}

#[derive(Debug, Clone)]
pub struct CgiResponse {
    pub status: StatusCode,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

impl CgiResponse {
    pub fn into_http_response(self) -> http::Response<Bytes> {
        let mut builder = http::Response::builder().status(self.status);

        for (name, value) in self.headers {
            let name_lower = name.to_lowercase();
            if FORBIDDEN_RESPONSE_HEADERS.contains(&name_lower.as_str()) {
                continue;
            }

            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&value),
            ) {
                builder = builder.header(name, value);
            }
        }

        builder.body(self.body).unwrap_or_else(|_| {
            http::Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Bytes::new())
                .unwrap()
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CgiError {
    #[error("Script not found: {0}")]
    NotFound(String),
    #[error("Access forbidden: {0}")]
    Forbidden(String),
    #[error("Failed to execute script: {0}")]
    ExecutionFailed(String),
    #[error("Script execution timed out")]
    Timeout,
    #[error("Invalid response from script")]
    InvalidResponse,
}
