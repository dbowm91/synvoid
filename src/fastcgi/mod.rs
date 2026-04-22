pub mod pool;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;
use fastcgi_client::{Client, Params, Request};
use http::{header::HeaderName, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use parking_lot::RwLock;

use crate::config::site::FastCgiConfig;

const FORBIDDEN_RESPONSE_HEADERS: &[&str] = &["server", "x-powered-by", "connection", "keep-alive"];

static FASTCGI_POOL_MANAGER: LazyLock<RwLock<pool::FastCgiPoolManager>> =
    LazyLock::new(|| RwLock::new(pool::FastCgiPoolManager::new()));

pub fn get_pool(socket: &str, config: &FastCgiConfig) -> Arc<pool::FastCgiPool> {
    let manager = FASTCGI_POOL_MANAGER.read();
    manager.get_or_create_pool(socket, config)
}

pub fn remove_pool(socket: &str) {
    let manager = FASTCGI_POOL_MANAGER.read();
    manager.remove_pool(socket);
}

pub fn close_all_pools() {
    let manager = FASTCGI_POOL_MANAGER.read();
    manager.close_all();
}

pub fn get_all_pool_statuses() -> Vec<pool::FastCgiPoolStatus> {
    let manager = FASTCGI_POOL_MANAGER.read();
    manager.get_all_pool_statuses()
}

pub async fn drain_and_reload_pool(socket: &str, timeout: Duration) -> Result<(), String> {
    let pool = {
        let manager = FASTCGI_POOL_MANAGER.read();
        manager
            .get_pool(socket)
            .ok_or_else(|| format!("Pool not found for socket: {}", socket))?
    };
    pool.drain_with_timeout(timeout).await
}

pub struct FastCgiClient {
    socket_path: String,
    is_tcp: bool,
}

impl FastCgiClient {
    pub fn new(socket_path: String) -> Self {
        let (socket, is_tcp) =
            parse_socket_address(&socket_path).unwrap_or((socket_path.clone(), false));
        FastCgiClient {
            socket_path: socket,
            is_tcp,
        }
    }

    pub async fn execute(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponse, FastCgiError> {
        if self.is_tcp {
            self.execute_tcp(method, uri, headers, body, config).await
        } else {
            self.execute_unix(method, uri, headers, body, config).await
        }
    }

    async fn execute_unix(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponse, FastCgiError> {
        let socket = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| FastCgiError::ConnectionFailed(e.to_string()))?;

        let mut client = Client::new_keep_alive(socket);

        let params = self.build_params(method, uri, headers, config);

        let body_vec = body.to_vec();

        let output = client
            .execute(Request::new(params, &mut body_vec.as_slice()))
            .await
            .map_err(|e| FastCgiError::RequestFailed(e.to_string()))?;

        Self::parse_response(output.stdout, output.stderr)
    }

    async fn execute_tcp(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        body: Bytes,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponse, FastCgiError> {
        let socket = tokio::net::TcpStream::connect(&self.socket_path)
            .await
            .map_err(|e| FastCgiError::ConnectionFailed(e.to_string()))?;

        let mut client = Client::new_keep_alive(socket);

        let params = self.build_params(method, uri, headers, config);

        let body_vec = body.to_vec();

        let output = client
            .execute(Request::new(params, &mut body_vec.as_slice()))
            .await
            .map_err(|e| FastCgiError::RequestFailed(e.to_string()))?;

        Self::parse_response(output.stdout, output.stderr)
    }

    fn parse_response(
        stdout: Option<Vec<u8>>,
        stderr: Option<Vec<u8>>,
    ) -> Result<FastCgiResponse, FastCgiError> {
        let stdout = stdout.unwrap_or_default();

        if let Some(stderr) = stderr {
            if !stderr.is_empty() {
                if let Ok(stderr_str) = String::from_utf8(stderr) {
                    tracing::debug!("FastCGI stderr: {}", stderr_str);
                }
            }
        }

        let (status, response_headers, body) =
            if let Some(pos) = Self::find_header_body_separator(&stdout) {
                let header_bytes = &stdout[..pos];
                let body_bytes = &stdout[pos + 4..];

                let status = Self::parse_status(header_bytes);
                let headers = Self::parse_headers(header_bytes);

                (status, headers, Bytes::from(body_bytes.to_vec()))
            } else {
                (StatusCode::OK, HashMap::new(), Bytes::from(stdout))
            };

        Ok(FastCgiResponse {
            status,
            headers: response_headers,
            body,
        })
    }

    fn find_header_body_separator(data: &[u8]) -> Option<usize> {
        (0..data.len().saturating_sub(3)).find(|&i| {
            data[i] == b'\r' && data[i + 1] == b'\n' && data[i + 2] == b'\r' && data[i + 3] == b'\n'
        })
    }

    fn parse_status(header_bytes: &[u8]) -> StatusCode {
        if let Ok(header_str) = String::from_utf8(header_bytes.to_vec()) {
            for line in header_str.lines() {
                if line.to_ascii_lowercase().starts_with("status:") {
                    let status_str = line["status:".len()..].trim();
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
                    let name = line[..colon_pos].trim().to_ascii_lowercase();
                    let value = line[colon_pos + 1..].trim().to_string();

                    if !name.is_empty() && name != "status" {
                        headers.insert(name, value);
                    }
                }
            }
        }

        if headers.is_empty() {
            headers.insert("content-type".to_string(), "text/html".to_string());
        }

        headers
    }

    fn build_params(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
        config: &FastCgiConfig,
    ) -> Params<'static> {
        let path_str = uri.path().to_string();

        let script_filename = config
            .script_filename
            .clone()
            .unwrap_or_else(|| path_str.clone());

        let script_name = config.index.clone().unwrap_or_else(|| path_str.clone());

        let method_str = method.as_str();
        let query_str = uri.query().unwrap_or("");

        let request_uri = if query_str.is_empty() {
            path_str.clone()
        } else {
            format!("{}?{}", path_str, query_str)
        };

        let mut params = Params::default()
            .request_method(Cow::Owned(method_str.to_string()))
            .request_uri(Cow::Owned(request_uri))
            .document_uri(Cow::Owned(path_str.clone()))
            .query_string(Cow::Owned(query_str.to_string()))
            .server_protocol(Cow::Borrowed("HTTP/1.1"))
            .gateway_interface(Cow::Borrowed("CGI/1.1"))
            .script_filename(Cow::Owned(script_filename))
            .script_name(Cow::Owned(script_name));

        if let Some(remote_addr) = headers.get("x-real-ip") {
            if let Ok(addr) = remote_addr.to_str() {
                params = params.remote_addr(Cow::Owned(addr.to_string()));
            }
        }

        if let Some(host) = headers.get("host") {
            if let Ok(h) = host.to_str() {
                params = params.server_name(Cow::Owned(h.to_string()));
            }
        }

        if let Some(content_type) = headers.get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                params = params.content_type(Cow::Owned(ct.to_string()));
            }
        }

        if let Some(content_length) = headers.get("content-length") {
            if let Ok(cl) = content_length.to_str() {
                if let Ok(len) = cl.parse::<usize>() {
                    params = params.content_length(len);
                }
            }
        }

        if let Some(ref extra_params) = config.params {
            for (key, value) in extra_params {
                params.insert(key.clone().into(), value.clone().into());
            }
        }

        if let Some(ref env_vars) = config.env_vars {
            for (key, value) in env_vars {
                params.insert(
                    format!("FCGI_ENV:{}", key).into(),
                    value.clone().into(),
                );
            }
        }

        params
    }
}

#[derive(Debug, Clone)]
pub struct FastCgiResponse {
    pub status: StatusCode,
    pub headers: HashMap<String, String>,
    pub body: Bytes,
}

impl FastCgiResponse {
    pub fn into_http_response(self) -> http::Response<Bytes> {
        let mut builder = http::Response::builder().status(self.status);

        for (name, value) in self.headers {
            let name_lower = name.to_ascii_lowercase();
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

        builder.body(self.body.clone()).unwrap_or_else(|_| http::Response::new(self.body))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FastCgiError {
    #[error("Failed to connect to FastCGI server: {0}")]
    ConnectionFailed(String),
    #[error("FastCGI protocol error: {0}")]
    ProtocolError(String),
    #[error("FastCGI request failed: {0}")]
    RequestFailed(String),
    #[error("No request received")]
    NoRequest,
}

pub fn parse_socket_address(socket: &str) -> Result<(String, bool), String> {
    let socket = socket.trim();

    if socket.starts_with("unix:") || socket.starts_with("unix://") {
        Ok((
            socket
                .trim_start_matches("unix:")
                .trim_start_matches("unix://")
                .to_string(),
            false,
        ))
    } else if socket.starts_with('/') {
        Ok((socket.to_string(), false))
    } else if socket.starts_with("tcp:") || socket.starts_with("tcp://") {
        let addr = socket
            .trim_start_matches("tcp:")
            .trim_start_matches("tcp://")
            .to_string();
        Ok((addr, true))
    } else if socket.starts_with('[') {
        if let Some(bracket_end) = socket.find("]:") {
            let ip = &socket[1..bracket_end];
            let port = &socket[bracket_end + 2..];
            Ok((format!("{}:{}", ip, port), true))
        } else {
            Err(format!("Invalid bracketed IPv6 address: {}", socket))
        }
    } else if socket.contains(':') {
        Ok((socket.to_string(), true))
    } else {
        Err(format!("Invalid socket address: {}", socket))
    }
}
