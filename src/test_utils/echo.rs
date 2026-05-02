use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

#[derive(Debug, Clone, Default)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EchoResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub delay_ms: u64,
    pub chunked: bool,
    pub chunk_size: Option<usize>,
}

impl Default for EchoResponse {
    fn default() -> Self {
        EchoResponse {
            status: 200,
            headers: vec![],
            body: b"OK".to_vec(),
            delay_ms: 0,
            chunked: false,
            chunk_size: None,
        }
    }
}

impl EchoResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        EchoResponse {
            status,
            body: body.into(),
            ..Default::default()
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn with_delay(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn with_chunked(mut self, chunk_size: usize) -> Self {
        self.chunked = true;
        self.chunk_size = Some(chunk_size);
        self
    }

    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(status, body).with_header("content-type", "application/json")
    }
}

#[derive(Clone)]
pub struct EchoServerHandle {
    responses: Arc<Mutex<VecDeque<EchoResponse>>>,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    pub addr: SocketAddr,
}

impl EchoServerHandle {
    pub fn push_response(&self, response: EchoResponse) {
        self.responses.lock().unwrap().push_back(response);
    }

    pub fn push_default(&self) {
        self.push_response(EchoResponse::default());
    }

    pub fn take_captured(&self) -> Vec<CapturedRequest> {
        std::mem::take(&mut *self.captured.lock().unwrap())
    }

    pub fn captured_count(&self) -> usize {
        self.captured.lock().unwrap().len()
    }

    pub fn shutdown(&self) {
        if let Some(tx) = self.shutdown.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for EchoServerHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub async fn start_echo_server() -> EchoServerHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let responses: Arc<Mutex<VecDeque<EchoResponse>>> = Arc::new(Mutex::new(VecDeque::new()));
    let captured: Arc<Mutex<Vec<CapturedRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let responses_clone = responses.clone();
    let captured_clone = captured.clone();

    tokio::spawn(async move {
        let mut shutdown = Some(shutdown_rx);

        loop {
            let accept_result = tokio::select! {
                result = listener.accept() => result,
                _ = async { shutdown.take().unwrap().await }, if shutdown.is_some() => break,
            };

            let (mut stream, _) = match accept_result {
                Ok(s) => s,
                Err(_) => continue,
            };

            let responses = responses_clone.clone();
            let captured = captured_clone.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.truncate(n);
                let raw = String::from_utf8_lossy(&buf);

                let captured_req = parse_http_request(&raw);
                captured.lock().unwrap().push(captured_req);

                let response = responses.lock().unwrap().pop_front().unwrap_or_default();

                if response.delay_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(response.delay_ms)).await;
                }

                let resp_bytes = build_http_response(&response);
                let _ = stream.write_all(&resp_bytes).await;
                let _ = stream.flush().await;
            });
        }
    });

    EchoServerHandle {
        responses,
        captured,
        shutdown: Arc::new(Mutex::new(Some(shutdown_tx))),
        addr,
    }
}

fn parse_http_request(raw: &str) -> CapturedRequest {
    let mut lines = raw.lines();
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    let method = parts.first().unwrap_or(&"").to_string();
    let full_uri = parts.get(1).unwrap_or(&"").to_string();

    let (path, query) = if let Some(pos) = full_uri.find('?') {
        (
            full_uri[..pos].to_string(),
            Some(full_uri[pos + 1..].to_string()),
        )
    } else {
        (full_uri.clone(), None)
    };

    let mut headers = Vec::new();
    let mut body_start = 0;
    for (i, line) in raw.lines().enumerate() {
        if i == 0 {
            continue;
        }
        if line.is_empty() {
            body_start = raw.find("\r\n\r\n").map(|p| p + 4).unwrap_or(raw.len());
            break;
        }
        if let Some(colon_pos) = line.find(':') {
            let name = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            headers.push((name, value));
        }
    }

    let body = if body_start < raw.len() {
        raw[body_start..].as_bytes().to_vec()
    } else {
        Vec::new()
    };

    CapturedRequest {
        method,
        path,
        query,
        headers,
        body,
    }
}

fn build_http_response(response: &EchoResponse) -> Vec<u8> {
    let status_text = match response.status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    };

    if response.chunked {
        let mut header_section = format!(
            "HTTP/1.1 {} {}\r\nTransfer-Encoding: chunked\r\n",
            response.status, status_text
        );
        for (name, value) in &response.headers {
            header_section.push_str(&format!("{}: {}\r\n", name, value));
        }
        header_section.push_str("\r\n");

        let mut result = header_section.into_bytes();
        let chunk_size = response.chunk_size.unwrap_or(64);

        for chunk in response.body.chunks(chunk_size) {
            result.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            result.extend_from_slice(chunk);
            result.extend_from_slice(b"\r\n");
        }
        result.extend_from_slice(b"0\r\n\r\n");
        return result;
    }

    let mut header_section = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
        response.status,
        status_text,
        response.body.len()
    );
    for (name, value) in &response.headers {
        header_section.push_str(&format!("{}: {}\r\n", name, value));
    }
    header_section.push_str("\r\n");

    let mut result = header_section.into_bytes();
    result.extend_from_slice(&response.body);
    result
}
