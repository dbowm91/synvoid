use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::config::site::FastCgiConfig;
use crate::fastcgi::FastCgiError;

const FCGI_VERSION: u8 = 1;
const FCGI_HEADER_SIZE: usize = 8;

const FCGI_BEGIN_REQUEST: u8 = 1;
const FCGI_ABORT_REQUEST: u8 = 2;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;
const FCGI_STDERR: u8 = 7;
const FCGI_DATA: u8 = 8;
const FCGI_GET_VALUES: u8 = 9;
const FCGI_GET_VALUES_RESULT: u8 = 10;
const FCGI_UNKOWN_TYPE: u8 = 11;

const FCGI_REQUEST_COMPLETE: u8 = 0;
const FCGI_CANT_MULTIPLEX: u8 = 1;
const FCGI_OVERLOADED: u8 = 2;
const FCGI_UNKNOWN_ROLE: u8 = 3;

pub struct FastCgiRecord {
    pub version: u8,
    pub record_type: u8,
    pub request_id: u16,
    pub content: BytesMut,
}

pub struct FastCgiHeader {
    pub version: u8,
    pub record_type: u8,
    pub request_id: u16,
    pub content_length: u16,
    pub padding_length: u8,
}

impl FastCgiHeader {
    pub fn parse(buf: &[u8; FCGI_HEADER_SIZE]) -> Option<Self> {
        if buf[0] != FCGI_VERSION {
            return None;
        }
        Some(FastCgiHeader {
            version: buf[0],
            record_type: buf[1],
            request_id: u16::from_be_bytes([buf[2], buf[3]]),
            content_length: u16::from_be_bytes([buf[4], buf[5]]),
            padding_length: buf[6],
        })
    }

    pub fn total_length(&self) -> usize {
        FCGI_HEADER_SIZE + self.content_length as usize + self.padding_length as usize
    }
}

#[derive(Clone)]
pub struct FastCgiResponseStream {
    chunks: Vec<Bytes>,
    position: usize,
    status: Option<u16>,
    headers: std::collections::HashMap<String, String>,
}

impl FastCgiResponseStream {
    pub fn new() -> Self {
        FastCgiResponseStream {
            chunks: Vec::new(),
            position: 0,
            status: None,
            headers: std::collections::HashMap::new(),
        }
    }

    pub fn with_body_chunks(chunks: Vec<Bytes>) -> Self {
        FastCgiResponseStream {
            chunks,
            position: 0,
            status: Some(200),
            headers: std::collections::HashMap::new(),
        }
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn headers(&self) -> &std::collections::HashMap<String, String> {
        &self.headers
    }

    pub fn into_chunks(self) -> Vec<Bytes> {
        self.chunks
    }

    pub fn add_chunk(&mut self, chunk: Bytes) {
        self.chunks.push(chunk);
    }

    pub fn set_status(&mut self, status: u16) {
        self.status = Some(status);
    }

    pub fn set_headers(&mut self, headers: std::collections::HashMap<String, String>) {
        self.headers = headers;
    }
}

impl Default for FastCgiResponseStream {
    fn default() -> Self {
        Self::new()
    }
}

impl futures::Stream for FastCgiResponseStream {
    type Item = Result<Bytes, FastCgiError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.position < self.chunks.len() {
            let chunk = self.chunks[self.position].clone();
            self.position += 1;
            Poll::Ready(Some(Ok(chunk)))
        } else {
            Poll::Ready(None)
        }
    }
}

pub trait StreamingBody: Send + Sync {
    fn poll_next_chunk(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, std::io::Error>>>;
}

pub struct BytesStream {
    chunks: Vec<Bytes>,
    position: usize,
}

impl BytesStream {
    pub fn new(chunks: Vec<Bytes>) -> Self {
        BytesStream {
            chunks,
            position: 0,
        }
    }
}

impl StreamingBody for BytesStream {
    fn poll_next_chunk(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, std::io::Error>>> {
        if self.position < self.chunks.len() {
            let chunk = self.chunks[self.position].clone();
            self.position += 1;
            Poll::Ready(Some(Ok(chunk)))
        } else {
            Poll::Ready(None)
        }
    }
}

pub struct StreamingFastCgiClient {
    socket_path: String,
    is_tcp: bool,
}

impl StreamingFastCgiClient {
    pub fn new(socket_path: String) -> Self {
        let (socket, is_tcp) = crate::fastcgi::parse_socket_address(&socket_path)
            .unwrap_or((socket_path.clone(), false));
        StreamingFastCgiClient {
            socket_path: socket,
            is_tcp,
        }
    }

    pub async fn execute_stream<S>(
        &self,
        params: std::collections::HashMap<String, String>,
        body_stream: S,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponseStream, FastCgiError>
    where
        S: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        if self.is_tcp {
            self.execute_stream_tcp(params, body_stream, config).await
        } else {
            self.execute_stream_unix(params, body_stream, config).await
        }
    }

    async fn execute_stream_unix<S>(
        &self,
        params: std::collections::HashMap<String, String>,
        mut body_stream: S,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponseStream, FastCgiError>
    where
        S: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        let socket = tokio::net::UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| FastCgiError::ConnectionFailed(e.to_string()))?;

        self.do_execute_stream(socket, params, &mut body_stream, config)
            .await
    }

    async fn execute_stream_tcp<S>(
        &self,
        params: std::collections::HashMap<String, String>,
        mut body_stream: S,
        config: &FastCgiConfig,
    ) -> Result<FastCgiResponseStream, FastCgiError>
    where
        S: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        let socket = tokio::net::TcpStream::connect(&self.socket_path)
            .await
            .map_err(|e| FastCgiError::ConnectionFailed(e.to_string()))?;

        self.do_execute_stream(socket, params, &mut body_stream, config)
            .await
    }

    async fn do_execute_stream<S>(
        &self,
        mut socket: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        params: std::collections::HashMap<String, String>,
        body_stream: &mut S,
        _config: &FastCgiConfig,
    ) -> Result<FastCgiResponseStream, FastCgiError>
    where
        S: tokio::io::AsyncRead + Send + Unpin + 'static,
    {
        let request_id: u16 = 1;

        let begin_request = Self::build_begin_request(request_id, false);
        Self::write_record(&mut socket, FCGI_BEGIN_REQUEST, request_id, &begin_request).await?;

        let params_record = Self::build_params_record(&params);
        Self::write_record(&mut socket, FCGI_PARAMS, request_id, &params_record).await?;

        let empty_params = Self::build_empty_params_record();
        Self::write_record(&mut socket, FCGI_PARAMS, request_id, &empty_params).await?;

        let mut body_buf = [0u8; 8192];
        loop {
            match body_stream.read(&mut body_buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &body_buf[..n];
                    Self::write_record(&mut socket, FCGI_STDIN, request_id, chunk).await?;
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    return Err(FastCgiError::RequestFailed(e.to_string()));
                }
            }
        }

        let empty_stdin = Self::build_empty_stdin_record();
        Self::write_record(&mut socket, FCGI_STDIN, request_id, &empty_stdin).await?;

        let mut response_chunks: Vec<Bytes> = Vec::new();
        let mut reader = FastCgiRecordReader::new();

        loop {
            let record = match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                reader.read_record(&mut socket),
            )
            .await
            {
                Ok(Ok(record)) => record,
                Ok(Err(e)) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        continue;
                    }
                    tracing::debug!("FastCGI stream complete: {}", e);
                    break;
                }
                Err(_) => {
                    tracing::debug!("FastCGI stream timeout");
                    break;
                }
            };

            match record.record_type {
                FCGI_STDOUT | FCGI_STDERR => {
                    if record.record_type == FCGI_STDOUT {
                        if !record.content.is_empty() {
                            response_chunks.push(record.content.freeze());
                        } else {
                            break;
                        }
                    } else if !record.content.is_empty() {
                        if let Ok(s) = String::from_utf8(record.content.to_vec()) {
                            tracing::debug!("FastCGI stderr: {}", s);
                        }
                    }
                }
                FCGI_END_REQUEST => {
                    let _app_status = u32::from_be_bytes([
                        record.content[0],
                        record.content[1],
                        record.content[2],
                        record.content[3],
                    ]);
                    let _protocol_status = record.content[4];

                    tracing::debug!("FastCGI request complete");
                    break;
                }
                _ => {}
            }
        }

        Ok(FastCgiResponseStream::with_body_chunks(response_chunks))
    }

    async fn write_record<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        socket: &mut T,
        record_type: u8,
        request_id: u16,
        content: &[u8],
    ) -> Result<(), FastCgiError> {
        let content_len = content.len() as u16;
        let padding_len = if content_len as usize % 8 != 0 {
            (8 - content_len as usize % 8) as u8
        } else {
            0
        };

        let mut header = [0u8; FCGI_HEADER_SIZE];
        header[0] = FCGI_VERSION;
        header[1] = record_type;
        header[2] = (request_id >> 8) as u8;
        header[3] = (request_id & 0xFF) as u8;
        header[4] = (content_len >> 8) as u8;
        header[5] = (content_len & 0xFF) as u8;
        header[6] = padding_len;
        header[7] = 0;

        socket.write_all(&header).await.map_err(|e| {
            FastCgiError::RequestFailed(format!("Failed to write FCGI header: {}", e))
        })?;

        socket.write_all(content).await.map_err(|e| {
            FastCgiError::RequestFailed(format!("Failed to write FCGI content: {}", e))
        })?;

        if padding_len > 0 {
            socket
                .write_all(&vec![0u8; padding_len as usize])
                .await
                .map_err(|e| {
                    FastCgiError::RequestFailed(format!("Failed to write FCGI padding: {}", e))
                })?;
        }

        Ok(())
    }

    fn build_begin_request(request_id: u16, keep_alive: bool) -> Vec<u8> {
        let mut data = vec![0u8; 8];
        data[0] = 0;
        data[1] = if keep_alive { 1 } else { 0 };
        data[2] = 0;
        data[3] = 0;
        data[4..8].fill(0);
        data
    }

    fn build_params_record(params: &std::collections::HashMap<String, String>) -> Vec<u8> {
        let mut encoded = Vec::new();

        let mut add_name_value = |name: &str, value: &str| {
            let name_len = if name.len() < 128 {
                encode_varint(name.len() as u64)
            } else {
                let mut encoded_len = encode_varint((name.len() as u64) | 0x80000000);
                encoded_len.extend_from_slice(&name.len().to_be_bytes());
                encoded_len
            };

            let value_len = if value.len() < 128 {
                encode_varint(value.len() as u64)
            } else {
                let mut encoded_len = encode_varint((value.len() as u64) | 0x80000000);
                encoded_len.extend_from_slice(&value.len().to_be_bytes());
                encoded_len
            };

            encoded.extend(name_len);
            encoded.extend(value_len);
            encoded.extend_from_slice(name.as_bytes());
            encoded.extend_from_slice(value.as_bytes());
        };

        for (name, value) in params {
            add_name_value(name, value);
        }

        encoded
    }

    fn build_empty_params_record() -> Vec<u8> {
        vec![0u8]
    }

    fn build_empty_stdin_record() -> Vec<u8> {
        vec![0u8]
    }

    pub fn build_params_from_request(
        &self,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        config: &FastCgiConfig,
    ) -> std::collections::HashMap<String, String> {
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

        let mut params = std::collections::HashMap::new();
        params.insert("REQUEST_METHOD".to_string(), method_str.to_string());
        params.insert("REQUEST_URI".to_string(), request_uri);
        params.insert("DOCUMENT_URI".to_string(), path_str.clone());
        params.insert("QUERY_STRING".to_string(), query_str.to_string());
        params.insert("SERVER_PROTOCOL".to_string(), "HTTP/1.1".to_string());
        params.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
        params.insert("SCRIPT_FILENAME".to_string(), script_filename);
        params.insert("SCRIPT_NAME".to_string(), script_name);

        if let Some(remote_addr) = headers.get("x-real-ip") {
            if let Ok(addr) = remote_addr.to_str() {
                params.insert("REMOTE_ADDR".to_string(), addr.to_string());
            }
        }

        if let Some(host) = headers.get("host") {
            if let Ok(h) = host.to_str() {
                params.insert("SERVER_NAME".to_string(), h.to_string());
            }
        }

        if let Some(content_type) = headers.get("content-type") {
            if let Ok(ct) = content_type.to_str() {
                params.insert("CONTENT_TYPE".to_string(), ct.to_string());
            }
        }

        if let Some(content_length) = headers.get("content-length") {
            if let Ok(cl) = content_length.to_str() {
                if let Ok(len) = cl.parse::<usize>() {
                    params.insert("CONTENT_LENGTH".to_string(), len.to_string());
                }
            }
        }

        if let Some(ref extra_params) = config.params {
            for (key, value) in extra_params {
                params.insert(key.clone(), value.clone());
            }
        }

        if let Some(ref env_vars) = config.env_vars {
            for (key, value) in env_vars {
                params.insert(format!("FCGI_ENV:{}", key), value.clone());
            }
        }

        params
    }
}

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            break;
        }
    }
    encoded
}

struct FastCgiRecordReader {
    header_buf: BytesMut,
    content_buf: BytesMut,
}

impl FastCgiRecordReader {
    fn new() -> Self {
        FastCgiRecordReader {
            header_buf: BytesMut::with_capacity(FCGI_HEADER_SIZE),
            content_buf: BytesMut::with_capacity(65536),
        }
    }

    async fn read_record<T: AsyncRead + Unpin>(
        &mut self,
        socket: &mut T,
    ) -> Result<FastCgiRecord, std::io::Error> {
        let mut header = [0u8; FCGI_HEADER_SIZE];
        socket.read_exact(&mut header).await?;

        let fcgi_header = FastCgiHeader::parse(&header).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid FCGI header")
        })?;

        let mut content = vec![0u8; fcgi_header.content_length as usize];
        socket.read_exact(&mut content).await?;

        if fcgi_header.padding_length > 0 {
            let mut padding_buf = vec![0u8; fcgi_header.padding_length as usize];
            socket.read_exact(&mut padding_buf).await?;
        }

        Ok(FastCgiRecord {
            version: fcgi_header.version,
            record_type: fcgi_header.record_type,
            request_id: fcgi_header.request_id,
            content: BytesMut::from(&content[..]),
        })
    }
}

impl Default for FastCgiRecordReader {
    fn default() -> Self {
        Self::new()
    }
}

pub struct FastCgiChunkStream {
    chunks: std::vec::IntoIter<Bytes>,
}

impl FastCgiChunkStream {
    pub fn new(chunks: Vec<Bytes>) -> Self {
        FastCgiChunkStream {
            chunks: chunks.into_iter(),
        }
    }
}

impl futures::Stream for FastCgiChunkStream {
    type Item = Result<Bytes, FastCgiError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.chunks.next() {
            Some(chunk) => Poll::Ready(Some(Ok(chunk))),
            None => Poll::Ready(None),
        }
    }
}

pub fn build_response_stream(
    chunks: Vec<Bytes>,
    _status: u16,
    _headers: std::collections::HashMap<String, String>,
) -> impl futures::Stream<Item = Result<Bytes, FastCgiError>> {
    FastCgiChunkStream::new(chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_varint() {
        assert_eq!(encode_varint(0), vec![0]);
        assert_eq!(encode_varint(127), vec![127]);
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(16383), vec![0xFF, 0x7F]);
    }

    #[test]
    fn test_fastcgi_header_parse() {
        let valid_header = [1, 6, 0, 1, 0, 10, 0, 0];
        let header = FastCgiHeader::parse(&valid_header).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.record_type, 6);
        assert_eq!(header.request_id, 1);
        assert_eq!(header.content_length, 10);
        assert_eq!(header.padding_length, 0);
    }

    #[test]
    fn test_fastcgi_response_stream_default() {
        let stream = FastCgiResponseStream::default();
        assert_eq!(stream.status(), None);
        assert!(stream.headers().is_empty());
    }

    #[test]
    fn test_fastcgi_response_stream_with_chunks() {
        let chunks = vec![Bytes::from("hello"), Bytes::from(" world")];
        let stream = FastCgiResponseStream::with_body_chunks(chunks);
        assert_eq!(stream.status(), Some(200));
        assert!(stream.headers().is_empty());
    }
}
