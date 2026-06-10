// Root-owned because it depends on root tunnel runtime (QUIC_TUNNEL_REGISTRY, crate::tunnel::quic).
// is_quictunnel_url is duplicated in crate for direct synvoid_http_client importers; this version is for src/ paths.

use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http::{HeaderMap, Method};
use synvoid_http_client::HttpResponse;

pub fn is_quictunnel_url(url: &str) -> bool {
    url.starts_with("quictunnel://") || url.starts_with("quictunnel:")
}

pub async fn send_request_via_quic_tunnel(
    method: Method,
    url: &str,
    headers: Option<HeaderMap>,
    body: Option<Bytes>,
    timeout: Option<Duration>,
) -> Result<HttpResponse> {
    use crate::tunnel::quic::framing::{read_message, write_message};
    use crate::tunnel::quic::messages::TunnelMessage;
    use crate::tunnel::QUIC_TUNNEL_REGISTRY;

    let trimmed = url
        .trim_start_matches("quictunnel://")
        .trim_start_matches("quictunnel:");

    let (peer, port_str) = if let Some(colon_pos) = trimmed.rfind(':') {
        let peer = &trimmed[..colon_pos];
        let path_start = trimmed[colon_pos + 1..].find('/');
        let (port_str, _path) = if let Some(idx) = path_start {
            let remaining = &trimmed[colon_pos + 1..];
            (&remaining[..idx], Some(&remaining[idx..]))
        } else {
            (&trimmed[colon_pos + 1..], None)
        };
        (peer, port_str)
    } else {
        return Err(anyhow::anyhow!(
            "Invalid quictunnel URL format: expected quictunnel://peer:port"
        ));
    };

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port in quictunnel URL: {}", port_str))?;

    let runtime = QUIC_TUNNEL_REGISTRY
        .get_runtime()
        .await
        .ok_or_else(|| anyhow::anyhow!("QUIC tunnel runtime not available"))?;

    let identifier = format!("http-port-{}", port);

    let (mut send_stream, mut recv_stream) = runtime
        .open_tunnel_stream_to_peer(peer, &identifier)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open QUIC tunnel stream: {}", e))?;

    let stream_open = TunnelMessage::StreamOpen {
        identifier: identifier.clone(),
        port,
        protocol: "http".to_string(),
        tls_passthrough: false,
    };
    write_message(&mut send_stream, &stream_open).await?;

    let response = read_message(&mut recv_stream, 65536).await?;
    match response {
        TunnelMessage::StreamOpenAck {
            success, message, ..
        } => {
            if !success {
                return Err(anyhow::anyhow!(
                    "Stream open failed: {}",
                    message.unwrap_or_default()
                ));
            }
        }
        _ => return Err(anyhow::anyhow!("Unexpected response to StreamOpen")),
    }

    let mut http_request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        method, "/", peer
    );

    if let Some(h) = headers {
        for (name, value) in h.iter() {
            if name != http::header::HOST && name != http::header::CONNECTION {
                http_request.push_str(&format!("{}: {}\r\n", name, value.to_str().unwrap_or("")));
            }
        }
    }

    if let Some(ref b) = body {
        http_request.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }

    http_request.push_str("\r\n");

    send_stream.write_all(http_request.as_bytes()).await?;

    if let Some(b) = body {
        send_stream.write_all(&b).await?;
    }

    send_stream
        .finish()
        .map_err(|e| anyhow::anyhow!("Failed to finish send stream: {}", e))?;

    let result = if let Some(t) = timeout {
        match tokio::time::timeout(t, async {
            let mut response_data = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                match recv_stream.read(&mut buf).await {
                    Ok(Some(0)) => break,
                    Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                    Ok(None) => break,
                    Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                }
            }
            Ok::<_, anyhow::Error>(response_data)
        })
        .await
        {
            Ok(Ok(data)) => data,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("Request timed out")),
        }
    } else {
        let mut response_data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match recv_stream.read(&mut buf).await {
                Ok(Some(0)) => break,
                Ok(Some(n)) => response_data.extend_from_slice(&buf[..n]),
                Ok(None) => break,
                Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
            }
        }
        response_data
    };

    let response_str = String::from_utf8_lossy(&result);
    let mut header_lines = response_str.split("\r\n");

    let status_line = header_lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("No status line in response"))?;

    let status_parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    let status_code: u16 = status_parts
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("No status code in response"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid status code"))?;

    let mut response_headers = http::HeaderMap::new();
    loop {
        match header_lines.next() {
            Some("") => break,
            Some(line) => {
                if let Some(colon_pos) = line.find(':') {
                    let name = line[..colon_pos].trim();
                    let value = line[colon_pos + 1..].trim();
                    if let Ok(header_name) = http::header::HeaderName::try_from(name) {
                        if let Ok(header_value) = http::header::HeaderValue::from_str(value) {
                            response_headers.append(header_name, header_value);
                        }
                    }
                }
            }
            None => break,
        }
    }

    let response_headers = {
        use crate::proxy::headers::filter_response_headers_buf_with_str_set;
        let hop_by_hop: std::collections::HashSet<&str> = crate::proxy::headers::HOP_BY_HOP_HEADERS
            .iter()
            .copied()
            .collect();
        filter_response_headers_buf_with_str_set(&response_headers, &hop_by_hop)
    };

    let body_start = response_str
        .find("\r\n\r\n")
        .map(|pos| pos + 4)
        .unwrap_or(0);
    let response_body = Bytes::from(result[body_start..].to_vec());

    Ok(HttpResponse {
        status: http::StatusCode::from_u16(status_code)
            .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        headers: response_headers,
        body: response_body,
    })
}
