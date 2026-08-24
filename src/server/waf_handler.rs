use crate::proxy::ForwardedProtocol;
use crate::waf::WafDecision;
use bytes::Bytes;
use http::{HeaderMap, Method, Response};
use http_body_util::Full;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Https,
    Http3,
}

#[derive(Clone, Debug)]
pub struct TlsMetadata {
    pub ja4_hash: Option<String>,
}

#[derive(Clone, Debug)]
pub enum WafResponseIntent {
    Drop,
    Stall {
        duration: Duration,
    },
    Block {
        status: u16,
        body: String,
        content_type: &'static str,
    },
    Challenge {
        body: String,
    },
    ChallengeWithCookie {
        body: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
    TarPit {
        body: String,
    },
    Pass,
}

#[derive(Clone, Debug)]
pub struct WafContext {
    pub client_ip: IpAddr,
    pub method: Method,
    pub path: String,
    pub query_string: Option<String>,
    pub host: String,
    pub headers: HeaderMap,
    pub user_agent: Option<String>,
    pub is_tls: bool,
    pub protocol: Protocol,
    pub ja4_hash: Option<String>,
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: SocketAddr,
}

impl fmt::Display for WafContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WafContext {{ method: {}, path: {}, host: {}, is_tls: {}, protocol: {:?} }}",
            self.method, self.path, self.host, self.is_tls, self.protocol
        )
    }
}

impl WafContext {
    pub fn new_http(
        method: Method,
        path: String,
        query_string: Option<String>,
        host: String,
        headers: HeaderMap,
        client_ip: IpAddr,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            client_ip,
            method,
            path,
            query_string,
            host,
            headers,
            user_agent: None,
            is_tls: false,
            protocol: Protocol::Http,
            ja4_hash: None,
            local_addr: None,
            remote_addr,
        }
    }

    pub fn new_https(
        method: Method,
        path: String,
        query_string: Option<String>,
        host: String,
        headers: HeaderMap,
        client_ip: IpAddr,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        ja4_hash: Option<String>,
    ) -> Self {
        Self {
            client_ip,
            method,
            path,
            query_string,
            host,
            headers,
            user_agent: None,
            is_tls: true,
            protocol: Protocol::Https,
            ja4_hash,
            local_addr: Some(local_addr),
            remote_addr,
        }
    }

    pub fn new_http3(
        method: Method,
        path: String,
        query_string: Option<String>,
        host: String,
        headers: HeaderMap,
        client_ip: IpAddr,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            client_ip,
            method,
            path,
            query_string,
            host,
            headers,
            user_agent: None,
            is_tls: true,
            protocol: Protocol::Http3,
            ja4_hash: None,
            local_addr: Some(local_addr),
            remote_addr,
        }
    }
}

pub fn interpret_waf_decision(decision: &WafDecision, _ctx: &WafContext) -> WafResponseIntent {
    match decision {
        WafDecision::Drop => WafResponseIntent::Drop,
        WafDecision::Stall => WafResponseIntent::Stall {
            duration: Duration::from_secs(5),
        },
        WafDecision::Block(status, body) => WafResponseIntent::Block {
            status: *status,
            body: body.clone(),
            content_type: "text/html",
        },
        WafDecision::Challenge(_type, html) => WafResponseIntent::Challenge { body: html.clone() },
        WafDecision::ChallengeWithCookie {
            challenge_type: _,
            html,
            session_cookie_name,
            session_cookie_value,
            session_cookie_max_age,
        } => WafResponseIntent::ChallengeWithCookie {
            body: html.clone(),
            session_cookie_name: session_cookie_name.clone(),
            session_cookie_value: session_cookie_value.clone(),
            session_cookie_max_age: *session_cookie_max_age,
        },
        WafDecision::Tarpit(html) => WafResponseIntent::TarPit { body: html.clone() },
        WafDecision::Pass => WafResponseIntent::Pass,
    }
}

pub fn format_session_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!(
        "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
        name, value, max_age
    )
}

#[allow(async_fn_in_trait)]
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_tls(&self) -> bool;
    fn supports_websocket(&self) -> bool;
    fn forwarded_protocol(&self) -> ForwardedProtocol;
    fn build_waf_response(&self, intent: &WafResponseIntent) -> http::Response<Full<Bytes>>;
    async fn send_waf_response(
        &self,
        intent: WafResponseIntent,
    ) -> Result<http::Response<Full<Bytes>>, anyhow::Error>;
}

fn build_waf_response_inner(intent: &WafResponseIntent) -> http::Response<Full<Bytes>> {
    match intent {
        WafResponseIntent::Drop => http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        WafResponseIntent::Stall { .. } => http::Response::builder()
            .status(http::StatusCode::REQUEST_TIMEOUT)
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        WafResponseIntent::Block {
            status,
            body,
            content_type,
        } => http::Response::builder()
            .status(http::StatusCode::from_u16(*status).unwrap_or(http::StatusCode::FORBIDDEN))
            .header(http::header::CONTENT_TYPE, *content_type)
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        WafResponseIntent::Challenge { body } => http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "text/html")
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        WafResponseIntent::ChallengeWithCookie {
            body,
            session_cookie_name,
            session_cookie_value,
            session_cookie_max_age,
        } => {
            let cookie = format!(
                "{}={}; path=/; max-age={}; Secure; SameSite=Strict",
                session_cookie_name, session_cookie_value, session_cookie_max_age
            );
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "text/html")
                .header(http::header::SET_COOKIE, &cookie)
                .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
        }
        WafResponseIntent::TarPit { body } => http::Response::builder()
            .status(http::StatusCode::OK)
            .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        WafResponseIntent::Pass => http::Response::builder()
            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from_static(
                b"invalid WAF response intent",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
    }
}

#[derive(Clone)]
pub struct HttpProtocolAdapter;

impl ProtocolAdapter for HttpProtocolAdapter {
    fn name(&self) -> &'static str {
        "http"
    }
    fn is_tls(&self) -> bool {
        false
    }
    fn supports_websocket(&self) -> bool {
        true
    }
    fn forwarded_protocol(&self) -> ForwardedProtocol {
        ForwardedProtocol::Http
    }

    fn build_waf_response(&self, intent: &WafResponseIntent) -> http::Response<Full<Bytes>> {
        build_waf_response_inner(intent)
    }

    async fn send_waf_response(
        &self,
        intent: WafResponseIntent,
    ) -> Result<http::Response<Full<Bytes>>, anyhow::Error> {
        let response = self.build_waf_response(&intent);
        Ok(response)
    }
}

#[derive(Clone)]
pub struct HttpsProtocolAdapter {
    pub ja4_hash: Option<String>,
}

impl ProtocolAdapter for HttpsProtocolAdapter {
    fn name(&self) -> &'static str {
        "https"
    }
    fn is_tls(&self) -> bool {
        true
    }
    fn supports_websocket(&self) -> bool {
        true
    }
    fn forwarded_protocol(&self) -> ForwardedProtocol {
        ForwardedProtocol::Https
    }

    fn build_waf_response(&self, intent: &WafResponseIntent) -> http::Response<Full<Bytes>> {
        build_waf_response_inner(intent)
    }

    async fn send_waf_response(
        &self,
        intent: WafResponseIntent,
    ) -> Result<http::Response<Full<Bytes>>, anyhow::Error> {
        let response = self.build_waf_response(&intent);
        Ok(response)
    }
}

#[derive(Clone)]
pub struct Http3ProtocolAdapter;

impl ProtocolAdapter for Http3ProtocolAdapter {
    fn name(&self) -> &'static str {
        "http3"
    }
    fn is_tls(&self) -> bool {
        true
    }
    fn supports_websocket(&self) -> bool {
        false
    }
    fn forwarded_protocol(&self) -> ForwardedProtocol {
        ForwardedProtocol::Https
    }

    fn build_waf_response(&self, intent: &WafResponseIntent) -> http::Response<Full<Bytes>> {
        build_waf_response_inner(intent)
    }

    async fn send_waf_response(
        &self,
        intent: WafResponseIntent,
    ) -> Result<http::Response<Full<Bytes>>, anyhow::Error> {
        let response = self.build_waf_response(&intent);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn context() -> WafContext {
        WafContext::new_http(
            Method::GET,
            "/".to_string(),
            None,
            "localhost".to_string(),
            HeaderMap::new(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
        )
    }

    #[test]
    fn block_status_and_pass_intent_are_preserved_safely() {
        let intent = interpret_waf_decision(&WafDecision::Block(451, "blocked".into()), &context());
        match intent {
            WafResponseIntent::Block { status, .. } => assert_eq!(status, 451),
            other => panic!("expected block response, got {other:?}"),
        }

        assert_eq!(
            HttpProtocolAdapter
                .build_waf_response(&WafResponseIntent::Pass)
                .status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            HttpsProtocolAdapter { ja4_hash: None }
                .build_waf_response(&WafResponseIntent::Pass)
                .status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            Http3ProtocolAdapter
                .build_waf_response(&WafResponseIntent::Pass)
                .status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
