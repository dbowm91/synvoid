use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use bytes::Bytes;
use http::{HeaderMap, Method, Uri};
use crate::waf::WafDecision;

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
    Stall { duration: Duration },
    Block { status: u16, body: String, content_type: &'static str },
    Challenge { body: String },
    ChallengeWithCookie {
        body: String,
        session_cookie_name: String,
        session_cookie_value: String,
        session_cookie_max_age: u64,
    },
    TarPit { body: String },
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

pub fn interpret_waf_decision(
    decision: &WafDecision,
    _ctx: &WafContext,
) -> WafResponseIntent {
    match decision {
        WafDecision::Drop => WafResponseIntent::Drop,
        WafDecision::Stall => WafResponseIntent::Stall { duration: Duration::from_secs(5) },
        WafDecision::Block(_status, body) => WafResponseIntent::Block {
            status: 403,
            body: body.clone(),
            content_type: "text/html",
        },
        WafDecision::Challenge(html) => WafResponseIntent::Challenge {
            body: html.clone(),
        },
        WafDecision::ChallengeWithCookie {
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
        WafDecision::Tarpit(html) => WafResponseIntent::TarPit {
            body: html.clone(),
        },
        WafDecision::Pass => WafResponseIntent::Pass,
    }
}

pub fn format_session_cookie(name: &str, value: &str, max_age: u64) -> String {
    format!("{}={}; path=/; max-age={}; Secure; SameSite=Strict", name, value, max_age)
}
