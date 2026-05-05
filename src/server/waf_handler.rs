use std::net::IpAddr;
use std::time::Duration;
use crate::waf::WafDecision;

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

pub struct WafContext {
    pub client_ip: IpAddr,
    pub method: &'static str,
    pub path: &'static str,
    pub is_tls: bool,
    pub protocol: &'static str,
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
