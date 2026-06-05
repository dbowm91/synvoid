#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    ReverseProxy { upstream_id: String },
    Static { location_id: String },
    FastCgi { pool_id: String },
    Cgi { handler_id: String },
    Php { pool_id: String },
    Serverless { function_id: String },
    Plugin { plugin_id: String },
    Tunnel { tunnel_id: String },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    pub site_id: Option<String>,
    pub target: RouteTarget,
    pub cache_policy_id: Option<String>,
    pub security_policy_id: Option<String>,
}
