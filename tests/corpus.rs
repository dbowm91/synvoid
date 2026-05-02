use http::HeaderMap;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct RequestFixture {
    pub id: String,
    pub description: String,
    pub entry_point: String,
    pub expected_result: ExpectedResult,
    pub attack_type: FixtureAttackType,
    pub notes: String,
    pub request: RequestSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExpectedResult {
    #[default]
    Detect,
    Pass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum FixtureAttackType {
    #[default]
    None,
    Sqli,
    Xss,
    PathTraversal,
    Rfi,
    Ssrf,
    Ssti,
    CmdInjection,
    Xxe,
    Jwt,
    RequestSmuggling,
    LdapInjection,
    XPathInjection,
    OpenRedirect,
}

impl<'de> Deserialize<'de> for FixtureAttackType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "none" => Ok(FixtureAttackType::None),
            "sqli" => Ok(FixtureAttackType::Sqli),
            "xss" => Ok(FixtureAttackType::Xss),
            "path_traversal" => Ok(FixtureAttackType::PathTraversal),
            "rfi" => Ok(FixtureAttackType::Rfi),
            "ssrf" => Ok(FixtureAttackType::Ssrf),
            "ssti" => Ok(FixtureAttackType::Ssti),
            "cmd_injection" => Ok(FixtureAttackType::CmdInjection),
            "xxe" => Ok(FixtureAttackType::Xxe),
            "jwt" => Ok(FixtureAttackType::Jwt),
            "request_smuggling" => Ok(FixtureAttackType::RequestSmuggling),
            "ldap_injection" => Ok(FixtureAttackType::LdapInjection),
            "xpath_injection" => Ok(FixtureAttackType::XPathInjection),
            "open_redirect" => Ok(FixtureAttackType::OpenRedirect),
            _ => Ok(FixtureAttackType::None),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HeadersField {
    Map(HashMap<String, String>),
    Array(Vec<(String, String)>),
}

impl<'de> Deserialize<'de> for HeadersField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Intermediate {
            Map(HashMap<String, String>),
            Array(Vec<Vec<String>>),
        }

        let intermediate = Intermediate::deserialize(deserializer)?;
        match intermediate {
            Intermediate::Map(m) => Ok(HeadersField::Map(m)),
            Intermediate::Array(a) => Ok(HeadersField::Array(
                a.into_iter()
                    .map(|v| (v[0].clone(), v[1].clone()))
                    .collect(),
            )),
        }
    }
}

impl Default for HeadersField {
    fn default() -> Self {
        HeadersField::Map(HashMap::new())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HeadersField,
    pub query_string: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub body_file: Option<String>,
}

impl RequestSpec {
    pub fn headers_array(&self) -> Vec<(String, String)> {
        match &self.headers {
            HeadersField::Map(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            HeadersField::Array(a) => a.clone(),
        }
    }
}

impl RequestFixture {
    pub fn load_all(fixtures_dir: &Path) -> Vec<Self> {
        let requests_dir = fixtures_dir.join("requests");
        if !requests_dir.exists() {
            return Vec::new();
        }

        let mut fixtures = Vec::new();
        for entry in fs::read_dir(&requests_dir).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(&path).unwrap();
                if let Ok(fixture) = serde_json::from_str::<RequestFixture>(&content) {
                    fixtures.push(fixture);
                }
            }
        }
        fixtures.sort_by_key(|f| f.id.clone());
        fixtures
    }

    pub fn build_headers(&self, _base_path: &Path) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in self.request.headers_array() {
            if let (Ok(name), Ok(value)) = (
                name.parse::<http::HeaderName>(),
                value.parse::<http::HeaderValue>(),
            ) {
                headers.insert(name, value);
            }
        }
        headers
    }

    pub fn body_bytes(&self, base_path: &Path) -> Option<Vec<u8>> {
        if let Some(ref body_file) = self.request.body_file {
            let body_path = base_path.join(body_file);
            fs::read(&body_path).ok()
        } else {
            self.request.body.as_ref().map(|s| s.as_bytes().to_vec())
        }
    }

    pub fn entry_point_location(&self) -> &'static str {
        if self.entry_point.starts_with("header:") {
            "header"
        } else {
            match self.entry_point.as_str() {
                "query_string" => "query_string",
                "post_body" => "post_body",
                "path" => "path",
                _ => "unknown",
            }
        }
    }
}

pub fn waf_decision_to_expected(detected: bool, expected: ExpectedResult) -> bool {
    match expected {
        ExpectedResult::Detect => detected,
        ExpectedResult::Pass => !detected,
    }
}
