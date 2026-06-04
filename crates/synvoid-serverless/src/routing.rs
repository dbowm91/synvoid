use http::Method;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum RouteMatch {
    Exact(String),
    Prefix(String),
    Suffix(String),
    Regex {
        pattern: String,
        compiled: Option<Arc<regex::Regex>>,
    },
    Glob(String),
}

impl RouteMatch {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            RouteMatch::Exact(pattern) => path == *pattern,
            RouteMatch::Prefix(prefix) => {
                path == *prefix || path.starts_with(&format!("{}/", prefix))
            }
            RouteMatch::Suffix(suffix) => path.ends_with(suffix),
            RouteMatch::Regex { pattern, compiled } => {
                if let Some(ref re) = compiled {
                    re.is_match(path)
                } else if let Ok(re) = regex::Regex::new(pattern) {
                    re.is_match(path)
                } else {
                    false
                }
            }
            RouteMatch::Glob(pattern) => glob_match(pattern, path),
        }
    }
}

fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern = Path::new(pattern);
    let path = Path::new(path);
    let pattern_str = pattern.to_str().unwrap_or("");
    let path_str = path.to_str().unwrap_or("");

    let mut pattern_chars = pattern_str.chars().peekable();
    let mut path_chars = path_str.chars().peekable();

    while pattern_chars.peek().is_some() || path_chars.peek().is_some() {
        match pattern_chars.peek() {
            Some('*') => {
                pattern_chars.next();
                match pattern_chars.peek() {
                    Some('*') => {
                        pattern_chars.next();
                        if pattern_chars.peek().is_none() {
                            return true;
                        }
                        while path_chars.peek().is_some() {
                            if glob_match(
                                &pattern_chars.clone().collect::<String>(),
                                &path_chars.clone().collect::<String>(),
                            ) {
                                return true;
                            }
                            path_chars.next();
                        }
                        return false;
                    }
                    Some(c) => {
                        while path_chars.peek().is_some() && path_chars.peek() != Some(c) {
                            path_chars.next();
                        }
                    }
                    None => {
                        return path_chars.peek().is_none() || path_chars.all(|c| c != '/');
                    }
                }
            }
            Some(c) => {
                if path_chars.peek() != Some(c) {
                    return false;
                }
                pattern_chars.next();
                path_chars.next();
            }
            None => {
                return path_chars.peek().is_none();
            }
        }
    }
    true
}

#[derive(Debug, Clone)]
pub enum MethodMatch {
    Any,
    Specific(Method),
    Multiple(Vec<Method>),
}

impl MethodMatch {
    pub fn matches(&self, method: &Method) -> bool {
        match self {
            MethodMatch::Any => true,
            MethodMatch::Specific(m) => m == method,
            MethodMatch::Multiple(methods) => methods.iter().any(|m| m == method),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServerlessRoute {
    pub matcher: RouteMatch,
    pub method: MethodMatch,
    pub priority: i32,
    pub function_name: String,
}

impl ServerlessRoute {
    pub fn matches(&self, path: &str, method: &Method) -> bool {
        self.matcher.matches(path) && self.method.matches(method)
    }
}

pub fn parse_route_string(route: &str) -> Option<(MethodMatch, RouteMatch)> {
    let parts: Vec<&str> = route.trim().splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let method_part = parts[0];
    let path_part = parts[1];

    let method = parse_method(method_part);
    let matcher = parse_path_match(path_part);

    Some((method, matcher))
}

fn parse_method(method_part: &str) -> MethodMatch {
    if method_part == "*" || method_part.eq_ignore_ascii_case("ANY") {
        return MethodMatch::Any;
    }

    let methods: Vec<Method> = method_part
        .split(',')
        .filter_map(|m| match m.trim().to_uppercase().as_str() {
            "GET" => Some(Method::GET),
            "POST" => Some(Method::POST),
            "PUT" => Some(Method::PUT),
            "DELETE" => Some(Method::DELETE),
            "PATCH" => Some(Method::PATCH),
            "HEAD" => Some(Method::HEAD),
            "OPTIONS" => Some(Method::OPTIONS),
            _ => None,
        })
        .collect();

    if methods.len() == 1 {
        MethodMatch::Specific(methods.into_iter().next().unwrap())
    } else if methods.len() > 1 {
        MethodMatch::Multiple(methods)
    } else {
        MethodMatch::Any
    }
}

fn parse_path_match(path: &str) -> RouteMatch {
    if path.contains("**") {
        return RouteMatch::Glob(path.to_string());
    }

    if let Some(pattern) = path.strip_prefix("regex:") {
        let compiled = regex::Regex::new(pattern).ok().map(Arc::new);
        return RouteMatch::Regex {
            pattern: pattern.to_string(),
            compiled,
        };
    }

    if let Some(prefix) = path.strip_suffix('*') {
        if let Some(suffix) = prefix.strip_suffix(".*") {
            return RouteMatch::Suffix(suffix.to_string());
        }
        return RouteMatch::Prefix(prefix.trim_end_matches('/').to_string());
    }

    if let Some(suffix) = path.strip_prefix("*.") {
        return RouteMatch::Suffix(suffix.to_string());
    }

    RouteMatch::Exact(path.to_string())
}

pub fn parse_routes(
    routes_config: &[String],
    function_name: &str,
    default_priority: i32,
) -> Vec<ServerlessRoute> {
    let mut routes: Vec<ServerlessRoute> = Vec::new();

    for (idx, route_str) in routes_config.iter().enumerate() {
        if let Some((method, matcher)) = parse_route_string(route_str) {
            routes.push(ServerlessRoute {
                matcher,
                method,
                priority: default_priority - idx as i32,
                function_name: function_name.to_string(),
            });
        }
    }

    routes.sort_by_key(|r| r.priority);
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_route_match() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Exact("/api/users".to_string()),
            method: MethodMatch::Specific(Method::GET),
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/users", &Method::GET));
        assert!(!route.matches("/api/users/", &Method::GET));
        assert!(!route.matches("/api/users/1", &Method::GET));
    }

    #[test]
    fn test_prefix_route_match() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Prefix("/api/users".to_string()),
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/users", &Method::GET));
        assert!(route.matches("/api/users/", &Method::GET));
        assert!(route.matches("/api/users/1", &Method::GET));
        assert!(!route.matches("/api/user", &Method::GET));
    }

    #[test]
    fn test_suffix_route_match() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Suffix(".json".to_string()),
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/data.json", &Method::GET));
        assert!(route.matches("data.json", &Method::GET));
        assert!(!route.matches("/api/data.json2", &Method::GET));
    }

    #[test]
    fn test_method_match_any() {
        let method = MethodMatch::Any;
        assert!(method.matches(&Method::GET));
        assert!(method.matches(&Method::POST));
        assert!(method.matches(&Method::DELETE));
    }

    #[test]
    fn test_method_match_specific() {
        let method = MethodMatch::Specific(Method::GET);
        assert!(method.matches(&Method::GET));
        assert!(!method.matches(&Method::POST));
    }

    #[test]
    fn test_method_match_multiple() {
        let method = MethodMatch::Multiple(vec![Method::GET, Method::POST]);
        assert!(method.matches(&Method::GET));
        assert!(method.matches(&Method::POST));
        assert!(!method.matches(&Method::DELETE));
    }

    #[test]
    fn test_parse_route_string_exact() {
        let (method, matcher) = parse_route_string("GET /api/users").unwrap();
        assert!(matches!(method, MethodMatch::Specific(Method::GET)));
        assert!(matches!(matcher, RouteMatch::Exact(_)));
    }

    #[test]
    fn test_parse_route_string_prefix() {
        let (method, matcher) = parse_route_string("GET /api/*").unwrap();
        assert!(matches!(method, MethodMatch::Specific(Method::GET)));
        assert!(matches!(matcher, RouteMatch::Prefix(_)));
    }

    #[test]
    fn test_parse_route_string_suffix() {
        let (method, matcher) = parse_route_string("GET *.json").unwrap();
        assert!(matches!(method, MethodMatch::Specific(Method::GET)));
        assert!(matches!(matcher, RouteMatch::Suffix(_)));
    }

    #[test]
    fn test_parse_route_string_any_method() {
        let (method, matcher) = parse_route_string("ANY /api/*").unwrap();
        assert!(matches!(method, MethodMatch::Any));
        assert!(matches!(matcher, RouteMatch::Prefix(_)));
    }

    #[test]
    fn test_parse_route_string_regex() {
        let (method, matcher) = parse_route_string("GET regex:^/api/v\\d+/users").unwrap();
        assert!(matches!(method, MethodMatch::Specific(Method::GET)));
        assert!(matches!(matcher, RouteMatch::Regex { .. }));
        if let RouteMatch::Regex { ref pattern, .. } = matcher {
            assert_eq!(pattern, "^/api/v\\d+/users");
        }
    }

    #[test]
    fn test_regex_route_match() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Regex {
                pattern: "^/api/v[0-9]+/.*".to_string(),
                compiled: Some(Arc::new(regex::Regex::new("^/api/v[0-9]+/.*").unwrap())),
            },
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/v1/users", &Method::GET));
        assert!(route.matches("/api/v123/items", &Method::POST));
        assert!(!route.matches("/api/users", &Method::GET));
        assert!(!route.matches("/api/v/users", &Method::GET));
    }
}
