use http::Method;
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
                path == *prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|rest| rest.starts_with('/'))
            }
            RouteMatch::Suffix(suffix) => path.ends_with(suffix),
            RouteMatch::Regex {
                compiled,
                pattern: _,
            } => {
                if let Some(ref re) = compiled {
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
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let path_chars: Vec<char> = path.chars().collect();
    let mut pattern_index = 0;
    let mut path_index = 0;
    let mut star: Option<(usize, bool)> = None;
    let mut star_path_index = 0;

    while path_index < path_chars.len() {
        if pattern_index < pattern_chars.len()
            && pattern_chars[pattern_index] != '*'
            && pattern_chars[pattern_index] == path_chars[path_index]
        {
            pattern_index += 1;
            path_index += 1;
        } else if pattern_index < pattern_chars.len() && pattern_chars[pattern_index] == '*' {
            let crosses_segments =
                pattern_index + 1 < pattern_chars.len() && pattern_chars[pattern_index + 1] == '*';
            pattern_index += if crosses_segments { 2 } else { 1 };
            star = Some((pattern_index, crosses_segments));
            star_path_index = path_index;
        } else if let Some((after_star, crosses_segments)) = star {
            if crosses_segments && pattern_chars.get(after_star) == Some(&'/') {
                // A globstar followed by a separator may match zero path segments.
                pattern_index = after_star + 1;
                star = Some((pattern_index, true));
            } else {
                if star_path_index >= path_chars.len()
                    || (!crosses_segments && path_chars[star_path_index] == '/')
                {
                    return false;
                }
                star_path_index += 1;
                path_index = star_path_index;
                pattern_index = after_star;
            }
        } else {
            return false;
        }
    }

    while pattern_index < pattern_chars.len() && pattern_chars[pattern_index] == '*' {
        pattern_index +=
            if pattern_index + 1 < pattern_chars.len() && pattern_chars[pattern_index + 1] == '*' {
                2
            } else {
                1
            };
    }
    pattern_index == pattern_chars.len()
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

    #[test]
    fn test_invalid_regex_without_compiled_pattern_does_not_match() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Regex {
                pattern: "[invalid".to_string(),
                compiled: None,
            },
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(!route.matches("/api/users", &Method::GET));
    }

    #[test]
    fn test_glob_route_match_does_not_cross_segments_for_single_star() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Glob("/api/*/users".to_string()),
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/v1/users", &Method::GET));
        assert!(!route.matches("/api/v1/admin/users", &Method::GET));
    }

    #[test]
    fn test_glob_route_match_double_star_crosses_segments() {
        let route = ServerlessRoute {
            matcher: RouteMatch::Glob("/api/**/users".to_string()),
            method: MethodMatch::Any,
            priority: 0,
            function_name: "test".to_string(),
        };
        assert!(route.matches("/api/v1/admin/users", &Method::GET));
        assert!(route.matches("/api/users", &Method::GET));
    }
}
