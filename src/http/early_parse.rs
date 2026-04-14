use httparse::Request;

#[derive(Debug, Clone)]
pub struct EarlyHttpRequest {
    pub method: String,
    pub path: String,
    pub cookies: Option<String>,
    pub content_length: Option<usize>,
    pub host: Option<String>,
}

pub struct EarlyHttpParser;

impl EarlyHttpParser {
    pub fn parse(data: &[u8]) -> Option<EarlyHttpRequest> {
        let mut headers = [httparse::EMPTY_HEADER; 16];

        let mut req = Request::new(&mut headers);

        match req.parse(data) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => return None,
            Err(_) => return None,
        }

        let method = req.method.as_ref()?;
        let method_str = method.to_string();

        let path = req.path.as_ref()?;
        let path_str = path.to_string();

        let cookies = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("cookie"))
            .and_then(|h| std::str::from_utf8(h.value).ok().map(|s| s.to_string()));

        let content_length = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("content-length"))
            .and_then(|h| std::str::from_utf8(h.value).ok()?.parse::<usize>().ok());

        let host = req
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("host"))
            .and_then(|h| std::str::from_utf8(h.value).ok().map(|s| s.to_string()));

        Some(EarlyHttpRequest {
            method: method_str,
            path: path_str,
            cookies,
            content_length,
            host,
        })
    }
}

impl Default for EarlyHttpParser {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_get() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert_eq!(req.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_get_with_path() {
        let data = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/users");
    }

    #[test]
    fn test_parse_with_cookies() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nCookie: foo=bar; baz=qux\r\n\r\n";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert!(req.cookies.is_some());
        assert!(req.cookies.unwrap().contains("foo=bar"));
    }

    #[test]
    fn test_parse_incomplete() {
        let data = b"GET /";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_none());
    }

    #[test]
    fn test_parse_post_with_content_length() {
        let data = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let result = EarlyHttpParser::parse(data);

        assert!(result.is_some());
        let req = result.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/submit");
        assert_eq!(req.content_length, Some(5));
    }
}
