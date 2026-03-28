use bytes::Bytes;
use http::Response;
use http_body_util::Full;

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "An Error Occurred",
    }
}

pub fn error_body(status: u16) -> &'static [u8] {
    match status {
        400 => b"Bad Request",
        401 => b"Unauthorized",
        403 => b"Forbidden",
        404 => b"Not Found",
        405 => b"Method Not Allowed",
        408 => b"Request Timeout",
        413 => b"Payload Too Large",
        414 => b"URI Too Long",
        429 => b"Too Many Requests",
        431 => b"Request Header Fields Too Large",
        500 => b"Internal Server Error",
        501 => b"Not Implemented",
        502 => b"Bad Gateway",
        503 => b"Service Unavailable",
        504 => b"Gateway Timeout",
        _ => b"An Error Occurred",
    }
}

pub fn error_response_bytes(status: u16) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .body(Bytes::from_static(error_body(status)))
        .unwrap_or_else(|_| Response::new(Bytes::new()))
}

pub fn error_response_full(status: u16) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(error_body(status))))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

pub fn error_response_boxed(
    status: u16,
) -> Response<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>> {
    use http_body_util::BodyExt;
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from_static(error_body(status))).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

pub fn fallback_error_bytes() -> Response<Bytes> {
    error_response_bytes(500)
}

pub fn fallback_error_full() -> Response<Full<Bytes>> {
    error_response_full(500)
}

pub fn fallback_error_boxed(
) -> Response<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>> {
    error_response_boxed(500)
}

pub fn internal_server_error_bytes() -> Response<Bytes> {
    error_response_bytes(500)
}

pub fn internal_server_error_full() -> Response<Full<Bytes>> {
    error_response_full(500)
}

pub fn service_unavailable_full() -> Response<Full<Bytes>> {
    error_response_full(503)
}

pub fn bad_gateway_bytes() -> Response<Bytes> {
    error_response_bytes(502)
}

pub fn bad_gateway_full() -> Response<Full<Bytes>> {
    error_response_full(502)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reason_phrase_known_codes() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(400), "Bad Request");
        assert_eq!(reason_phrase(401), "Unauthorized");
        assert_eq!(reason_phrase(403), "Forbidden");
        assert_eq!(reason_phrase(404), "Not Found");
        assert_eq!(reason_phrase(405), "Method Not Allowed");
        assert_eq!(reason_phrase(408), "Request Timeout");
        assert_eq!(reason_phrase(413), "Payload Too Large");
        assert_eq!(reason_phrase(414), "URI Too Long");
        assert_eq!(reason_phrase(429), "Too Many Requests");
        assert_eq!(reason_phrase(431), "Request Header Fields Too Large");
        assert_eq!(reason_phrase(500), "Internal Server Error");
        assert_eq!(reason_phrase(501), "Not Implemented");
        assert_eq!(reason_phrase(502), "Bad Gateway");
        assert_eq!(reason_phrase(503), "Service Unavailable");
        assert_eq!(reason_phrase(504), "Gateway Timeout");
    }

    #[test]
    fn test_reason_phrase_unknown_code() {
        assert_eq!(reason_phrase(999), "An Error Occurred");
        assert_eq!(reason_phrase(0), "An Error Occurred");
    }

    #[test]
    fn test_error_body_matches_reason_phrase() {
        for code in [
            400, 401, 403, 404, 405, 408, 413, 414, 429, 431, 500, 501, 502, 503, 504,
        ] {
            assert_eq!(error_body(code), reason_phrase(code).as_bytes());
        }
    }

    #[test]
    fn test_error_response_bytes_status() {
        let resp = error_response_bytes(500);
        assert_eq!(resp.status(), 500);
        assert_eq!(resp.body(), &Bytes::from_static(b"Internal Server Error"));
    }

    #[test]
    fn test_error_response_full_status() {
        let resp = error_response_full(503);
        assert_eq!(resp.status(), 503);
    }

    #[test]
    fn test_error_response_boxed_status() {
        let resp = error_response_boxed(502);
        assert_eq!(resp.status(), 502);
    }

    #[test]
    fn test_fallback_responses_are_500() {
        let resp = fallback_error_bytes();
        assert_eq!(resp.status(), 500);

        let resp = fallback_error_full();
        assert_eq!(resp.status(), 500);

        let resp = fallback_error_boxed();
        assert_eq!(resp.status(), 500);

        let resp = internal_server_error_bytes();
        assert_eq!(resp.status(), 500);

        let resp = internal_server_error_full();
        assert_eq!(resp.status(), 500);
    }

    #[test]
    fn test_service_unavailable() {
        let resp = service_unavailable_full();
        assert_eq!(resp.status(), 503);
    }

    #[test]
    fn test_bad_gateway() {
        let resp = bad_gateway_bytes();
        assert_eq!(resp.status(), 502);

        let resp = bad_gateway_full();
        assert_eq!(resp.status(), 502);
    }
}
