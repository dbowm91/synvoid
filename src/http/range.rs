use http::{header, HeaderMap, HeaderValue, StatusCode};
use std::ops::Bound;

#[derive(Debug, Clone)]
pub struct RangeRequest {
    ranges: Vec<(u64, u64)>,
    total_size: u64,
}

#[derive(Debug, Clone)]
pub struct RangeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub content_range: Option<String>,
}

impl RangeRequest {
    pub fn parse(range_header: &str, total_size: u64) -> Option<Self> {
        if !range_header.starts_with("bytes=") {
            return None;
        }

        let range_spec = range_header.strip_prefix("bytes=")?;

        let mut ranges = Vec::new();

        for spec in range_spec.split(',') {
            let spec = spec.trim();
            if spec.is_empty() {
                continue;
            }

            let (start, end) = spec.split_once('-')?;

            let start = if start.is_empty() {
                if end.is_empty() {
                    return None;
                }
                let end_val: u64 = end.parse().ok()?;
                total_size.saturating_sub(end_val + 1)
            } else {
                start.parse().ok()?
            };

            let end = if end.is_empty() {
                total_size.saturating_sub(1)
            } else {
                end.parse().ok()?
            };

            if start > end || start >= total_size {
                continue;
            }

            ranges.push((start, end.min(total_size - 1)));
        }

        if ranges.is_empty() {
            return None;
        }

        Some(Self { ranges, total_size })
    }

    pub fn is_single_range(&self) -> bool {
        self.ranges.len() == 1
    }

    pub fn get_range(&self) -> Option<(u64, u64)> {
        if self.is_single_range() {
            Some(self.ranges[0])
        } else {
            None
        }
    }

    pub fn get_ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }
}

pub fn serve_range(
    data: &[u8],
    range_header: Option<&str>,
    content_type: &str,
    filename: Option<&str>,
) -> RangeResponse {
    let total_size = data.len() as u64;

    let Some(range_header) = range_header else {
        return RangeResponse {
            status: StatusCode::OK,
            headers: headers_for_full_file(total_size, content_type, filename),
            body: data.to_vec(),
            content_range: None,
        };
    };

    let Some(range) = RangeRequest::parse(range_header, total_size) else {
        return RangeResponse {
            status: StatusCode::RANGE_NOT_SATISFIABLE,
            headers: HeaderMap::new(),
            body: Vec::new(),
            content_range: Some(format!("bytes */{}", total_size)),
        };
    };

    if range.is_single_range() {
        let (start, end) = range.get_range().unwrap();
        let body = data[start as usize..=end as usize].to_vec();

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        headers.insert(
            header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", start, end, total_size)).unwrap(),
        );
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type).unwrap(),
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

        if let Some(name) = filename {
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("inline; filename=\"{}\"", name)).unwrap(),
            );
        }

        return RangeResponse {
            status: StatusCode::PARTIAL_CONTENT,
            headers,
            body,
            content_range: Some(format!("bytes {}-{}/{}", start, end, total_size)),
        };
    }

    let boundary = "THIS_STRING_SEPARATES";
    let mut body = Vec::new();

    for (start, end) in range.get_ranges() {
        let part = &data[*start as usize..=*end as usize];

        body.extend_from_slice(boundary.as_bytes());
        body.push(b'\r');
        body.push(b'\n');
        body.extend_from_slice(format!("Content-Type: {}\r\n", content_type).as_bytes());
        body.extend_from_slice(
            format!("Content-Range: bytes {}-{}/{}\r\n", start, end, total_size).as_bytes(),
        );
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(part);
        body.extend_from_slice(b"\r\n");
    }

    let body_len = body.len();
    body.extend_from_slice(boundary.as_bytes());

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&format!("multipart/byteranges; boundary={}", boundary)).unwrap(),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body_len));
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    RangeResponse {
        status: StatusCode::PARTIAL_CONTENT,
        headers,
        body,
        content_range: None,
    }
}

fn headers_for_full_file(total_size: u64, content_type: &str, filename: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(total_size));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).unwrap(),
    );
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    if let Some(name) = filename {
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("inline; filename=\"{}\"", name)).unwrap(),
        );
    }

    headers
}
