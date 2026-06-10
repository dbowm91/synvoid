//! HttpResponse wrapper and conversion from hyper responses.

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: http::StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    pub async fn from_hyper(response: Response<Incoming>, max_size: Option<usize>) -> Self {
        let status = response.status();
        let headers = response.headers().clone();

        let body = if let Some(limit) = max_size {
            let limited_body = Limited::new(response.into_body(), limit);
            match limited_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    return Self {
                        status,
                        headers,
                        body: Bytes::new(),
                    }
                }
            }
        } else {
            response
                .collect()
                .await
                .map(|collected| collected.to_bytes())
                .unwrap_or_default()
        };

        Self {
            status,
            headers,
            body,
        }
    }

    pub fn status_code(&self) -> u16 {
        self.status.as_u16()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn headers_iter(
        &self,
    ) -> impl Iterator<Item = (&http::header::HeaderName, &http::HeaderValue)> {
        self.headers.iter()
    }
}
