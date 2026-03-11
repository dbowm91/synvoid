use std::fs;
use std::path::PathBuf;

fn main() {
    let exe_path = std::env::current_exe().expect("Failed to get executable path");
    let exe_dir = exe_path
        .parent()
        .expect("Failed to get executable directory");
    let dist_dir = exe_dir.join("dist");

    let addr = "0.0.0.0:5999";
    println!("Website server starting on http://{}", addr);
    println!("Serving static files from: {:?}", dist_dir);

    let server = tiny_http::Server::http(addr).expect("Failed to bind to port");

    for request in server.incoming_requests() {
        let path = request.url();

        let response = match path {
            "/health" => json_response(r#"{"status":"ok"}"#),

            "/challenge" => file_response(&dist_dir, "challenge.html", "text/html"),
            "/challenge.css" => file_response(&dist_dir, "challenge.css", "text/css"),

            "/test" => file_response(&dist_dir, "test.html", "text/html"),
            "/test.css" => file_response(&dist_dir, "test.css", "text/css"),

            "/styles.css" => file_response(&dist_dir, "styles.css", "text/css"),

            // /fonts/* -> dist/fonts/*
            s if s.starts_with("/fonts/") => {
                let file_name = &s[7..];
                file_response(&dist_dir, &format!("fonts/{}", file_name), mime_type(s))
            }

            // Handle built WASM/JS files in dist root
            s if s.ends_with(".wasm") || s.ends_with(".js") => {
                let file_name = s.trim_start_matches('/');
                let mime = if s.ends_with(".wasm") {
                    "application/wasm"
                } else {
                    "application/javascript"
                };
                file_response(&dist_dir, file_name, mime)
            }

            // Handle built frontend assets (wasm/js) in dist root
            s if s.ends_with(".wasm") || s.ends_with(".js") => {
                let file_name = s.trim_start_matches('/');
                let mime = if s.ends_with(".wasm") {
                    "application/wasm"
                } else {
                    "application/javascript"
                };
                file_response(&dist_dir, file_name, mime)
            }

            // Root-level .js files -> check in dist/
            s if s.ends_with(".js") => {
                let file_name = s.trim_start_matches('/');
                file_response(&dist_dir, file_name, "application/javascript")
            }

            // SPA fallback
            _ => file_response(&dist_dir, "index.html", "text/html"),
        };

        let _ = request.respond(response);
    }
}

fn json_response(body: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_data::<Vec<u8>>(body.into())
        .with_header(header("Content-Type", "application/json"))
}

fn file_response(
    dist_dir: &PathBuf,
    path: &str,
    mime: &str,
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let full_path = dist_dir.join(path);

    match fs::read(&full_path) {
        Ok(content) => tiny_http::Response::from_data(content)
            .with_header(header("Content-Type", mime))
            .with_header(header("Cache-Control", "public, max-age=31536000")),
        Err(e) => tiny_http::Response::from_string(format!("File not found: {} - {}", path, e))
            .with_status_code(404)
            .with_header(header("Content-Type", "text/plain")),
    }
}

fn mime_type(path: &str) -> &'static str {
    if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".woff") {
        "font/woff"
    } else if path.ends_with(".ttf") {
        "font/ttf"
    } else if path.ends_with(".eot") {
        "application/vnd.ms-fontobject"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else {
        "application/octet-stream"
    }
}

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}
