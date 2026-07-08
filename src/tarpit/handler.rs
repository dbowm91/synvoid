use super::MarkovChain;
use super::TarpitConfig;
use metrics::{counter, histogram};
use rand::Rng;
use std::sync::Arc;
use synvoid_tarpit::admission::TarpitAdmission;
use synvoid_tarpit::budget::SessionBudget;
use synvoid_tarpit::config::RedirectPolicy;
use synvoid_tarpit::escaping::{
    html_attr_escape, html_escape, sanitize_redirect_target, url_path_encode,
};
use tokio::time::{sleep, Duration};

pub struct TarpitHandler {
    chain: Arc<MarkovChain>,
    config: TarpitConfig,
    admission: TarpitAdmission,
}

impl TarpitHandler {
    pub fn new(config: TarpitConfig) -> Self {
        let admission =
            TarpitAdmission::new(config.admission.max_concurrent, config.admission.max_per_ip);
        Self {
            chain: Arc::new(MarkovChain::new()),
            config,
            admission,
        }
    }

    pub fn with_custom_corpus(config: TarpitConfig, corpus: Vec<String>) -> Self {
        let admission =
            TarpitAdmission::new(config.admission.max_concurrent, config.admission.max_per_ip);
        Self {
            chain: Arc::new(MarkovChain::with_custom_corpus(corpus, 2)),
            config,
            admission,
        }
    }

    pub async fn handle_request(&self, path: &str, _user_agent: Option<&str>) -> String {
        let start = std::time::Instant::now();

        let depth = self.extract_depth_from_path(path);
        let path_seed = self.generate_path_seed(path);

        if self.config.response_delay_ms > 0 {
            sleep(Duration::from_millis(self.config.response_delay_ms)).await;
        }

        let effective_max_depth = self.config.max_depth.max(1);
        let content = self.chain.generate_html_page(
            depth,
            effective_max_depth,
            self.config.links_per_page,
            &path_seed,
        );

        counter!("synvoid.tarpit.requests").increment(1);
        counter!("synvoid.tarpit.admitted").increment(1);
        histogram!("synvoid.tarpit.response_time").record(start.elapsed());

        content
    }

    pub fn stream_request(
        &self,
        path: &str,
        _user_agent: Option<&str>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
        let depth = self.extract_depth_from_path(path);
        let path_seed = self.generate_path_seed(path);
        let chain = self.chain.clone();
        let max_depth = self.config.max_depth.max(1);
        let links_per_page = self.config.links_per_page;
        let budget = SessionBudget::new(self.config.budget.clone());
        let fingerprint = self.config.fingerprint.clone();

        async_stream::try_stream! {
            let session_seed: u64 = {
                let mut rng = rand::rng();
                rng.random()
            };

            let content_type = if fingerprint.vary_content_type {
                let types = [
                    "text/html; charset=utf-8",
                    "text/html",
                ];
                types[session_seed as usize % types.len()]
            } else {
                "text/html; charset=utf-8"
            };

            let title = chain.generate_sentence(3, 6);
            let escaped_title = html_escape(&title);
            yield bytes::Bytes::from(format!(
                "<!DOCTYPE html><html><head><title>{}</title><meta http-equiv=\"Content-Type\" content=\"{}\"></head><body>\n",
                escaped_title,
                content_type
            ));

            let mut total_bytes: u64 = 0;

            loop {
                if budget.is_expired() {
                    counter!("synvoid.tarpit.timed_out").increment(1);
                    break;
                }
                if budget.is_idle() {
                    counter!("synvoid.tarpit.timed_out").increment(1);
                    break;
                }

                let sentence = chain.generate_sentence(5, 12);
                let escaped_sentence = html_escape(&sentence);
                let chunk = format!("<p>{}</p>\n", escaped_sentence);

                if !budget.record_chunk(chunk.len()) {
                    counter!("synvoid.tarpit.timed_out").increment(1);
                    break;
                }

                total_bytes += chunk.len() as u64;
                yield bytes::Bytes::from(chunk);

                for i in 0..links_per_page {
                    let random_path = format!("{}-{}", path_seed, i);
                    let link_text = chain.generate_sentence(2, 4);
                    let escaped_link_text = html_escape(&link_text);
                    let link_chunk = format!(
                        "<a href=\"/{}/{}\">{}</a>\n",
                        (depth + 1).min(max_depth),
                        url_path_encode(&random_path),
                        escaped_link_text
                    );

                    if !budget.record_chunk(link_chunk.len()) {
                        counter!("synvoid.tarpit.timed_out").increment(1);
                        return;
                    }

                    total_bytes += link_chunk.len() as u64;
                    yield bytes::Bytes::from(link_chunk);
                }

                let delay_ms = if fingerprint.max_chunk_delay_ms > fingerprint.min_chunk_delay_ms {
                    let mut rng = rand::rng();
                    rng.random_range(fingerprint.min_chunk_delay_ms..=fingerprint.max_chunk_delay_ms)
                } else {
                    fingerprint.min_chunk_delay_ms.max(1)
                };

                sleep(Duration::from_millis(delay_ms)).await;
            }

            yield bytes::Bytes::from("</body></html>");

            counter!("synvoid.tarpit.completed").increment(1);
            counter!("synvoid.tarpit.bytes_sent").increment(total_bytes);
        }
    }

    fn extract_depth_from_path(&self, path: &str) -> u32 {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        if let Some(first) = parts.first() {
            if let Ok(depth) = first.parse::<u32>() {
                return depth.min(self.config.max_depth);
            }
        }

        0
    }

    fn generate_path_seed(&self, path: &str) -> String {
        let mut rng = rand::rng();

        if path.is_empty() || path == "/" {
            return format!("page{}", rng.random_range(1..100));
        }

        let clean_path = path
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        if clean_path.len() >= 3 {
            clean_path[..clean_path.len().min(10)].to_string()
        } else {
            format!("{}{}", clean_path, rng.random_range(1..100))
        }
    }

    pub fn generate_redirect_page(
        &self,
        target_path: &str,
    ) -> Result<String, synvoid_tarpit::escaping::RedirectRejection> {
        let allowed_hosts = match &self.config.redirect_policy {
            RedirectPolicy::RelativeOnly => vec![],
            RedirectPolicy::AllowList(hosts) => hosts.clone(),
            RedirectPolicy::AllowAll => vec![],
        };

        let safe_target = sanitize_redirect_target(target_path, &allowed_hosts)?;

        let mut rng = rand::rng();
        let sentences = self.chain.generate_sentences(8);

        let escaped_target = html_attr_escape(&safe_target);
        let js_escaped_target = synvoid_tarpit::escaping::js_string_escape(&safe_target);

        let body_text = sentences.join(" ");
        let escaped_body = html_escape(&body_text);

        Ok(format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="refresh" content="0;url={}">
    <title>Redirecting...</title>
</head>
<body>
    <p>{}</p>
    <p>If you are not redirected, <a href="{}">click here</a>.</p>
    <script>setTimeout(function(){{ window.location.href = "{}"; }}, {});</script>
</body>
</html>"#,
            escaped_target,
            escaped_body,
            escaped_target,
            js_escaped_target,
            rng.random_range(1000..3000)
        ))
    }

    pub fn active_sessions(&self) -> usize {
        self.admission.active_count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TarpitRejection {
    AdmissionLimit,
}

impl std::fmt::Display for TarpitRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TarpitRejection::AdmissionLimit => write!(f, "tarpit admission limit exceeded"),
        }
    }
}
