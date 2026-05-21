use crate::tarpit::generator::MarkovChain;
use crate::tarpit::TarpitConfig;
use metrics::{counter, histogram};
use rand::Rng;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

pub struct TarpitHandler {
    chain: Arc<MarkovChain>,
    config: TarpitConfig,
}

impl TarpitHandler {
    pub fn new(config: TarpitConfig) -> Self {
        Self {
            chain: Arc::new(MarkovChain::new()),
            config,
        }
    }

    pub fn with_custom_corpus(config: TarpitConfig, corpus: Vec<String>) -> Self {
        Self {
            chain: Arc::new(MarkovChain::with_custom_corpus(corpus, 2)),
            config,
        }
    }

    pub async fn handle_request(&self, path: &str, _user_agent: Option<&str>) -> String {
        let start = std::time::Instant::now();

        let depth = self.extract_depth_from_path(path);
        let path_seed = self.generate_path_seed(path);

        if self.config.response_delay_ms > 0 {
            sleep(Duration::from_millis(self.config.response_delay_ms)).await;
        }

        let content = self.chain.generate_html_page(
            depth,
            self.config.max_depth,
            self.config.links_per_page,
            &path_seed,
        );

        counter!("synvoid.tarpit.requests").increment(1);
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
        let max_depth = self.config.max_depth;
        let links_per_page = self.config.links_per_page;

        async_stream::try_stream! {
            // Initial HTML headers
            let title = chain.generate_sentence(3, 6);
            yield bytes::Bytes::from(format!(
                "<!DOCTYPE html><html><head><title>{}</title></head><body>\n",
                title
            ));

            // Drip feed sentences
            for _ in 0..100 {
                let sentence = chain.generate_sentence(5, 12);
                yield bytes::Bytes::from(format!("<p>{}</p>\n", sentence));
                
                // Add some links to keep them busy
                for i in 0..5 {
                    let random_path = format!("{}-{}", path_seed, i);
                    let link_text = chain.generate_sentence(2, 4);
                    yield bytes::Bytes::from(format!(
                        "<a href=\"/{}/{}\">{}</a>\n",
                        (depth + 1).min(max_depth),
                        random_path,
                        link_text
                    ));
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }

            yield bytes::Bytes::from("</body></html>");
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

    pub fn generate_redirect_page(&self, target_path: &str) -> String {
        let mut rng = rand::rng();

        let sentences = self.chain.generate_sentences(8);

        format!(
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
            target_path,
            sentences.join(" "),
            target_path,
            target_path,
            rng.random_range(1000..3000)
        )
    }
}
