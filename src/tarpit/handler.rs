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

    pub async fn handle_request(
        &self,
        path: &str,
        user_agent: Option<&str>,
    ) -> String {
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

        counter!("rustwaf.tarpit.requests").increment(1);
        histogram!("rustwaf.tarpit.response_time").record(start.elapsed());

        content
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
        let mut rng = rand::thread_rng();
        
        if path.is_empty() || path == "/" {
            return format!("page{}", rng.gen_range(1..100));
        }

        let clean_path = path.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();
        
        if clean_path.len() >= 3 {
            clean_path[..clean_path.len().min(10)].to_string()
        } else {
            format!("{}{}", clean_path, rng.gen_range(1..100))
        }
    }

    pub fn generate_redirect_page(&self, target_path: &str) -> String {
        let mut rng = rand::thread_rng();
        
        let sentences = self.chain.generate_sentences(8);
        
        format!(r#"<!DOCTYPE html>
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
            rng.gen_range(1000..3000)
        )
    }
}
