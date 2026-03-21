use once_cell::sync::Lazy;
use rand::Rng;
use std::collections::HashMap;

static CORPORA: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        "The quick brown fox jumps over the lazy dog. This is a sample text for generating realistic content that appears natural and readable.",
        "In the world of technology, innovations are constantly emerging. Companies and developers work tirelessly to create new solutions that improve our daily lives.",
        "Web development has evolved significantly over the years. From static HTML pages to dynamic web applications, the landscape continues to change.",
        "Data science and machine learning have become essential tools for businesses. Analytics help organizations make informed decisions based on patterns.",
        "Cloud computing offers scalable resources for businesses of all sizes. Infrastructure as a service provides flexibility and cost-effectiveness.",
        "Security remains a top priority in modern applications. Best practices include encryption, authentication, and regular vulnerability assessments.",
        "APIs enable communication between different software systems. RESTful architectures have become the standard for web services.",
        "Database optimization improves application performance. Indexing, caching, and query optimization are critical for large-scale systems.",
        "Containerization simplifies deployment and scaling. Docker and Kubernetes have revolutionized how applications are packaged and managed.",
        "DevOps practices bridge development and operations. Continuous integration and deployment streamline the release process.",
    ]
});

pub struct MarkovChain {
    model: HashMap<String, Vec<String>>,
    order: usize,
}

impl Default for MarkovChain {
    fn default() -> Self {
        Self::new()
    }
}

impl MarkovChain {
    pub fn new() -> Self {
        let mut model = HashMap::new();
        let order = 2;

        for text in CORPORA.iter() {
            let words: Vec<String> = text.split_whitespace().map(|s| s.to_string()).collect();

            for window in words.windows(order + 1) {
                let key = window[..order].join(" ");
                let value = window[order].clone();
                model.entry(key).or_insert_with(Vec::new).push(value);
            }
        }

        Self { model, order }
    }

    pub fn with_custom_corpus(corpus: Vec<String>, order: usize) -> Self {
        let mut model = HashMap::new();

        for text in corpus {
            let words: Vec<String> = text.split_whitespace().map(|s| s.to_string()).collect();

            if words.len() <= order {
                continue;
            }

            for window in words.windows(order + 1) {
                let key = window[..order].join(" ");
                let value = window[order].clone();
                model.entry(key).or_insert_with(Vec::new).push(value);
            }
        }

        Self { model, order }
    }

    pub fn generate_sentence(&self, min_words: usize, max_words: usize) -> String {
        let mut rng = rand::rng();
        let target_words = rng.random_range(min_words..=max_words);

        let first_key = self
            .model
            .keys()
            .find(|k| k.chars().next().map(|c| c.is_uppercase()).unwrap_or(false))
            .cloned();

        let mut words: Vec<String> = if let Some(key) = first_key {
            key.split_whitespace().map(|s| s.to_string()).collect()
        } else {
            vec!["The".to_string()]
        };

        if words.is_empty() {
            words.push("The".to_string());
        }

        while words.len() < target_words {
            let key = words[words.len().saturating_sub(self.order)..].join(" ");

            let next_words = self.model.get(&key);

            if let Some(choices) = next_words {
                let next = choices[rng.random_range(0..choices.len())].clone();
                words.push(next);
            } else {
                let random_key = self.model.keys().nth(rng.random_range(0..self.model.len()));
                if let Some(k) = random_key {
                    words = k.split_whitespace().map(|s| s.to_string()).collect();
                }
                break;
            }
        }

        words.join(" ")
    }

    pub fn generate_sentences(&self, count: usize) -> Vec<String> {
        (0..count)
            .map(|i| {
                let (min, max) = if i == 0 { (8, 15) } else { (5, 12) };
                self.generate_sentence(min, max)
            })
            .collect()
    }

    pub fn generate_html_page(
        &self,
        current_depth: u32,
        max_depth: u32,
        links_per_page: u32,
        path_seed: &str,
    ) -> String {
        let mut rng = rand::rng();
        let sentences = self.generate_sentences(15 + rng.random_range(0..10));
        let paragraph_count = rng.random_range(3..6);

        let paragraphs: Vec<String> = sentences
            .chunks(paragraph_count)
            .map(|chunk| format!("<p>{}</p>", chunk.join(" ")))
            .collect();

        let title = self.generate_sentence(3, 6);

        let mut links = Vec::new();
        for i in 0..links_per_page {
            let link_depth = if current_depth >= max_depth {
                max_depth.saturating_sub(1)
            } else {
                current_depth + 1
            };
            let random_path = generate_random_path(&mut rng, path_seed, i as u32);
            links.push(format!(
                "<a href=\"/{}/{}\">{}</a>",
                link_depth,
                random_path,
                self.generate_sentence(2, 4)
            ));
        }

        let link_html = links.join("\n        ");

        let nav_links: Vec<String> = (0..5)
            .map(|i| {
                let random_path = generate_random_path(&mut rng, path_seed, i as u32 + 100);
                format!(
                    "<a href=\"/{}/{}\">Page {}</a>",
                    current_depth,
                    random_path,
                    i + 1
                )
            })
            .collect();

        let footer_links: Vec<String> = (0..10)
            .map(|i| {
                let random_path = generate_random_path(&mut rng, path_seed, i as u32 + 200);
                format!(
                    "<a href=\"/{}/{}\">Related Link {}</a>",
                    current_depth,
                    random_path,
                    i + 1
                )
            })
            .collect();

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
    <meta name="description" content="{}">
    <style>
        body {{
            font-family: Georgia, serif;
            line-height: 1.8;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }}
        nav {{ margin-bottom: 30px; padding: 10px; background: #f5f5f5; }}
        nav a {{ margin-right: 15px; color: #0066cc; }}
        .content {{ margin: 20px 0; }}
        p {{ margin-bottom: 15px; text-align: justify; }}
        .links-section {{ margin-top: 40px; padding: 20px; background: #f9f9f9; }}
        .links-section a {{ display: block; margin: 8px 0; color: #0066cc; }}
        footer {{ margin-top: 40px; padding: 20px; border-top: 1px solid #ddd; }}
        footer a {{ margin-right: 15px; color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <header>
        <h1>{}</h1>
    </header>
    
    <nav>
        {}
    </nav>
    
    <main class="content">
        {}
    </main>
    
    <section class="links-section">
        <h2>Explore Related Content</h2>
        {}
    </section>
    
    <footer>
        <p>Related articles:</p>
        {}
    </footer>
</body>
</html>"#,
            title,
            sentences.join(" "),
            title,
            nav_links.join("\n        "),
            paragraphs.join("\n        "),
            link_html,
            footer_links.join("\n        ")
        )
    }
}

fn generate_random_path(rng: &mut impl Rng, seed: &str, index: u32) -> String {
    let adjectives = [
        "interesting",
        "related",
        "popular",
        "latest",
        "featured",
        "recommended",
        "top",
        "best",
        "new",
        "updated",
    ];
    let nouns = [
        "article", "post", "page", "content", "resource", "guide", "tutorial", "review",
        "analysis", "overview",
    ];
    let extensions = ["html", "htm", "php", "asp", "aspx", "jsp", "do", "action"];

    let adj = adjectives[rng.random_range(0..adjectives.len())];
    let noun = nouns[rng.random_range(0..nouns.len())];
    let _ext = extensions[rng.random_range(0..extensions.len())];
    let num = rng.random_range(1000..9999);

    format!(
        "{}-{}-{}-{}{}",
        seed,
        adj,
        noun,
        num,
        if index > 0 {
            format!("-{}", index)
        } else {
            String::new()
        }
    )
}

pub fn generate_infinite_streaming_response(
    chain: &MarkovChain,
    max_depth: u32,
    links_per_page: u32,
) -> String {
    let mut rng = rand::rng();
    let current_depth = rng.random_range(0..max_depth);
    let path_seed = format!("page{}", rng.random_range(1..1000));

    chain.generate_html_page(current_depth, max_depth, links_per_page, &path_seed)
}
