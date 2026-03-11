use crate::components::Footer;
use yew::prelude::*;

#[function_component]
pub fn Docs() -> Html {
    let doc_sections = vec![
        (
            "Getting Started",
            vec![
                (
                    "getting-started",
                    "Getting Started",
                    "Quick start guide for new users",
                ),
                ("installation", "Installation", "Installing MaluWAF"),
                (
                    "configuration",
                    "Configuration",
                    "Configuration file reference",
                ),
            ],
        ),
        (
            "Security",
            vec![
                (
                    "attack-detection",
                    "Attack Detection",
                    "WAF attack detection rules",
                ),
                (
                    "flood-protection",
                    "Flood Protection",
                    "DDoS and flood mitigation",
                ),
                (
                    "bot-protection",
                    "Bot Protection",
                    "Bot detection and blocking",
                ),
                ("threat-level", "Threat Level", "Threat level management"),
            ],
        ),
        (
            "Advanced",
            vec![
                ("waf-mesh", "WAF Mesh", "Peer-to-peer mesh networking"),
                ("tunnels", "Tunnels", "WireGuard and tunnel support"),
                ("plugins", "Plugins", "WASM plugin system"),
                ("deployment", "Deployment", "Production deployment guide"),
            ],
        ),
        (
            "Reference",
            vec![
                ("architecture", "Architecture", "System architecture"),
                ("api-reference", "API Reference", "Admin API documentation"),
                ("developer", "Developer", "Developer guide"),
                (
                    "troubleshooting",
                    "Troubleshooting",
                    "Common issues and solutions",
                ),
            ],
        ),
    ];

    html! {
        <div class="min-h-screen bg-[var(--bg-primary)]">
            <section class="pt-32 pb-16">
                <div class="container">
                    <h1 class="text-5xl font-bold mb-4">{"Documentation"}</h1>
                    <p class="text-xl text-[var(--text-secondary)] max-w-[600px]">
                        {"Everything you need to know about MaluWAF, from getting started to advanced configuration."}
                    </p>
                </div>
            </section>
            <section class="pb-32">
                <div class="container">
                    <div class="grid grid-cols-4 gap-8">
                        {for doc_sections.iter().map(|(section_title, docs)| {
                            html! {
                                <div>
                                    <h2 class="text-lg font-semibold mb-4 text-[var(--accent-primary)]">{section_title}</h2>
                                    <div class="space-y-3">
                                        {for docs.iter().map(|(slug, title, desc)| {
                                            html! {
                                                <a href={format!("/docs/{}", slug)} class="block group">
                                                    <div class="font-medium text-[var(--text-primary)] group-hover:text-[var(--accent-primary)] transition-colors">{title}</div>
                                                    <div class="text-sm text-[var(--text-muted)]">{desc}</div>
                                                </a>
                                            }
                                        })}
                                    </div>
                                </div>
                            }
                        })}
                    </div>
                </div>
            </section>
            <Footer />
        </div>
    }
}
