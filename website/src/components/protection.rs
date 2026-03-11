use yew::prelude::*;

#[function_component]
pub fn Protection() -> Html {
    let protections = vec![
        "SQL Injection (SQLi)",
        "Cross-Site Scripting (XSS)",
        "Server-Side Request Forgery (SSRF)",
        "Remote File Inclusion (RFI)",
        "Path Traversal",
        "Command Injection",
        "LDAP Injection",
        "XML External Entity (XXE)",
        "Template Injection (SSTI)",
        "Open Redirects",
        "Request Smuggling",
        "JWT Attacks",
    ];

    html! {
        <section id="protection" class="py-[100px] bg-[var(--bg-secondary)] relative overflow-hidden">
            <div class="features-bg">
                <div class="feature-orb feature-orb-2"></div>
            </div>
            <div class="container relative z-10">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-bold mb-4">{"Attack Detection & Prevention"}</h2>
                    <p class="text-lg text-[var(--text-secondary)] max-w-[560px] mx-auto">{"Industry-leading protection against the OWASP Top 10 and beyond"}</p>
                </div>
                <div class="grid grid-cols-2 gap-4 mt-12">
                    {for protections.iter().map(|name| {
                        html! {
                            <div class="flex items-center gap-3 bg-[var(--bg-card)] border border-[var(--border-color)] rounded-lg px-5 py-4">
                                <span class="text-[var(--success)] text-xl">{"✓"}</span>
                                <span class="font-medium">{name}</span>
                            </div>
                        }
                    })}
                </div>
            </div>
        </section>
    }
}
