use yew::prelude::*;

#[function_component]
pub fn Deployment() -> Html {
    html! {
        <section id="deployment" class="py-[100px]">
            <div class="container">
                <div class="text-center mb-16">
                    <h2 class="text-4xl font-bold mb-4">{"Deploy Your Way"}</h2>
                    <p class="text-lg text-[var(--text-secondary)] max-w-[560px] mx-auto">{"Flexible deployment options for any infrastructure"}</p>
                </div>
                <div class="grid grid-cols-3 gap-6 mt-12">
                    <div class="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-8 text-center transition-all hover:border-[var(--accent-primary)] hover:translate-y-[-4px]">
                        <div class="text-5xl mb-5">{"🐳"}</div>
                        <h3 class="text-xl mb-3">{"Docker"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm mb-5">{"Run anywhere with our official Docker image"}</p>
                        <code class="bg-[var(--bg-tertiary)] px-3 py-1 rounded text-sm text-[var(--accent-primary)]">{"docker run -p 80:80 maluwaf/maluwaf"}</code>
                    </div>
                    <div class="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-8 text-center transition-all hover:border-[var(--accent-primary)] hover:translate-y-[-4px]">
                        <div class="text-5xl mb-5">{"☸️"}</div>
                        <h3 class="text-xl mb-3">{"Kubernetes"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm mb-5">{"Native K8s support with Helm charts"}</p>
                        <code class="bg-[var(--bg-tertiary)] px-3 py-1 rounded text-sm text-[var(--accent-primary)]">{"helm install maluwaf"}</code>
                    </div>
                    <div class="bg-[var(--bg-secondary)] border border-[var(--border-color)] rounded-xl p-8 text-center transition-all hover:border-[var(--accent-primary)] hover:translate-y-[-4px]">
                        <div class="text-5xl mb-5">{"⚙️"}</div>
                        <h3 class="text-xl mb-3">{"Binary"}</h3>
                        <p class="text-[var(--text-secondary)] text-sm mb-5">{"Standalone binary for any Linux system"}</p>
                        <code class="bg-[var(--bg-tertiary)] px-3 py-1 rounded text-sm text-[var(--accent-primary)]">{"./maluwaf --config main.toml"}</code>
                    </div>
                </div>
            </div>
        </section>
    }
}
