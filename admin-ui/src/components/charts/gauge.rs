use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct GaugeProps {
    pub value: f64,
    pub max: f64,
    pub label: String,
    pub unit: Option<String>,
}

#[function_component]
pub fn Gauge(props: &GaugeProps) -> Html {
    let percentage = (props.value / props.max * 100.0).min(100.0);
    let color_class = match percentage {
        p if p < 50.0 => "text-green-500",
        p if p < 75.0 => "text-yellow-500",
        _ => "text-red-500",
    };

    let circumference = 2.0 * std::f64::consts::PI * 45.0;
    let stroke_dashoffset = circumference * (1.0 - percentage / 100.0);

    html! {
        <div class="flex flex-col items-center">
            <div class="relative w-32 h-32">
                <svg class="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                    <circle
                        cx="50"
                        cy="50"
                        r="45"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="8"
                        class="text-tertiary"
                    />
                    <circle
                        cx="50"
                        cy="50"
                        r="45"
                        fill="none"
                        stroke="currentColor"
                        stroke-width="8"
                        stroke-dasharray={circumference.to_string()}
                        stroke-dashoffset={stroke_dashoffset.to_string()}
                        class={color_class}
                        stroke-linecap="round"
                    />
                </svg>
                <div class="absolute inset-0 flex flex-col items-center justify-center">
                    <span class={format!("text-2xl font-bold {}", color_class)}>
                        { format!("{:.0}", props.value) }
                    </span>
                    if let Some(unit) = &props.unit {
                        <span class="text-xs text-secondary">{ unit }</span>
                    }
                </div>
            </div>
            <span class="mt-2 text-sm text-secondary">{ &props.label }</span>
        </div>
    }
}
