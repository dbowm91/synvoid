use yew::prelude::*;

#[derive(Properties, PartialEq)]
#[allow(dead_code)]
pub struct LineChartProps {
    pub data: Vec<f64>,
    pub labels: Vec<String>,
    #[prop_or_default]
    pub title: Option<String>,
    #[prop_or_default]
    pub height: Option<String>,
}

#[function_component]
pub fn LineChart(props: &LineChartProps) -> Html {
    let height = props.height.as_deref().unwrap_or("200px");

    if props.data.is_empty() {
        return html! {
            <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
                <p class="text-secondary text-center">{ "No data available" }</p>
            </div>
        };
    }

    let max = props.data.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = props.data.iter().cloned().fold(f64::INFINITY, f64::min);
    let range = (max - min).max(1.0);

    let points: Vec<(f64, f64)> = props
        .data
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = (i as f64 / (props.data.len().max(1) - 1).max(1) as f64) * 100.0;
            let y = 100.0 - ((v - min) / range) * 100.0;
            (x, y)
        })
        .collect();

    let path_data = points
        .iter()
        .enumerate()
        .fold(String::new(), |acc, (i, (x, y))| {
            if i == 0 {
                format!("M {} {}", x, y)
            } else {
                format!("{} L {} {}", acc, x, y)
            }
        });

    html! {
        <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
            if let Some(title) = &props.title {
                <h4 class="text-sm font-medium text-secondary mb-4">{ title }</h4>
            }
            <svg class="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
                <path
                    d={path_data}
                    fill="none"
                    stroke="currentColor"
                    stroke-width="2"
                    class="accent"
                />
            </svg>
        </div>
    }
}
