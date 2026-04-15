use std::collections::HashMap;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct MultiSeriesLineChartProps {
    pub data_series: HashMap<String, Vec<f64>>,
    pub labels: Vec<String>,
    #[prop_or_default]
    pub title: Option<String>,
    #[prop_or_default]
    pub height: Option<String>,
    #[prop_or_default]
    pub show_legend: bool,
    #[prop_or_default]
    pub time_window: Option<String>,
}

const COLORS: &[&str] = &[
    "#3b82f6", // blue
    "#ef4444", // red
    "#22c55e", // green
    "#f59e0b", // amber
    "#8b5cf6", // violet
    "#ec4899", // pink
    "#06b6d4", // cyan
    "#84cc16", // lime
];

#[function_component]
pub fn MultiSeriesLineChart(props: &MultiSeriesLineChartProps) -> Html {
    let height = props.height.as_deref().unwrap_or("250px");

    if props.data_series.is_empty() || props.labels.is_empty() {
        return html! {
            <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
                <p class="text-secondary text-center">{ "No data available" }</p>
            </div>
        };
    }

    let all_values: Vec<f64> = props.data_series.values().flatten().cloned().collect();
    let max = all_values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = all_values.iter().cloned().fold(f64::INFINITY, f64::min);
    let range = (max - min).max(1.0);

    let data_len = props.labels.len();
    let paths: Vec<_> = props
        .data_series
        .iter()
        .enumerate()
        .map(|(idx, (name, data))| {
            if data.is_empty() {
                return html! {};
            }

            let color = COLORS[idx % COLORS.len()];

            let points: Vec<(f64, f64)> = data
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    let x = (i as f64 / (data_len.max(1) - 1).max(1) as f64) * 100.0;
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
                <path
                    d={path_data}
                    fill="none"
                    stroke={color}
                    stroke-width="2"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />
            }
        })
        .collect();

    let legend_items: Vec<_> = props.data_series.iter().enumerate().map(|(idx, (name, _))| {
        let color = COLORS[idx % COLORS.len()];
        html! {
            <div class="flex items-center gap-2">
                <span class="w-3 h-3 rounded-full" style={format!("background-color: {}", color)} />
                <span class="text-xs text-secondary">{ name }</span>
            </div>
        }
    }).collect();

    html! {
        <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
            if let Some(title) = &props.title {
                <div class="flex justify-between items-center mb-4">
                    <h4 class="text-sm font-medium text-secondary">{ title }</h4>
                    if let Some(window) = &props.time_window {
                        <span class="text-xs text-secondary bg-tertiary px-2 py-1 rounded">{ window }</span>
                    }
                </div>
            }
            <svg class="w-full" style={format!("height: calc({} - 50px)", height)} viewBox="0 0 100 100" preserveAspectRatio="none">
                <defs>
                    <linearGradient id="gridGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" style="stop-color:currentColor;stop-opacity:0.1" />
                        <stop offset="100%" style="stop-color:currentColor;stop-opacity:0.05" />
                    </linearGradient>
                </defs>
                {paths}
            </svg>
            if props.show_legend && !legend_items.is_empty() {
                <div class="flex flex-wrap gap-4 mt-2 justify-center">
                    {legend_items}
                </div>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct StackedAreaChartProps {
    pub data_series: HashMap<String, Vec<f64>>,
    pub labels: Vec<String>,
    #[prop_or_default]
    pub title: Option<String>,
    #[prop_or_default]
    pub height: Option<String>,
    #[prop_or_default]
    pub time_window: Option<String>,
}

#[function_component]
pub fn StackedAreaChart(props: &StackedAreaChartProps) -> Html {
    let height = props.height.as_deref().unwrap_or("250px");

    if props.data_series.is_empty() || props.labels.is_empty() {
        return html! {
            <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
                <p class="text-secondary text-center">{ "No data available" }</p>
            </div>
        };
    }

    let data_len = props.labels.len();

    let mut cumulative: Vec<f64> = vec![0.0; data_len];

    let stacked_paths: Vec<_> = props
        .data_series
        .iter()
        .enumerate()
        .map(|(idx, (name, data))| {
            let color = COLORS[idx % COLORS.len()];

            let points: Vec<(f64, f64, f64)> = data
                .iter()
                .enumerate()
                .map(|(i, &v)| {
                    let x = (i as f64 / (data_len.max(1) - 1).max(1) as f64) * 100.0;
                    let bottom = cumulative[i];
                    let top = cumulative[i] + v;
                    cumulative[i] = top;
                    (x, bottom, top)
                })
                .collect();

            let max_total = cumulative.iter().cloned().fold(0.0f64, f64::max).max(1.0);

            let area_points: String =
                points
                    .iter()
                    .enumerate()
                    .fold(String::new(), |acc, (i, (x, bottom, top))| {
                        let y_bottom = 100.0 - (bottom / max_total) * 100.0;
                        let y_top = 100.0 - (top / max_total) * 100.0;
                        if i == 0 {
                            format!("M {} {} L {} {}", x, y_bottom, x, y_top)
                        } else {
                            format!("{} L {} {} L {} {}", acc, x, y_bottom, x, y_top)
                        }
                    });

            let close_path = format!("{} Z", area_points);

            html! {
                <path
                    d={close_path}
                    fill={format!("{color}40")}
                    stroke={color}
                    stroke-width="1"
                />
            }
        })
        .collect();

    html! {
        <div class="bg-secondary rounded-lg p-4" style={format!("height: {}", height)}>
            if let Some(title) = &props.title {
                <div class="flex justify-between items-center mb-4">
                    <h4 class="text-sm font-medium text-secondary">{ title }</h4>
                    if let Some(window) = &props.time_window {
                        <span class="text-xs text-secondary bg-tertiary px-2 py-1 rounded">{ window }</span>
                    }
                </div>
            }
            <svg class="w-full" style={format!("height: calc({} - 50px)", height)} viewBox="0 0 100 100" preserveAspectRatio="none">
                {stacked_paths}
            </svg>
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct SparklineProps {
    pub data: Vec<f64>,
    #[prop_or_default]
    pub color: Option<String>,
    #[prop_or_default]
    pub width: Option<String>,
    #[prop_or_default]
    pub height: Option<String>,
}

#[function_component]
pub fn Sparkline(props: &SparklineProps) -> Html {
    let width = props.width.clone().unwrap_or_else(|| "80px".to_string());
    let height = props.height.clone().unwrap_or_else(|| "24px".to_string());
    let color = props.color.clone().unwrap_or_else(|| "#3b82f6".to_string());

    if props.data.is_empty() {
        return html! {};
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
        <svg class="inline-block" {width} {height} viewBox="0 0 100 100" preserveAspectRatio="none">
            <path
                d={path_data}
                fill="none"
                stroke={color}
                stroke-width="4"
                stroke-linecap="round"
                stroke-linejoin="round"
            />
        </svg>
    }
}
