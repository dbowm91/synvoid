use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct SkeletonProps {
    #[prop_or_default]
    pub width: String,
    #[prop_or_default]
    pub height: String,
    #[prop_or_default]
    pub rounded: bool,
}

#[function_component]
pub fn Skeleton(props: &SkeletonProps) -> Html {
    let class = if props.rounded {
        "animate-pulse bg-tertiary rounded"
    } else {
        "animate-pulse bg-tertiary"
    };

    html! {
        <div class={class} style={format!("width: {}; height: {};", props.width, props.height)} />
    }
}

#[derive(Properties, PartialEq)]
pub struct SkeletonCardProps {
    #[prop_or_default]
    pub lines: usize,
}

#[function_component]
pub fn SkeletonCard(props: &SkeletonCardProps) -> Html {
    let lines = if props.lines > 0 { props.lines } else { 3 };

    html! {
        <div class="bg-secondary rounded-lg border border-default p-6">
            <div class="flex items-center gap-3 mb-4">
                <Skeleton width="40px" height="40px" rounded={true} />
                <Skeleton width="120px" height="20px" />
            </div>
            { for (0..lines).map(|_| {
                html! {
                    <div class="mb-3">
                        <Skeleton width="80px" height="14px" />
                    </div>
                }
            })}
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct SkeletonTableProps {
    #[prop_or_default]
    pub rows: usize,
    #[prop_or_default]
    pub columns: usize,
}

#[function_component]
pub fn SkeletonTable(props: &SkeletonTableProps) -> Html {
    let rows = if props.rows > 0 { props.rows } else { 5 };
    let cols = if props.columns > 0 { props.columns } else { 4 };

    html! {
        <div class="bg-secondary rounded-lg border border-default overflow-hidden">
            <div class="border-b border-default">
                <div class="flex">
                    { for (0..cols).map(|_| {
                        html! {
                            <div class="flex-1 p-4">
                                <Skeleton width="80px" height="16px" />
                            </div>
                        }
                    })}
                </div>
            </div>
            { for (0..rows).map(|_| {
                html! {
                    <div class="border-b border-default">
                        <div class="flex">
                            { for (0..cols).map(|_| {
                                html! {
                                    <div class="flex-1 p-4">
                                        <Skeleton width="100%" height="16px" />
                                    </div>
                                }
                            })}
                        </div>
                    </div>
                }
            })}
        </div>
    }
}

#[function_component]
pub fn LoadingSpinner() -> Html {
    html! {
        <div class="flex items-center justify-center p-8">
            <div class="w-8 h-8 border-2 border-default border-t-accent rounded-full animate-spin" />
        </div>
    }
}

#[function_component]
pub fn LoadingPage() -> Html {
    html! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <Skeleton width="200px" height="32px" />
                <Skeleton width="100px" height="40px" rounded={true} />
            </div>
            <SkeletonCard lines={4} />
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <SkeletonCard lines={3} />
                <SkeletonCard lines={3} />
            </div>
            <SkeletonTable rows={5} columns={4} />
        </div>
    }
}
