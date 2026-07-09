use yew::prelude::*;

#[derive(Properties, PartialEq)]
#[allow(dead_code, unpredictable_function_pointer_comparisons)]
pub struct DataTableProps<T: PartialEq + Clone + 'static>
where
    T: PartialEq + Clone,
{
    pub columns: Vec<ColumnDef>,
    pub data: Vec<T>,
    pub row_key: fn(&T) -> String,
    pub render_cell: fn(&T, &str) -> Html,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub struct ColumnDef {
    pub key: String,
    pub label: String,
    pub sortable: Option<bool>,
}

#[function_component]
pub fn DataTable<T>(props: &DataTableProps<T>) -> Html
where
    T: PartialEq + Clone + 'static,
{
    html! {
        <div class="overflow-x-auto bg-secondary rounded-lg border border-default">
            <table class="w-full">
                <thead>
                    <tr class="border-b border-default">
                        { for props.columns.iter().map(|col| {
                            html! {
                                <th class="px-4 py-3 text-left text-sm font-medium text-secondary">
                                    { &col.label }
                                </th>
                            }
                        })}
                    </tr>
                </thead>
                <tbody>
                    if props.data.is_empty() {
                        <tr>
                            <td
                                colspan={props.columns.len().to_string()}
                                class="px-4 py-8 text-center text-secondary"
                            >
                                { "No data available" }
                            </td>
                        </tr>
                    } else {
                        { for props.data.iter().map(|row| {
                            let _key = (props.row_key)(row);
                            html! {
                                <tr class="border-b border-default hover:bg-tertiary last:border-b-0">
                                    { for props.columns.iter().map(|col| {
                                        html! {
                                            <td class="px-4 py-3 text-sm">
                                                { (props.render_cell)(row, &col.key) }
                                            </td>
                                        }
                                    })}
                                </tr>
                            }
                        })}
                    }
                </tbody>
            </table>
        </div>
    }
}
