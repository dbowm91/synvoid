use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
pub struct MonthlyResetConfig {
    pub mode: MonthlyResetMode,
    pub fixed_day: Option<u32>,
}

impl Default for MonthlyResetConfig {
    fn default() -> Self {
        Self {
            mode: MonthlyResetMode::Rolling30Days,
            fixed_day: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq)]
pub enum MonthlyResetMode {
    #[serde(rename = "rolling_30_days")]
    Rolling30Days,
    #[serde(rename = "calendar_month")]
    CalendarMonth,
    #[serde(rename = "fixed_date")]
    FixedDate,
}
