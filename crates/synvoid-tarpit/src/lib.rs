//! SynVoid tarpit Markov chain generator and configuration.
//!
//! This crate provides the pure Markov chain text generation logic,
//! tarpit configuration types, escaping utilities, and admission control,
//! independent of HTTP handling.

pub mod admission;
pub mod budget;
pub mod config;
pub mod escaping;
pub mod generator;

pub use admission::{AdmissionGuard, TarpitAdmission};
pub use budget::{BudgetState, SessionBudget};
pub use config::TarpitConfig;
pub use escaping::{
    html_attr_escape, html_escape, js_string_escape, sanitize_redirect_target, url_path_encode,
};
pub use generator::MarkovChain;
