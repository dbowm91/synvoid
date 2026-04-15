use crate::components::toast::{toast_error, toast_info, toast_success, toast_warning};
use yew::hook;

pub struct UseToast;

impl UseToast {
    pub fn success(msg: &str) {
        toast_success(msg);
    }

    pub fn error(msg: &str) {
        toast_error(msg);
    }

    pub fn warning(msg: &str) {
        toast_warning(msg);
    }

    pub fn info(msg: &str) {
        toast_info(msg);
    }
}

#[hook]
pub fn use_toast() -> UseToast {
    UseToast
}
