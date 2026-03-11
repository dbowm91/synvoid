mod app;
mod components;
mod pages;
mod services;
mod types;
mod hooks;

use wasm_bindgen::prelude::*;
use yew::Renderer;

#[wasm_bindgen(start)]
pub fn run() {
    wasm_logger::init(wasm_logger::Config::default());
    Renderer::<app::App>::new().render();
}
