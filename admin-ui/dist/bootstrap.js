import init, * as bindings from '/admin-ui-6257c6c4f9a3a9ea.js';
const wasm = await init({ module_or_path: '/admin-ui-6257c6c4f9a3a9ea_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

