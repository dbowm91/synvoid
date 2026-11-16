import init, * as bindings from '/admin-ui-8915bc4a3350ee1d.js';
const wasm = await init({ module_or_path: '/admin-ui-8915bc4a3350ee1d_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

