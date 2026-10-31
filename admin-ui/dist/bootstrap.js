import init, * as bindings from '/admin-ui-b5b6abcd2c5ad607.js';
const wasm = await init({ module_or_path: '/admin-ui-b5b6abcd2c5ad607_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

