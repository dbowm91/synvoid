import init, * as bindings from '/admin-ui-728a4aa4d454b6e.js';
const wasm = await init({ module_or_path: '/admin-ui-728a4aa4d454b6e_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

