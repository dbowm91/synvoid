import init, * as bindings from '/admin-ui-b508eb6e80295677.js';
const wasm = await init({ module_or_path: '/admin-ui-b508eb6e80295677_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

