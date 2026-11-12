import init, * as bindings from '/admin-ui-5fcde02bd4dd84ea.js';
const wasm = await init({ module_or_path: '/admin-ui-5fcde02bd4dd84ea_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

