import init, * as bindings from '/admin-ui-faefedd1e0f985e4.js';
const wasm = await init({ module_or_path: '/admin-ui-faefedd1e0f985e4_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

