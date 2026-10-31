import init, * as bindings from '/admin-ui-63088aabb2b1ebf3.js';
const wasm = await init({ module_or_path: '/admin-ui-63088aabb2b1ebf3_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

