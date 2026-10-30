import init, * as bindings from '/admin-ui-287f91c2f622558c.js';
const wasm = await init({ module_or_path: '/admin-ui-287f91c2f622558c_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

