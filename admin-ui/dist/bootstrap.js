import init, * as bindings from '/admin-ui-7f92cf9edcb3335e.js';
const wasm = await init({ module_or_path: '/admin-ui-7f92cf9edcb3335e_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

