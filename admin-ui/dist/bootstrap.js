import init, * as bindings from '/admin-ui-f2b65ffa420691e5.js';
const wasm = await init({ module_or_path: '/admin-ui-f2b65ffa420691e5_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

