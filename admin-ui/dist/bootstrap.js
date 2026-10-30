import init, * as bindings from '/admin-ui-dcf1fe494cda25d0.js';
const wasm = await init({ module_or_path: '/admin-ui-dcf1fe494cda25d0_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

