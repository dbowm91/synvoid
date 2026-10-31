import init, * as bindings from '/admin-ui-552f5ea39f048dff.js';
const wasm = await init({ module_or_path: '/admin-ui-552f5ea39f048dff_bg.wasm' });


window.wasmBindings = bindings;


dispatchEvent(new CustomEvent("TrunkApplicationStarted", {detail: {wasm}}));

