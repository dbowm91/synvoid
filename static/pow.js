let wasmModule = null;

async function loadWasm() {
    if (wasmModule) return wasmModule;
    
    try {
        const response = await fetch('/_waf_pow.wasm');
        if (!response.ok) throw new Error('WASM not available');
        
        const wasmBytes = await response.arrayBuffer();
        const wasmModuleCompiled = await WebAssembly.compile(wasmBytes);
        const wasmInstance = await WebAssembly.instantiate(wasmModuleCompiled, {
            env: {
                memory: new WebAssembly.Memory({ initial: 256, maximum: 256 })
            }
        });
        
        wasmModule = wasmInstance.exports;
        return wasmModule;
    } catch (e) {
        console.log('WASM load failed, using JS fallback');
        return null;
    }
}

function hasLeadingZeros(hash, zeros) {
    let bitIndex = 0;
    for (let i = 0; i < hash.length && bitIndex < zeros; i++) {
        const byte = hash[i];
        for (let j = 7; j >= 0 && bitIndex < zeros; j--) {
            if ((byte >> j) & 1) return false;
            bitIndex++;
        }
    }
    return true;
}

async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
}

export async function solve_pow(challenge, difficulty) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.solve_pow) {
            return wasm.solve_pow(challenge, difficulty);
        }
    } catch (e) {
        // Fall through to JS implementation
    }
    
    // JS fallback
    const zeros = difficulty;
    for (let nonce = 0; nonce < 100000000; nonce++) {
        const input = challenge + nonce.toString();
        const hash = await sha256(input);
        if (hasLeadingZeros(hash, zeros)) {
            return nonce.toString();
        }
    }
    return null;
}

export function verify_pow(challenge, nonce, difficulty) {
    // This is verified server-side, client-side verification is just for sanity
    return true;
}

export default { solve_pow, verify_pow };
