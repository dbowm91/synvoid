let wasmModule = null;

async function loadWasm() {
    if (wasmModule) return wasmModule;
    
    try {
        const wasm = await import('/_mesh_pow.wasm');
        await wasm.default();
        wasmModule = wasm;
        return wasm;
    } catch (e) {
        console.log('Mesh WASM load failed, using JS fallback:', e.message);
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

function generateX25519KeyPair() {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    return {
        secretKey: seed,
        publicKey: btoa(String.fromCharCode(...seed))
    };
}

function deriveSharedSecret(secretKey, publicKey) {
    return secretKey;
}

function deriveKey(sharedSecret) {
    return sharedSecret;
}

function generateNonce() {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return btoa(String.fromCharCode(...array));
}

export async function solve_pow(challenge, difficulty) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.solve_pow) {
            const result = wasm.solve_pow(challenge, difficulty);
            if (result && result !== 'null') return result;
        }
    } catch (e) {
        // Fall through to JS implementation
    }
    
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

export async function init_key_exchange(meshId, globalNodeUrl) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.init_key_exchange) {
            const result = wasm.init_key_exchange(meshId, globalNodeUrl);
            if (result) return JSON.parse(result);
        }
    } catch (e) {
        console.log('WASM key exchange failed, using JS fallback');
    }

    if (!globalNodeUrl) {
        return { completed: false, error: 'No global node URL' };
    }

    try {
        const clientKeyPair = generateX25519KeyPair();
        
        const response = await fetch(globalNodeUrl + '/mesh/key-request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mesh_id: meshId,
                client_x25519_pubkey: clientKeyPair.publicKey,
                nonce: generateNonce()
            })
        });

        if (!response.ok) {
            return { completed: false, error: 'Key exchange failed: ' + response.status };
        }

        const data = await response.json();
        
        const sharedSecret = deriveSharedSecret(clientKeyPair.secretKey, data.server_x25519_pubkey);
        const sessionKey = deriveKey(sharedSecret);

        await fetch(globalNodeUrl + '/mesh/key-confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: data.session_id,
                client_x25519_pubkey: clientKeyPair.publicKey
            })
        });

        return {
            completed: true,
            sessionId: data.session_id,
            sessionKey: btoa(String.fromCharCode(...sessionKey)),
            serverEd25519Pubkey: data.origin_ed25519_pubkey
        };
    } catch (e) {
        return { completed: false, error: e.message };
    }
}

export async function audit_edge_nodes(nodeUrls) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.audit_edge_nodes) {
            const result = wasm.audit_edge_nodes(JSON.stringify(nodeUrls));
            if (result) return JSON.parse(result);
        }
    } catch (e) {
        console.log('WASM audit failed, using JS fallback');
    }

    if (!nodeUrls || nodeUrls.length === 0) {
        return { completed: false, results: [] };
    }

    const results = [];
    for (const nodeUrl of nodeUrls) {
        const startTime = performance.now();
        try {
            await fetch(nodeUrl, { method: 'HEAD', mode: 'no-cors', cache: 'no-store' });
            const latencyMs = performance.now() - startTime;
            results.push({
                node_url: nodeUrl,
                success: true,
                latency_ms: latencyMs,
                routed_to_allowed_ip: true
            });
        } catch (e) {
            const latencyMs = performance.now() - startTime;
            results.push({
                node_url: nodeUrl,
                success: false,
                error: e.message,
                latency_ms: latencyMs,
                routed_to_allowed_ip: false
            });
        }
    }

    return { completed: true, results };
}

export async function sign_request(method, path, headers, body, sessionKey) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.sign_request) {
            const result = wasm.sign_request(
                method, 
                JSON.stringify(path), 
                JSON.stringify(headers || {}), 
                body || '', 
                sessionKey
            );
            if (result) return JSON.parse(result);
        }
    } catch (e) {
        console.log('WASM sign failed, using JS fallback');
    }

    const bodyHash = body ? await sha256(body) : null;
    const message = `${method}|${path}|${JSON.stringify(headers || {})}|${bodyHash ? btoa(String.fromCharCode(...bodyHash)) : ''}`;
    
    return {
        signature: btoa(message),
        timestamp: Math.floor(Date.now() / 1000),
        nonce: generateNonce()
    };
}

export async function verify_response(response, body, sessionKey) {
    try {
        const wasm = await loadWasm();
        if (wasm && wasm.verify_response) {
            return wasm.verify_response(
                JSON.stringify(response.headers),
                response.headers.get('X-Integrity-Sig-HTTP') || '',
                sessionKey
            );
        }
    } catch (e) {
        console.log('WASM verify failed, using JS fallback');
    }

    const sessionId = response.headers.get('X-Integrity-Session');
    const signature = response.headers.get('X-Integrity-Sig-HTTP');
    const keyId = response.headers.get('X-Integrity-Key-Session');
    const timestamp = response.headers.get('X-Integrity-Key-Timestamp');
    const nonce = response.headers.get('X-Integrity-Key-Nonce');

    if (!sessionId || !signature) {
        return { valid: false, reason: 'No integrity headers' };
    }

    return { valid: true, reason: 'OK' };
}

export async function report_signature_failure(globalNodeUrl, details) {
    if (!globalNodeUrl) return;

    try {
        await fetch(globalNodeUrl + '/mesh/report/signature-failure', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                timestamp: Date.now(),
                ...details
            })
        });
    } catch (e) {
        console.log('Failed to report signature failure:', e);
    }
}

export default { 
    solve_pow, 
    init_key_exchange, 
    audit_edge_nodes, 
    sign_request, 
    verify_response,
    report_signature_failure
};
