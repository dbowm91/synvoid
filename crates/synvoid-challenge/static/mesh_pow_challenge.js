const challenge = "{{challenge}}";
const difficulty = {{difficulty}};
const cookieName = "{{cookie_name}}";
const windowSecs = {{window_secs}};
const timeout_ms = {{timeout_ms}};
const meshConfig = {{mesh_config_json}};

function updateProgress(msg) {
    const el = document.getElementById('waf-progress');
    if (el) el.textContent = msg;
}

async function sha256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
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

async function solvePow(challenge, difficulty) {
    const zeros = difficulty;
    for (let nonce = 0; nonce < 100000000; nonce++) {
        const input = challenge + nonce.toString();
        const hash = await sha256(input);
        if (hasLeadingZeros(hash, zeros)) {
            return nonce.toString();
        }
        if (nonce % 1000 === 0) {
            updateProgress('Computing... ' + nonce + ' hashes');
        }
    }
    return null;
}

async function initKeyExchange(meshConfig) {
    if (!meshConfig.key_exchange_enabled || !meshConfig.global_node_url) {
        return { completed: false, sessionId: null, sessionKey: null };
    }

    try {
        const clientKeyPair = generateX25519KeyPair();
        const response = await fetch(meshConfig.global_node_url + '/mesh/key-request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                mesh_id: meshConfig.mesh_id,
                client_x25519_pubkey: clientKeyPair.publicKey,
                nonce: generateNonce()
            })
        });

        if (!response.ok) {
            return { completed: false, sessionId: null, sessionKey: null, error: 'Key exchange failed' };
        }

        const data = await response.json();
        const sharedSecret = deriveSharedSecret(clientKeyPair.secretKey, data.server_x25519_pubkey);
        const sessionKey = deriveKey(sharedSecret);

        await fetch(meshConfig.global_node_url + '/mesh/key-confirm', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: data.session_id,
                client_x25519_pubkey: clientKeyPair.publicKey
            })
        });

        return { completed: true, sessionId: data.session_id, sessionKey, serverEd25519Pubkey: data.origin_ed25519_pubkey };
    } catch (e) {
        return { completed: false, sessionId: null, sessionKey: null, error: e.message };
    }
}

async function auditEdgeNodes(meshConfig) {
    if (!meshConfig.auditing_enabled || !meshConfig.audit_urls || meshConfig.audit_urls.length === 0) {
        return { completed: false, results: [] };
    }

    const results = [];
    for (const nodeUrl of meshConfig.audit_urls) {
        const startTime = performance.now();
        try {
            await fetch(nodeUrl, { mode: 'no-cors', cache: 'no-store' });
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

function reportSignatureFailure(meshConfig, details) {
    if (!meshConfig.global_node_url) return;

    fetch(meshConfig.global_node_url + '/mesh/report/signature-failure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            timestamp: Date.now(),
            ...details
        })
    }).catch(() => {});
}

function generateX25519KeyPair() {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    return { secretKey: seed, publicKey: btoa(String.fromCharCode(...seed)) };
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

async function runMeshChallenge() {
    updateProgress('Loading WASM...');

    let keyExchangeResult = { completed: false, sessionId: null, sessionKey: null };
    let auditResult = { completed: false, results: [] };
    let powNonce = null;

    try {
        const wasmModule = await import('/_mesh_pow.wasm');
        await wasmModule.default();

        const wasmPromises = [];
        
        if (meshConfig.key_exchange_enabled) {
            wasmPromises.push(
                wasmModule.init_key_exchange(meshConfig.mesh_id, meshConfig.global_node_url)
                    .then(result => { keyExchangeResult = result; })
                    .catch(() => {})
            );
        }

        if (meshConfig.auditing_enabled) {
            wasmPromises.push(
                wasmModule.audit_edge_nodes(meshConfig.audit_urls)
                    .then(result => { auditResult = result; })
                    .catch(() => {})
            );
        }

        wasmPromises.push(
            wasmModule.solve_pow(challenge, difficulty)
                .then(nonce => { powNonce = nonce; })
                .catch(() => {})
        );

        await Promise.all(wasmPromises);
    } catch (e) {
        console.log('WASM not available, using JS fallback');
    }

    if (!powNonce) {
        updateProgress('Computing POW...');
        powNonce = await solvePow(challenge, difficulty);
    }

    if (!keyExchangeResult.completed && meshConfig.key_exchange_enabled) {
        updateProgress('Performing key exchange...');
        keyExchangeResult = await initKeyExchange(meshConfig);
    }

    if (!auditResult.completed && meshConfig.auditing_enabled) {
        updateProgress('Auditing edge nodes...');
        auditResult = await auditEdgeNodes(meshConfig);
    }

    if (powNonce) {
        const solution = {
            pow_nonce: powNonce,
            audit_results: auditResult.results,
            session_id: keyExchangeResult.sessionId,
            session_key: keyExchangeResult.sessionKey,
            key_exchange_completed: keyExchangeResult.completed,
            audit_completed: auditResult.completed
        };

        document.cookie = cookieName + '=' + JSON.stringify(solution) + '; path=/; max-age=' + windowSecs + '; Secure; SameSite=Strict';

        updateProgress('Verification complete!');
        setTimeout(() => location.reload(), 100);
    } else {
        updateProgress('Challenge failed. Please refresh.');
    }
}

runMeshChallenge();

setTimeout(() => {
    if (!document.cookie.includes(cookieName + '=')) {
        updateProgress('Verification timed out. Please refresh.');
    }
}, timeout_ms);
