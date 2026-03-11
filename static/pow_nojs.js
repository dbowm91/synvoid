(function() {
    const form = document.getElementById('pow-form');
    const challengeInput = form ? form.querySelector('input[name="c"]') : null;
    const difficultyInput = form ? form.querySelector('input[name="d"]') : null;
    const nonceInput = document.getElementById('pow-nonce');
    
    if (!form || !challengeInput || !difficultyInput || !nonceInput) {
        console.error('POW form elements not found');
        return;
    }
    
    const challenge = challengeInput.value;
    const difficulty = parseInt(difficultyInput.value, 10) || 6;
    const progressEl = document.getElementById('progress');
    
    function updateProgress(msg) {
        if (progressEl) progressEl.textContent = msg;
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
    
    async function runChallenge() {
        updateProgress('Computing...');
        
        const nonce = await solvePow(challenge, difficulty);
        
        if (nonce) {
            updateProgress('Solution found! Submitting...');
            nonceInput.value = nonce;
            form.submit();
        } else {
            updateProgress('Failed to find solution. Please refresh.');
        }
    }
    
    if (typeof WebAssembly !== 'undefined') {
        fetch('/_waf_pow.wasm')
            .then(r => r.arrayBuffer())
            .then(bytes => WebAssembly.compile(bytes))
            .then(module => WebAssembly.instantiate(module, {
                env: { memory: new WebAssembly.Memory({ initial: 256, maximum: 256 }) }
            }))
            .then(instance => {
                if (instance.exports.solve_pow) {
                    const nonce = instance.exports.solve_pow(challenge, difficulty);
                    if (nonce) {
                        updateProgress('Solution found! Submitting...');
                        nonceInput.value = nonce;
                        form.submit();
                        return;
                    }
                }
                return runChallenge();
            })
            .catch(() => runChallenge());
    } else {
        runChallenge();
    }
})();
