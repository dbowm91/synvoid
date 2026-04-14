(function() {
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
    
    function sha256Sync(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        // Note: crypto.subtle.digest is async, for sync we'd need a pure JS SHA256
        // For older browsers without WASM, we'll use async
        return null;
    }
    
    async function sha256(text) {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return new Uint8Array(hash);
    }
    
    async function solvePow(challenge, difficulty, cookieName, windowSecs) {
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
    
    async function runChallenge() {
        const challenge = window.__WAF_CHALLENGE__;
        const difficulty = window.__WAF_DIFFICULTY__ || 6;
        const cookieName = window.__WAF_COOKIE_NAME__ || 'waf_challenge';
        const windowSecs = window.__WAF_WINDOW_SECS__ || 300;
        
        if (!challenge) {
            console.error('No challenge found');
            return;
        }
        
        const nonce = await solvePow(challenge, difficulty, cookieName, windowSecs);
        
        if (nonce) {
            const cookieValue = nonce + ':' + challenge;
            document.cookie = cookieName + '=' + cookieValue + '; path=/; max-age=' + windowSecs + '; SameSite=Strict';
            setTimeout(function() {
                location.reload();
            }, 100);
        }
    }
    
    runChallenge();
})();
