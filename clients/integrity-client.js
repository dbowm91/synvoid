/**
 * Integrity Client Library
 * 
 * Provides end-to-end integrity verification for HTTP traffic flowing through
 * edge WAF nodes. This enables:
 * - Detection of tampered content from malicious edge nodes
 * - Secure key exchange with origins via global nodes
 * - Audit reporting to global nodes
 * 
 * Dependencies: TweetNaCl (https://tweetnacl.js.org/)
 * 
 * Usage:
 * <script src="https://unpkg.com/tweetnacl@1.0.3/nacl-fast.min.js"></script>
 * <script src="integrity-client.js"></script>
 * <script>
 *   const client = new IntegrityClient({
 *     keyExchangeUrl: 'https://keys.global.example.com',
 *     meshId: 'mesh-1',
 *     auditReportUrl: 'https://audit.global.example.com'
 *   });
 *   
 *   // Initialize on page load
 *   await client.init();
 *   
 *   // Or for manual verification:
 *   const result = await client.verifyResponse(response);
 * </script>
 */

class IntegrityClient {
  constructor(options = {}) {
    this.keyExchangeUrl = options.keyExchangeUrl || null;
    this.meshId = options.meshId || null;
    this.auditReportUrl = options.auditReportUrl || null;
    this.sessionId = null;
    this.sessionKey = null;
    this.verifyingKey = null;
    this.enabled = false;
    this.clientKeyPair = null;
    this.signingKeyPair = null;
    this.serverVerifyingKey = null;
    this.originVerifyingKey = null;
    this.originVerified = false;
    this.originMeshId = null;
    this.originEd25519Pubkey = null;
    this.originSignature = null;
    this.globalPubkey = null;
    
    // Post-Quantum Key Exchange
    this.mlKemKeyPair = null;  // { publicKey, secretKey }
    this.serverMlKemPubkey = null;
    this.mlKemCiphertext = null;
    
    this.auditNodes = options.auditNodes || [];
    this.allowedUpstreamIps = options.allowedUpstreamIps || [];
    this.auditTimeoutMs = options.auditTimeoutMs || 500;
    this.edgeNodeId = options.edgeNodeId || null;
    this.auditResults = null;
    this.auditCompleted = false;
    this.auditPowRequired = options.auditPowRequired || false;
    this.auditPowDifficulty = options.auditPowDifficulty || 2;
    this.auditPowTimeout = options.auditPowTimeout || 30000;
    this.auditPowChallenge = options.auditPowChallenge || null;
    this.auditPowSolved = false;
    this.auditPowNonce = null;
  }

  /**
   * Initialize the integrity client
   * Checks for integrity configuration headers and establishes session if available
   */
  async init(options = {}) {
    if (typeof nacl === 'undefined') {
      console.warn('Integrity: TweetNaCl not loaded');
      return false;
    }

    try {
      this.signingKeyPair = await this._generateSigningKeyPair();
    } catch (e) {
      console.warn('Integrity: Failed to generate Ed25519 signing key pair:', e);
      return false;
    }

    const runAuditOnInit = options.runAuditOnInit !== false;

    const configHeader = this._getHeader('X-Integrity-Config');
    
    if (configHeader) {
      try {
        const config = JSON.parse(configHeader);
        
        if (config.key_exchange_url) {
          this.keyExchangeUrl = config.key_exchange_url;
        }
        if (config.mesh_id) {
          this.meshId = config.mesh_id;
        }
        if (config.audit_nodes && Array.isArray(config.audit_nodes)) {
          this.auditNodes = config.audit_nodes;
        }
        if (config.allowed_upstream_ips && Array.isArray(config.allowed_upstream_ips)) {
          this.allowedUpstreamIps = config.allowed_upstream_ips;
        }
        if (config.edge_node_id) {
          this.edgeNodeId = config.edge_node_id;
        }
        
        if (config.audit_pow_required === true) {
          this.auditPowRequired = true;
          this.auditPowDifficulty = config.audit_pow_difficulty || 2;
          this.auditPowTimeout = config.audit_pow_timeout || 30000;
        }
        
        if (config.audit_pow_challenge) {
          this.auditPowChallenge = config.audit_pow_challenge;
        }
        
        const keyExchangePromise = this._initiateKeyExchange(config.mesh_id)
          .then(() => {
            this.enabled = true;
          })
          .catch(e => {
            console.warn('Integrity: Key exchange failed:', e);
            this.enabled = false;
          });
        
        let auditPromise = null;
        if (runAuditOnInit && this.auditNodes.length > 0) {
          auditPromise = this.auditMeshConvergence(this.auditNodes, this.auditTimeoutMs)
            .then(results => {
              this.auditResults = results;
              this.auditCompleted = true;
              return results;
            });
        }
        
        await Promise.allSettled([keyExchangePromise, auditPromise]);
        
        if (auditPromise) {
          const results = await auditPromise;
          if (this.auditReportUrl) {
            this._reportAuditResults(results);
          }
        }
      } catch (e) {
        console.warn('Integrity: Failed to parse config header:', e);
      }
    }
    
    return this.enabled;
  }

  /**
   * Get a header value from the current document or response
   */
  _getHeader(name) {
    const meta = document.querySelector(`meta[name="${name}"]`);
    if (meta) {
      return meta.getAttribute('content');
    }
    return null;
  }

  /**
   * Generate an X25519 key pair using TweetNaCl for key exchange
   */
  _generateKeyPair() {
    const keyPair = nacl.box.keyPair();
    return {
      publicKey: this._arrayToBase64(keyPair.publicKey),
      secretKey: keyPair.secretKey
    };
  }

  /**
   * Generate an Ed25519 key pair for message signing using Web Crypto API
   */
  async _generateSigningKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'Ed25519',
      },
      true,
      ['sign', 'verify']
    );
    
    const publicKeyExport = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKeyExport = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    return {
      publicKey: this._arrayToBase64(new Uint8Array(publicKeyExport)),
      privateKey: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
      cryptoKey: keyPair
    };
  }

  /**
   * Import an Ed25519 public key from SPKI format
   */
  async _importVerifyingKey(publicKeyBase64) {
    const publicKeyBytes = this._base64ToArray(publicKeyBase64);
    return crypto.subtle.importKey(
      'spki',
      publicKeyBytes,
      { name: 'Ed25519' },
      true,
      ['verify']
    );
  }

  /**
   * Derive a shared secret from key exchange
   * X25519 scalar multiplication
   */
  _deriveSharedSecret(clientSecretKey, serverPublicKey) {
    const sharedKey = nacl.box.before(
      this._base64ToArray(serverPublicKey),
      clientSecretKey
    );
    return sharedKey;
  }

/**
 * Generate ML-KEM-768 key pair using WASM (self-contained, no external deps)
 * Returns { publicKey, secretKey } in base64 format
 */
_generateMlKemKeyPair() {
  if (typeof window.generate_ml_kem_keypair !== 'function') {
    console.warn('Integrity: ML-KEM WASM not available - using X25519 only');
    return null;
  }
  
  try {
    const result = window.generate_ml_kem_keypair();
    return {
      publicKey: this._arrayToBase64(new Uint8Array(result.public_key)),
      secretKey: this._arrayToBase64(new Uint8Array(result.secret_key))
    };
  } catch (e) {
    console.warn('Integrity: ML-KEM key generation failed:', e);
    return null;
  }
}

/**
 * Decapsulate ML-KEM shared secret from ciphertext using WASM
 */
_decapsulateMlKem(ciphertextBase64, secretKeyBase64) {
  if (typeof window.ml_kem_decapsulate !== 'function') {
    throw new Error('ML-KEM not available - WASM not loaded');
  }
  
  try {
    const ct = this._base64ToArray(ciphertextBase64);
    const sk = this._base64ToArray(secretKeyBase64);
    
    const sharedSecret = window.ml_kem_decapsulate(ct, sk);
    return new Uint8Array(sharedSecret);
  } catch (e) {
    console.error('Integrity: ML-KEM decapsulation failed:', e);
    throw e;
  }
}

  /**
   * Derive hybrid secret from X25519 and ML-KEM secrets
   * This MUST match the Rust implementation in combine_secrets()
   */
  async _deriveHybridSecret(x25519Secret, mlKemSecret) {
    // Combine using SHA256: H(x25519_secret || "hybrid-v1" || ml_kem_secret)
    // This matches the Rust implementation in passover_key_exchange.rs
    const encoder = new TextEncoder();
    const hybridLabel = encoder.encode('hybrid-v1');
    
    const combined = new Uint8Array(x25519Secret.length + hybridLabel.length + mlKemSecret.length);
    combined.set(x25519Secret, 0);
    combined.set(hybridLabel, x25519Secret.length);
    combined.set(mlKemSecret, x25519Secret.length + hybridLabel.length);
    
    // Use SHA-256 for the combination (matches Rust implementation)
    // Note: Using SHA-256 here instead of SHA3-256 to match the Rust combine_secrets
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Derive a session key from shared secret using SHA3-256
   * This MUST match the Rust implementation in src/integrity/protocol.rs::derive_session_key
   */
  async _deriveKey(sharedSecret) {
    const salt = this._strToArray('integrity-session');
    const info = this._strToArray('waf-integrity');
    
    const combined = new Uint8Array(salt.length + info.length + sharedSecret.length);
    combined.set(salt, 0);
    combined.set(info, salt.length);
    combined.set(sharedSecret, salt.length + info.length);
    
    // Use SHA3-256 to match Rust implementation
    const hashBuffer = await crypto.subtle.digest('SHA3-256', combined);
    const hash = new Uint8Array(hashBuffer);
    return hash.slice(0, 32);
  }

  /**
   * Synchronous key derivation using SHA3-256 via Web Worker approach
   * Fallback for when async is not convenient
   */
  _deriveKeySync(sharedSecret) {
    // Simple synchronous hash using SubtleCrypto is not possible
    // This falls back to the old nacl.hash for compatibility but logs a warning
    console.warn('Using nacl.hash for key derivation - this is a security risk if not updated');
    const salt = this._strToArray('integrity-session');
    const info = this._strToArray('waf-integrity');
    
    const combined = new Uint8Array(salt.length + info.length + sharedSecret.length);
    combined.set(salt, 0);
    combined.set(info, salt.length);
    combined.set(sharedSecret, salt.length + info.length);
    
    const hash = nacl.hash(combined);
    return hash.slice(0, 32);
  }

  _strToArray(str) {
    return new TextEncoder().encode(str);
  }

  _arrayToBase64(arr) {
    const binary = String.fromCharCode.apply(null, arr);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  _base64ToArray(base64) {
    const binary = atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
    const arr = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      arr[i] = binary.charCodeAt(i);
    }
    return arr;
  }

  _generateNonce() {
    const random = nacl.randomBytes(16);
    return this._arrayToBase64(random);
  }

  /**
   * Sign data using Ed25519
   * This MUST match the Rust implementation in src/integrity/signing.rs
   */
  async _sign(data) {
    if (!this.signingKeyPair || !this.signingKeyPair.cryptoKey) {
      throw new Error('Signing key not available');
    }
    
    const message = this._strToArray(data);
    const signature = await crypto.subtle.sign(
      'Ed25519',
      this.signingKeyPair.cryptoKey.privateKey,
      message
    );
    return this._arrayToBase64(new Uint8Array(signature));
  }

  /**
   * Verify Ed25519 signature
   * This MUST match the Rust implementation in src/integrity/signing.rs
   */
  async _verify(verifyingKey, data, signatureBase64) {
    const message = this._strToArray(data);
    const sig = this._base64ToArray(signatureBase64);
    
    return crypto.subtle.verify(
      'Ed25519',
      verifyingKey,
      sig,
      message
    );
  }

  /**
   * Synchronous sign - NOT SUPPORTED for Ed25519
   */
  _signSync(key, data) {
    throw new Error('Synchronous signing not supported with Ed25519 - use async _sign()');
  }

  /**
   * Synchronous verify - NOT SUPPORTED for Ed25519
   */
  _verifySync(key, data, signature) {
    throw new Error('Synchronous verification not supported with Ed25519 - use async _verify()');
  }

  /**
   * Initiate key exchange with global node
   * Includes Ed25519 public key for message signing
   */
  async _initiateKeyExchange(meshId) {
    if (!this.keyExchangeUrl) {
      throw new Error('Key exchange URL not configured');
    }
    
    this.clientKeyPair = this._generateKeyPair();
    
    const response = await fetch(this.keyExchangeUrl + '/key-request', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        mesh_id: meshId,
        client_x25519_pubkey: this.clientKeyPair.publicKey,
        client_ed25519_pubkey: this.signingKeyPair.publicKey,
        nonce: this._generateNonce()
      })
    });
    
    if (!response.ok) {
      throw new Error('Key exchange failed: ' + response.status);
    }
    
    const data = await response.json();
    
    this.sessionId = data.session_id;
    
    const sharedSecret = this._deriveSharedSecret(
      this.clientKeyPair.secretKey,
      data.server_x25519_pubkey
    );
    this.sessionKey = await this._deriveKey(sharedSecret);
    this.verifyingKey = data.server_ed25519_pubkey;
    
    // Import the origin's Ed25519 verifying key for verifying the key-offer
    // (This is used to verify origin_signature in key-offer-origin)
    if (data.origin_ed25519_pubkey) {
      this.originVerifyingKey = await this._importVerifyingKey(data.origin_ed25519_pubkey);
    }
    
    // Send key-confirm and get the GLOBAL node's Ed25519 pubkey
    // This is used to verify subsequent HTTP responses from the global node
    const confirmResponse = await fetch(this.keyExchangeUrl + '/key-confirm', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        session_id: this.sessionId,
        client_x25519_pubkey: this.clientKeyPair.publicKey,
        client_ed25519_pubkey: this.signingKeyPair.publicKey
      })
    });
    
    if (!confirmResponse.ok) {
      throw new Error('Key confirm failed: ' + confirmResponse.status);
    }
    
    const confirmData = await confirmResponse.json();
    if (!confirmData.success) {
      throw new Error('Key confirm failed: ' + (confirmData.error || 'unknown error'));
    }
    
    // Import the global node's Ed25519 key for verifying responses
    if (confirmData.server_ed25519_pubkey) {
      this.serverVerifyingKey = await this._importVerifyingKey(confirmData.server_ed25519_pubkey);
    } else {
      throw new Error('Key confirm did not return server Ed25519 public key');
    }
  }

  /**
   * Sign an HTTP request using Ed25519
   * This MUST match the Rust implementation in src/integrity/signing.rs
   */
  async signRequest(method, path, headers = {}, body = null) {
    if (!this.sessionKey || !this.sessionId || !this.signingKeyPair) {
      return null;
    }
    
    const bodyHash = body ? this._hashBodySync(body) : null;
    const message = this._buildSignMessage(method, path, headers, bodyHash);
    const signature = await this._sign(message);
    
    return {
      'X-Integrity-Session': this.sessionId,
      'X-Integrity-Sig-HTTP': signature,
      'X-Integrity-Key-Session': this.sessionId.substring(0, 8),
      'X-Integrity-Key-Timestamp': Math.floor(Date.now() / 1000).toString(),
      'X-Integrity-Key-Nonce': this._generateNonce()
    };
  }

  /**
   * Verify an HTTP response using Ed25519
   * This MUST match the Rust implementation in src/integrity/signing.rs
   */
  async verifyResponse(response, body = null) {
    if (!this.serverVerifyingKey) {
      return { valid: false, reason: 'No server verifying key' };
    }
    
    const sessionId = response.headers.get('X-Integrity-Session');
    const signature = response.headers.get('X-Integrity-Sig-HTTP');
    const keyId = response.headers.get('X-Integrity-Key-Session');
    const timestamp = response.headers.get('X-Integrity-Key-Timestamp');
    const nonce = response.headers.get('X-Integrity-Key-Nonce');
    
    if (!sessionId || !signature) {
      return { valid: false, reason: 'No integrity headers' };
    }
    
    if (sessionId !== this.sessionId) {
      return { valid: false, reason: 'Session ID mismatch' };
    }
    
    const bodyHash = body ? this._hashBodySync(body) : null;
    const headers = this._extractSignableHeaders(response.headers);
    const message = this._buildSignMessage(
      response.status.toString(),
      null,
      headers,
      bodyHash,
      { sessionId, keyId, timestamp, nonce }
    );
    
    const valid = await this._verify(this.serverVerifyingKey, message, signature);
    
    if (!valid) {
      if (this.auditReportUrl) {
        this._reportAuditFailure('signature_mismatch', {
          session_id: sessionId,
          path: response.url
        });
      }
    }
    
    return { valid, reason: valid ? 'OK' : 'Signature mismatch' };
  }

  /**
   * Hash body content (sync version using TweetNaCl hash)
   */
  _hashBodySync(body) {
    const encoder = new TextEncoder();
    const data = typeof body === 'string' ? encoder.encode(body) : body;
    const hash = nacl.hash(data);
    return this._arrayToBase64(hash.slice(0, 32));
  }

  /**
   * Hash body content (async version using WebCrypto)
   */
  async _hashBody(body) {
    const encoder = new TextEncoder();
    const data = typeof body === 'string' ? encoder.encode(body) : body;
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    return this._arrayBufferToBase64(hashBuffer);
  }

  /**
   * Build the message that gets signed
   */
  _buildSignMessage(method, path, headers, bodyHash, headerInfo = null) {
    const parts = [];
    
    if (headerInfo) {
      parts.push(headerInfo.sessionId || '');
      parts.push(headerInfo.keyId || '');
      parts.push(headerInfo.timestamp || '');
      parts.push(headerInfo.nonce || '');
    }
    
    if (method) parts.push(method);
    if (path) parts.push(path);
    if (bodyHash) parts.push(bodyHash);
    
    // Add sorted headers
    const sortedKeys = Object.keys(headers).sort();
    for (const key of sortedKeys) {
      parts.push(`${key}:${headers[key]}`);
    }
    
    return parts.join('|');
  }

  /**
   * Extract headers that should be included in signature
   */
  _extractSignableHeaders(headers) {
    const signable = [
      'content-type',
      'content-length',
      'cache-control',
      'etag',
      'last-modified'
    ];
    
    const result = {};
    for (const key of signable) {
      const value = headers.get(key);
      if (value) {
        result[key] = value;
      }
    }
    return result;
  }

  /**
   * Report audit failure to global node
   */
  async _reportAuditFailure(failureType, details) {
    if (!this.auditReportUrl) return;
    
    try {
      await fetch(this.auditReportUrl + '/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mesh_id: this.meshId,
          edge_node_id: this.edgeNodeId || 'unknown',
          session_id: details.session_id,
          failure_type: failureType,
          details: JSON.stringify(details),
          timestamp: Math.floor(Date.now() / 1000)
        })
      });
    } catch (e) {
      console.warn('Integrity: Failed to report audit failure:', e);
    }
  }

  /**
   * Audit mesh convergence by probing other edge nodes
   * Makes parallel key exchange requests to verify routing integrity
   * @param {string[]} auditNodes - Array of edge node URLs to probe
   * @param {number} timeoutMs - Timeout in milliseconds (default 500)
   * @returns {Promise<AuditResults>} - Audit results with pass/fail status
   */
  async auditMeshConvergence(auditNodes, timeoutMs = 500) {
    if (!auditNodes || auditNodes.length === 0) {
      return {
        success: true,
        passed: true,
        results: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          timestamp: Math.floor(Date.now() / 1000)
        }
      };
    }

    const results = [];
    const totalExpected = auditNodes.length;

    const probePromises = auditNodes.map(nodeUrl => {
      const startTime = performance.now();
      return this._probeNode(nodeUrl, timeoutMs)
        .then(probeResult => {
          probeResult.latencyMs = performance.now() - startTime;
          results.push(probeResult);
          return probeResult;
        })
        .catch(error => {
          const probeResult = {
            nodeUrl,
            success: false,
            latencyMs: performance.now() - startTime,
            error: error.message || 'Probe failed',
            routedToAllowedIp: false,
            upstreamIp: null
          };
          results.push(probeResult);
          return probeResult;
        });
    });

    const timeoutPromise = new Promise(resolve => setTimeout(resolve, timeoutMs + 100));
    await Promise.race([
      Promise.all(probePromises),
      timeoutPromise
    ]);

    const passedCount = results.filter(r => r.success && r.routedToAllowedIp).length;
    const failedCount = totalExpected - passedCount;
    const overallPassed = failedCount === 0;

    const auditResults = {
      success: true,
      passed: overallPassed,
      results,
      summary: {
        total: results.length,
        passed: passedCount,
        failed: failedCount,
        timestamp: Math.floor(Date.now() / 1000)
      }
    };

    if (!overallPassed) {
      console.warn('Integrity: Mesh convergence audit failed:', auditResults.summary);
    }

    return auditResults;
  }

  /**
   * Probe a single edge node for mesh convergence verification
   */
  async _probeNode(nodeUrl, timeoutMs) {
    const probeKeyPair = this._generateKeyPair();
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(nodeUrl + '/key-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mesh_id: this.meshId,
          client_x25519_pubkey: probeKeyPair.publicKey,
          nonce: this._generateNonce(),
          _audit_probe: true
        }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          nodeUrl,
          success: false,
          error: `HTTP ${response.status}`,
          routedToAllowedIp: false,
          upstreamIp: null
        };
      }

      const data = await response.json();
      
      let upstreamIp = null;
      let routedToAllowedIp = false;

      if (data.upstream_ip) {
        upstreamIp = data.upstream_ip;
        routedToAllowedIp = this._isIpAllowed(upstreamIp);
      } else if (data.routed_to_ip) {
        upstreamIp = data.routed_to_ip;
        routedToAllowedIp = this._isIpAllowed(upstreamIp);
      } else if (this.allowedUpstreamIps.length === 0) {
        routedToAllowedIp = true;
      }

      return {
        nodeUrl,
        upstreamIp,
        routedToAllowedIp,
        nodeId: data.node_id || null,
        success: routedToAllowedIp,
        error: routedToAllowedIp ? null : `Routed to disallowed IP: ${upstreamIp}`
      };
    } catch (error) {
      clearTimeout(timeoutId);
      if (error.name === 'AbortError') {
        return {
          nodeUrl,
          success: false,
          error: 'Timeout',
          routedToAllowedIp: false,
          upstreamIp: null
        };
      }
      throw error;
    }
  }

  /**
   * Solve POW challenge (mirrors WAF POW implementation)
   * @param {string} challenge - The challenge string (timestamp:hash)
   * @param {number} difficulty - Number of leading zero bits required
   * @param {number} timeoutMs - Maximum time to spend solving
   * @returns {Promise<string|null>} - The nonce solution or null if failed
   */
  async solveAuditPow(challenge, difficulty, timeoutMs = 30000) {
    const startTime = performance.now();
    const zeros = difficulty;
    const maxNonce = 100000000;
    
    const self = this;
    
    async function sha256(text) {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return new Uint8Array(hashBuffer);
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
    
    try {
      for (let nonce = 0; nonce < maxNonce; nonce++) {
        if (performance.now() - startTime > timeoutMs) {
          console.warn('Integrity: POW timeout after', timeoutMs, 'ms');
          return null;
        }
        
        const input = challenge + nonce.toString();
        const hash = await sha256(input);
        
        if (hasLeadingZeros(hash, zeros)) {
          console.log('Integrity: POW solved with nonce', nonce, 'in', Math.round(performance.now() - startTime), 'ms');
          return nonce.toString();
        }
      }
      
      console.warn('Integrity: POW failed to find solution after', maxNonce, 'attempts');
      return null;
    } catch (error) {
      console.error('Integrity: POW solve error:', error);
      return null;
    }
  }

  /**
   * Solve and store POW solution for audit reports
   */
  async solveAuditPowIfNeeded() {
    if (!this.auditPowRequired || this.auditPowSolved) {
      return true;
    }
    
    if (!this.auditPowChallenge) {
      console.warn('Integrity: POW required but no challenge provided');
      return false;
    }
    
    const nonce = await this.solveAuditPow(
      this.auditPowChallenge,
      this.auditPowDifficulty,
      this.auditPowTimeout
    );
    
    if (nonce) {
      this.auditPowNonce = nonce;
      this.auditPowSolved = true;
      return true;
    }
    
    return false;
  }

  /**
   * Sign audit results using Ed25519
   */
  async signAuditResults(auditResults) {
    if (!this.signingKeyPair) {
      console.warn('Integrity: No signing key available for signing');
      return null;
    }
    
    const message = JSON.stringify(auditResults);
    const signature = await this._sign(message);
    return signature;
  }

  /**
   * Check if an IP is in the allowed list (supports CIDR notation)
   */
  _isIpAllowed(ip) {
    if (!ip || this.allowedUpstreamIps.length === 0) {
      return this.allowedUpstreamIps.length === 0;
    }

    for (const allowed of this.allowedUpstreamIps) {
      if (this._ipMatches(ip, allowed)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if IP matches allowed pattern (supports IP or CIDR)
   */
  _ipMatches(ip, pattern) {
    if (ip === pattern) return true;
    
    if (pattern.includes('/')) {
      if (ip.includes(':')) {
        return this._ipv6CidrContains(pattern, ip);
      }
      return this._ipv4CidrContains(pattern, ip);
    }
    
    return false;
  }

  /**
   * Check if IPv4 is within CIDR range
   */
  _ipv4CidrContains(cidr, ip) {
    const [range, bits] = cidr.split('/');
    const mask = ~(2 ** (32 - parseInt(bits)) - 1) >>> 0;
    
    const ipInt = this._ipv4ToInt(ip);
    const rangeInt = this._ipv4ToInt(range);
    
    return (ipInt & mask) === (rangeInt & mask);
  }

  /**
   * Check if IPv6 is within CIDR range
   */
  _ipv6CidrContains(cidr, ip) {
    const [range, bits] = cidr.split('/');
    const prefixLen = parseInt(bits);
    
    const ipParts = this._ipv6ToParts(ip);
    const rangeParts = this._ipv6ToParts(range);
    
    const fullBytes = Math.floor(prefixLen / 8);
    const remainingBits = prefixLen % 8;
    
    for (let i = 0; i < fullBytes; i++) {
      if (ipParts[i] !== rangeParts[i]) return false;
    }
    
    if (remainingBits > 0 && fullBytes < 16) {
      const mask = 0xFF << (8 - remainingBits);
      if ((ipParts[fullBytes] & mask) !== (rangeParts[fullBytes] & mask)) return false;
    }
    
    return true;
  }

  /**
   * Convert IPv4 string to number
   */
  _ipv4ToInt(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
  }

  /**
   * Convert IPv6 string to array of 16 bytes
   */
  _ipv6ToParts(ip) {
    const parts = [];
    let doubleColonIndex = -1;
    
    const ipLower = ip.toLowerCase();
    const segments = ipLower.split(':');
    
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === '') {
        if (i === 0 || i === segments.length - 1) {
          parts.push(0);
        } else {
          doubleColonIndex = parts.length;
        }
      } else {
        if (segments[i].includes('.')) {
          const ipv4Parts = segments[i].split('.');
          parts.push((parseInt(ipv4Parts[0]) << 8) | parseInt(ipv4Parts[1]));
          parts.push((parseInt(ipv4Parts[2]) << 8) | parseInt(ipv4Parts[3]));
        } else {
          parts.push(parseInt(segments[i], 16));
        }
      }
    }
    
    if (doubleColonIndex >= 0) {
      const missing = 8 - parts.length;
      parts.splice(doubleColonIndex, 0, ...Array(missing).fill(0));
    }
    
    while (parts.length < 8) {
      parts.push(0);
    }
    
    return parts.slice(0, 8);
  }

  /**
   * Report audit results to the edge node
   */
  async _reportAuditResults(auditResults) {
    if (!this.auditReportUrl) return;

    const payload = {
      mesh_id: this.meshId,
      edge_node_id: this.edgeNodeId,
      session_id: this.sessionId,
      audit_results: auditResults,
      timestamp: Math.floor(Date.now() / 1000)
    };

    if (this.auditPowRequired) {
      if (!this.auditPowSolved) {
        const solved = await this.solveAuditPowIfNeeded();
        if (!solved) {
          console.warn('Integrity: POW not solved, skipping report');
          return;
        }
      }
      payload.pow_challenge = this.auditPowChallenge;
      payload.pow_nonce = this.auditPowNonce;
    }

    if (this.sessionKey) {
      payload.signature = await this.signAuditResults(auditResults);
    }

    try {
      await fetch(this.auditReportUrl + '/mesh/audit/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } catch (e) {
      console.warn('Integrity: Failed to report audit results:', e);
    }
  }

  /**
   * Get the last audit results
   */
  getAuditResults() {
    return this.auditResults;
  }

  /**
   * Check if audit completed and passed
   */
  isAuditPassed() {
    return this.auditCompleted && this.auditResults && this.auditResults.passed;
  }

  /**
   * Manually run mesh convergence audit
   * Can be called after init() to re-run audit with different nodes
   * @param {string[]} nodes - Optional custom nodes to audit (uses configured auditNodes if not provided)
   * @param {number} timeout - Optional timeout in ms
   * @returns {Promise<AuditResults>}
   */
  async runAudit(nodes = null, timeout = null) {
    const auditNodes = nodes || this.auditNodes;
    const auditTimeout = timeout || this.auditTimeoutMs;
    
    if (auditNodes.length === 0) {
      console.warn('Integrity: No audit nodes configured');
      return { success: false, passed: false, error: 'No audit nodes configured' };
    }
    
    this.auditResults = await this.auditMeshConvergence(auditNodes, auditTimeout);
    this.auditCompleted = true;
    
    if (this.auditReportUrl) {
      this._reportAuditResults(this.auditResults);
    }
    
    return this.auditResults;
  }

  /**
   * Generate a random nonce
   */
  _generateNonce() {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return this._arrayBufferToBase64(bytes);
  }

  /**
   * Convert ArrayBuffer to base64
   */
  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 to ArrayBuffer
   */
  _base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Initiate origin-signed key exchange with global node
   * This ensures the session key is signed by the origin's mesh Ed25519 key
   */
  async _initiateOriginKeyExchange(meshId) {
    if (!this.keyExchangeUrl) {
      throw new Error('Key exchange URL not configured');
    }
    
    this.clientKeyPair = this._generateKeyPair();
    
    // Generate ML-KEM key pair if available (for post-quantum security)
    // This uses self-contained WASM - no external dependencies
    if (this._generateMlKemKeyPair) {
      try {
        this.mlKemKeyPair = this._generateMlKemKeyPair();
      } catch (e) {
        console.warn('Integrity: ML-KEM key generation failed, using X25519 only:', e);
        this.mlKemKeyPair = null;
      }
    }
    
    const requestBody = {
      mesh_id: meshId,
      client_x25519_pubkey: this.clientKeyPair.publicKey,
      nonce: this._generateNonce()
    };
    
    // Add ML-KEM public key if available (for hybrid post-quantum security)
    if (this.mlKemKeyPair && this.mlKemKeyPair.publicKey) {
      requestBody.client_ml_kem_pubkey = this.mlKemKeyPair.publicKey;
    }
    
    const response = await fetch(this.keyExchangeUrl + '/key-request-origin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });
    
    if (!response.ok) {
      throw new Error('Origin key exchange failed: ' + response.status);
    }
    
    const data = await response.json();
    
    if (data.type !== 'key_offer_origin') {
      throw new Error('Unexpected response type: ' + data.type);
    }
    
    this.sessionId = data.session_id;
    this.originMeshId = data.origin_mesh_id;
    this.originEd25519Pubkey = data.origin_ed25519_pubkey;
    this.originSignature = data.origin_signature;
    this.globalPubkey = data.server_ed25519_pubkey;
    
    // Store ML-KEM data from response for hybrid key derivation
    this.serverMlKemPubkey = data.server_ml_kem_pubkey || null;
    this.mlKemCiphertext = data.ml_kem_ciphertext || null;
    
    const originValid = this._verifyOriginSignature(
      data.origin_ed25519_pubkey,
      data.session_id,
      data.key_id,
      data.mesh_id,
      data.server_x25519_pubkey,
      data.expires_at,
      data.origin_signature
    );
    
    if (!originValid) {
      throw new Error('Origin signature verification failed');
    }
    
    this.originVerified = true;
    
    // Derive X25519 shared secret
    const x25519Secret = this._deriveSharedSecret(
      this.clientKeyPair.secretKey,
      data.server_x25519_pubkey
    );
    
    // If ML-KEM ciphertext is present, derive hybrid secret
    let sharedSecret;
    if (this.mlKemCiphertext && this.mlKemKeyPair && this.mlKemKeyPair.secretKey) {
      // Hybrid mode: combine X25519 and ML-KEM secrets
      try {
        // WASM ml_kem_decapsulate returns a Promise
        const mlKemSecret = await this._decapsulateMlKem(
          this.mlKemCiphertext,
          this.mlKemKeyPair.secretKey
        );
        sharedSecret = await this._deriveHybridSecret(x25519Secret, mlKemSecret);
        console.log('Integrity: Using hybrid X25519+ML-KEM session key');
      } catch (e) {
        console.warn('Integrity: ML-KEM decapsulation failed, using X25519 only:', e);
        sharedSecret = x25519Secret;
      }
    } else {
      // Classical mode: X25519 only
      sharedSecret = x25519Secret;
    }
    
    this.sessionKey = await this._deriveKey(sharedSecret);
    this.verifyingKey = data.origin_ed25519_pubkey;
    
    await fetch(this.keyExchangeUrl + '/key-confirm', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        session_id: this.sessionId,
        client_x25519_pubkey: this.clientKeyPair.publicKey
      })
    });
  }

  /**
   * Verify origin Ed25519 signature
   * Requires TweetNaCl library with sign.detached_verify support
   * If not available, verification will fail for security
   */
  _verifyOriginSignature(pubkeyB64, sessionId, keyId, meshId, serverPubkey, expiresAt, signatureB64) {
    if (typeof nacl === 'undefined') {
      console.error('Integrity: TweetNaCl not loaded - cannot verify origin signature');
      return false;
    }
    
    if (!nacl.sign) {
      console.error('Integrity: Ed25519 support not available - cannot verify origin signature');
      console.error('Integrity: Include tweetnacl-sign or tweetnacl library for Ed25519 verification');
      return false;
    }
    
    try {
      const message = `${sessionId}|${keyId}|${meshId}|${serverPubkey}|${expiresAt}`;
      const messageBytes = this._strToArray(message);
      const sigBytes = this._base64ToArray(signatureB64);
      const pubkeyBytes = this._base64ToArray(pubkeyB64);
      
      if (nacl.sign.detached_verify) {
        return nacl.sign.detached_verify(messageBytes, sigBytes, pubkeyBytes);
      }
      
      console.error('Integrity: Ed25519 detached verify not available');
      return false;
    } catch (e) {
      console.error('Integrity: Origin signature verification error:', e);
      return false;
    }
  }

  /**
   * Check if origin was verified for this session
   */
  isOriginVerified() {
    return this.originVerified;
  }
}

// Export for use
window.IntegrityClient = IntegrityClient;
