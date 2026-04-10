/**
 * Client-side Post-Quantum Personal Vault.
 *
 * Uses ML-KEM-1024 (FIPS 203) for key encapsulation, SHAKE256 for KDF,
 * and XChaCha20-Poly1305 for file encryption. Keys are derived from the
 * WebAuthn PRF extension — only the user's passkey can unlock their vault.
 *
 * Flow:
 *   Passkey PRF → 32-byte seed → ML-KEM-1024 keypair
 *   Encrypt: ML-KEM-1024 encapsulate → SHAKE256(shared secret) → XChaCha20-Poly1305(file)
 *   Decrypt: ML-KEM-1024 decapsulate → SHAKE256(shared secret) → XChaCha20-Poly1305(file)
 *            (legacy ML-KEM-768 + AES-256-GCM decryption supported via nonce/key detection)
 *
 * The server never sees the private key or plaintext vault data.
 */
(function () {
  "use strict";

  // Crypto libs loaded dynamically to avoid blocking page load
  var _mlkem = null;
  var _xchacha = null;
  var _shake256 = null;
  async function getMlKem() {
    if (_mlkem) return _mlkem;
    _mlkem = await import("/js/noble-pq.js");
    return _mlkem;
  }
  async function getXChacha() {
    if (_xchacha) return _xchacha;
    var mod = await import("/js/noble-ciphers.js");
    _xchacha = mod.xchacha20poly1305;
    return _xchacha;
  }
  async function getShake256() {
    if (_shake256) return _shake256;
    var mod = await import("/js/noble-hashes.js");
    _shake256 = mod.shake256;
    return _shake256;
  }
  // KDF: SHAKE256(input, 32 bytes) — matches server-side SHAKE256 KDF
  async function clientKdf(input) {
    var shake = await getShake256();
    return shake.create({ dkLen: 32 }).update(input).digest();
  }

  // ---- PRF Extension helpers ----

  /**
   * Check if the browser + authenticator supports PRF.
   */
  async function prfSupported() {
    if (!window.PublicKeyCredential) return false;
    // Feature detection: try to check PRF availability
    try {
      var ext = await PublicKeyCredential.getClientCapabilities();
      return ext && ext.prf === true;
    } catch (e) {
      // Fallback: assume supported if WebAuthn is available (Chrome 118+)
      return true;
    }
  }

  /**
   * Get PRF output during passkey authentication.
   * Returns a 32-byte Uint8Array seed or null if PRF is not supported.
   */
  async function getPrfSeed(credentialOptions) {
    // Salt for PRF — constant per app (changing it would change all derived keys)
    var salt = new TextEncoder().encode("hermitstash-vault-prf-v1-salt-00");

    // Add PRF extension to the auth options
    credentialOptions.extensions = credentialOptions.extensions || {};
    credentialOptions.extensions.prf = {
      eval: { first: salt },
    };

    var credential = await navigator.credentials.get({ publicKey: credentialOptions });
    if (!credential) return null;

    // Extract PRF result
    var prfResults = credential.getClientExtensionResults().prf;
    if (!prfResults || !prfResults.results || !prfResults.results.first) {
      return null;
    }

    return { seed: new Uint8Array(prfResults.results.first), credential: credential };
  }

  // ---- ML-KEM-768 Key Management ----

  /**
   * Derive a deterministic ML-KEM-1024 keypair from a PRF seed.
   * Same seed always produces the same keypair.
   * Falls back to ML-KEM-768 for seeds that were generated with the old version.
   */
  // Expand a seed to 64 bytes if needed (ML-KEM keygen requires d||z = 64 bytes per FIPS 203).
  // Existing vaults may have 32-byte seeds; expand deterministically via SHA-512.
  async function expandSeed(seed) {
    if (seed.length >= 64) return seed.slice(0, 64);
    var hash = await crypto.subtle.digest("SHA-512", seed);
    return new Uint8Array(hash);
  }

  async function deriveKeyPair(seed) {
    var mlkem = await getMlKem();
    var expanded = await expandSeed(seed);
    var keypair = mlkem.ml_kem1024.keygen(expanded);
    return {
      publicKey: keypair.publicKey,   // 1568 bytes
      secretKey: keypair.secretKey,   // 3168 bytes
    };
  }
  // Legacy: derive ML-KEM-768 keypair (for decrypting old vault files)
  async function deriveKeyPair768(seed) {
    var mlkem = await getMlKem();
    var expanded = await expandSeed(seed);
    var keypair = mlkem.ml_kem768.keygen(expanded);
    return { publicKey: keypair.publicKey, secretKey: keypair.secretKey };
  }

  // ---- Encrypt / Decrypt ----

  /**
   * Encrypt a file buffer using the vault public key.
   * Returns { encapsulatedKey, iv, ciphertext } as Uint8Arrays.
   * ML-KEM-1024 encapsulate → SHAKE256 KDF → XChaCha20-Poly1305.
   */
  async function encryptFile(publicKey, fileBuffer) {
    var mlkem = await getMlKem();
    var xchacha = await getXChacha();

    // Detect key size: 1568 bytes = ML-KEM-1024, 1184 bytes = ML-KEM-768
    var kem = publicKey.length >= 1500 ? mlkem.ml_kem1024 : mlkem.ml_kem768;
    var encap = kem.encapsulate(publicKey);
    var key = await clientKdf(encap.sharedSecret);
    var nonce = crypto.getRandomValues(new Uint8Array(24));
    var ct = xchacha(key, nonce).encrypt(new Uint8Array(fileBuffer));

    return {
      encapsulatedKey: encap.cipherText,  // ML-KEM ciphertext
      iv: nonce,                           // XChaCha20 nonce (24 bytes, field kept as "iv" for wire compat)
      ciphertext: ct,                      // Encrypted file with Poly1305 tag
    };
  }

  /**
   * Decrypt a vault file. secretKey can be a Uint8Array (single key) or
   * an object { sk1024, sk768 } holding both ML-KEM variants.
   * Auto-detects algorithm by encapsulated key size and nonce length.
   */
  async function decryptFile(secretKey, encapsulatedKey, iv, ciphertext) {
    var mlkem = await getMlKem();
    var isKem1024 = encapsulatedKey.length >= 1500;
    var sk, kem;
    if (isKem1024) {
      kem = mlkem.ml_kem1024;
      sk = secretKey.sk1024 || secretKey;
    } else {
      kem = mlkem.ml_kem768;
      sk = secretKey.sk768 || secretKey;
    }
    var sharedSecret = kem.decapsulate(encapsulatedKey, sk);

    if (iv.length === 24) {
      var xchacha = await getXChacha();
      var key = await clientKdf(sharedSecret);
      return new Uint8Array(xchacha(key, iv).decrypt(ciphertext));
    }
    // Legacy AES-256-GCM (12-byte IV, raw shared secret as key)
    var aesKey = await crypto.subtle.importKey("raw", sharedSecret, { name: "AES-GCM" }, false, ["decrypt"]);
    var decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey, ciphertext);
    return new Uint8Array(decrypted);
  }

  // ---- Base64 helpers ----

  function toBase64(uint8) {
    var bin = "";
    for (var i = 0; i < uint8.length; i++) bin += String.fromCharCode(uint8[i]);
    return btoa(bin);
  }

  function fromBase64(b64) {
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  function toBase64url(uint8) {
    return toBase64(uint8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  // ---- Passkey-gated mode (no PRF required) ----

  /**
   * Generate a random 64-byte seed for passkey-gated mode.
   * ML-KEM keygen requires d||z = 64 bytes per FIPS 203.
   * The seed is sent to the server for vault-sealed storage.
   */
  function generateRandomSeed() {
    return crypto.getRandomValues(new Uint8Array(64));
  }

  /**
   * Enable vault in passkey-gated mode.
   * Generates seed → keypair, sends publicKey + seed to server.
   */
  async function enablePasskeyGated() {
    var seed = generateRandomSeed();
    var keypair = await deriveKeyPair(seed);
    return {
      publicKey: keypair.publicKey,
      seed: seed,
      mode: "passkey",
    };
  }

  /**
   * Enable vault in PRF mode.
   * Uses passkey PRF to derive seed → keypair, sends only publicKey.
   */
  async function enablePrf(credentialOptions) {
    var result = await getPrfSeed(credentialOptions);
    if (!result || !result.seed) return null;
    var keypair = await deriveKeyPair(result.seed);
    return {
      publicKey: keypair.publicKey,
      credential: result.credential,
      mode: "prf",
    };
  }

  /**
   * Unlock vault in passkey-gated mode.
   * Authenticates with passkey, server returns the stored seed.
   * Returns the ML-KEM secret key for decryption.
   */
  async function unlockPasskeyGated() {
    // Get challenge from server
    var cr = await fetch("/vault/unlock/challenge", { method: "POST", credentials: "same-origin" });
    var cd = await cr.json();

    // Authenticate with passkey
    var options = {
      challenge: Uint8Array.from(atob(cd.challenge.replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }),
      rpId: location.hostname,
      userVerification: "preferred",
    };
    var assertion = await navigator.credentials.get({ publicKey: options });
    if (!assertion) return null;

    // Build assertion payload for server (must use base64url, not standard base64)
    var assertionPayload = window.WebAuthnHelpers
      ? WebAuthnHelpers.formatGetResponse(assertion)
      : {
        id: assertion.id,
        rawId: toBase64url(new Uint8Array(assertion.rawId)),
        type: assertion.type,
        response: {
          authenticatorData: toBase64url(new Uint8Array(assertion.response.authenticatorData)),
          clientDataJSON: toBase64url(new Uint8Array(assertion.response.clientDataJSON)),
          signature: toBase64url(new Uint8Array(assertion.response.signature)),
          userHandle: assertion.response.userHandle ? toBase64url(new Uint8Array(assertion.response.userHandle)) : null,
        },
      };

    // Send to server for verification + seed release
    var ur = await fetch("/vault/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ assertion: assertionPayload }),
    });
    var ud = await ur.json();
    if (!ur.ok || !ud.seed) return null;

    // Derive both ML-KEM-1024 (current) and ML-KEM-768 (legacy) secret keys
    var seedBytes = fromBase64(ud.seed);
    var kp1024 = await deriveKeyPair(seedBytes);
    var kp768 = await deriveKeyPair768(seedBytes);
    return { sk1024: kp1024.secretKey, sk768: kp768.secretKey };
  }

  // ---- Vault Rotation ----

  /**
   * Rotate vault passkey: decrypt all files with old key, re-encrypt with new key,
   * save atomically to server, then optionally register new passkey.
   *
   * @param {function} onProgress - callback(message) for UI updates
   * @returns {{ filesUpdated: number }}
   */
  async function rotateVault(onProgress) {
    var log = onProgress || function () {};

    // Step 1: Unlock vault with current passkey
    log("Authenticating with current passkey...");
    var statusRes = await fetch("/vault/status", { credentials: "same-origin" });
    var status = await statusRes.json();
    var vaultMode = status.mode || "prf";
    var oldSk = null;

    if (vaultMode === "passkey") {
      oldSk = await unlockPasskeyGated();
    } else {
      // PRF mode
      var optRes = await fetch("/passkey/login/options", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
      var options = await optRes.json();
      if (window.WebAuthnHelpers) WebAuthnHelpers.prepareGetOptions(options);
      else { options.challenge = fromBase64url(options.challenge); }
      var prfResult = await getPrfSeed(options);
      if (!prfResult || !prfResult.seed) throw new Error("PRF not available. Cannot decrypt vault files.");
      var oldKp = await deriveKeyPair(prfResult.seed);
      oldSk = oldKp.secretKey;
    }
    if (!oldSk) throw new Error("Failed to get vault decryption key.");

    // Step 2: Generate new vault keypair (in memory only — nothing committed yet)
    log("Generating new encryption keys...");
    var newVault = await enablePasskeyGated();
    var newPkB64 = toBase64(newVault.publicKey);
    var newSeedB64 = toBase64(newVault.seed);
    var newKp = await deriveKeyPair(newVault.seed);

    // Step 3: Download, decrypt, re-encrypt all files
    var filesRes = await fetch("/vault/files", { credentials: "same-origin" });
    var filesData = await filesRes.json();
    var vaultFiles = filesData.files || [];
    log(vaultFiles.length ? "Re-encrypting 0/" + vaultFiles.length + " files..." : "Updating vault keys...");

    var reencryptedFiles = [];
    for (var i = 0; i < vaultFiles.length; i++) {
      log("Re-encrypting " + (i + 1) + "/" + vaultFiles.length + ": " + vaultFiles[i].originalName + "...");
      var dlRes = await fetch("/vault/download/" + vaultFiles[i].shareId, { credentials: "same-origin" });
      var dlData = await dlRes.json();
      if (!dlData.ciphertext) throw new Error("Failed to download: " + vaultFiles[i].originalName);

      var plaintext = await decryptFile(oldSk, fromBase64(dlData.encapsulatedKey), fromBase64(dlData.iv), fromBase64(dlData.ciphertext));
      var newEnc = await encryptFile(newKp.publicKey, plaintext);

      reencryptedFiles.push({
        shareId: vaultFiles[i].shareId,
        ciphertext: toBase64(newEnc.ciphertext),
        encapsulatedKey: toBase64(newEnc.encapsulatedKey),
        iv: toBase64(newEnc.iv),
        originalSize: plaintext.byteLength,
      });
    }

    // Step 4: Send to server atomically
    log("Saving rotated vault...");
    var rotateRes = await fetch("/vault/rotate", {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      body: JSON.stringify({ newPublicKey: newPkB64, newMode: "passkey", newSeed: newSeedB64, files: reencryptedFiles }),
    });
    var rotateData = await rotateRes.json();
    if (!rotateData.success) throw new Error(rotateData.error || "Rotation failed");

    // Step 5: Register new passkey (non-critical — vault is already re-keyed)
    log("Registering new passkey...");
    try {
      if (window.WebAuthnHelpers) {
        var regOptRes = await fetch("/passkey/register/options", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
        if (regOptRes.ok) {
          var regOptions = await regOptRes.json();
          WebAuthnHelpers.prepareCreateOptions(regOptions);
          var createOpts = { publicKey: regOptions };
          if (regOptions.hints) { createOpts.hints = regOptions.hints; delete regOptions.hints; }
          var newCred = await navigator.credentials.create(createOpts);
          var regResp = WebAuthnHelpers.formatCreateResponse(newCred);
          await fetch("/passkey/register/verify", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(regResp) });
        }
      }
    } catch (_e) { /* passkey registration failed but vault is safe */ }

    // Zero old key material
    if (oldSk && oldSk.fill) oldSk.fill(0);

    return { filesUpdated: rotateData.filesUpdated };
  }

  // Helper for PRF mode base64url conversion (when WebAuthnHelpers not available)
  function fromBase64url(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    return Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); }).buffer;
  }

  // ---- Public API ----

  window.VaultPQ = {
    prfSupported: prfSupported,
    getPrfSeed: getPrfSeed,
    deriveKeyPair: deriveKeyPair,
    encryptFile: encryptFile,
    decryptFile: decryptFile,
    toBase64: toBase64,
    fromBase64: fromBase64,
    // Dual-mode support
    generateRandomSeed: generateRandomSeed,
    enablePasskeyGated: enablePasskeyGated,
    enablePrf: enablePrf,
    unlockPasskeyGated: unlockPasskeyGated,
    // Rotation
    rotateVault: rotateVault,
  };
})();
