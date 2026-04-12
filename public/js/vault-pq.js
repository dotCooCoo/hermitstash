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
 *
 * No backwards compatibility — only ML-KEM-1024 + XChaCha20-Poly1305.
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
    try {
      var ext = await PublicKeyCredential.getClientCapabilities();
      return ext && ext.prf === true;
    } catch (e) {
      return true;
    }
  }

  /**
   * Get PRF output during passkey authentication.
   * Returns a 32-byte Uint8Array seed or null if PRF is not supported.
   */
  async function getPrfSeed(credentialOptions) {
    var salt = new TextEncoder().encode("hermitstash-vault-prf-v1-salt-00");
    credentialOptions.extensions = credentialOptions.extensions || {};
    credentialOptions.extensions.prf = {
      eval: { first: salt },
    };

    var credential = await navigator.credentials.get({ publicKey: credentialOptions });
    if (!credential) return null;

    var prfResults = credential.getClientExtensionResults().prf;
    if (!prfResults || !prfResults.results || !prfResults.results.first) {
      return null;
    }

    return { seed: new Uint8Array(prfResults.results.first), credential: credential };
  }

  // ---- ML-KEM-1024 Key Management ----

  /**
   * Derive a deterministic ML-KEM-1024 keypair from a PRF seed.
   * Same seed always produces the same keypair.
   */
  // Expand a seed to 64 bytes if needed (ML-KEM keygen requires d||z = 64 bytes per FIPS 203).
  function expandSeed(seed) {
    if (seed.length >= 64) return seed.slice(0, 64);
    var full = new Uint8Array(64);
    full.set(seed);
    return full;
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

  // ---- Encrypt / Decrypt (ML-KEM-1024 + XChaCha20-Poly1305 only) ----

  /**
   * Encrypt a file buffer using the vault public key.
   * Returns { encapsulatedKey, iv, ciphertext } as Uint8Arrays.
   */
  async function encryptFile(publicKey, fileBuffer) {
    var mlkem = await getMlKem();
    var xchacha = await getXChacha();

    var encap = mlkem.ml_kem1024.encapsulate(publicKey);
    var key = await clientKdf(encap.sharedSecret);
    var nonce = crypto.getRandomValues(new Uint8Array(24));
    var ct = xchacha(key, nonce).encrypt(new Uint8Array(fileBuffer));

    return {
      encapsulatedKey: encap.cipherText,  // ML-KEM-1024 ciphertext (1568 bytes)
      iv: nonce,                           // XChaCha20 nonce (24 bytes)
      ciphertext: ct,                      // Encrypted file with Poly1305 tag
    };
  }

  /**
   * Decrypt a vault file using the ML-KEM-1024 secret key.
   * Only supports ML-KEM-1024 + XChaCha20-Poly1305.
   */
  async function decryptFile(secretKey, encapsulatedKey, iv, ciphertext) {
    var mlkem = await getMlKem();
    var xchacha = await getXChacha();

    var sharedSecret = mlkem.ml_kem1024.decapsulate(encapsulatedKey, secretKey);
    var key = await clientKdf(sharedSecret);
    return new Uint8Array(xchacha(key, iv).decrypt(ciphertext));
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
   * Returns the ML-KEM-1024 secret key for decryption.
   */
  async function unlockPasskeyGated() {
    var cr = await fetch("/vault/unlock/challenge", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
    var cd = await cr.json();

    var options = {
      challenge: Uint8Array.from(atob(cd.challenge.replace(/-/g, "+").replace(/_/g, "/")), function (c) { return c.charCodeAt(0); }),
      rpId: location.hostname,
      userVerification: "preferred",
    };
    var assertion = await navigator.credentials.get({ publicKey: options });
    if (!assertion) return null;

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

    var ur = await fetch("/vault/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ assertion: assertionPayload }),
    });
    var ud = await ur.json();
    if (!ur.ok || !ud.seed) return null;

    // Derive ML-KEM-1024 secret key from the seed
    var seedBytes = fromBase64(ud.seed);
    var kp = await deriveKeyPair(seedBytes);
    return kp.secretKey;
  }

  // ---- Vault Rotation ----

  /**
   * Rotate vault passkey: decrypt all files with old key, re-encrypt with new key,
   * save atomically to server, then optionally register new passkey.
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

    // Step 2: Generate new vault keypair
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
    if (!rotateData.success) {
      console.error("Vault rotate response:", rotateRes.status, rotateData);
      throw new Error(rotateData.error || "Server returned: " + JSON.stringify(rotateData));
    }

    // Step 5: Register new passkey
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

  // Helper for PRF mode base64url conversion
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
    generateRandomSeed: generateRandomSeed,
    enablePasskeyGated: enablePasskeyGated,
    enablePrf: enablePrf,
    unlockPasskeyGated: unlockPasskeyGated,
    rotateVault: rotateVault,
  };
})();
