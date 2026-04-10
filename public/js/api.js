/**
 * Client-side API payload encryption.
 * Overrides fetch() to automatically encrypt JSON requests
 * and decrypt JSON responses using the per-session XChaCha20-Poly1305 key.
 *
 * The key is delivered via window.__ak (set by the server in each page).
 * Without the key, API calls work unencrypted (graceful fallback for
 * pages that don't set it, like public landing).
 */
(function () {
  var _fetch = window.fetch;
  var _xchacha = null;

  function getKey() {
    return window.__ak || null;
  }

  // Lazy-load XChaCha20-Poly1305 from vendored noble-ciphers
  async function getXChacha() {
    if (_xchacha) return _xchacha;
    var mod = await import("/js/noble-ciphers.js");
    _xchacha = mod.xchacha20poly1305;
    return _xchacha;
  }

  // --- Base64url helpers ---

  function base64urlToBuffer(b64url) {
    var b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    var arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }

  function bufferToBase64url(buf) {
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  // --- XChaCha20-Poly1305 encrypt/decrypt ---

  async function encryptPayload(data, keyB64) {
    var xchacha = await getXChacha();
    var keyBytes = new Uint8Array(base64urlToBuffer(keyB64));
    var nonce = crypto.getRandomValues(new Uint8Array(24));
    var plaintext = new TextEncoder().encode(JSON.stringify({ _d: data, _t: Date.now() }));
    var ct = xchacha(keyBytes, nonce).encrypt(plaintext);
    // Pack: nonce(24) + ciphertext_with_tag
    var packed = new Uint8Array(24 + ct.length);
    packed.set(nonce, 0);
    packed.set(ct, 24);
    return bufferToBase64url(packed.buffer);
  }

  async function decryptPayload(sealed, keyB64) {
    var xchacha = await getXChacha();
    var keyBytes = new Uint8Array(base64urlToBuffer(keyB64));
    var packed = new Uint8Array(base64urlToBuffer(sealed));
    var nonce = packed.slice(0, 24);
    var ct = packed.slice(24);
    var decrypted = xchacha(keyBytes, nonce).decrypt(ct);
    var parsed = JSON.parse(new TextDecoder().decode(decrypted));
    return (parsed && parsed._d !== undefined) ? parsed._d : parsed;
  }

  // --- Override fetch ---

  window.fetch = async function (url, opts) {
    var ak = getKey();
    opts = opts || {};

    // Encrypt outgoing JSON body
    if (ak && opts.body && opts.headers) {
      var ct = opts.headers["Content-Type"] || opts.headers["content-type"] || "";
      if (ct.includes("application/json")) {
        try {
          var data = JSON.parse(opts.body);
          var encrypted = await encryptPayload(data, ak);
          opts.body = JSON.stringify({ _e: encrypted });
        } catch (e) {
          // If encryption fails, send unencrypted (should not happen)
        }
      }
    }

    var resp = await _fetch(url, opts);

    // Decrypt incoming JSON response
    if (ak && resp.headers.get("content-type") && resp.headers.get("content-type").includes("application/json")) {
      var clone = resp.clone();
      try {
        var body = await clone.json();
        if (body && body._e) {
          var decrypted = await decryptPayload(body._e, ak);
          // Return a new Response with decrypted data
          return new Response(JSON.stringify(decrypted), {
            status: resp.status,
            statusText: resp.statusText,
            headers: resp.headers,
          });
        }
      } catch (e) {
        console.error("API decrypt failed:", url, e.message, "ak length:", ak ? ak.length : 0);
      }
    }

    return resp;
  };
})();
