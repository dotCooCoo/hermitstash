/**
 * API payload encryption/decryption.
 * All JSON request/response bodies are XChaCha20-Poly1305 encrypted
 * with a per-session key. Prevents plaintext API interaction
 * even with a valid session cookie.
 */
var { generateBytes } = require("./crypto");
var { xchacha20poly1305 } = require("./vendor/noble-ciphers.cjs");

// Encrypt a JSON-serializable object → base64url string
// Timestamp is embedded inside the ciphertext (authenticated by Poly1305)
// Pack: nonce(24) + ciphertext_with_tag
function encryptPayload(data, keyBase64) {
  var key = Buffer.from(keyBase64, "base64url");
  var nonce = generateBytes(24);
  var plaintext = Buffer.from(JSON.stringify({ _d: data, _t: Date.now() }), "utf8");
  var ct = xchacha20poly1305(key, nonce).encrypt(plaintext);
  return Buffer.concat([nonce, Buffer.from(ct)]).toString("base64url");
}

// Decrypt a base64url string → parsed object
// Verifies the authenticated timestamp inside the ciphertext
// Pack: nonce(24) + ciphertext_with_tag
function decryptPayload(sealed, keyBase64, replayWindow) {
  var key = Buffer.from(keyBase64, "base64url");
  var packed = Buffer.from(sealed, "base64url");
  if (packed.length < 41) return null; // nonce(24) + tag(16) + 1
  var nonce = packed.subarray(0, 24);
  var ct = packed.subarray(24);
  var plaintext = Buffer.from(xchacha20poly1305(key, nonce).decrypt(ct)).toString("utf8");
  var parsed;
  try { parsed = JSON.parse(plaintext); } catch (_e) { return null; }
  if (parsed && parsed._d !== undefined) {
    if (replayWindow && parsed._t && Math.abs(Date.now() - parsed._t) > replayWindow) {
      throw new Error("Request expired");
    }
    return parsed._d;
  }
  return parsed;
}

// Generate a random 256-bit key
function generateApiKey() {
  return generateBytes(32).toString("base64url");
}

module.exports = { encryptPayload, decryptPayload, generateApiKey };
