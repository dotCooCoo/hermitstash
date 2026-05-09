/**
 * API payload encryption/decryption.
 * All JSON request/response bodies are XChaCha20-Poly1305 encrypted
 * with a per-session key. Prevents plaintext API interaction
 * even with a valid session cookie.
 *
 * Wire format (base64url):
 *   [1-byte version=0x02] [24-byte nonce] [ciphertext + 16-byte Poly1305 tag]
 *
 * Plaintext is the UTF-8 encoding of {"_d": <data>, "_t": <epoch_ms>}.
 * The _t field gates an optional replay window at decrypt time.
 *
 * The on-the-wire bytes match blamejs's encryptPacked envelope so the
 * primitive is shared with the framework; the JSON wrap is HermitStash's
 * own — replay-window enforcement is HS's product concern, not blamejs's.
 */
var b = require("./vendor/blamejs");

function encryptPayload(data, keyBase64) {
  var key = Buffer.from(keyBase64, "base64url");
  var plaintext = Buffer.from(JSON.stringify({ _d: data, _t: Date.now() }), "utf8");
  return b.crypto.encryptPacked(plaintext, key).toString("base64url");
}

function decryptPayload(sealed, keyBase64, replayWindow) {
  var key = Buffer.from(keyBase64, "base64url");
  var packed = Buffer.from(sealed, "base64url");
  if (packed.length < 42) return null; // version(1) + nonce(24) + tag(16) + 1
  var plaintext;
  try {
    plaintext = b.crypto.decryptPacked(packed, key).toString("utf8");
  } catch (_e) {
    throw new Error("Decryption failed");
  }
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

function generateApiKey() {
  return b.crypto.generateBytes(32).toString("base64url");
}

module.exports = { encryptPayload, decryptPayload, generateApiKey };
