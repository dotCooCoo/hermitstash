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
var C = require("./constants");

function encryptPayload(data, keyBase64) {
  var key = Buffer.from(keyBase64, "base64url");
  var plaintext = Buffer.from(JSON.stringify({ _d: data, _t: Date.now() }), "utf8");
  return b.crypto.encryptPacked(plaintext, key).toString("base64url");
}

function decryptPayload(sealed, keyBase64, replayWindow, maxBytes) {
  var key = Buffer.from(keyBase64, "base64url");
  var packed = Buffer.from(sealed, "base64url");
  if (packed.length < 42) return null; // allow:raw-byte-literal — minimum envelope: version(1) + nonce(24) + tag(16) + 1
  var plaintext;
  try {
    plaintext = b.crypto.decryptPacked(packed, key).toString("utf8");
  } catch (_e) {
    throw new Error("Decryption failed");
  }
  // Plaintext is post-AEAD-decrypt output: XChaCha20-Poly1305 has already
  // authenticated the bytes above, tampering would have failed decryptPacked.
  // The caller (middleware/api-encrypt.js) passes the same MAX_JSON_BODY budget it
  // uses for the OUTER envelope parse — config.maxFileSize*2 on a vault upload,
  // 1 MiB otherwise — so a legitimately-large vault ciphertext parses instead of
  // silently capping to the null default and surfacing as a misleading
  // "Decryption failed". Without a budget we fall back to 16 MiB. b.safeJson
  // clamps either value to its 64 MiB ABSOLUTE_MAX, and still enforces depth +
  // key bounds + null-prototype output.
  var cap = maxBytes && maxBytes > 0 ? maxBytes : C.BYTES.mib(16);
  var parsed = b.safeJson.parseOrDefault(plaintext, null, { maxBytes: cap });
  if (parsed && parsed._d !== undefined) {
    if (replayWindow && parsed._t) {
      // `_t` is attacker-chosen plaintext sealed inside the AEAD. An absolute-value
      // window symmetrically accepts a FUTURE-dated `_t`, which slides the staleness
      // check past the single-use nonce's TTL (anchored to receive time) and opens
      // a replay gap. Reject a future timestamp (beyond a small clock-skew tolerance)
      // AND an expired one with one-sided checks.
      var skew = Date.now() - parsed._t;
      if (skew < -C.TIME.seconds(2)) throw new Error("Request timestamp is in the future");
      if (skew > replayWindow) throw new Error("Request expired");
    }
    return parsed._d;
  }
  return parsed;
}

function generateApiKey() {
  return b.crypto.generateBytes(C.BYTES.bytes(32)).toString("base64url");
}

module.exports = { encryptPayload, decryptPayload, generateApiKey };
