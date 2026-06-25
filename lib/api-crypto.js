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

// Future-skew tolerance for the inner-AEAD freshness check: a `_t` up to this
// many ms ahead of server time is accepted (legitimate client clock lead).
// Bound to one constant so the nonce TTL in middleware/api-encrypt.js can be
// widened to REPLAY_WINDOW + FUTURE_SKEW_MS in lockstep — the single-use nonce
// must outlive the maximum freshness lifetime (_t + replayWindow, where _t may
// itself lead by FUTURE_SKEW_MS) or an in-window replay slips through after the
// nonce expires but before the freshness window closes.
var FUTURE_SKEW_MS = C.TIME.seconds(2);

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
  if (replayWindow) {
    // The freshness contract is hoisted ABOVE the `_d` discriminator so it
    // covers every decryptable envelope shape uniformly. `_t`/`_d` are
    // attacker-chosen plaintext sealed inside the AEAD. Fail CLOSED when the
    // caller asked for replay enforcement:
    //   * A missing `_d` is malformed — every legitimate producer (server
    //     encryptPayload above, browser public/js/api.js) co-stamps {_d,_t}.
    //     Treating a no-_d envelope as fresh would skip the timestamp checks
    //     and re-open a replay path for that one shape once the single-use
    //     nonce TTL lapses, so reject it the same way as a bad `_t`.
    //   * A missing or non-numeric `_t` would make the skew arithmetic NaN, and
    //     every comparison against NaN is false, so both the future- and
    //     expired-checks would silently pass — bypassing the window entirely.
    //   * An absolute-value window also symmetrically accepts a FUTURE-dated
    //     `_t`, which slides the staleness check past the single-use nonce's
    //     TTL (anchored to receive time) and opens a replay gap. Require a
    //     finite numeric timestamp, then reject both a future one (beyond a
    //     small clock-skew tolerance, FUTURE_SKEW_MS — the same bound the nonce
    //     TTL is widened by) and an expired one with one-sided checks.
    if (!parsed || parsed._d === undefined) {
      throw new Error("Request payload missing data");
    }
    if (typeof parsed._t !== "number" || !Number.isFinite(parsed._t)) {
      throw new Error("Request timestamp missing or invalid");
    }
    var skew = Date.now() - parsed._t;
    if (skew < -FUTURE_SKEW_MS) throw new Error("Request timestamp is in the future");
    if (skew > replayWindow) throw new Error("Request expired");
    return parsed._d;
  }
  if (parsed && parsed._d !== undefined) {
    return parsed._d;
  }
  return parsed;
}

function generateApiKey() {
  return b.crypto.generateBytes(C.BYTES.bytes(32)).toString("base64url");
}

module.exports = { encryptPayload, decryptPayload, generateApiKey, FUTURE_SKEW_MS };
