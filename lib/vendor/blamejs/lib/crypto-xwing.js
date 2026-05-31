"use strict";
/**
 * @module b.crypto.xwing
 * @nav    Crypto
 * @title  X-Wing KEM
 *
 * @intro
 *   X-Wing is a general-purpose hybrid post-quantum / traditional key
 *   encapsulation mechanism: it runs ML-KEM-768 and X25519 side by side and
 *   binds their shared secrets with SHA3-256, so the resulting key stays
 *   secure as long as <em>either</em> ML-KEM-768 or X25519 holds. That is the
 *   conservative shape for migrating off classical ECDH today — a harvest-now-
 *   decrypt-later attacker must break the lattice KEM, and a hypothetical
 *   ML-KEM break still leaves X25519 standing.
 *
 *   The construction follows
 *   <code>draft-connolly-cfrg-xwing-kem</code>. The combiner is frozen — it
 *   hashes the ML-KEM shared secret, the X25519 shared secret, the X25519
 *   ephemeral public key, the recipient's X25519 public key, and a fixed
 *   six-byte label — but the document is still an IETF Internet-Draft, so this
 *   primitive is marked <code>experimental</code> and sits beside the other
 *   pre-RFC post-quantum drafts (<code>b.crypto.hpke.pq</code>). The wire
 *   sizes are fixed: a 1216-byte public key (ML-KEM-768 1184 ‖ X25519 32), a
 *   1120-byte ciphertext (ML-KEM-768 1088 ‖ X25519 32), a 32-byte decapsulation
 *   seed, and a 32-byte shared secret.
 *
 *   X-Wing composes the framework's vendored ML-KEM-768 and X25519 plus
 *   SHA3 — it adds no new cryptographic core, only the standard combiner and
 *   wire framing.
 *
 * @card
 *   X-Wing hybrid PQ/T KEM (`b.crypto.xwing`) — ML-KEM-768 + X25519 bound by
 *   SHA3-256 per draft-connolly-cfrg-xwing-kem, secure if either component
 *   holds. 1216-byte key, 1120-byte ciphertext, 32-byte shared secret.
 */

var nodeCrypto = require("node:crypto");
var pqc = require("./vendor/noble-post-quantum.cjs");
var { defineClass } = require("./framework-error");

var XWingError = defineClass("XWingError", { alwaysPermanent: true });

var mlkem = pqc.ml_kem768;

// draft-connolly-cfrg-xwing-kem: the combiner label, ASCII "\./" + "/^\".
var XWING_LABEL = Buffer.from("5c2e2f2f5e5c", "hex");

// Component + composite sizes (bytes), fixed by the draft — protocol wire
// widths, not buffer-capacity tunables.
var ML_KEM_PK = 1184;                  // ML-KEM-768 public key
var ML_KEM_CT = 1088;                  // ML-KEM-768 ciphertext
var X25519_LEN = 32;                   // X25519 key/share length
var SEED_LEN = 32;                     // X-Wing seed length
var SS_LEN = 32;                       // shared-secret length
var PK_LEN = ML_KEM_PK + X25519_LEN;   // 1216
var CT_LEN = ML_KEM_CT + X25519_LEN;   // 1120
var MLKEM_SEED = 64;                   // d ‖ z for ML-KEM KeyGen_internal
var EXPAND_LEN = 96;                   // SHAKE256(seed) → d ‖ z ‖ sk_X

// X25519 raw-scalar helpers via fixed PKCS8 / SPKI DER prefixes (OID
// 1.3.101.110). Node clamps the scalar per RFC 7748 on use, matching X-Wing.
var X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
var X25519_SPKI_PREFIX  = Buffer.from("302a300506032b656e032100", "hex");

function _x25519Public(sk) {
  var key = nodeCrypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, sk]), format: "der", type: "pkcs8" });
  var spki = nodeCrypto.createPublicKey(key).export({ format: "der", type: "spki" });
  return spki.subarray(spki.length - X25519_LEN);
}
function _x25519Shared(sk, pk) {
  return nodeCrypto.diffieHellman({
    privateKey: nodeCrypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, sk]), format: "der", type: "pkcs8" }),
    publicKey:  nodeCrypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, pk]), format: "der", type: "spki" }),
  });
}

function _shake256(buf, outLen) { return nodeCrypto.createHash("shake256", { outputLength: outLen }).update(buf).digest(); }

/**
 * @primitive  b.crypto.xwing.combiner
 * @signature  b.crypto.xwing.combiner(ssM, ssX, ctX, pkX)
 * @since      0.13.3
 * @status     experimental
 * @compliance soc2
 * @related    b.crypto.xwing.encapsulate, b.crypto.xwing.decapsulate
 *
 * The X-Wing combiner: <code>SHA3-256(ssM ‖ ssX ‖ ctX ‖ pkX ‖ label)</code>,
 * where the label is the fixed six bytes the draft defines. Exposed for
 * advanced use and known-answer testing; <code>encapsulate</code> and
 * <code>decapsulate</code> call it internally. Each input must be 32 bytes.
 *
 * @example
 *   var ss = b.crypto.xwing.combiner(ssMlkem, ssX25519, ephPub, recipientPub);
 *   // → 32-byte shared secret
 */
function combiner(ssM, ssX, ctX, pkX) {
  [["ssM", ssM, SS_LEN], ["ssX", ssX, X25519_LEN], ["ctX", ctX, X25519_LEN], ["pkX", pkX, X25519_LEN]].forEach(function (t) {
    // ML-KEM outputs are Uint8Array; X25519 outputs are Buffer — accept both.
    if (!(Buffer.isBuffer(t[1]) || t[1] instanceof Uint8Array) || t[1].length !== t[2]) throw new XWingError("xwing/bad-input", "xwing.combiner: " + t[0] + " must be a " + t[2] + "-byte byte array");
  });
  return nodeCrypto.createHash("sha3-256").update(Buffer.concat([ssM, ssX, ctX, pkX, XWING_LABEL])).digest();
}

// Expand a 32-byte seed into ML-KEM key material + the X25519 scalar.
function _expand(seed) {
  var e = _shake256(seed, EXPAND_LEN);
  var kp = mlkem.keygen(e.subarray(0, MLKEM_SEED));     // KeyGen_internal(d, z)
  var skX = e.subarray(MLKEM_SEED, EXPAND_LEN);
  return { skM: kp.secretKey, pkM: kp.publicKey, skX: skX, pkX: _x25519Public(skX) };
}

/**
 * @primitive  b.crypto.xwing.keygen
 * @signature  b.crypto.xwing.keygen(seed?)
 * @since      0.13.3
 * @status     experimental
 * @compliance soc2
 * @related    b.crypto.xwing.encapsulate, b.crypto.xwing.decapsulate
 *
 * Generate an X-Wing keypair. The decapsulation key is a 32-byte seed (store
 * this); the encapsulation key is the 1216-byte public key to publish. Pass a
 * 32-byte <code>seed</code> for deterministic generation, or omit it for a
 * random key.
 *
 * @example
 *   var kp = b.crypto.xwing.keygen();
 *   kp.publicKey.length;   // → 1216
 *   kp.secretKey.length;   // → 32  (the seed — keep it secret)
 */
function keygen(seed) {
  if (seed == null) seed = nodeCrypto.randomBytes(SEED_LEN);
  if (!Buffer.isBuffer(seed) || seed.length !== SEED_LEN) throw new XWingError("xwing/bad-seed", "xwing.keygen: seed must be a " + SEED_LEN + "-byte Buffer");
  var k = _expand(seed);
  return { publicKey: Buffer.concat([k.pkM, k.pkX]), secretKey: Buffer.from(seed) };
}

/**
 * @primitive  b.crypto.xwing.encapsulate
 * @signature  b.crypto.xwing.encapsulate(publicKey, eseed?)
 * @since      0.13.3
 * @status     experimental
 * @compliance soc2
 * @related    b.crypto.xwing.decapsulate, b.crypto.xwing.keygen
 *
 * Encapsulate to a 1216-byte X-Wing public key. Returns the 1120-byte
 * <code>ciphertext</code> to send and the 32-byte <code>sharedSecret</code> to
 * key a symmetric cipher with. Pass a 64-byte <code>eseed</code>
 * (X25519 ephemeral scalar ‖ ML-KEM coins) for deterministic encapsulation, or
 * omit it for fresh randomness.
 *
 * @example
 *   var enc = b.crypto.xwing.encapsulate(recipientPublicKey);
 *   enc.ciphertext.length;   // → 1120
 *   enc.sharedSecret.length; // → 32
 */
function encapsulate(publicKey, eseed) {
  if (!Buffer.isBuffer(publicKey) || publicKey.length !== PK_LEN) throw new XWingError("xwing/bad-public-key", "xwing.encapsulate: publicKey must be a " + PK_LEN + "-byte Buffer");
  var pkM = publicKey.subarray(0, ML_KEM_PK);
  var pkX = publicKey.subarray(ML_KEM_PK, PK_LEN);
  var ekX, mlkemCoins = null;
  if (eseed == null) {
    ekX = nodeCrypto.randomBytes(X25519_LEN);
  } else {
    if (!Buffer.isBuffer(eseed) || eseed.length !== 2 * X25519_LEN) throw new XWingError("xwing/bad-eseed", "xwing.encapsulate: eseed must be a " + (2 * X25519_LEN) + "-byte Buffer");
    // draft EncapsulateDerand: eseed[0:32] = ML-KEM coins, eseed[32:64] = X25519
    // ephemeral scalar. This order matches the draft's test vectors.
    mlkemCoins = eseed.subarray(0, X25519_LEN);
    ekX = eseed.subarray(X25519_LEN, 2 * X25519_LEN);
  }
  var ctX = _x25519Public(ekX);
  var ssX = _x25519Shared(ekX, pkX);
  var kem = mlkemCoins ? mlkem.encapsulate(pkM, mlkemCoins) : mlkem.encapsulate(pkM);
  var ss = combiner(kem.sharedSecret, ssX, ctX, pkX);
  return { ciphertext: Buffer.concat([kem.cipherText, ctX]), sharedSecret: ss };
}

/**
 * @primitive  b.crypto.xwing.decapsulate
 * @signature  b.crypto.xwing.decapsulate(secretKey, ciphertext)
 * @since      0.13.3
 * @status     experimental
 * @compliance soc2
 * @related    b.crypto.xwing.encapsulate, b.crypto.xwing.keygen
 *
 * Recover the 32-byte shared secret from a 1120-byte X-Wing ciphertext using
 * the 32-byte decapsulation seed. ML-KEM-768's implicit-rejection means a
 * tampered ciphertext yields a different (still 32-byte) secret rather than an
 * error, so never branch on success — derive keys and let the AEAD tag fail.
 *
 * @example
 *   var ss = b.crypto.xwing.decapsulate(kp.secretKey, enc.ciphertext);
 *   ss.equals(enc.sharedSecret);   // → true
 */
function decapsulate(secretKey, ciphertext) {
  if (!Buffer.isBuffer(secretKey) || secretKey.length !== SEED_LEN) throw new XWingError("xwing/bad-seed", "xwing.decapsulate: secretKey must be a " + SEED_LEN + "-byte Buffer");
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length !== CT_LEN) throw new XWingError("xwing/bad-ciphertext", "xwing.decapsulate: ciphertext must be a " + CT_LEN + "-byte Buffer");
  var k = _expand(secretKey);
  var ctM = ciphertext.subarray(0, ML_KEM_CT);
  var ctX = ciphertext.subarray(ML_KEM_CT, CT_LEN);
  var ssM = mlkem.decapsulate(ctM, k.skM);
  var ssX = _x25519Shared(k.skX, ctX);
  return combiner(ssM, ssX, ctX, k.pkX);
}

module.exports = {
  NAME:        "X-Wing",
  keygen:      keygen,
  encapsulate: encapsulate,
  decapsulate: decapsulate,
  combiner:    combiner,
  SIZES:       { publicKey: PK_LEN, ciphertext: CT_LEN, secretKey: SEED_LEN, sharedSecret: SS_LEN },
  XWingError:  XWingError,
};
