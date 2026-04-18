/**
 * API payload encryption middleware.
 *
 * - Generates a per-session XChaCha20-Poly1305 key (vault-sealed at rest)
 * - Decrypts incoming JSON POST bodies ({_e: "encrypted"})
 * - Wraps res.json() to encrypt outgoing responses
 * - Rejects requests with stale timestamps (anti-replay)
 * - Skips encryption for non-JSON routes (HTML pages, file downloads)
 *
 * Hybrid ECIES key exchange for mTLS clients (ML-KEM-1024 + ECDH P-384):
 * On the first response to an mTLS client with an API key, the session
 * XChaCha20 key is encrypted using a hybrid shared secret derived from
 * both ML-KEM-1024 encapsulation and ECDH P-384 key agreement. The two
 * shared secrets are concatenated and run through HKDF-SHA3-512 to produce
 * a wrapping key, which encrypts the session key via XChaCha20-Poly1305.
 *
 * The client sends its ML-KEM-1024 public key in the X-KEM-Public-Key header
 * on its first request. The server's ECDH P-384 leg uses the client cert's
 * public key (from mTLS). No plaintext key material ever appears in a response.
 *
 * Browser clients receive the session key via template embedding (res._apiKey).
 */
var crypto = require("node:crypto");
var vault = require("../lib/vault");
var config = require("../lib/config");
var { encryptPayload, decryptPayload, generateApiKey } = require("../lib/api-crypto");
var { xchacha20poly1305 } = require("../lib/vendor/noble-ciphers.cjs");
var { ml_kem1024 } = require("../lib/vendor/noble-pq.cjs");

var REPLAY_WINDOW = 30000; // 30 seconds
var HYBRID_HKDF_INFO = "hermitstash-hybrid-ecies-v1";

// ECIES protocol version — prefixed to _ek for algorithm agility.
// Clients read this byte to determine which KEM/ECDH/KDF to use for decapsulation.
// 0x01 = ML-KEM-1024 + ECDH P-384 + HKDF-SHA3-512 + XChaCha20-Poly1305
var ECIES_PROTOCOL_VERSION = 0x01;

/**
 * Hybrid ECIES encrypt: encrypt a session key using ML-KEM-1024 + ECDH P-384.
 *
 * @param {Buffer} sessionKeyBuffer - the 32-byte session key to protect
 * @param {Buffer} clientKemPubKeyBytes - client's ML-KEM-1024 public key (from X-KEM-Public-Key header)
 * @param {crypto.KeyObject} clientEcdhPubKey - client's P-384 public key (from mTLS cert)
 * @returns {{ ek, epk, kem }} base64url-encoded fields for the response
 */
function hybridEciesEncrypt(sessionKeyBuffer, clientKemPubKeyBytes, clientEcdhPubKey) {
  // --- ML-KEM-1024 leg ---
  var kemResult = ml_kem1024.encapsulate(clientKemPubKeyBytes);
  var sharedSecretKem = kemResult.sharedSecret;   // 32 bytes
  var ciphertextKem = kemResult.cipherText;        // 1088 bytes

  // --- ECDH P-384 leg ---
  var ephemeral = crypto.generateKeyPairSync("ec", { namedCurve: "secp384r1" });
  var sharedSecretEcdh = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: clientEcdhPubKey,
  });

  // --- Combine shared secrets ---
  var combinedSecret = Buffer.concat([
    Buffer.from(sharedSecretKem),
    sharedSecretEcdh,
  ]);

  // --- Derive wrapping key via HKDF-SHA3-512 ---
  var wrappingKey = crypto.hkdfSync("sha3-512", combinedSecret, "", HYBRID_HKDF_INFO, 32);

  // --- Encrypt session key with XChaCha20-Poly1305 using the wrapping key ---
  var nonce = crypto.randomBytes(24);
  var ct = xchacha20poly1305(new Uint8Array(Buffer.from(wrappingKey)), nonce).encrypt(new Uint8Array(sessionKeyBuffer));
  // Pack: version(1) + nonce(24) + ciphertext_with_tag
  var encryptedSessionKey = Buffer.concat([Buffer.from([ECIES_PROTOCOL_VERSION]), Buffer.from(nonce), Buffer.from(ct)]);

  // Export ephemeral ECDH public key as SPKI DER
  var epkDer = ephemeral.publicKey.export({ type: "spki", format: "der" });

  return {
    ek: encryptedSessionKey.toString("base64url"),
    epk: epkDer.toString("base64url"),
    kem: Buffer.from(ciphertextKem).toString("base64url"),
  };
}

module.exports = function apiEncrypt(req, res, next) {
  // Track whether this is a new session (key just generated)
  var isNewSession = !req.session.apiKey;

  // Ensure session has an API encryption key (vault-sealed for PQC at rest)
  if (!req.session.apiKey) {
    req.session.apiKey = vault.seal(generateApiKey());
  }

  // Unseal the key for this request's crypto operations
  var apiKey = vault.unseal(req.session.apiKey);

  // Expose plaintext key to send() middleware for template embedding (browser clients)
  res._apiKey = apiKey;

  // Capture the client's ML-KEM public key from the first request header (if present)
  var clientKemPubKey = null;
  if (isNewSession && req.headers["x-kem-public-key"]) {
    try {
      clientKemPubKey = Buffer.from(req.headers["x-kem-public-key"], "base64url");
    } catch (_e) { /* invalid base64 — ignore */ }
  }

  // Decrypt incoming JSON body if encrypted
  if (req.method === "POST") {
    var contentType = req.headers["content-type"] || "";
    if (contentType.includes("application/json")) {
      var chunks = [];
      var origOn = req.on.bind(req);
      var listeners = { data: [], end: [], error: [] };
      var bodyReady = false;

      req.on = function (event, fn) {
        if ((event === "data" || event === "end" || event === "error") && !bodyReady) {
          listeners[event].push(fn);
          return req;
        }
        return origOn(event, fn);
      };

      var bodySize = 0;
      var isVaultUpload = req.pathname && (req.pathname === "/vault/upload" || req.pathname === "/vault/rotate");
      var MAX_JSON_BODY = isVaultUpload ? config.maxFileSize * 2 : 1048576;
      origOn("data", function (c) {
        bodySize += c.length;
        if (bodySize > MAX_JSON_BODY) {
          req.destroy();
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Request body too large." }));
          return;
        }
        chunks.push(c);
      });
      origOn("end", function () {
        var raw = Buffer.concat(chunks).toString();
        var body;
        try { body = JSON.parse(raw); } catch (_e) { body = null; }

        if (body && body._e) {
          try {
            var decrypted = decryptPayload(body._e, apiKey, REPLAY_WINDOW);
            if (decrypted === null || decrypted === undefined) throw new Error("Invalid payload");
            raw = JSON.stringify(decrypted);
          } catch (_e) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Decryption failed." }));
            return;
          }
        }

        bodyReady = true;
        var buf = Buffer.from(raw);
        for (var i = 0; i < listeners.data.length; i++) listeners.data[i](buf);
        for (var j = 0; j < listeners.end.length; j++) listeners.end[j]();
      });
      origOn("error", function (e) {
        for (var i = 0; i < listeners.error.length; i++) listeners.error[i](e);
      });
    }
  }

  // Wrap res.json to encrypt outgoing responses
  var origJson = res.json;
  res.json = function (data) {
    var encrypted = encryptPayload(data, apiKey);
    var response = { _e: encrypted, _t: Date.now() };

    // Hybrid ECIES key exchange on first response for mTLS clients with ML-KEM public key.
    // Both legs (ML-KEM-1024 + ECDH P-384) must succeed. The combined shared secret
    // derives a wrapping key that encrypts the session XChaCha20 key.
    if (isNewSession && clientKemPubKey && req.socket && typeof req.socket.getPeerCertificate === "function") {
      var peerCert = req.socket.getPeerCertificate(true);
      if (peerCert && peerCert.raw && peerCert.raw.length > 0) {
        try {
          // Extract the client's P-384 public key from the mTLS certificate
          var clientEcdhPubKey = crypto.createPublicKey({
            key: peerCert.raw,
            format: "der",
            type: "x509",
          });

          // Perform hybrid ECIES encryption of the session key
          var sessionKeyBuffer = Buffer.from(apiKey, "base64url");
          var result = hybridEciesEncrypt(sessionKeyBuffer, clientKemPubKey, clientEcdhPubKey);

          response._ek = result.ek;
          response._epk = result.epk;
          response._kem = result.kem;
        } catch (hybridErr) {
          // For mTLS sync clients, ECIES failure means no key exchange — log and warn.
          // Browser clients get the key via template embedding (res._apiKey) so this is non-fatal for them.
          if (req.socket && req.socket.authorized) {
            var logger = require("../app/shared/logger");
            logger.error("[api-encrypt] Hybrid ECIES failed for mTLS client", { error: hybridErr.message });
          }
        }
      }
      isNewSession = false;
    }

    origJson.call(res, response);
  };

  next();
};
