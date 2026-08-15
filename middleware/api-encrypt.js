/**
 * API payload encryption middleware.
 *
 * - Generates a per-session XChaCha20-Poly1305 key (vault-sealed at rest)
 * - Decrypts incoming JSON POST bodies ({_e: "encrypted"})
 * - Wraps res.json() to encrypt outgoing responses
 * - Rejects requests with stale timestamps (anti-replay)
 * - Skips encryption for non-JSON routes (HTML pages, file downloads)
 *
 * No session key is ever placed in a response body, wrapped or otherwise.
 * Browser clients receive it via template embedding (res._apiKey) over TLS;
 * clients authenticating with an API key bypass this layer entirely and take
 * their payload protection from the framework's encrypted wrapper, which runs
 * its own ML-KEM-1024 exchange against the server's published public key.
 *
 * A hybrid ECIES wrap used to ride along on the first response to an mTLS
 * client, deriving a wrapping key from ML-KEM-1024 encapsulation plus ECDH
 * against the P-384 key in the peer's certificate. Certificates are now
 * post-quantum and carry a signature key with no ECDH counterpart, so that
 * wrap could no longer be computed; the ECDH leg was also the only thing
 * binding the wrap to the authenticated peer rather than to whatever key a
 * caller put in a header, so there was nothing to fall back to.
 */
var b = require("../lib/vendor/blamejs");
var vault = require("../lib/vault");
var config = require("../lib/config");
var { encryptPayload, decryptPayload, generateApiKey, FUTURE_SKEW_MS } = require("../lib/api-crypto");
var replayNonce = require("../lib/replay-nonce");

var REPLAY_WINDOW = 30000; // 30 seconds
// The single-use nonce must outlive the maximum inner-AEAD freshness lifetime.
// A freshly-stamped `_t` may lead server time by up to FUTURE_SKEW_MS, so the
// freshness window stays open until receiveTime + REPLAY_WINDOW + FUTURE_SKEW_MS.
// Claiming the nonce for only REPLAY_WINDOW would let it expire ~FUTURE_SKEW_MS
// before that ceiling, re-opening an in-window replay gap. Bind the two values
// to one constant (FUTURE_SKEW_MS from lib/api-crypto) so the future-skew
// tolerance and the nonce TTL can never drift apart.
var NONCE_TTL = REPLAY_WINDOW + FUTURE_SKEW_MS;

module.exports = function apiEncrypt(req, res, next) {
  // Ensure session has an API encryption key (vault-sealed for PQC at rest)
  if (!req.session.apiKey) {
    req.session.apiKey = vault.seal(generateApiKey());
  }

  // Unseal the key for this request's crypto operations
  var apiKey = vault.unseal(req.session.apiKey);

  // Expose plaintext key to send() middleware for template embedding (browser clients)
  res._apiKey = apiKey;

  // Bearer-authenticated clients (sync, API key holders) bypass the
  // legacy `_e/_t` envelope. The session apiKey above is cookie-bound,
  // and a Bearer client has no way to learn it — so wrapping a body
  // with it would be dead-end ciphertext for them. Bearer auth
  // implies mTLS + API-key transport security; encryption-grade JSON
  // payloads route through blamejs apiEncrypt instead. Bypass here
  // means: no body interception, no res.json wrap. Browser cookie-
  // auth flows (no req.apiKey) continue with legacy encryption.
  if (req.apiKey) return next();

  // Decrypt incoming JSON body if encrypted
  if (req.method === "POST") {
    var contentType = req.headers["content-type"] || "";
    if (contentType.includes("application/json")) {
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

      var isVaultUpload = req.pathname && (req.pathname === "/vault/upload" || req.pathname === "/vault/rotate");
      var MAX_JSON_BODY = isVaultUpload ? config.maxFileSize * 2 : b.constants.BYTES.mib(1);
      var collector = b.safeBuffer.boundedChunkCollector({ maxBytes: MAX_JSON_BODY });
      var aborted = false;
      origOn("data", function (c) {
        if (aborted) return;
        try {
          collector.push(c);
        } catch (_e) {
          aborted = true;
          // res.json (wrapped below) encrypts on this cookie session. Emit the
          // rejection through it so the body isn't shipped cleartext via
          // res.end. A throw here would escape the request-stream callback as
          // an uncaughtException — it never reaches the route error boundary —
          // so write directly, mirroring the wrapped res.json error path.
          //
          // Deliver the 413 BEFORE tearing down the stream: req.destroy() takes
          // the shared socket down with it, so destroying first would make this
          // res.json write land on a dead socket and the client would see an
          // ECONNRESET instead of the encrypted 413. Send the response, then
          // stop consuming the oversized upload once the response has flushed
          // (the aborted guard already drops any further chunks meanwhile).
          res.statusCode = 413;
          res.setHeader("Cache-Control", "no-store");
          res.json({
            type: "https://hermitstash.com/problems/payload-too-large",
            title: "Payload Too Large",
            status: 413,
            detail: "Request body too large.",
          });
          res.on("finish", function () {
            try { req.destroy(); } catch (_de) { /* socket already gone */ }
          });
        }
      });
      origOn("end", async function () {
        if (aborted) return;
        var raw = collector.result().toString();
        // b.safeJson.parseOrDefault — bounded depth + key-count + null-
        // prototype output object that defends against __proto__ /
        // constructor / prototype keys polluting the chain before
        // downstream property reads. Pass maxBytes=MAX_JSON_BODY so
        // vault uploads (which legitimately exceed safeJson's 16 MiB
        // default) parse — the stream-side cap above already refuses
        // bodies larger than MAX_JSON_BODY before they reach here.
        var body = b.safeJson.parseOrDefault(raw, null, { maxBytes: MAX_JSON_BODY });

        if (body && body._e) {
          try {
            var decrypted = decryptPayload(body._e, apiKey, REPLAY_WINDOW, MAX_JSON_BODY);
            if (decrypted === null || decrypted === undefined) throw new Error("Invalid payload");
            // Atomic single-use claim of the exact envelope bytes. A replayed
            // request re-sends a byte-identical _e (the XChaCha20 nonce lives
            // inside the ciphertext), so claiming sha3(_e) within the staleness
            // window refuses an in-window replay — the _t timestamp check alone
            // admits unlimited replays for the whole 30s window (CWE-367). The
            // TTL is REPLAY_WINDOW + FUTURE_SKEW_MS (not just REPLAY_WINDOW) so
            // the nonce outlives a future-dated _t's freshness ceiling.
            if (!(await replayNonce.claimOnce("apienc:" + body._e, NONCE_TTL))) {
              throw new Error("Replayed request");
            }
            raw = JSON.stringify(decrypted);
          } catch (_e) {
            // Encrypted cookie session: route the rejection through the wrapped
            // res.json (set below) so it isn't shipped cleartext via res.end.
            // Emit directly — a throw escapes this request-stream callback.
            res.statusCode = 400;
            res.setHeader("Cache-Control", "no-store");
            res.json({
              type: "https://hermitstash.com/problems/decryption-failed",
              title: "Decryption Failed",
              status: 400,
              detail: "Decryption failed.",
            });
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
    // The body carries the encrypted payload and its timestamp, and nothing
    // else. In particular it carries no copy of the session key, wrapped to a
    // peer certificate or otherwise — see the note at the top of this file.
    var response = { _e: encrypted, _t: Date.now() };

    origJson.call(res, response);
  };

  // Signal the centralized error handler that res.json on this (cookie-
  // authenticated) session encrypts the body. The error handler must route
  // problem-details through res.json rather than b.problemDetails' raw
  // res.end — otherwise an error on a session the client established as
  // encrypted ships its problem+json body in cleartext (and unauthenticated),
  // which matters most where this layer is the only on-wire payload
  // confidentiality (an HTTP-mode deployment with no fronting TLS).
  res._apiEncryptJson = true;

  next();
};
