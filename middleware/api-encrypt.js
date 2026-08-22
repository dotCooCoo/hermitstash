/**
 * Payload encryption for cookie-authenticated sessions: a per-session
 * XChaCha20-Poly1305 key, sealed at rest, that decrypts incoming JSON bodies
 * and encrypts outgoing ones through a wrapped res.json.
 *
 * No session key ever goes in a response body, wrapped or otherwise. Browsers
 * receive it embedded in the page template over TLS; an API-key client bypasses
 * this layer and takes its payload protection from the framework's own
 * ML-KEM-1024 exchange against the server's published public key.
 *
 * Do not reintroduce a key wrap here. The hybrid ECIES wrap that once rode
 * along on the first response to an mTLS client cannot be computed against a
 * post-quantum certificate, which carries a signature key with no ECDH
 * counterpart — and that ECDH leg was the only thing binding the wrap to the
 * authenticated peer rather than to whatever key a caller named in a header.
 */
var b = require("../lib/vendor/blamejs");
var vault = require("../lib/vault");
var config = require("../lib/config");
var { encryptPayload, decryptPayload, generateApiKey, FUTURE_SKEW_MS } = require("../lib/api-crypto");
var replayNonce = require("../lib/replay-nonce");

var REPLAY_WINDOW = 30000;
// The single-use nonce has to outlive the freshness window, which stays open
// until receiveTime + REPLAY_WINDOW + FUTURE_SKEW_MS because a fresh `_t` may
// lead server time. A nonce expiring earlier would re-open an in-window replay.
var NONCE_TTL = REPLAY_WINDOW + FUTURE_SKEW_MS;

module.exports = function apiEncrypt(req, res, next) {
  if (!req.session.apiKey) {
    req.session.apiKey = vault.seal(generateApiKey());
  }

  var apiKey = vault.unseal(req.session.apiKey);

  // send() reads this to embed the key in the page template.
  res._apiKey = apiKey;

  // The session key is cookie-bound, so a Bearer client has no way to learn it
  // and a body wrapped with it would be ciphertext it can never open. Those
  // clients take their payload protection from the framework layer instead.
  if (req.apiKey) return next();

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
          // Written directly rather than thrown: a throw from a request-stream
          // callback becomes an uncaughtException and never reaches the route
          // error boundary. It goes through the wrapped res.json so the body
          // stays encrypted.
          //
          // The response must flush before req.destroy(), which takes the
          // shared socket with it — destroying first would turn the 413 into an
          // ECONNRESET.
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
        // maxBytes is raised to match the stream cap above, so a vault upload
        // exceeding safeJson's own default still parses.
        var body = b.safeJson.parseOrDefault(raw, null, { maxBytes: MAX_JSON_BODY });

        if (body && body._e) {
          try {
            var decrypted = decryptPayload(body._e, apiKey, REPLAY_WINDOW, MAX_JSON_BODY);
            if (decrypted === null || decrypted === undefined) throw new Error("Invalid payload");
            // A replay re-sends byte-identical `_e`, so claiming it once
            // refuses one. The `_t` check alone admits unlimited replays for
            // the whole window (CWE-367).
            if (!(await replayNonce.claimOnce("apienc:" + body._e, NONCE_TTL))) {
              throw new Error("Replayed request");
            }
            raw = JSON.stringify(decrypted);
          } catch (_e) {
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

  var origJson = res.json;
  res.json = function (data) {
    var encrypted = encryptPayload(data, apiKey);
    // The payload and its timestamp, and nothing else — in particular no copy
    // of the session key. See the note at the top of this file.
    var response = { _e: encrypted, _t: Date.now() };

    origJson.call(res, response);
  };

  // Tells the error handler to route problem documents through res.json rather
  // than res.end, so an error on a session the client established as encrypted
  // does not ship its body in cleartext. That is the whole of the on-wire
  // payload confidentiality on a deployment with no TLS in front of it.
  res._apiEncryptJson = true;

  next();
};
