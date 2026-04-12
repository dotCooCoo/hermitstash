/**
 * API payload encryption middleware.
 *
 * - Generates a per-session AES-256-GCM key (stored server-side)
 * - Decrypts incoming JSON POST bodies ({_e: "encrypted"})
 * - Wraps res.json() to encrypt outgoing responses
 * - Rejects requests with stale timestamps (anti-replay)
 * - Skips encryption for non-JSON routes (HTML pages, file downloads)
 */
var vault = require("../lib/vault");
var config = require("../lib/config");
var { encryptPayload, decryptPayload, generateApiKey } = require("../lib/api-crypto");

var REPLAY_WINDOW = 30000; // 30 seconds

module.exports = function apiEncrypt(req, res, next) {
  // Ensure session has an API encryption key (vault-sealed for PQC at rest)
  if (!req.session.apiKey) {
    req.session.apiKey = vault.seal(generateApiKey());
  }

  // Unseal the key for this request's crypto operations
  var apiKey = vault.unseal(req.session.apiKey);

  // Expose plaintext key to send() middleware for template embedding
  res._apiKey = apiKey;

  // Decrypt incoming JSON body if encrypted
  if (req.method === "POST") {
    var contentType = req.headers["content-type"] || "";
    if (contentType.includes("application/json")) {
      // Buffer the raw body, then check for encryption
      var chunks = [];
      var origOn = req.on.bind(req);
      var listeners = { data: [], end: [], error: [] };
      var bodyReady = false;

      // Intercept stream events
      req.on = function (event, fn) {
        if ((event === "data" || event === "end" || event === "error") && !bodyReady) {
          listeners[event].push(fn);
          return req;
        }
        return origOn(event, fn);
      };

      var bodySize = 0;
      // Vault uploads send files as base64 in JSON — allow larger bodies for those
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
          // Encrypted payload — decrypt (timestamp verified inside GCM ciphertext)
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

        // Replay the buffered data to downstream listeners
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
    origJson.call(res, { _e: encrypted, _t: Date.now() });
  };

  next();
};
