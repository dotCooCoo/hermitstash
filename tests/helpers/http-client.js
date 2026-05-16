/**
 * HTTP client for tests. Tracks cookies and handles API payload encryption.
 *
 * Two protocols are supported, mirroring server-main.js's gating exactly:
 *
 *   1. Cookie-authenticated (default) — wraps requests in the legacy
 *      `{ _e: <packed>, _t: <ts> }` shape that browser-side
 *      `public/js/api.js` produces. Server routes these through the
 *      legacy api-encrypt middleware. Use `initApiKey()` to pull the
 *      per-session XChaCha20 key from a rendered HTML page.
 *
 *   2. Bearer-authenticated — switches to the blamejs apiEncrypt
 *      protocol (`{ _ek, _ct, _ts, _nonce, _sid, _ctr }` bootstrap; then
 *      `{ _ct, _ts, _sid, _ctr }` per-session). Mirrors what sync
 *      clients send to /drop/init, /drop/finalize, /sync/rename in
 *      production. Construct via `await client.bearer(apiKey)` — fetches
 *      the server's pubkey from /.well-known/blamejs-pubkey, builds a
 *      per-session b.middleware.apiEncrypt.client, and attaches the
 *      Authorization header to every subsequent request.
 *
 * Both protocols MUST exist in this file because tests/helpers/test-
 * server.js wires both legacy and blamejs middleware (matching production).
 * Without bearer() coverage, the integration suite would only exercise the
 * legacy path and a class of browser-upload regressions that the divergence
 * hid would re-emerge.
 */
const http = require("http");
const path = require("path");

class TestClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.cookies = {};
    this._apiKey = null;             // legacy per-session XChaCha20 key
    this._bearerToken = null;        // raw API key — sent as Authorization
    this._blamejsClient = null;      // b.middleware.apiEncrypt.client instance
  }

  // Lazy-load api-crypto (avoid circular deps at module level)
  _crypto() {
    if (!this._cryptoMod) {
      this._cryptoMod = require(path.join(__dirname, "..", "..", "lib", "api-crypto"));
    }
    return this._cryptoMod;
  }

  // Returns true when this request path should be wrapped in the blamejs
  // envelope on the wire — must match server-main.js's
  // isBlamejsApiEncryptPath() exactly.
  _isBlamejsPath(method, pathStr) {
    if (!this._blamejsClient || method !== "POST") return false;
    if (pathStr === "/drop/init") return true;
    if (pathStr.indexOf("/drop/finalize/") === 0) return true;
    if (pathStr === "/sync/rename") return true;
    return false;
  }

  request(method, pathStr, opts) {
    var self = this;
    opts = opts || {};
    return new Promise(function (resolve, reject) {
      var url = new URL(pathStr, self.baseUrl);
      var headers = Object.assign({}, opts.headers || {});

      var cookieStr = Object.entries(self.cookies).map(function (e) { return e[0] + "=" + e[1]; }).join("; ");
      if (cookieStr) headers.cookie = cookieStr;
      if (self._bearerToken) headers["authorization"] = "Bearer " + self._bearerToken;

      var body = null;
      var responseShape = "legacy";    // determines how we decrypt the response
      var blamejsDecrypt = null;       // captured per-request from encryptRequest
      if (opts.json) {
        var jsonData = opts.json;
        if (self._isBlamejsPath(method, url.pathname) && !opts.raw) {
          // Bearer + blamejs path → wrap with the per-session blamejs envelope
          var enc = self._blamejsClient.encryptRequest(jsonData);
          body = JSON.stringify(enc.body);
          blamejsDecrypt = enc.decryptResponse;
          responseShape = "blamejs";
        } else if (self._apiKey && !opts.raw) {
          // Cookie + legacy path → wrap with the per-session XChaCha20 envelope
          var ac = self._crypto();
          var encrypted = ac.encryptPayload(jsonData, self._apiKey);
          body = JSON.stringify({ _e: encrypted, _t: Date.now() });
        } else {
          body = JSON.stringify(jsonData);
        }
        headers["content-type"] = "application/json";
        headers["content-length"] = Buffer.byteLength(body);
      } else if (opts.body) {
        body = opts.body;
        if (opts.contentType) headers["content-type"] = opts.contentType;
        headers["content-length"] = Buffer.byteLength(body);
      }

      var req = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: method,
        headers: headers,
      }, function (res) {
        var setCookies = res.headers["set-cookie"] || [];
        if (!Array.isArray(setCookies)) setCookies = [setCookies];
        for (var i = 0; i < setCookies.length; i++) {
          var parts = setCookies[i].split(";")[0].split("=");
          self.cookies[parts[0]] = parts.slice(1).join("=");
        }

        var chunks = [];
        res.on("data", function (c) { chunks.push(c); });
        res.on("end", function () {
          var text = Buffer.concat(chunks).toString();
          var json = null;
          try {
            var parsed = JSON.parse(text);
            if (responseShape === "blamejs" && blamejsDecrypt && parsed && typeof parsed._ct === "string") {
              try { json = blamejsDecrypt(parsed); }
              catch (_e) { json = parsed; }
            } else if (parsed && parsed._e && self._apiKey) {
              try {
                var ac = self._crypto();
                json = ac.decryptPayload(parsed._e, self._apiKey);
              } catch (_e) {
                json = parsed;
              }
            } else {
              json = parsed;
            }
          } catch {}
          resolve({
            status: res.statusCode,
            headers: res.headers,
            text: text,
            json: json,
            location: res.headers.location,
          });
        });
      });
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
  }

  get(pathStr, opts) { return this.request("GET", pathStr, opts); }
  post(pathStr, opts) { return this.request("POST", pathStr, opts); }

  uploadFile(pathStr, fieldName, filename, content, extraFields) {
    var boundary = "----TestBoundary" + Date.now();
    var parts = [];
    if (extraFields) {
      for (var key in extraFields) {
        parts.push("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + key + "\"\r\n\r\n" + extraFields[key]);
      }
    }
    parts.push("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + filename + "\"\r\nContent-Type: application/octet-stream\r\n\r\n" + content);
    parts.push("--" + boundary + "--\r\n");
    var body = parts.join("\r\n");
    return this.post(pathStr, { body: body, contentType: "multipart/form-data; boundary=" + boundary });
  }

  // Fetch a page to get the API encryption key from the embedded script
  async initApiKey() {
    var res = await this.get("/auth/login");
    var match = res.text.match(/__ak="([^"]+)"/);
    if (match) this._apiKey = match[1];
    return this._apiKey;
  }

  // Switch this client to Bearer authentication + blamejs apiEncrypt
  // protocol. Fetches /.well-known/blamejs-pubkey to bootstrap a
  // per-session b.middleware.apiEncrypt.client. After this returns,
  // POSTs to /drop/init, /drop/finalize/:id, /sync/rename are wrapped
  // in the blamejs envelope automatically; everything else stays
  // plaintext (Bearer-authed callers don't need legacy api-encrypt
  // because mTLS / Bearer is the wire guarantee for non-payload paths).
  async bearer(apiKey) {
    this._bearerToken = apiKey;
    this._apiKey = null;             // legacy per-session key cleared so we don't double-wrap
    var pubkeyRes = await this.get("/.well-known/blamejs-pubkey");
    if (pubkeyRes.status !== 200 || !pubkeyRes.json) {
      throw new Error("bearer(): /.well-known/blamejs-pubkey did not return 200/JSON, got " + pubkeyRes.status);
    }
    var b = require(path.join(__dirname, "..", "..", "lib", "vendor", "blamejs"));
    this._blamejsClient = b.middleware.apiEncrypt.client({
      pubkey: pubkeyRes.json,
      keying: "per-session",
    });
    return this;
  }

  clearCookies() {
    this.cookies = {};
    this._apiKey = null;
    this._bearerToken = null;
    this._blamejsClient = null;
  }
}

module.exports = { TestClient };
