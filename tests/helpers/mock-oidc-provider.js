/**
 * In-process mock OpenID Connect provider for the sign-in tests.
 *
 * It signs id_tokens with a generated RS256 key and serves discovery, JWKS,
 * token and userinfo. Two ways to reach it:
 *
 *   - listen(): a real HTTP server on 127.0.0.1, used as the issuer for the
 *     generic OIDC tests (the server reaches it through OIDC_ALLOW_INTERNAL).
 *   - handle(): the same handlers as a function, used by the Google tests,
 *     which intercept b.httpClient.request for Google's fixed https URLs.
 *
 * authorize(authUrl, opts) plays the provider's consent step: it records the
 * nonce and PKCE challenge from the authorization URL and returns the
 * callback path the browser would be sent to. opts.claims overrides id_token
 * claims for that login; opts.token selects a misbehaving token response.
 */
var http = require("node:http");
var nodeCrypto = require("node:crypto");

function b64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function signJwt(header, payload, opts) {
  opts = opts || {};
  var h = b64url(JSON.stringify(header));
  var p = b64url(JSON.stringify(payload));
  var input = h + "." + p;
  if (header.alg === "none") return input + ".";
  if (header.alg === "HS256") {
    return input + "." + b64url(nodeCrypto.createHmac("sha256", opts.secret || "").update(input).digest());
  }
  var sig = nodeCrypto.createSign("RSA-SHA256").update(input).sign(opts.key);
  return input + "." + b64url(sig);
}

function create(opts) {
  opts = opts || {};
  var keys = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var otherKeys = nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  var jwk = keys.publicKey.export({ format: "jwk" });
  jwk.kid = "k1";
  jwk.alg = "RS256";
  jwk.use = "sig";

  var op = {
    issuer: opts.issuer || null,
    clientId: opts.clientId || "hs-test-client",
    clientSecret: opts.clientSecret || "hs-test-secret",
    jwksPath: opts.jwksPath || "/jwks",
    discoveryOverrides: {},
    codes: new Map(),
    tokenRequests: 0,
    userinfoResponses: new Map(),
    server: null,
  };

  op.discovery = function () {
    var base = op.issuer.replace(/\/$/, "");
    return Object.assign({
      issuer: op.issuer,
      authorization_endpoint: base + "/authorize",
      token_endpoint: base + "/token",
      userinfo_endpoint: base + "/userinfo",
      jwks_uri: opts.jwksUri || base + op.jwksPath,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
    }, op.discoveryOverrides);
  };

  op.defaultClaims = function () {
    var now = Math.floor(Date.now() / 1000);
    return {
      iss: op.issuer,
      sub: "sub-default",
      aud: op.clientId,
      iat: now,
      exp: now + 300,
      email: "user@corp.test",
      email_verified: true,
      name: "Test User",
    };
  };

  // Record a consent for the authorization URL HS redirected to, and return
  // the callback path + query the provider would redirect the browser to.
  op.authorize = function (authUrl, aopts) {
    aopts = aopts || {};
    var u = new URL(authUrl);
    var params = u.searchParams;
    var code = b64url(nodeCrypto.randomBytes(18));
    // A provider that receives max_age returns auth_time (OpenID Connect Core
    // 1.0, section 3.1.2.1). A test's own auth_time, or its explicit
    // undefined, is kept.
    if (params.has("max_age") && !(aopts.claims && Object.prototype.hasOwnProperty.call(aopts.claims, "auth_time"))) {
      aopts = Object.assign({}, aopts, { claims: Object.assign({ auth_time: Math.floor(Date.now() / 1000) }, aopts.claims || {}) });
    }
    op.codes.set(code, {
      nonce: params.get("nonce"),
      challenge: params.get("code_challenge"),
      method: params.get("code_challenge_method"),
      redirectUri: params.get("redirect_uri"),
      clientId: params.get("client_id"),
      claims: aopts.claims || {},
      token: aopts.token || null,
      userinfo: aopts.userinfo,
    });
    var redirect = new URL(params.get("redirect_uri"));
    var q = new URLSearchParams();
    q.set("code", code);
    q.set("state", aopts.state !== undefined ? aopts.state : params.get("state"));
    if (aopts.iss) q.set("iss", aopts.iss);
    if (aopts.extraQuery) q.append(aopts.extraQuery[0], aopts.extraQuery[1]);
    return { path: redirect.pathname + "?" + q.toString(), code: code, params: params };
  };

  function tokenResponse(form) {
    op.tokenRequests += 1;
    var code = form.get("code");
    var rec = op.codes.get(code);
    if (!rec) return { status: 400, json: { error: "invalid_grant" } };
    op.codes.delete(code);
    var verifier = form.get("code_verifier") || "";
    var expected = b64url(nodeCrypto.createHash("sha256").update(verifier).digest());
    if (rec.method !== "S256" || expected !== rec.challenge) return { status: 400, json: { error: "invalid_grant", error_description: "PKCE verification failed" } };
    if (form.get("redirect_uri") !== rec.redirectUri) return { status: 400, json: { error: "invalid_grant" } };

    var claims = Object.assign(op.defaultClaims(), { nonce: rec.nonce }, rec.claims);
    Object.keys(claims).forEach(function (k) { if (claims[k] === undefined) delete claims[k]; });
    var header = { alg: "RS256", kid: "k1", typ: "JWT" };
    var signOpts = { key: keys.privateKey };
    var mode = rec.token;
    if (mode === "alg-none") header = { alg: "none", typ: "JWT" };
    if (mode === "hs256") { header = { alg: "HS256", kid: "k1", typ: "JWT" }; signOpts = { secret: op.clientSecret }; }
    if (mode === "unknown-kid") header.kid = "k-unknown";
    if (mode === "bad-signature") signOpts = { key: otherKeys.privateKey };
    var accessToken = "at-" + b64url(nodeCrypto.randomBytes(12));
    op.userinfoResponses.set(accessToken, rec.userinfo !== undefined ? rec.userinfo : Object.assign({ sub: claims.sub }, rec.claims.userinfoExtra || {}));
    var body = { access_token: accessToken, token_type: "Bearer", expires_in: 300 };
    if (mode !== "no-id-token") body.id_token = signJwt(header, claims, signOpts);
    return { status: 200, json: body };
  }

  // Shared request handler: method, absolute URL, form body (string).
  op.handle = function (method, url, bodyText, headers) {
    var u = new URL(url);
    var path = u.pathname;
    var base = new URL(op.issuer).pathname.replace(/\/$/, "");
    if (path === base + "/.well-known/openid-configuration") return { status: 200, json: op.discovery() };
    if (path === op.jwksPath || url === opts.jwksUri) return { status: 200, json: { keys: [jwk] } };
    if (path === base + "/token" && method === "POST") return tokenResponse(new URLSearchParams(bodyText || ""));
    if (path === base + "/userinfo") {
      var auth = (headers && (headers.authorization || headers.Authorization)) || "";
      var at = String(auth).replace(/^Bearer\s+/i, "");
      if (!op.userinfoResponses.has(at)) return { status: 401, json: { error: "invalid_token" } };
      var ui = op.userinfoResponses.get(at);
      if (ui === null) return { status: 500, json: { error: "server_error" } };
      return { status: 200, json: ui };
    }
    return { status: 404, json: { error: "not_found" } };
  };

  // Route b.httpClient.request calls for the issuer's origin to handle(),
  // leaving every other URL to the real client. Returns a restore function.
  // The server runs in-process, so the stub reaches the same b.httpClient the
  // oauth client calls.
  op.installHttpStub = function (b) {
    var real = b.httpClient.request;
    var origin = new URL(op.issuer).origin;
    b.httpClient.request = function (ropts) {
      var url = String(ropts && ropts.url || "");
      if (url.indexOf(origin + "/") !== 0) return real.call(b.httpClient, ropts);
      var body = ropts.body ? (Buffer.isBuffer(ropts.body) ? ropts.body.toString("utf8") : String(ropts.body)) : "";
      var out = op.handle(String(ropts.method || "GET").toUpperCase(), url, body, ropts.headers || {});
      return Promise.resolve({ statusCode: out.status, status: out.status, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify(out.json)) });
    };
    return function restore() { b.httpClient.request = real; };
  };

  op.listen = function () {
    return new Promise(function (resolve) {
      op.server = http.createServer(function (req, res) {
        var chunks = [];
        req.on("data", function (c) { chunks.push(c); });
        req.on("end", function () {
          var url = "http://127.0.0.1:" + op.server.address().port + req.url;
          var out = op.handle(req.method, url, Buffer.concat(chunks).toString("utf8"), req.headers);
          var body = Buffer.from(JSON.stringify(out.json));
          res.writeHead(out.status, { "content-type": "application/json", "content-length": body.length });
          res.end(body);
        });
      });
      op.server.listen(0, "127.0.0.1", function () {
        if (!op.issuer) op.issuer = "http://127.0.0.1:" + op.server.address().port;
        resolve(op);
      });
    });
  };

  op.close = function () {
    return new Promise(function (resolve) {
      if (!op.server) return resolve();
      op.server.close(function () { resolve(); });
      if (typeof op.server.closeAllConnections === "function") op.server.closeAllConnections();
    });
  };

  return op;
}

module.exports = { create: create, signJwt: signJwt };
