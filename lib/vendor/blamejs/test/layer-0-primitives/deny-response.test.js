"use strict";
/**
 * Deny-path response convention — every access-refusal middleware
 * routes its refusal through lib/middleware/deny-response.js, giving a
 * consumer one uniform way to shape it:
 *
 *   - default            — the middleware's existing body + Content-Type
 *                          (no behavior change)
 *   - problemDetails:true — RFC 9457 application/problem+json
 *   - onDeny(req,res,info) — the consumer fully owns the response; a
 *                          throwing or no-op hook falls through to the
 *                          default rather than hanging the request
 *
 * The deny-path response headers (Allow / WWW-Authenticate /
 * Retry-After / Accept) survive every mode.
 *
 * The shared b.testing mocks don't capture setHeader + writeHead body
 * + writableEnded together (problem mode writes via setHeader; default
 * mode via writeHead), so — like require-auth-cache-control.test.js —
 * this file rolls one complete response mock.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mkRes() {
  var hdrs = {};
  return {
    statusCode:    0,
    headersSent:   false,
    writableEnded: false,
    body:          null,
    setHeader: function (k, v) { hdrs[k.toLowerCase()] = v; },
    getHeader: function (k) { return hdrs[k.toLowerCase()]; },
    writeHead: function (sc, h) {
      this.statusCode = sc;
      this.headersSent = true;
      if (h && typeof h === "object") {
        for (var k in h) if (Object.prototype.hasOwnProperty.call(h, k)) {
          hdrs[k.toLowerCase()] = h[k];
        }
      }
      return this;
    },
    end: function (x) {
      if (x !== undefined && x !== null) this.body = x;
      this.writableEnded = true;
    },
    _hdrs: hdrs,
  };
}

function _mkReq(opts) {
  opts = opts || {};
  return {
    method:  opts.method || "GET",
    url:     opts.url || "/x",
    pathname: opts.pathname || "/x",
    headers: opts.headers || {},
    socket:  { remoteAddress: "127.0.0.1", encrypted: false },
    connection: {},
  };
}

function _json(s) { try { return JSON.parse(s); } catch (_e) { return {}; } }

async function _drive(mw, req) {
  var res = _mkRes();
  await mw(req, res, function () { res._nextCalled = true; });
  return res;
}

async function run() {
  var denyResponse = require("../../lib/middleware/deny-response").denyResponse;

  // ---- Helper unit: the three resolution modes ----
  (function () {
    // default mode
    var res = _mkRes();
    denyResponse(_mkReq(), res, {
      status: 403, contentType: "text/plain", body: "no",
      headers: { "Allow": "GET" },
      info: { status: 403, reason: "x" },
      problemTitle: "Forbidden",
    });
    check("denyResponse default: status + content-type + body + extra header",
      res.statusCode === 403 && res._hdrs["content-type"] === "text/plain" &&
      res.body === "no" && res._hdrs["allow"] === "GET");

    // problem mode
    var res2 = _mkRes();
    denyResponse(_mkReq(), res2, {
      problem: true, status: 403, contentType: "text/plain", body: "no",
      headers: { "Allow": "GET" }, problemCode: "x-refused", problemTitle: "Forbidden",
      problemDetail: "nope", info: { status: 403, reason: "x" },
    });
    var p = _json(res2.body);
    check("denyResponse problem: application/problem+json + RFC 9457 fields + extra header survives",
      res2.statusCode === 403 && res2._hdrs["content-type"] === "application/problem+json" &&
      p.status === 403 && p.title === "Forbidden" && p.detail === "nope" &&
      typeof p.type === "string" && res2._hdrs["allow"] === "GET");

    // onDeny owns
    var seen = null;
    var res3 = _mkRes();
    denyResponse(_mkReq(), res3, {
      onDeny: function (req, rs, info) { seen = info; rs.writeHead(418, {}); rs.end("teapot"); },
      status: 403, contentType: "text/plain", body: "no", info: { status: 403, reason: "x" },
    });
    check("denyResponse onDeny owns response + receives info",
      res3.statusCode === 418 && res3.body === "teapot" && seen && seen.reason === "x");

    // onDeny throws -> falls through to default (audited via onThrow)
    var threw = false;
    var res4 = _mkRes();
    denyResponse(_mkReq(), res4, {
      onDeny: function () { throw new Error("boom"); },
      onThrow: function () { threw = true; },
      status: 403, contentType: "text/plain", body: "default-after-throw",
      info: { status: 403, reason: "x" },
    });
    check("denyResponse onDeny throws -> default written + onThrow audited",
      res4.statusCode === 403 && res4.body === "default-after-throw" && threw === true);

    // onDeny no-op (doesn't write) -> falls through to default
    var res5 = _mkRes();
    denyResponse(_mkReq(), res5, {
      onDeny: function () { /* returns without writing */ },
      status: 403, contentType: "text/plain", body: "default-after-noop",
      info: { status: 403, reason: "x" },
    });
    check("denyResponse onDeny no-op -> default written (no hang)",
      res5.statusCode === 403 && res5.body === "default-after-noop");
  })();

  // ---- require-methods (405 / text/plain) ----
  (function () {
    var def = _mkRes();
    b.middleware.requireMethods(["GET"])(_mkReq({ method: "DELETE" }), def, function () {});
    check("requireMethods default 405 text/plain + Allow",
      def.statusCode === 405 && def._hdrs["content-type"] === "text/plain; charset=utf-8" &&
      def._hdrs["allow"] === "GET" && def.body === "Method Not Allowed");

    var pj = _mkRes();
    b.middleware.requireMethods(["GET"], { problemDetails: true })(_mkReq({ method: "DELETE" }), pj, function () {});
    check("requireMethods problemDetails 405 problem+json + Allow survives",
      pj.statusCode === 405 && pj._hdrs["content-type"] === "application/problem+json" &&
      pj._hdrs["allow"] === "GET" && _json(pj.body).status === 405);
  })();

  // ---- rate-limit (429) — X-RateLimit-* + Retry-After survive problem mode ----
  (function () {
    var mw = b.middleware.rateLimit({ backend: "memory", algorithm: "fixed-window", limit: 1, windowMs: 60000, problemDetails: true });
    var req = _mkReq();
    mw(req, _mkRes(), function () {});
    var res = _mkRes();
    mw(req, res, function () {});
    check("rateLimit problemDetails 429 problem+json + X-RateLimit-Limit survives",
      res.statusCode === 429 && res._hdrs["content-type"] === "application/problem+json" &&
      res._hdrs["x-ratelimit-limit"] === "1" && _json(res.body).status === 429);
  })();

  // ---- age-gate (451 / JSON envelope default) ----
  (function () {
    var opts = { getAge: function () { return 5; }, requireAge: 13, consentRequired: 13 };
    var def = _mkRes();
    b.middleware.ageGate(opts)(_mkReq(), def, function () {});
    check("ageGate default 451 JSON envelope",
      def.statusCode === 451 && def._hdrs["content-type"] === "application/json; charset=utf-8" &&
      _json(def.body).parentalConsent === false);

    var pj = _mkRes();
    b.middleware.ageGate(Object.assign({ problemDetails: true }, opts))(_mkReq(), pj, function () {});
    check("ageGate problemDetails 451 problem+json + requireAge extension",
      pj.statusCode === 451 && pj._hdrs["content-type"] === "application/problem+json" &&
      _json(pj.body).requireAge === 13);
  })();

  // ---- cors (403) ----
  (function () {
    var mw = b.middleware.cors({ origins: ["https://ok.example"], problemDetails: true });
    var res = _mkRes();
    mw(_mkReq({ headers: { origin: "https://evil.example" } }), res, function () {});
    check("cors problemDetails 403 problem+json on disallowed origin",
      res.statusCode === 403 && res._hdrs["content-type"] === "application/problem+json");
  })();

  // ---- require-bound-key — now reachable on b.middleware + RFC 6750 challenge ----
  (function () {
    check("requireBoundKey reachable on b.middleware (was unwired)",
      typeof b.middleware.requireBoundKey === "function");
  })();

  await (async function () {
    var mw = b.middleware.requireBoundKey({
      resolver: async function () { return { id: "k1", scopes: ["other"], boundFields: {} }; },
      requiredScopes: ["needed"],
    });
    var scope = await _drive(mw, _mkReq({ headers: { authorization: "Bearer abc" } }));
    check("requireBoundKey 403 missing-scope -> WWW-Authenticate insufficient_scope (RFC 6750)",
      scope.statusCode === 403 && /insufficient_scope/.test(scope._hdrs["www-authenticate"] || ""));
    var noTok = await _drive(mw, _mkReq());
    check("requireBoundKey 401 no-token omits error code (RFC 6750 §3)",
      noTok.statusCode === 401 && noTok._hdrs["www-authenticate"] === 'Bearer realm="api"');
  })();

  // ---- bearer-auth — requiredScopes now accepted (was rejected by validateOpts) ----
  await (async function () {
    var mw = b.middleware.bearerAuth({
      verify: async function () { return { id: 1, scopes: ["read"] }; },
      requiredScopes: ["admin"],
    });
    var res = await _drive(mw, _mkReq({ headers: { authorization: "Bearer good" } }));
    check("bearerAuth requiredScopes reachable -> 403 insufficient_scope",
      res.statusCode === 403 && /insufficient_scope/.test(res._hdrs["www-authenticate"] || "") &&
      _json(res.body).required[0] === "admin");
  })();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}
