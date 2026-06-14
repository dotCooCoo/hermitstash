var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");

var testServer = require("../helpers/test-server");

// RFC 9457 (Problem Details for HTTP APIs) — non-HTML clients receive
// `application/problem+json` bodies with { type, title, status,
// detail? }; 5xx detail is suppressed so internal failure text never
// leaks. HTML clients get the templated error page via Accept
// negotiation.
//
// Test scope: routes that reach the centralized error-handler
// (middleware/error-handler.js) via thrown AppError subclasses. Two
// classes of bypass exist (asserted as current behavior to guard
// against further drift):
//
//   1. onNotFound at server-main.js — always renders HTML via
//      send(res, "error", ...). Skips Accept negotiation.
//   2. Inline `res.status(N).json({ error })` patterns in routes/ —
//      validation paths that emit the legacy { error } shape directly
//      and never reach the centralized handler. routes/auth.js
//      catches AppError locally and re-emits as { error }.
//
// As routes migrate to throwing AppError at the boundary, more
// responses route through the centralized handler and gain
// problem+json. Today's integration coverage exercises the handler
// directly to lock the wire format.

describe("RFC 9457 problem-details (error-handler contract)", function () {
  before(async function () { await testServer.start(); });
  after(function () { return testServer.stop(); });

  describe("error-handler module contract", function () {
    var errorHandler;
    var Mocks;

    before(function () {
      // Require error-handler from the running test server so its
      // module-load side effects (problemDetails.setBase) take effect.
      errorHandler = require(path.join(testServer.projectRoot, "middleware", "error-handler"));
      Mocks = (function () {
        function mockReq(headers) { return { method: "POST", url: "/x", pathname: "/x", headers: headers || {} }; }
        function mockRes() {
          var state = { statusCode: 0, headers: {}, body: "", ended: false, writableEnded: false };
          return {
            _state: state,
            get writableEnded() { return state.writableEnded; },
            get statusCode() { return state.statusCode; },
            set statusCode(v) { state.statusCode = v; },
            setHeader: function (k, v) { state.headers[k.toLowerCase()] = v; },
            writeHead: function (code, hdrs) {
              state.statusCode = code;
              if (hdrs) Object.keys(hdrs).forEach(function (k) { state.headers[k.toLowerCase()] = hdrs[k]; });
            },
            end: function (chunk) {
              if (chunk != null) state.body += chunk;
              state.ended = true;
              state.writableEnded = true;
            },
          };
        }
        return { mockReq: mockReq, mockRes: mockRes };
      })();
    });

    function loadAppErrors() {
      return require(path.join(testServer.projectRoot, "app", "shared", "errors"));
    }

    it("ValidationError → 400 problem+json with validation-error type", function () {
      var { ValidationError } = loadAppErrors();
      var req = Mocks.mockReq({ accept: "application/json" });
      var res = Mocks.mockRes();
      errorHandler(new ValidationError("name must be a non-empty string"), req, res);

      assert.strictEqual(res._state.statusCode, 400);
      assert.strictEqual(res._state.headers["content-type"], "application/problem+json");
      assert.strictEqual(res._state.headers["cache-control"], "no-store");
      var body = JSON.parse(res._state.body);
      assert.strictEqual(body.type, "https://hermitstash.com/problems/validation-error");
      assert.strictEqual(body.title, "Validation Error");
      assert.strictEqual(body.status, 400);
      assert.strictEqual(body.detail, "name must be a non-empty string");
    });

    it("AuthenticationError → 401 problem+json with auth-required type", function () {
      var { AuthenticationError } = loadAppErrors();
      var req = Mocks.mockReq({ accept: "application/json" });
      var res = Mocks.mockRes();
      errorHandler(new AuthenticationError("Token expired"), req, res);

      assert.strictEqual(res._state.statusCode, 401);
      var body = JSON.parse(res._state.body);
      assert.strictEqual(body.type, "https://hermitstash.com/problems/auth-required");
      assert.strictEqual(body.title, "Auth Required");
      assert.strictEqual(body.detail, "Token expired");
    });

    it("NotFoundError → 404 problem+json", function () {
      var { NotFoundError } = loadAppErrors();
      var req = Mocks.mockReq({ accept: "application/json" });
      var res = Mocks.mockRes();
      errorHandler(new NotFoundError("Bundle abc not found"), req, res);

      assert.strictEqual(res._state.statusCode, 404);
      var body = JSON.parse(res._state.body);
      assert.strictEqual(body.type, "https://hermitstash.com/problems/not-found");
      assert.strictEqual(body.status, 404);
    });

    it("plain Error → 500 problem+json with detail SUPPRESSED (no internal leak)", function () {
      var req = Mocks.mockReq({ accept: "application/json" });
      var res = Mocks.mockRes();
      // Non-AppError throws become 500s. The handler must NOT echo the
      // internal error message to the response body — only the generic
      // "Internal Server Error" title.
      errorHandler(new Error("/etc/passwd not found, db.password=hunter2"), req, res);

      assert.strictEqual(res._state.statusCode, 500);
      var body = JSON.parse(res._state.body);
      assert.strictEqual(body.type, "https://hermitstash.com/problems/internal-error");
      assert.strictEqual(body.title, "Internal Error");
      assert.strictEqual(body.detail, undefined,
        "5xx detail must be suppressed — internal failure text never reaches the client");
      assert.ok(!body.detail || !body.detail.includes("hunter2"),
        "credential-shaped strings must not leak");
    });

    it("HTML client (Accept: text/html) gets templated error, NOT problem+json", function () {
      var { ValidationError } = loadAppErrors();
      var req = Mocks.mockReq({ accept: "text/html,application/xhtml+xml" });
      var res = Mocks.mockRes();
      errorHandler(new ValidationError("bad shape"), req, res);

      var ctype = (res._state.headers["content-type"] || "").toLowerCase();
      // Either text/html (template rendered) or text/plain (template
      // render failed → fallback). NOT problem+json — Accept negotiated.
      assert.ok(ctype.includes("text/html") || ctype.includes("text/plain"),
        "HTML client should NOT receive problem+json, got " + ctype);
      assert.ok(!ctype.includes("application/problem+json"));
    });
  });

  describe("api-encrypt × error-handler — encrypted-session error responses", function () {
    // Regression guard for the confidentiality-boundary fix: on a cookie-
    // authenticated session the api-encrypt middleware wraps res.json, and the
    // error handler must route problem-details THROUGH that wrap (res.json)
    // rather than b.problemDetails' raw res.end — otherwise error bodies ship
    // in cleartext on a session the client negotiated as encrypted. This
    // matters most on an HTTP-mode deployment where the api-encrypt layer is
    // the only on-wire payload confidentiality.
    var apiEncrypt, errorHandler, decryptPayload, AppErrors;

    before(function () {
      apiEncrypt = require(path.join(testServer.projectRoot, "middleware", "api-encrypt"));
      errorHandler = require(path.join(testServer.projectRoot, "middleware", "error-handler"));
      decryptPayload = require(path.join(testServer.projectRoot, "lib", "api-crypto")).decryptPayload;
      AppErrors = require(path.join(testServer.projectRoot, "app", "shared", "errors"));
    });

    // Cookie session (no Bearer apiKey) + a router-shaped res.json baseline so
    // the api-encrypt wrap has a real res.json to wrap.
    function cookieReq() {
      return { method: "GET", url: "/x", pathname: "/x", headers: { accept: "application/json" }, session: {}, socket: {}, on: function () {} };
    }
    function resWithJson() {
      var state = { statusCode: 200, headers: {}, body: "", writableEnded: false };
      var res = {
        _state: state,
        get writableEnded() { return state.writableEnded; },
        get statusCode() { return state.statusCode; },
        set statusCode(v) { state.statusCode = v; },
        setHeader: function (k, v) { state.headers[k.toLowerCase()] = v; },
        getHeader: function (k) { return state.headers[k.toLowerCase()]; },
        writeHead: function (code, hdrs) { state.statusCode = code; if (hdrs) Object.keys(hdrs).forEach(function (k) { state.headers[k.toLowerCase()] = hdrs[k]; }); },
        end: function (chunk) { if (chunk != null) state.body += chunk; state.writableEnded = true; },
      };
      // Mirror lib/vendor/blamejs/lib/router.js res.json (statusCode || 200, application/json).
      res.json = function (data) { res.writeHead(state.statusCode || 200, { "Content-Type": "application/json" }); res.end(JSON.stringify(data)); };
      return res;
    }

    it("cookie-encrypted session: 4xx error body is encrypted, not plaintext problem+json", function () {
      var req = cookieReq();
      var res = resWithJson();
      apiEncrypt(req, res, function () {});
      assert.strictEqual(res._apiEncryptJson, true, "api-encrypt should flag res.json as encrypting");

      errorHandler(new AppErrors.ValidationError("bad input value"), req, res);

      assert.strictEqual(res._state.statusCode, 400);
      assert.strictEqual(res._state.headers["content-type"], "application/json",
        "encrypted error ships as the application/json envelope, not application/problem+json");
      var body = JSON.parse(res._state.body);
      assert.strictEqual(typeof body._e, "string", "error body must be the encrypted envelope");
      assert.strictEqual(body.detail, undefined, "no plaintext problem fields on the wire");
      assert.strictEqual(body.title, undefined);

      var problem = decryptPayload(body._e, res._apiKey, 60000);
      assert.strictEqual(problem.status, 400);
      assert.strictEqual(problem.title, "Validation Error");
      assert.strictEqual(problem.detail, "bad input value");
      assert.strictEqual(problem.type, "https://hermitstash.com/problems/validation-error");
    });

    it("cookie-encrypted session: 5xx detail stays suppressed inside the envelope", function () {
      var req = cookieReq();
      var res = resWithJson();
      apiEncrypt(req, res, function () {});

      errorHandler(new Error("db.password=hunter2 at /etc/secret"), req, res);

      assert.strictEqual(res._state.statusCode, 500);
      assert.ok(res._state.body.indexOf("hunter2") === -1, "internal text must not appear, encrypted or not");
      var problem = decryptPayload(JSON.parse(res._state.body)._e, res._apiKey, 60000);
      assert.strictEqual(problem.detail, undefined, "5xx detail suppressed inside the encrypted envelope too");
    });

    it("bearer-encrypted session: error body routes through the encrypting res.json wrap", function () {
      // The Bearer/sync routes (/drop/init, /drop/finalize, /sync/rename) are
      // covered by blamejs apiEncrypt, which sets req.apiEncryptSessionKey and
      // wraps res.json with a per-session encrypting envelope — but does NOT
      // set res._apiEncryptJson. The error handler must route problem-details
      // through that wrap on this flag too, or a thrown AppError ships in
      // cleartext via b.problemDetails' raw res.end on a session the client
      // negotiated as encrypted.
      var req = cookieReq();
      req.apiEncryptSessionKey = Buffer.alloc(32, 7); // blamejs sets this per request
      var res = resWithJson();
      // Stand in for the blamejs wrap: res.json envelopes into { _ct }.
      var origJson = res.json;
      res.json = function (data) {
        return origJson.call(res, { _ct: Buffer.from(JSON.stringify(data), "utf8").toString("base64") });
      };

      errorHandler(new AppErrors.NotFoundError("no such bundle"), req, res);

      assert.strictEqual(res._state.statusCode, 404, "status preserved through the wrap");
      assert.strictEqual(res._state.headers["content-type"], "application/json",
        "routes through res.json envelope, not application/problem+json");
      var body = JSON.parse(res._state.body);
      assert.strictEqual(typeof body._ct, "string", "error body must be the encrypted envelope");
      assert.strictEqual(body.detail, undefined, "no plaintext problem fields on the wire");
      assert.strictEqual(body.title, undefined);
      var problem = JSON.parse(Buffer.from(body._ct, "base64").toString("utf8"));
      assert.strictEqual(problem.status, 404);
      assert.strictEqual(problem.title, "Not Found");
      assert.strictEqual(problem.detail, "no such bundle");
      assert.strictEqual(problem.type, "https://hermitstash.com/problems/not-found");
    });

    it("unencrypted session: still plaintext application/problem+json (no envelope)", function () {
      // No api-encrypt run → res.json not wrapped, _apiEncryptJson unset →
      // b.problemDetails plaintext path (unchanged for non-encrypted sessions).
      var req = cookieReq();
      var res = resWithJson();
      errorHandler(new AppErrors.ValidationError("plain validation"), req, res);
      assert.strictEqual(res._state.headers["content-type"], "application/problem+json");
      var body = JSON.parse(res._state.body);
      assert.strictEqual(body.detail, "plain validation");
      assert.strictEqual(body._e, undefined);
    });
  });

  describe("known bypass paths (current behavior — guard against further drift)", function () {
    // onNotFound below is a pre-RFC 9457 pattern not yet migrated — asserted as
    // current behavior so a future fix updates both the test + the call site.
    // (requireAdmin USED to be here too; it now content-negotiates and is
    // asserted as fixed behavior below.)

    it("onNotFound (server-main.js:570) renders HTML, not problem+json", async function () {
      var { TestClient } = require("../helpers/http-client");
      var client = new TestClient(testServer.baseUrl());
      var res = await client.get("/this-path-does-not-exist", {
        headers: { Accept: "application/json" },
      });
      assert.strictEqual(res.status, 404);
      var ctype = (res.headers["content-type"] || "").toLowerCase();
      // Currently HTML. When the onNotFound handler migrates to throw
      // NotFoundError instead of calling send() directly, this will
      // become application/problem+json — flip this assertion at that
      // point.
      assert.ok(ctype.includes("text/html"),
        "current behavior: 404 always HTML; migrate onNotFound to throw NotFoundError to fix");
    });

    it("requireAdmin (middleware/require-admin.js) returns problem+json to JSON clients", async function () {
      var { TestClient } = require("../helpers/http-client");
      var client = new TestClient(testServer.baseUrl());
      client.clearCookies();
      var res = await client.get("/admin/apikeys/api", {
        headers: { Accept: "application/json" },
      });
      assert.ok([401, 403].includes(res.status));
      var ctype = (res.headers["content-type"] || "").toLowerCase();
      // requireAdmin now content-negotiates via emitError: a JSON client gets a
      // structured JSON error (problem+json on a plaintext session, or the
      // problem document inside the api-encrypt envelope — application/json —
      // on an encrypted one), NEVER the HTML error template. The exact ctype
      // depends on the encryption layer; the contract is "JSON, not HTML".
      assert.ok(ctype.includes("json") && !ctype.includes("text/html"),
        "admin guard must return a JSON error, not the HTML template, to JSON clients, got: " + ctype);
    });

    it("requireAdmin still renders HTML to browser clients (Accept: text/html)", async function () {
      var { TestClient } = require("../helpers/http-client");
      var client = new TestClient(testServer.baseUrl());
      client.clearCookies();
      var res = await client.get("/admin/apikeys/api", {
        headers: { Accept: "text/html" },
      });
      assert.ok([401, 403].includes(res.status));
      var ctype = (res.headers["content-type"] || "").toLowerCase();
      assert.ok(ctype.includes("text/html"),
        "admin guard must still render the HTML template to browser clients, got: " + ctype);
    });
  });
});
