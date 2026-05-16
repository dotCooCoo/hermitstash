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

  describe("known bypass paths (current behavior — guard against further drift)", function () {
    // Both bypasses below are pre-RFC 9457 patterns that haven't been
    // migrated yet. Asserting current behavior so a future fix knows
    // to update both the test + the call site.

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

    it("requireAdmin (middleware/require-admin.js) renders HTML on auth refusal", async function () {
      var { TestClient } = require("../helpers/http-client");
      var client = new TestClient(testServer.baseUrl());
      client.clearCookies();
      var res = await client.get("/admin/apikeys/api", {
        headers: { Accept: "application/json" },
      });
      assert.ok([401, 403].includes(res.status));
      var ctype = (res.headers["content-type"] || "").toLowerCase();
      // Currently HTML. requireAdmin uses send(res, "error", ...).
      // Migration target: throw ForbiddenError / AuthenticationError.
      assert.ok(ctype.includes("text/html"),
        "current behavior: admin guard renders HTML; migrate to throw ForbiddenError to fix");
    });
  });
});
