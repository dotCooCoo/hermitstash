const { describe, it } = require("node:test");
const assert = require("node:assert");
const b = require("../../lib/vendor/blamejs");

const requireAuth = require("../../middleware/require-auth");

function mkRes() {
  return {
    status: null, statusCode: null, headers: {}, body: "",
    setHeader(k, v) { this.headers[k] = v; return this; },
    writeHead(s, h) { this.status = s; this.statusCode = s; if (h) Object.assign(this.headers, h); return this; },
    end(x) { this.body = x || ""; return this; },
  };
}

describe("require-auth — 2-arg shim over b.middleware.requireAuth", function () {
  it("returns true and writes nothing for an authenticated request", function () {
    const res = mkRes();
    assert.strictEqual(requireAuth({ user: { id: 1 }, headers: {} }, res), true);
    assert.strictEqual(res.status, null);
  });

  it("rejects an API client (req.apiKey) with 401 application/problem+json + Cache-Control no-store", function () {
    const res = mkRes();
    assert.strictEqual(requireAuth({ headers: {}, apiKey: "k" }, res), false);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.headers["Content-Type"], "application/problem+json");
    assert.strictEqual(res.headers["Cache-Control"], "no-store");
    const problem = JSON.parse(res.body);
    assert.strictEqual(problem.status, 401);
    assert.strictEqual(typeof problem.title, "string");
  });

  it("rejects a JSON-Accept client with 401 application/problem+json", function () {
    const res = mkRes();
    assert.strictEqual(requireAuth({ headers: { accept: "application/json" } }, res), false);
    assert.strictEqual(res.statusCode, 401);
    assert.strictEqual(res.headers["Content-Type"], "application/problem+json");
  });

  it("redirects a browser to /auth/login (302) with Cache-Control no-store", function () {
    const res = mkRes();
    assert.strictEqual(requireAuth({ headers: { accept: "text/html" } }, res), false);
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.headers.Location, "/auth/login");
    assert.strictEqual(res.headers["Cache-Control"], "no-store");
  });
});

describe("require-auth — b.middleware.requireAuth contract (the primitive the shim wraps)", function () {
  it("calls next() when req.user is present", function () {
    const gate = b.middleware.requireAuth({ redirectTo: "/login" });
    let passed = false;
    gate({ user: { id: 1 }, headers: {} }, mkRes(), function () { passed = true; });
    assert.strictEqual(passed, true);
  });

  it("writes a rejection (no next) when req.user is absent", function () {
    const gate = b.middleware.requireAuth({ redirectTo: "/login", prefersJson: function () { return true; } });
    let passed = false;
    const res = mkRes();
    gate({ headers: {} }, res, function () { passed = true; });
    assert.strictEqual(passed, false);
    assert.strictEqual(res.status, 401);
  });
});
