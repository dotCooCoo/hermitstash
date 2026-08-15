"use strict";

/**
 * Every route under /admin checks that the caller is an admin.
 *
 * The check is a line inside each handler rather than a mount-wide middleware,
 * so adding a route is also remembering to add the guard. Nothing enforced
 * that. Forty-eight of them are right today; the forty-ninth is the one this
 * test exists for.
 *
 * It reads the source rather than driving requests because the failure it
 * catches is an omission, and an omitted guard has no request to drive — the
 * route simply answers. Reading every registration is what makes the check
 * exhaustive instead of a list someone has to maintain.
 */

var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var fs = require("node:fs");
var path = require("node:path");

// The guard writes an audit entry when it denies, so loading it reaches the
// database. Point that at a disposable one before anything requires it.
var testEnv = require("../helpers/test-env");

// And the data directory, which test-env does not touch — so without this the
// module would read and write the real one.
var tmpDataDir = require("node:fs").mkdtempSync(require("node:path").join(require("node:os").tmpdir(), "hs-test-"));
process.env.HERMITSTASH_DATA_DIR = tmpDataDir;
var vault = require("../../lib/vault");
var audit = require("../../lib/audit");

// And the audit write seals its fields, which needs the vault open. Without
// this the denials still happen and the test still passes, but each one logs an
// insert failure — error output from a passing test is exactly the noise that
// hides a real one.
before(async function () { await vault.init(); });

after(async function () {
  // The denial checks queue audit writes. Deleting the database out from under
  // them races the insert and logs a failure from a passing test; draining also
  // lets the audit subsystem settle instead of holding the process open.
  try { await audit.drainChain(); } catch (_e) { /* nothing queued */ }
  if (testEnv && typeof testEnv.cleanup === "function") testEnv.cleanup();
  try { require("node:fs").rmSync(tmpDataDir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
});

var projectRoot = path.join(__dirname, "..", "..");
var routesDir = path.join(projectRoot, "routes");

// Scanned over the whole source rather than line by line, because a
// registration is not always one line: `app.post(\n  "/admin/x", …)` would be
// invisible to a per-line match, and the route it hid would be the one worth
// catching.
var REGISTER = /\bapp\.(get|post|put|patch|delete)\s*\(/g;
var FIRST_STRING = /^[\s,]*(["'`])([^"'`]*)\1/;

// Both supported spellings. require-admin.js works as 3-arg middleware —
// app.post("/admin/x", requireAdmin, handler), which its own docblock calls the
// preferred form — and as the 2-arg inline guard the existing routes use.
// Recognising only the inline call would fail a route written the recommended
// way, which teaches people to avoid the recommendation.
// The inline form must BRANCH on the result. A bare `requireAdmin(req, res);`
// calls the guard, gets false back, and carries straight on into the handler —
// so accepting the call alone would pass exactly the route this test exists to
// fail. All 97 inline uses in routes/ are written the one way, so requiring it
// costs nothing and closes that hole.
var GUARD_INLINE = /if\s*\(\s*!\s*require(Admin|AdminApi)\s*\(\s*req\s*,\s*res\s*\)\s*\)\s*return/;
var GUARD_MIDDLEWARE = /^[\s,]*(["'`])[^"'`]*\1\s*,\s*require(Admin|AdminApi)\b/;

// Comments are stripped before any of this is applied — a guard named in prose
// protects nothing, whether the prose sits above the route or trails the line
// that opens it. The trailing case matters most: a commented-out guard on the
// handler's first line would otherwise read as the guard itself.
//
// The `[^:]` before the slashes keeps `https://` in a string from being treated
// as the start of a comment, which would swallow the rest of that line.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter(function (line) { return !/^\s*(\/\/|\*)/.test(line); })
    .map(function (line) { return line.replace(/(^|[^:])\/\/.*$/, "$1"); })
    .join("\n");
}

// Enough source to cover the path, any middleware arguments, and the opening
// lines of the handler — but never past the NEXT registration. A fixed window
// reaches into the following route, and these are packed closely enough that an
// unguarded one would borrow its neighbour's check and read as guarded, which
// is precisely the omission this is here to catch.
var WINDOW = 600;

function registrations(src) {
  var found = [];
  var m;
  REGISTER.lastIndex = 0;
  while ((m = REGISTER.exec(src)) !== null) {
    found.push({ method: m[1], at: m.index, after: m.index + m[0].length });
  }
  return found;
}

function adminRoutes() {
  var out = [];
  fs.readdirSync(routesDir).forEach(function (name) {
    if (!/\.js$/.test(name)) return;
    var src = stripComments(fs.readFileSync(path.join(routesDir, name), "utf8"));
    var regs = registrations(src);

    regs.forEach(function (reg, idx) {
      var next = regs[idx + 1] ? regs[idx + 1].at : src.length;
      var rest = src.slice(reg.after, next);
      var pathMatch = rest.match(FIRST_STRING);
      if (!pathMatch) return;                // computed path — not an admin literal
      var routePath = pathMatch[2];
      if (routePath !== "/admin" && routePath.indexOf("/admin/") !== 0) return;

      out.push({
        file: name,
        line: src.slice(0, reg.at).split("\n").length,
        method: reg.method.toUpperCase(),
        path: routePath,
        guarded: GUARD_MIDDLEWARE.test(rest) || GUARD_INLINE.test(rest.slice(0, WINDOW)),
      });
    });
  });
  return out;
}

describe("admin routes are guarded", function () {
  it("finds the admin surface at all", function () {
    // If the registration form changes, the scan above stops matching and every
    // other assertion here passes over an empty list. Pin a floor so the test
    // cannot quietly become a no-op.
    var routes = adminRoutes();
    assert.ok(routes.length >= 40,
      "expected the admin surface to be found; matched only " + routes.length
      + " routes, so the scanner is probably out of step with how routes are registered");
  });

  it("every one of them checks the caller is an admin", function () {
    var missing = adminRoutes().filter(function (r) { return !r.guarded; });
    assert.deepEqual(missing.map(function (r) {
      return r.file + ":" + r.line + " " + r.method + " " + r.path;
    }), [], "these admin routes reach their handler without requireAdmin");
  });

  it("the guard actually refuses everyone it should", function () {
    // Otherwise the check above only proves a call to something harmless. The
    // guard audits a denial, so the database has to be the disposable one —
    // test-env is required at the top of this file for that.
    var requireAdmin = require(path.join(projectRoot, "middleware", "require-admin"));
    assert.equal(typeof requireAdmin, "function", "requireAdmin must be callable");

    function res() {
      var r = {
        statusCode: 200,
        headersSent: false,
        setHeader: function () { return r; },
        getHeader: function () { return undefined; },
        writeHead: function (c) { r.statusCode = c; return r; },
        status: function (c) { r.statusCode = c; return r; },
        json: function () { return r; },
        end: function () { return r; },
      };
      return r;
    }
    function req(user, apiKey) {
      return {
        user: user, apiKey: apiKey, method: "GET", pathname: "/admin/probe",
        headers: { accept: "application/json" },
      };
    }

    assert.equal(requireAdmin(req(null), res()), false,
      "an unauthenticated caller must be refused");
    assert.equal(requireAdmin(req({ _id: "u1", role: "user" }), res()), false,
      "a signed-in non-admin must be refused");
    assert.equal(requireAdmin(req({ _id: "u1", role: "admin" }), res()), true,
      "an admin must be admitted, or the guard is refusing everyone and proves nothing");
    assert.equal(requireAdmin(req({ _id: "u1", role: "admin" }, { scopes: "read" }), res()), false,
      "an admin's API key without the admin scope must still be refused");
  });
});
