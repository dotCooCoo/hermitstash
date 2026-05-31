var b = require("../lib/vendor/blamejs");
var { prefersJson } = require("./require-access");

// b.middleware.requireAuth gates on req.user. On rejection it emits an
// `auth.required.denied` audit event and Cache-Control: no-store (so a shared
// or back-button cache can't replay an unauthenticated 401/redirect to another
// user), answers JSON-preferring callers with 401 application/json
// { error: "Authentication required." }, and redirects browsers to the login
// page. prefersJson is HS's own — it keys on req.apiKey so API and sync clients
// still receive JSON rather than a redirect (the framework default checks only
// Accept / X-Requested-With).
var gate = b.middleware.requireAuth({
  redirectTo: "/auth/login",
  prefersJson: prefersJson,
});

// Preserve the 2-arg boolean call contract — `if (!requireAuth(req, res)) return;`
// at every protected route — over the framework's 3-arg middleware: pass a
// next() that records the pass; a rejection is written by the middleware and
// leaves the flag false.
module.exports = function requireAuth(req, res) {
  var authed = false;
  gate(req, res, function () { authed = true; });
  return authed;
};
