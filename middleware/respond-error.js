/**
 * Shared error-response emitter with content negotiation.
 *
 * Renders an error as either the HTML error template (browser clients —
 * Accept: text/html and no API key) or RFC 9457 application/problem+json
 * (everything else, including Bearer / API clients).
 *
 * On a session whose responses are application-layer encrypted, the problem
 * document is routed through res.json so the encryption covers it —
 * b.problemDetails.send writes via res.end, which bypasses the encryption wrap
 * and would otherwise ship the error in cleartext (Security Invariant: payload
 * encryption applies to all clients). Two wrappers cover res.json: the legacy
 * cookie/browser layer (res._apiEncryptJson) and the blamejs per-session layer
 * on Bearer/sync routes (req.apiEncryptSessionKey).
 *
 * The centralized error-handler (for thrown AppErrors) and inline guards that
 * send a response directly (e.g. require-admin, the logout CSRF check) both go
 * through here, so a 403 looks identical whether it was thrown or sent inline.
 */
var b = require("../lib/vendor/blamejs");
var { send } = require("./send");

// Point problem-type URIs at HermitStash's own namespace. URIs are identifiers,
// not resolvable links — nothing has to live at the URL. Idempotent; whichever
// module loads first wins.
b.problemDetails.setBase("https://hermitstash.com/problems");

// VALIDATION_ERROR → validation-error
function codeToTypeSlug(code) {
  return (code || "internal-error").toLowerCase().replace(/_/g, "-");
}

// VALIDATION_ERROR → Validation Error
function codeToTitle(code) {
  if (!code) return "Error";
  return code.split("_").map(function (w) {
    return w.charAt(0) + w.slice(1).toLowerCase();
  }).join(" ");
}

/**
 * Emit an error response. opts:
 *   { status, code, title?, htmlTitle?, detail?, exposeDetail?, extras?, retryAfter? }
 * - title        → problem+json `title` (defaults to a prettified `code`)
 * - htmlTitle    → title shown on the HTML error template (defaults to `title`)
 * - detail       → problem+json `detail` / HTML message, withheld on a 5xx
 *                  unless exposeDetail is true
 * - exposeDetail → send `detail` on a 5xx (ServiceUnavailableError sets it)
 * - extras       → RFC 9457 extension members merged at the top level
 * - retryAfter   → on a 429 or 503, a Retry-After header + a problem+json hint
 */
function emitError(req, res, opts) {
  if (res.writableEnded) return;
  var status = opts.status || 500;
  var code = opts.code || "INTERNAL_ERROR";
  var problemTitle = opts.title || codeToTitle(code);
  var detail = opts.detail;
  // A 5xx detail is withheld from the client unless the error sets exposeDetail.
  var hideDetail = status >= 500 && !opts.exposeDetail;

  // A 429 (RFC 6585 §4), or a 503 that names a delay, gets a Retry-After header
  // (RFC 9110 §10.2.3) on both HTML and problem+json responses. A problem+json
  // body also carries the value as `retryAfter`.
  var retryAfter = (status === 429 || status === 503) && opts.retryAfter != null ? opts.retryAfter : null;
  if (retryAfter != null && !res.headersSent) res.setHeader("Retry-After", String(retryAfter));

  var accept = req.headers && req.headers.accept || "";
  var wantsHtml = (req && !req.apiKey) && accept.indexOf("text/html") !== -1;

  if (wantsHtml) {
    var htmlTitle = opts.htmlTitle || problemTitle;
    try {
      send(res, "error", {
        user: req.user || null,
        title: htmlTitle,
        message: hideDetail ? "Something went wrong. Please try again later." : (detail || htmlTitle),
      }, status);
    } catch (_) {
      // Template rendering failed — fall back to plain text.
      res.writeHead(status, { "Content-Type": "text/plain" });
      res.end(hideDetail ? "Internal Server Error" : (detail || htmlTitle));
    }
    return;
  }

  // RFC 9457 problem-details.
  var problem = {
    type:   "https://hermitstash.com/problems/" + codeToTypeSlug(code),
    title:  problemTitle,
    status: status,
    detail: hideDetail ? undefined : detail,
  };

  if (opts.extras && typeof opts.extras === "object") {
    Object.keys(opts.extras).forEach(function (k) {
      // Skip all five RFC 9457 reserved members (type/title/status/detail/instance)
      // so an extension can't overwrite a reserved field or trip the framework's
      // instance validator.
      if (k !== "type" && k !== "title" && k !== "status" && k !== "detail" && k !== "instance") {
        problem[k] = opts.extras[k];
      }
    });
  }

  if (retryAfter != null && problem.retryAfter === undefined) problem.retryAfter = retryAfter;

  if ((res._apiEncryptJson || (req && req.apiEncryptSessionKey)) && typeof res.json === "function") {
    res.statusCode = status;
    res.setHeader("Cache-Control", "no-store");
    res.json(problem);
    return;
  }

  b.problemDetails.send(res, problem);
}

module.exports = { emitError: emitError, codeToTypeSlug: codeToTypeSlug, codeToTitle: codeToTitle };
