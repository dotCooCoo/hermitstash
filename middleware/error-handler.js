/**
 * Centralized error handler.
 *
 * Registered on the Router via onError() — catches all unhandled errors from
 * middleware and route handlers.
 *
 * - AppError subclasses: returns their status code + message
 * - Security errors (401/403/429): logged to audit
 * - 500 errors: stack trace logged to stderr, generic message to client
 * - HTML clients get the error template
 * - Non-HTML clients get RFC 9457 application/problem+json via b.problemDetails
 * - Stack traces are NEVER leaked to the client
 */
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var b = require("../lib/vendor/blamejs");
var { send } = require("./send");

// Security-relevant status codes that warrant an audit entry
var SECURITY_CODES = { 401: true, 403: true, 429: true };

// Point problem-type URIs at HermitStash's own namespace so operators
// know the catalog they're looking at. URIs are identifiers, not resolvable
// links — nothing has to live at the URL.
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

function errorHandler(err, req, res) {
  // Determine status and client-facing message
  var status = 500;
  var message = "Internal Server Error";
  var code = "INTERNAL_ERROR";

  if (err && err.isAppError) {
    status = err.statusCode || 500;
    message = err.message || message;
    code = err.code || code;
  }

  // Log 500s with full stack trace to stderr
  if (status >= 500) {
    logger.error("Unhandled server error", {
      status: status,
      code: code,
      stack: err && err.stack ? err.stack : String(err),
      path: req.pathname || req.url,
      method: req.method,
    });
  }

  // Audit security-related errors
  if (SECURITY_CODES[status]) {
    try {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, {
        req: req,
        details: "error-handler: " + status + " " + code + " — " + (req.pathname || req.url),
      });
    } catch (_) {
      // Audit failures must not break the error response
    }
  }

  // Don't attempt to respond if headers already sent
  if (res.writableEnded) return;

  // Decide response format: HTML vs RFC 9457 problem+json
  var accept = req.headers && req.headers.accept || "";
  var wantsHtml = accept.indexOf("text/html") !== -1;

  if (wantsHtml) {
    try {
      send(res, "error", {
        user: req.user || null,
        title: status === 404 ? "Page Not Found" : "Error",
        message: status >= 500 ? "Something went wrong. Please try again later." : message,
      }, status);
    } catch (_) {
      // Template rendering failed — fall back to plain text
      res.writeHead(status, { "Content-Type": "text/plain" });
      res.end(status >= 500 ? "Internal Server Error" : message);
    }
    return;
  }

  // RFC 9457 problem-details. 5xx detail is suppressed so internal failure
  // text never reaches the client.
  var problem = {
    type:   "https://hermitstash.com/problems/" + codeToTypeSlug(code),
    title:  codeToTitle(code),
    status: status,
    detail: status >= 500 ? undefined : message,
  };

  // Merge any RFC 9457 extension members the thrown AppError attached (e.g.
  // requiresEmail / pending) as top-level problem fields the client reads
  // alongside detail. Reserved keys can't be overridden.
  if (err && err.extras && typeof err.extras === "object") {
    Object.keys(err.extras).forEach(function (k) {
      if (k !== "type" && k !== "title" && k !== "status" && k !== "detail") {
        problem[k] = err.extras[k];
      }
    });
  }

  // If res.json encrypts on this session, emit the problem document through
  // res.json so the encryption covers it. b.problemDetails writes via res.end,
  // which bypasses the wrap and would ship the error in cleartext on a session
  // the client negotiated as encrypted. Two layers wrap res.json: the legacy
  // cookie/browser layer (res._apiEncryptJson) and the blamejs per-session layer
  // on the Bearer/sync routes (req.apiEncryptSessionKey — its _ctr is frozen per
  // request, so routing the error through res.json keeps the counter consistent).
  // The client decrypts the envelope like any other response; status is preserved.
  if ((res._apiEncryptJson || (req && req.apiEncryptSessionKey)) && typeof res.json === "function") {
    res.statusCode = status;
    res.setHeader("Cache-Control", "no-store");
    res.json(problem);
    return;
  }

  // Plaintext application/problem+json for sessions whose responses are not
  // encrypted at the application layer. b.problemDetails.send sets the
  // application/problem+json content type + Cache-Control: no-store.
  b.problemDetails.send(res, problem);
}

module.exports = errorHandler;
