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

  // RFC 9457 problem+json — 5xx detail is suppressed so internal failure
  // text never reaches clients. b.problemDetails.send (v0.9.41+) is the
  // single-call form of create(fields) + respond(res, problem); same
  // application/problem+json + Cache-Control: no-store wire shape.
  b.problemDetails.send(res, {
    type:   "https://hermitstash.com/problems/" + codeToTypeSlug(code),
    title:  codeToTitle(code),
    status: status,
    detail: status >= 500 ? undefined : message,
  });
}

module.exports = errorHandler;
