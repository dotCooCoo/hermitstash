/**
 * Centralized error handler.
 *
 * Registered on the Router via onError() — catches all unhandled errors from
 * middleware and route handlers.
 *
 * - AppError subclasses: returns their status code + message
 * - Security errors (401/403/429): logged to audit
 * - 500 errors: stack trace logged to stderr, generic message to client
 * - Response shape (HTML template vs RFC 9457 problem+json), encrypted-session
 *   routing, and the Retry-After header are handled by emitError in
 *   middleware/respond-error.js — shared with the inline guards (require-admin,
 *   logout CSRF) so thrown and inline errors render identically.
 * - Stack traces are NEVER leaked to the client
 */
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var { emitError } = require("./respond-error");

// Security-relevant status codes that warrant an audit entry
var SECURITY_CODES = { 401: true, 403: true, 429: true };

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

  emitError(req, res, {
    status: status,
    code: code,
    detail: message,
    htmlTitle: status === 404 ? "Page Not Found" : "Error",
    extras: err && err.extras,
    retryAfter: err && err.retryAfter,
  });
}

module.exports = errorHandler;
