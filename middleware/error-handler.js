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
  } else if (err && typeof err === "object") {
    // Map blamejs typed FrameworkErrors (thrown by config validators, the guards,
    // the storage/queue/external-db adapters, safe-json, etc.) to their real HTTP
    // status instead of degrading every one to a 500. Branch order mirrors the
    // framework's own error-page._classify so HS stays in lockstep. A derived 4xx
    // surfaces err.message as the problem-detail; a FrameworkError carrying no
    // status stays a genuine 500 (and emitError suppresses its detail).
    if (err.isAuthError) {
      status = 401; code = err.code || "AUTH_FAILED"; message = err.message || message;
    } else if (err.code === "VALIDATION_ERROR" || err.name === "ValidationError") {
      status = 400; code = err.code || "VALIDATION_ERROR"; message = err.message || message;
    } else if (err.isSafeJsonError) {
      status = 400; code = err.code || "BAD_REQUEST"; message = err.message || message;
    } else if ((err.isStorageError || err.isQueueError || err.isExternalDbError) && err.permanent) {
      // A non-retryable infrastructure failure. Its message can carry internal
      // detail (an S3 bucket/endpoint, a backend host:port, an access-key error),
      // so log the real message for diagnosis but return a generic client detail —
      // never echo backend internals to the caller.
      status = 400; code = err.code || "ERROR"; message = "The request could not be processed.";
      logger.error("Infrastructure error (storage/queue/external-db)", {
        code: code, detail: err.message, path: req.pathname || req.url, method: req.method,
      });
    } else if (Number.isInteger(err.statusCode) && err.statusCode >= 100 && err.statusCode <= 599) {
      status = err.statusCode; code = err.code || code; message = err.message || message;
    }
    // else: leave the 500 / INTERNAL_ERROR default — a genuine internal failure.
  }
  // Defensive floor: clamp any out-of-range derived status back to 500.
  if (!(status >= 100 && status <= 599)) status = 500;

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
