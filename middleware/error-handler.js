/**
 * Centralized error handler.
 *
 * Registered on the Router via onError() — catches all unhandled errors from
 * middleware and route handlers.
 *
 * - AppError subclasses: returns their status code + message
 * - Security errors (401/403/429): logged to audit
 * - 500 errors: stack trace logged to stderr, generic message to client
 * - HTML clients get the error template; JSON clients get { error: message }
 * - Stack traces are NEVER leaked to the client
 */
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var { send } = require("./send");

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

  // Don't attempt to respond if headers already sent
  if (res.writableEnded) return;

  // Decide response format: HTML vs JSON
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
  } else {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: status >= 500 ? "Internal Server Error" : message }));
  }
}

module.exports = errorHandler;
