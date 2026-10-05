/**
 * Centralized error handler.
 *
 * Registered on the Router via onError() — catches all unhandled errors from
 * middleware and route handlers.
 *
 * - AppError subclasses: returns their status code + message
 * - Security errors (401/403/429): logged to audit
 * - 5xx errors: stack trace logged to stderr, generic message to client. An
 *   AppError with exposeDetail set (ServiceUnavailableError) sends its message
 *   and is not logged here.
 * - Response shape (HTML template vs RFC 9457 problem+json), encrypted-session
 *   routing, and the Retry-After header are handled by emitError in
 *   middleware/respond-error.js — shared with the inline guards (require-admin,
 *   logout CSRF) so thrown and inline errors render identically.
 * - Stack traces are NEVER leaked to the client
 * - Log lines and audit details name the request with logger.requestPath(req):
 *   the route pattern, or the path with its token segments replaced. Log lines
 *   carry req.requestId.
 * - guardRouterLogs(app) answers a failed request through this handler before
 *   b.router writes its own log line for it.
 */
var b = require("../lib/vendor/blamejs");
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
      _logForRequest(req, function () {
        logger.error("Infrastructure error (storage/queue/external-db)", {
          code: code, detail: err.message, path: logger.requestPath(req), method: req.method,
        });
      });
    } else if (Number.isInteger(err.statusCode) && err.statusCode >= 100 && err.statusCode <= 599) {
      status = err.statusCode; code = err.code || code; message = err.message || message;
    }
    // else: leave the 500 / INTERNAL_ERROR default — a genuine internal failure.
  }
  // Defensive floor: clamp any out-of-range derived status back to 500.
  if (!(status >= 100 && status <= 599)) status = 500;

  // An AppError with exposeDetail set (ServiceUnavailableError) keeps its detail
  // on a 5xx and is not logged here. The code that raises it logs it.
  var exposeDetail = !!(err && err.isAppError && err.exposeDetail);

  // Log 5xx with a full stack trace to stderr.
  if (status >= 500 && !exposeDetail) {
    _logForRequest(req, function () {
      logger.error("Unhandled server error", {
        status: status,
        code: code,
        stack: err && err.stack ? err.stack : String(err),
        path: logger.requestPath(req),
        method: req.method,
      });
    });
  } else if (status >= 400 && status < 500) {
    // Written at debug level, so it appears only with LOG_LEVEL=debug.
    _logForRequest(req, function () {
      logger.debug("Request refused", {
        status: status,
        code: code,
        path: logger.requestPath(req),
        method: req.method,
      });
    });
  }

  // Audit security-related errors
  if (SECURITY_CODES[status]) {
    try {
      audit.log(audit.ACTIONS.AUTH_FAILED_PAGE, {
        req: req,
        details: "error-handler: " + status + " " + code + " — " + logger.requestPath(req),
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
    exposeDetail: exposeDetail,
  });
}

// Runs fn with req.requestId attached to the log lines it writes. The request
// ID context the request-id middleware opens ends with the composed pipeline.
function _logForRequest(req, fn) {
  var id = req && typeof req.requestId === "string" ? req.requestId : null;
  if (!id) return fn();
  return logger.runWithRequestId(id, fn);
}

/**
 * Answers every failed request through the handler registered with
 * app.onError(), so b.router does not write its own line for it. That line
 * holds the full request URL, query string included, and the router writes it
 * before the handler runs. Call it on a new Router before the first app.use().
 *
 * Each middleware passed to app.use() is wrapped. When one throws, rejects or
 * calls next(err), the wrapper passes the error to app.errorHandler and ends
 * the request there.
 * app.handle() is replaced, and a request that fails in a route goes to
 * app.errorHandler the same way. When app.errorHandler itself throws, the
 * failure is logged and the reply is a plain 500. With no handler registered,
 * req.url is set to logger.requestPath(req) and the error goes back to the
 * router.
 */
function guardRouterLogs(app) {
  var routerUse = app.use.bind(app);
  app.use = function () {
    var args = Array.prototype.slice.call(arguments).map(function (arg) {
      return typeof arg === "function" ? _guardMiddleware(app, arg) : arg;
    });
    return routerUse.apply(null, args);
  };

  var routerHandle = app.handle.bind(app);
  app.handle = function (req, res) {
    return routerHandle(req, res).catch(function (err) {
      _answerFailure(app, err, req, res);
    });
  };
  return app;
}

// The middleware gets its own next. The router's next is called only after the
// middleware returns or settles without an error. A middleware that throws,
// rejects, or calls next(err) ends the request with the error response, and so
// does one that calls next() and then fails. A call to next after the
// middleware has settled goes to the router's next, or with an error to the
// error handler.
function _guardMiddleware(app, mw) {
  var guarded = function (req, res, next) {
    var settled = false;
    var nextCalled = false;
    var nextErr = null;
    function middlewareNext(err) {
      if (settled) {
        if (err) _answerFailure(app, err, req, res);
        else next();
        return;
      }
      nextCalled = true;
      if (err) nextErr = err;
    }
    function finish() {
      settled = true;
      if (nextErr) {
        _answerFailure(app, nextErr, req, res);
        return;
      }
      if (nextCalled) next();
    }
    var out;
    try {
      out = mw(req, res, middlewareNext);
    } catch (err) {
      settled = true;
      _answerFailure(app, err, req, res);
      return undefined;
    }
    if (out && typeof out.then === "function") {
      return out.then(function (value) {
        finish();
        return value;
      }, function (err) {
        settled = true;
        _answerFailure(app, err, req, res);
      });
    }
    finish();
    return out;
  };
  // The router prints the middleware's name when it writes a failure line.
  Object.defineProperty(guarded, "name", { value: mw.name });
  return guarded;
}

// Sends err to app.errorHandler. Without a handler, err goes back to the
// router with req.url replaced by the logged form of the path.
function _answerFailure(app, err, req, res) {
  if (typeof app.errorHandler !== "function") {
    try { req.url = logger.requestPath(req); } catch (_e) { /* the original error is the one to report */ }
    throw err;
  }
  try {
    app.errorHandler(err, req, res);
  } catch (handlerErr) {
    try {
      _logForRequest(req, function () {
        logger.error("Error handler failed", {
          path: logger.requestPath(req),
          error: handlerErr && handlerErr.message ? String(handlerErr.message) : String(handlerErr),
        });
      });
    } catch (_e) { /* the reply below is still sent */ }
    _lastResortError(res);
  }
}

// The reply b.router sends when its error handler throws.
function _lastResortError(res) {
  try {
    if (b.requestHelpers.failAfterHeaders(res)) return;
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Internal Server Error");
  } catch (_e) { /* the connection is already gone */ }
}

module.exports = errorHandler;
module.exports.guardRouterLogs = guardRouterLogs;
