/**
 * Request ID middleware.
 *
 * Mints (or honors a trusted upstream) X-Request-Id via the framework
 * primitive, which attaches it to req.requestId and sets the response
 * header, then runs the rest of the request chain inside an
 * AsyncLocalStorage context so all log lines produced during the request
 * (including in awaited code) include the correct requestId — even when
 * multiple requests are in flight.
 */
var b = require("../lib/vendor/blamejs");
var logger = require("../app/shared/logger");

var mintRequestId = b.middleware.requestId();

module.exports = function requestId(req, res, next) {
  mintRequestId(req, res, function () {
    logger.runWithRequestId(req.requestId, function () {
      next();
    });
  });
};
