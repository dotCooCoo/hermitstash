/**
 * Request ID middleware.
 *
 * Generates a random 8-char hex ID for each request, attaches it to
 * req.requestId, sets the X-Request-Id response header, and runs the rest
 * of the request chain inside an AsyncLocalStorage context so all log
 * lines produced during the request (including in awaited code) include
 * the correct requestId — even when multiple requests are in flight.
 */
var { generateToken } = require("../lib/crypto");
var logger = require("../app/shared/logger");

module.exports = function requestId(req, res, next) {
  var id = generateToken(4); // 8 hex chars
  req.requestId = id;
  res.setHeader("X-Request-Id", id);
  logger.runWithRequestId(id, function () {
    next();
  });
};
