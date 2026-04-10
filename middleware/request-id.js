/**
 * Request ID middleware.
 *
 * Generates a random 8-char hex ID for each request, attaches it to
 * req.requestId, sets the X-Request-Id response header, and updates
 * the structured logger so all subsequent log lines include the ID.
 */
var { generateToken } = require("../lib/crypto");
var logger = require("../app/shared/logger");

module.exports = function requestId(req, res, next) {
  var id = generateToken(4); // 8 hex chars
  req.requestId = id;
  res.setHeader("X-Request-Id", id);
  logger.setRequestId(id);
  next();
};
