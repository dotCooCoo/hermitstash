/**
 * API key authentication middleware.
 * Checks Authorization: Bearer <key> header.
 * If valid, sets req.apiKey and req.user from the key's userId.
 */
var b = require("../lib/vendor/blamejs");
var { apiKeys, users } = require("../lib/db");
var { validateBearerToken } = require("../app/shared/validate");
var C = require("../lib/constants");

module.exports = function apiAuth(req, res, next) {
  var token = b.requestHelpers.extractBearer(req);
  if (!token) return next();
  if (!validateBearerToken(token)) return next(); // malformed token — skip auth, don't waste cycles hashing
  var hash = b.crypto.sha3Hash(token);
  var key = apiKeys.findOne({ keyHash: hash });
  if (!key) return next();

  // Set user from key's userId
  if (key.userId) {
    var user = users.findOne({ _id: key.userId });
    if (user && user.status === "active") {
      req.user = user;
      req.apiKey = key;
      // Record last use only on successful auth (a suspended or deleted
      // user's key shouldn't bump it), throttled to once per five minutes so
      // a busy sync client doesn't drive a database write on every request.
      var lastUsedMs = key.lastUsed ? Date.parse(key.lastUsed) : 0;
      if (!lastUsedMs || (Date.now() - lastUsedMs) > C.TIME.minutes(5)) {
        apiKeys.update({ _id: key._id }, { $set: { lastUsed: new Date().toISOString() } });
      }
    }
  }
  next();
};
