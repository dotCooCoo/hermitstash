/**
 * API key authentication middleware.
 * Checks Authorization: Bearer <key> header.
 * If valid, sets req.apiKey and req.user from the key's userId.
 */
var { apiKeys, users } = require("../lib/db");
var { sha3Hash } = require("../lib/crypto");
var { validateBearerToken } = require("../app/shared/validate");
var { extractBearerToken } = require("../lib/http-utils");

module.exports = function apiAuth(req, res, next) {
  var token = extractBearerToken(req);
  if (!token) return next();
  if (!validateBearerToken(token)) return next(); // malformed token — skip auth, don't waste cycles hashing
  var hash = sha3Hash(token);
  var key = apiKeys.findOne({ keyHash: hash });
  if (!key) return next();

  // Update last used
  apiKeys.update({ _id: key._id }, { $set: { lastUsed: new Date().toISOString() } });

  // Set user from key's userId
  if (key.userId) {
    var user = users.findOne({ _id: key.userId });
    if (user && user.status === "active") {
      req.user = user;
      req.apiKey = key;
    }
  }
  next();
};
