"use strict";
/**
 * Request-ID middleware. Propagates an existing X-Request-Id header (or
 * trace ID from upstream) when present and well-formed; otherwise
 * generates a fresh 32-hex value. Sets req.requestId AND emits the same
 * value as a response header so downstream services + auditors can
 * correlate.
 *
 * Threading the request ID into audit.record() metadata is what makes
 * the cross-event correlation traceable; apps should pass this through
 * to every audit.record() they call within the request lifecycle.
 *
 * Options:
 *   {
 *     headerName:    'X-Request-Id'
 *     trustUpstream: true         // propagate upstream id if it matches
 *                                 //   the format check; false → always
 *                                 //   generate fresh
 *     formatRegex:   /^[A-Za-z0-9._-]{8,128}$/
 *   }
 */
var C = require("../constants");
var { generateToken } = require("../crypto");
var validateOpts = require("../validate-opts");

var DEFAULT_FORMAT = /^[A-Za-z0-9._-]{8,128}$/;
// Hard cap on inbound header length. The DEFAULT_FORMAT regex caps at
// 128 chars, but operator-supplied formatRegex values may be looser;
// length-bound the candidate before .test() so a multi-megabyte header
// can't drive ReDoS even against a careless operator pattern.
var MAX_INBOUND_LEN = C.BYTES.bytes(256);

function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "headerName", "trustUpstream", "formatRegex",
  ], "middleware.requestId");
  var headerName = (opts.headerName || "X-Request-Id");
  var headerNameLower = headerName.toLowerCase();
  var trustUpstream = opts.trustUpstream !== false;
  var format = opts.formatRegex || DEFAULT_FORMAT;

  return function requestId(req, res, next) {
    var inbound = req.headers && req.headers[headerNameLower];
    var id;
    if (trustUpstream && typeof inbound === "string" &&
        inbound.length > 0 && inbound.length <= MAX_INBOUND_LEN &&
        format.test(inbound)) {
      id = inbound;
    } else {
      id = generateToken(C.BYTES.bytes(16));  // 32 hex chars
    }
    req.requestId = id;
    if (typeof res.setHeader === "function") {
      res.setHeader(headerName, id);
    }
    next();
  };
}

module.exports = { create: create };
