"use strict";
/**
 * HTTP request/response mocks for middleware-style tests.
 *
 * As of v0.2.38 these are thin re-exports of `b.testing.{mockReq,
 * mockRes, bodyReq, bodyRes, streamingRes}` — the canonical
 * implementations now live in lib/testing.js so operators get the same
 * mocks the framework's own smoke suite uses. The underscore-prefixed
 * names below are preserved so existing tests don't churn.
 */

var b = require("../../index.js");

module.exports = {
  _mockReq:       b.testing.mockReq,
  _mockRes:       b.testing.mockRes,
  _bodyReq:       b.testing.bodyReq,
  _bodyRes:       b.testing.bodyRes,
  _streamingRes:  b.testing.streamingRes,
};
