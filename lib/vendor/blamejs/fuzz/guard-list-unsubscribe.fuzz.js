"use strict";
/**
 * Fuzz target: b.guardListUnsubscribe.validate
 *
 * Targets RFC 2369 / RFC 8058 header validation — refuses dangerous
 * URI schemes, CRLF injection, control chars, missing one-click
 * Post header, malformed Post header value.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var ctx;
  try { ctx = JSON.parse(data.toString("utf8")); }
  catch (_e) { return; }
  if (!ctx || typeof ctx !== "object") return;
  try {
    b.guardListUnsubscribe.validate(ctx);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-list-unsubscribe/") === 0) return;
    throw e;
  }
};
