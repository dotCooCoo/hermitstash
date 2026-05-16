"use strict";
/**
 * Fuzz target: b.guardEnvelope.check
 *
 * Targets the RFC 7489 §3.1 DMARC Identifier Alignment primitive.
 * Engine mutates a JSON-encoded ctx; we decode + check.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var ctx;
  try { ctx = JSON.parse(data.toString("utf8")); }
  catch (_e) { return; }
  if (!ctx || typeof ctx !== "object") return;
  try {
    b.guardEnvelope.check(ctx);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("guard-envelope/") === 0) return;
    throw e;
  }
};
