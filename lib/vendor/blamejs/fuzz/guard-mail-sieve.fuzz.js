"use strict";
/**
 * Fuzz target: b.guardMailSieve.validate
 *
 * Pre-parser shape-only validation; full Sieve parse lands at v0.9.26
 * via b.safeSieve.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  // Two shapes are exercised: the raw string as a script body, and a
  // JSON-shaped op envelope.
  try {
    b.guardMailSieve.validate({
      kind: "put", actor: { id: "fuzz", mailScope: "admin" },
      name: "f.sieve", script: text,
    });
  } catch (e) {
    if (!expected.isExpected(e) && (!e || typeof e.code !== "string" ||
        e.code.indexOf("mail-sieve/") !== 0)) throw e;
  }
  var op;
  try { op = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardMailSieve.validate(op);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("mail-sieve/") === 0) return;
    throw e;
  }
};
