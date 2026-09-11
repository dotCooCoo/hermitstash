// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts = require("../validate-opts");
var C = require("../constants");
var { AuthError } = require("../framework-error");

function _coerceClaim(claim) {
  if (claim == null) return null;
  if (typeof claim === "number" && isFinite(claim)) return claim;
  if (typeof claim === "string") {
    var parsed = parseInt(claim, 10);
    if (isFinite(parsed)) return parsed;
  }
  return null;
}

function readClaims(rawClaims) {
  if (!rawClaims || typeof rawClaims !== "object") {
    return { auth_time: null, acr: null, amr: null };
  }
  var authTime = _coerceClaim(rawClaims.auth_time);
  var acr      = (typeof rawClaims.acr === "string") ? rawClaims.acr : null;
  var amr      = Array.isArray(rawClaims.amr) ? rawClaims.amr.slice() : null;
  return { auth_time: authTime, acr: acr, amr: amr };
}

function ageSec(claims, now) {
  var c = readClaims(claims);
  if (c.auth_time == null) return null;
  var nowSec = (typeof now === "number" && isFinite(now)) ? now : Math.floor(Date.now() / C.TIME.seconds(1));
  if (c.auth_time > nowSec) return 0;
  return nowSec - c.auth_time;
}

function freshEnough(claims, maxAgeSec, now) {
  if (typeof maxAgeSec !== "number" || !isFinite(maxAgeSec) || maxAgeSec < 0) {
    throw new AuthError("auth-step-up/bad-max-age",
      "auth.authTime.freshEnough: maxAgeSec must be a finite number >= 0 — got " +
      JSON.stringify(maxAgeSec));
  }
  var age = ageSec(claims, now);
  if (age == null) return false;
  return age <= maxAgeSec;
}

function buildClaims(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "method", "prevAt", "now", "amr", "acr",
  ], "auth.authTime.buildClaims");
  var nowSec = (typeof opts.now === "number" && isFinite(opts.now))
    ? opts.now
    : Math.floor(Date.now() / C.TIME.seconds(1));
  var prev = _coerceClaim(opts.prevAt);
  var authTime = nowSec;
  if (typeof opts.method === "string" && opts.method === "refresh" && prev != null) {
    authTime = prev;
  }
  var out = { auth_time: authTime };
  if (Array.isArray(opts.amr)) out.amr = opts.amr.slice();
  if (typeof opts.acr === "string" && opts.acr.length > 0) out.acr = opts.acr;
  return out;
}

function recommendMaxAge(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "minSec", "maxSec", "default",
  ], "auth.authTime.recommendMaxAge");
  var min  = (typeof opts.minSec === "number") ? opts.minSec : (C.TIME.seconds(60) / C.TIME.seconds(1));
  var max  = (typeof opts.maxSec === "number") ? opts.maxSec : (C.TIME.minutes(15) / C.TIME.seconds(1));
  var dflt = (typeof opts.default === "number") ? opts.default : (C.TIME.minutes(5) / C.TIME.seconds(1));
  if (dflt < min) dflt = min;
  if (dflt > max) dflt = max;
  return dflt;
}

module.exports = {
  readClaims:        readClaims,
  ageSec:            ageSec,
  freshEnough:       freshEnough,
  buildClaims:       buildClaims,
  recommendMaxAge:   recommendMaxAge,
};
