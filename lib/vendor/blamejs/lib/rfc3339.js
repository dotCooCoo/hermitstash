// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * rfc3339 — strict RFC 3339 date-time validation, shared by the primitives
 * whose specs require the full "internet date/time" form (a mandatory
 * "T"/"t" separator and a mandatory "Z" or numeric UTC offset). b.jtd's
 * `timestamp` type and b.cloudevents' `time` attribute both point at
 * RFC 3339, so the field-range + leap-year + offset-range checks live here
 * once instead of drifting between them.
 *
 * This is intentionally NOT the lenient validator b.guardTime ships: that
 * one accepts a space separator and an absent offset by design (a content-
 * safety guard tuned per profile), whereas these consumers must reject
 * anything the spec disallows.
 *
 *   var rfc3339 = require("./rfc3339");
 *   rfc3339.isValidDateTime("2018-04-05T17:31:00Z");   // → true
 */

// "T" separator required; offset ("Z"/"z" or ±HH:MM) required.
var RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

function isValidDateTime(s) {
  if (typeof s !== "string") return false;
  var m = RFC3339_RE.exec(s);
  if (!m) return false;
  var mo = +m[2], d = +m[3], h = +m[4], mi = +m[5], se = +m[6];
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return false;   // allow:raw-time-literal — RFC 3339 field ranges (60 = leap second)
  var days = [31, ((+m[1] % 4 === 0 && +m[1] % 100 !== 0) || +m[1] % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (d > days[mo - 1]) return false;
  var tz = m[8];
  if (tz !== "Z" && tz !== "z") {
    if (+tz.slice(1, 3) > 23 || +tz.slice(4, 6) > 59) return false;
  }
  return true;
}

module.exports = { isValidDateTime: isValidDateTime, RFC3339_RE: RFC3339_RE };
