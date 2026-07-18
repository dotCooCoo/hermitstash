// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var b        = require("..");
var expected = require("./_expected");

// b.linkHeader.parse consumes an untrusted HTTP Link response-header string
// (RFC 8288) -- a server (or an SSRF-reachable origin) fully controls it. It
// MUST refuse a malformed header with a typed error or a benign return, never
// crash with an uncaught error or hang.
module.exports.fuzz = function (data) {
  var s;
  try { s = data.toString("latin1"); }
  catch (_e) { return; }
  try { b.linkHeader.parse(s); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
};
