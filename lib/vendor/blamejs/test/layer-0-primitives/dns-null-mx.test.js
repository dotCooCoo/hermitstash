// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.isNullMx — RFC 7505 Null-MX classifier.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function run() {
  check("isNullMx: canonical RFC 7505 shape ('.')",
        b.network.dns.isNullMx([{ priority: 0, exchange: "." }]) === true);
  check("isNullMx: node:dns shape (empty exchange)",
        b.network.dns.isNullMx([{ priority: 0, exchange: "" }]) === true);
  check("isNullMx: regular MX → false",
        b.network.dns.isNullMx([{ priority: 10, exchange: "mx.example.com" }]) === false);
  check("isNullMx: priority=0 but non-'.' exchange → false",
        b.network.dns.isNullMx([{ priority: 0, exchange: "mx.example.com" }]) === false);
  check("isNullMx: priority>0 with '.' → false",
        b.network.dns.isNullMx([{ priority: 5, exchange: "." }]) === false);
  check("isNullMx: zero records → false",
        b.network.dns.isNullMx([]) === false);
  check("isNullMx: multiple records → false",
        b.network.dns.isNullMx([
          { priority: 0, exchange: "." },
          { priority: 10, exchange: "mx.example.com" },
        ]) === false);
  check("isNullMx: non-array → false",
        b.network.dns.isNullMx(null) === false);
  check("isNullMx: non-object element → false",
        b.network.dns.isNullMx(["bad"]) === false);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK");
}
