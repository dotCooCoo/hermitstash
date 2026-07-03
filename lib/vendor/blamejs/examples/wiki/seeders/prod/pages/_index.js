// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Ordered list of wiki pages.
//
// Hand-authored seeders have been removed. The wiki is now driven
// entirely by:
//   1. ./api.js         — auto-generated symbol index (require'd
//                         here so it lands first and can harvest
//                         every other page's body)
//   2. _generatedPages() — every entry in examples/wiki/wiki.config.js
//                          (which itself derives from
//                          examples/wiki/site.config.js).
//
// Adding a new page is one edit to site.config.js. The validators
// (validate-site-coverage / validate-source-comment-blocks /
// validate-nav-coverage) gate every consistency invariant.

var path = require("node:path");
var pageGenerator = require("../../../lib/page-generator");
var curation = require("../../../wiki.config");
var LIB_DIR = path.join(__dirname, "..", "..", "..", "..", "..", "lib");

function _generatedPages() {
  try {
    return pageGenerator.generateAll(curation, LIB_DIR);
  } catch (e) {
     
    console.warn("[seeders] page-generator failed:", e && e.message);
    return [];
  }
}

module.exports = [
  require("./" + "api"),
].concat(_generatedPages());
