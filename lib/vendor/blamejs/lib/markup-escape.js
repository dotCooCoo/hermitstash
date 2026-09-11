// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

function markupEscape(str, opts) {
  var s = String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
  var apos = opts && opts.apos;
  return apos ? s.replace(/'/g, apos) : s;
}

module.exports = { markupEscape: markupEscape };
