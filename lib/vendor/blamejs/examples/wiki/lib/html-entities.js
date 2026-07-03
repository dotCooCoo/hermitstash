// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Single-pass decode of the built-in HTML entities the wiki page generator
// emits. A CHAINED decode (`.replace(/&amp;/g,"&").replace(/&lt;/g,"<")...`)
// double-decodes: `&amp;lt;` -> `&lt;` (step 1) -> `<` (step 2), un-escaping a
// level that was never escaped at the source (CodeQL js/double-escaping,
// CWE-116). One regex pass consumes each entity exactly once, so a replacement
// output is never re-scanned. Mirrors the framework's production decoders
// (lib/parsers/safe-xml.js etc.), which are all single-pass and not flagged.
var _ENT = {
  "&amp;":  "&",
  "&lt;":   "<",
  "&gt;":   ">",
  "&quot;": "\"",
  "&#39;":  "'",
  "&#x27;": "'",
};
var _ENT_RE = /&(?:amp|lt|gt|quot|#39|#x27);/g;

function unescapeBuiltinEntities(s) {
  return String(s).replace(_ENT_RE, function (m) { return _ENT[m]; });
}

module.exports = { unescapeBuiltinEntities: unescapeBuiltinEntities };
