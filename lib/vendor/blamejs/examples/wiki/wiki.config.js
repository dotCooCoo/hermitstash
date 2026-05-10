"use strict";
// wiki.config — thin re-export of the page-generator curation derived
// from site.config.js. Single source of truth for nav + cards +
// curation: site.config.js.
//
// The page-generator (lib/page-generator.js) walks `pages` here.
// Every entry whose source-driven kind is set (`concept` /
// `namespaces` / `harvest`) renders through the appropriate generator
// path and seeds into the DB alongside hand-authored pages.

var site = require("./site.config");

module.exports = {
  pages: site.curationPages(),
};
