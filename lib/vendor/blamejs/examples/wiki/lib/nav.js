"use strict";
// nav — thin re-export of the navigation derived from site.config.js.
// Single source of truth for nav + cards + curation: site.config.js.
//
// Both routes/pages.js and routes/admin.js feed NAV_GROUPS into
// _layoutData so the nav partial renders a {% for %} loop with the
// right <details open> flag on the section containing the current
// page.

var site = require("../site.config");

module.exports = {
  NAV_GROUPS:    site.navGroups(),
  groupForPath:  site.groupForPath,
};
