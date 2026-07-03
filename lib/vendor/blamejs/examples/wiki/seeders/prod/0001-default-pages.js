// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// Default wiki content. Per-page bodies live under ./pages/ — one file
// per page, each exporting { slug, title, body }. The ordered list at
// ./pages/_index.js drives both the seeder loop and the home-page nav
// (the latter via examples/wiki/views/home.html, which is hand-edited
// to match — adding a new page touches both files).

var PAGES = require("./pages/_index");

module.exports = {
  description: "Default wiki content",
  envs:        ["prod", "dev"],
  rerunnable:  true,
  run: async function (db, ctx) {
    var now = ctx.clock();
    for (var i = 0; i < PAGES.length; i++) {
      var p = PAGES[i];
      db.prepare(
        "INSERT INTO pages (groupName, slug, title, body, updatedAt, updatedBy) " +
        "VALUES (?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT (groupName, slug) DO UPDATE SET " +
        "  title = excluded.title, body = excluded.body, " +
        "  updatedAt = excluded.updatedAt, updatedBy = excluded.updatedBy"
      ).run(
        p.slug,             // groupName === slug for landing pages
        "index",
        p.title,
        p.body,
        now,
        "seeder"
      );
    }
  },
};
