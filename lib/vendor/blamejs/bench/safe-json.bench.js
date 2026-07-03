// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// bench safe-json — stringify + parse for a small + medium payload.

var safeJson = require("../lib/safe-json");

var smallObj = { id: "abc-123", count: 42, ok: true, tags: ["a", "b", "c"] };
var smallStr = safeJson.stringify(smallObj);

var mediumObj = {
  id: "user-9k2x",
  email: "robert@example.com",
  roles: ["admin", "editor", "viewer"],
  metadata: {
    createdAt: "2026-04-29T12:00:00Z",
    lastSeen:  "2026-04-29T15:32:11Z",
    flags:     { betaTester: true, mfaEnabled: false, theme: "dark" },
    counters:  { logins: 142, posts: 27, comments: 384 },
  },
  tags: Array.from({ length: 20 }, function (_, i) { return "tag-" + i; }),
};
var mediumStr = safeJson.stringify(mediumObj);

module.exports = {
  name: "safe-json",
  benchmarks: {
    "stringify small (4 keys)":      function () { safeJson.stringify(smallObj); },
    "parse small (4 keys)":          function () { safeJson.parse(smallStr); },
    "stringify medium (nested + 20 tags)": function () { safeJson.stringify(mediumObj); },
    "parse medium (nested + 20 tags)":     function () { safeJson.parse(mediumStr); },
  },
};
