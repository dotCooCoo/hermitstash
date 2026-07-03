// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// ClusterFuzzLite harness for b.guardPop3Command.

var guardPop3 = require("../lib/guard-pop3-command");

module.exports.fuzz = function (data) {
  var line;
  try { line = data.toString("utf8"); } catch (_e) { return; }
  if (line.length > 4096) line = line.slice(0, 4096);                                                 // allow:raw-byte-literal — bounded fuzz input

  for (var pi = 0; pi < 3; pi += 1) {
    var profile = ["strict", "balanced", "permissive"][pi];
    for (var ti = 0; ti < 2; ti += 1) {
      var tls = ti === 1;
      try {
        guardPop3.validate(line, { profile: profile, tls: tls });
      } catch (e) {
        if (!e || !e.isFrameworkError) throw e;
      }
    }
  }
};
