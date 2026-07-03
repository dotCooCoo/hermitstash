// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

// ClusterFuzzLite harness for b.guardJmap. Exercises the validate()
// entry point over arbitrary byte sequences interpreted as JMAP
// request-envelope JSON. The validator MUST never crash, never enter
// an infinite loop, and never accept a request that exceeds the
// profile caps.

var guardJmap = require("../lib/guard-jmap");

module.exports.fuzz = function (data) {
  var line;
  try { line = data.toString("utf8"); } catch (_e) { return; }
  // Cap inputs at slightly above the permissive maxSizeRequest so the
  // fuzzer doesn't burn cycles producing 200 MB strings the validator
  // immediately refuses on length cap.
  if (line.length > 110000000) line = line.slice(0, 110000000);                                       // allow:raw-byte-literal — bounded fuzz input

  for (var pi = 0; pi < 3; pi += 1) {
    var profile = ["strict", "balanced", "permissive"][pi];
    try {
      guardJmap.validate(line, { profile: profile });
    } catch (e) {
      // Validator MUST throw a GuardJmapError on rejection; any
      // other class is a fuzz hit.
      if (!e || !e.isFrameworkError) throw e;
    }
    try {
      guardJmap.validate(line, {
        profile: profile,
        serverCapabilities: {
          "urn:ietf:params:jmap:mail": true,
          "urn:ietf:params:jmap:contacts": true,
          "urn:ietf:params:jmap:calendars": true,
        },
      });
    } catch (e) {
      if (!e || !e.isFrameworkError) throw e;
    }
  }
};
