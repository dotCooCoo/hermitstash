"use strict";

// ClusterFuzzLite harness for b.guardManageSieveCommand.

var guardManageSieve = require("../lib/guard-managesieve-command");

module.exports.fuzz = function (data) {
  var line;
  try { line = data.toString("utf8"); } catch (_e) { return; }
  // Permissive cap is 64 KiB; bound the fuzz input slightly above so
  // line-too-long refusal paths are still exercised without burning
  // jazzer cycles on multi-megabyte inputs.
  if (line.length > 70000) line = line.slice(0, 70000);                                                 // allow:raw-byte-literal — bounded fuzz input

  for (var pi = 0; pi < 3; pi += 1) {
    var profile = ["strict", "balanced", "permissive"][pi];
    for (var ti = 0; ti < 2; ti += 1) {
      var tls = ti === 1;
      try {
        guardManageSieve.validate(line, { profile: profile, tls: tls });
      } catch (e) {
        if (!e || !e.isFrameworkError) throw e;
      }
    }
  }
};
