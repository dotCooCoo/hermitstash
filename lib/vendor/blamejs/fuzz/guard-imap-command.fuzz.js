"use strict";

// ClusterFuzzLite harness for b.guardImapCommand. Exercises the
// validate() entry point + the detectLiteralSmuggling boolean over
// arbitrary byte sequences interpreted as IMAP command lines. The
// validator MUST never crash, never enter an infinite loop, and
// never produce a parse for a smuggling-shaped input.

var guardImap = require("../lib/guard-imap-command");

module.exports.fuzz = function (data) {
  var line;
  try { line = data.toString("utf8"); } catch (_e) { return; }
  // Cap inputs at the permissive max + slop so the fuzzer doesn't
  // burn cycles producing 100 MB strings the validator would
  // immediately refuse on the length cap.
  if (line.length > 70000) line = line.slice(0, 70000);                                               // allow:raw-byte-literal — bounded fuzz input

  for (var pi = 0; pi < 3; pi += 1) {
    var profile = ["strict", "balanced", "permissive"][pi];
    try {
      guardImap.validate(line, { profile: profile, authenticated: false });
    } catch (e) {
      // Validator MUST throw a GuardImapCommandError on rejection;
      // any other class is a fuzz hit.
      if (!e || !e.isFrameworkError) throw e;
    }
    try {
      guardImap.validate(line, { profile: profile, authenticated: true });
    } catch (e) {
      if (!e || !e.isFrameworkError) throw e;
    }
  }
  guardImap.detectLiteralSmuggling(line);
};
