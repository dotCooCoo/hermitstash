// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditTools.forensicSnapshot — post-compromise composer that
 * bundles an audit slice + IR-context manifest into one
 * tamper-evident artifact.
 */

var fs = require("node:fs");
var os = require("node:os");
var path = require("node:path");

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

async function run() {
  var threw;
  try { await b.auditTools.forensicSnapshot({}); } catch (e) { threw = e; }
  check("auditTools.forensicSnapshot: missing passphrase throws",
    threw && /passphrase/i.test(threw.message));

  var tmpParent = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-fs-"));
  var tmpOut = path.join(tmpParent, "fs-out");
  var threw2;
  try {
    await b.auditTools.forensicSnapshot({
      out: tmpOut, passphrase: "test-pass-".padEnd(32, "x"),
      since: Date.now() - 60000,
    });
  } catch (e) { threw2 = e; }
  check("auditTools.forensicSnapshot: missing reason throws",
    threw2 && /reason/i.test(threw2.message));

  // F-AUD-4 — withRecordedAtIso surfaces ISO-8601 alongside the
  // existing Unix-ms recordedAt without mutating the canonical row.
  var ms = 1714896000000;     // 2026-05-05T08:00:00Z
  var enriched = b.auditTools.withRecordedAtIso({ counter: 1, recordedAt: ms, action: "x.y" });
  check("withRecordedAtIso: surfaces ISO-8601",
    enriched.recordedAtIso === new Date(ms).toISOString());
  check("withRecordedAtIso: preserves recordedAt ms",
    enriched.recordedAt === ms);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[forensic-snapshot] OK"); },
    function (e) { console.error(e); process.exit(1); }
  );
}
