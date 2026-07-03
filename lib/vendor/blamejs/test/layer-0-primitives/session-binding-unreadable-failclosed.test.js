// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.session.verify must FAIL CLOSED under a strict device-fingerprint policy
 * (requireFingerprintMatch / maxAnomalyScore) when the sealed `data` column —
 * which carries the bound fingerprint — cannot be decrypted (key-rotation skew,
 * DB corruption, or a tamper of the independently-AEAD-sealed data cell).
 *
 * Pre-fix, cryptoField.unsealRow swallowed the decrypt failure and returned
 * data=null, so storedFingerprint stayed null and the whole fingerprint gate
 * (including the strict refusals) was SKIPPED — a session was accepted from ANY
 * device even with requireFingerprintMatch:true. "Could not read the binding"
 * was treated as "the binding matches".
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var setupTestDb = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var fs = require("fs");
var os = require("os");
var path = require("path");

function _makeReq(headers) {
  return { headers: headers || {}, socket: {}, connection: {} };
}

async function run() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-binding-"));
  try {
    await setupTestDb(tmpDir);

    // Wrap a real store so we can corrupt ONLY the sealed `data` cell on read —
    // the userId column + lookup hash stay intact, so the row is still found,
    // but its AEAD-sealed data (the fingerprint binding) no longer decrypts.
    var real = b.session.stores.localDbThin({ file: path.join(tmpDir, "ses.db"), audit: false });
    var corrupt = false;
    var wrap = Object.assign({}, real, {
      executeOne: async function (sql, p) {
        var row = await real.executeOne(sql, p);
        if (corrupt && row && typeof row.data === "string" && row.data.length > 8) {
          var bytes = Buffer.from(row.data, "utf8");
          bytes[bytes.length - 3] = bytes[bytes.length - 3] ^ 0xff;   // flip a ciphertext byte
          row = Object.assign({}, row, { data: bytes.toString("utf8") });
        }
        return row;
      },
    });
    b.session.useStore(wrap);

    var devA = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "deviceA" });
    var s = await b.session.create({ userId: "u-strict", req: devA, data: { role: "admin" } });

    // Sanity — strict verify from the bound device, binding readable, succeeds.
    var okSame = await b.session.verify(s.token, { req: devA, requireFingerprintMatch: true });
    check("strict verify from the bound device succeeds (binding readable)",
          okSame && okSame.userId === "u-strict");

    // Now make the sealed data cell undecryptable, and verify from a DIFFERENT
    // device under the strict policy: it must FAIL CLOSED (the binding can't be
    // read, so we cannot prove it matches), not silently skip the gate.
    corrupt = true;
    var devB = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "deviceB" });
    var verdict = await b.session.verify(s.token, { req: devB, requireFingerprintMatch: true });
    check("strict verify FAILS CLOSED when the binding column can't be decrypted",
          verdict === null);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}
