// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.archive.sniffEnvelope — magic-byte identification
 * of recipient vs passphrase envelopes vs raw payload.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

async function testSniffRecipient() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("PHI"), { recipient: pair });
  check("sniffEnvelope: BAWRP buffer returns \"recipient\"",
    b.archive.sniffEnvelope(sealed) === "recipient");
}

async function testSniffPassphrase() {
  var sealed = await b.archive.wrapWithPassphrase(Buffer.from("PHI"), {
    passphrase: "aLongCorrectHorseBatteryStaple9876!Phrase",
  });
  check("sniffEnvelope: BAWPP buffer returns \"passphrase\"",
    b.archive.sniffEnvelope(sealed) === "passphrase");
}

async function testSniffRawBytes() {
  check("sniffEnvelope: plain bytes return \"none\"",
    b.archive.sniffEnvelope(Buffer.from("hello world")) === "none");
  check("sniffEnvelope: gzip bytes return \"none\" (gzip is not a wrap envelope)",
    b.archive.sniffEnvelope(Buffer.from([0x1f, 0x8b, 0x08, 0x00])) === "none");
  check("sniffEnvelope: tar header bytes return \"none\"",
    b.archive.sniffEnvelope(Buffer.alloc(512)) === "none");
}

async function testSniffEmpty() {
  check("sniffEnvelope: empty buffer returns \"none\"",
    b.archive.sniffEnvelope(Buffer.alloc(0)) === "none");
  check("sniffEnvelope: 1-byte buffer returns \"none\"",
    b.archive.sniffEnvelope(Buffer.from([0x42])) === "none");
  check("sniffEnvelope: 4-byte buffer (below magic) returns \"none\"",
    b.archive.sniffEnvelope(Buffer.from("BAWR")) === "none");
}

async function testSniffTruncatedEnvelope() {
  // Codex P2B on v0.12.14 PR #165 — a 5-byte BAWRP / BAWPP buffer is
  // a TRUNCATED envelope, not raw bytes. Sniff must classify by the
  // magic alone so dispatch routes to unwrap, which surfaces the
  // truncation error.
  check("sniffEnvelope: 5-byte BAWRP returns \"recipient\" (truncated envelope, not raw)",
    b.archive.sniffEnvelope(Buffer.from("BAWRP")) === "recipient");
  check("sniffEnvelope: 5-byte BAWPP returns \"passphrase\" (truncated envelope, not raw)",
    b.archive.sniffEnvelope(Buffer.from("BAWPP")) === "passphrase");
  // Operator dispatch path: truncated envelopes routed to unwrap
  // surface a structured wrap error rather than silent
  // misclassification.
  var refused = null;
  try {
    b.archive.unwrap(Buffer.from("BAWRP"), {
      recipient: b.crypto.generateEncryptionKeyPair(),
    });
  } catch (e) { refused = e; }
  check("sniffEnvelope → unwrap on truncated BAWRP: structured error surfaced",
    refused instanceof b.archive.ArchiveWrapError);
}

async function testSniffZeroCopyView() {
  // Codex P2A on v0.12.14 PR #165 — sniff must NOT copy the input
  // when given a Uint8Array. Construct a large Uint8Array, check
  // the sniff returns quickly without allocating a Buffer of the
  // full input length. We can't directly measure allocation here,
  // but we can verify the result is correct + the byte at the
  // typed-array's byteOffset is read (not byte 0 of the underlying
  // ArrayBuffer).
  var underlying = new ArrayBuffer(1024);
  var view = new Uint8Array(underlying, 100, 50);  // offset 100, length 50
  // Write BAWRP into the view starting at view[0] (which is
  // underlying[100]).
  view[0] = 0x42; view[1] = 0x41; view[2] = 0x57; view[3] = 0x52; view[4] = 0x50;
  check("sniffEnvelope: zero-copy view honours byteOffset",
    b.archive.sniffEnvelope(view) === "recipient");
}

async function testSniffNonBuffer() {
  check("sniffEnvelope: string input returns \"none\" (non-Buffer)",
    b.archive.sniffEnvelope("BAWRP") === "none");
  check("sniffEnvelope: null returns \"none\"",
    b.archive.sniffEnvelope(null) === "none");
  check("sniffEnvelope: undefined returns \"none\"",
    b.archive.sniffEnvelope(undefined) === "none");
}

async function testSniffUint8Array() {
  var pair = b.crypto.generateEncryptionKeyPair();
  var sealed = b.archive.wrap(Buffer.from("X"), { recipient: pair });
  var u8 = new Uint8Array(sealed);
  check("sniffEnvelope: Uint8Array carrying BAWRP returns \"recipient\"",
    b.archive.sniffEnvelope(u8) === "recipient");
}

async function run() {
  await testSniffRecipient();
  await testSniffPassphrase();
  await testSniffRawBytes();
  await testSniffEmpty();
  await testSniffTruncatedEnvelope();
  await testSniffZeroCopyView();
  await testSniffNonBuffer();
  await testSniffUint8Array();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[archive-sniff-envelope] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
