// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.auditTools — audit-chain inspection / export / archive / verify /
 * purge. This canonical suite drives the error, adversarial, defensive
 * and option-default branches of every verb:
 *
 *   - input validation (passphrase / out-dir / date coercion / mutually-
 *     exclusive out+returnBytes),
 *   - corrupt-bundle rejection in _readBundle (missing / oversized /
 *     checksum-mismatched blobs, bad format / kind),
 *   - chain-integrity failure surfacing in verifyBundle (prevHash break,
 *     rowHash break, first/last-rowHash disagreement, checkpoint binding),
 *   - purge refusal paths (unverified archive, wrong kind, non-monotonic,
 *     anchor mismatch, dual-control gate),
 *   - the CADF export mapping across every outcome / field shape.
 *
 * The happy paths run against a real encrypted db + audit chain +
 * ML-DSA-signed checkpoint (setupTestDb) so the default readers /
 * signature verifier / writer / reader are exercised end-to-end. The
 * adversarial paths tamper written bundles on disk or inject the
 * operator-overridable readers, never a fake crypto primitive.
 */

var helpers = require("../helpers");
var b              = helpers.b;
var check          = helpers.check;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var backupCrypto   = require("../../lib/backup/crypto");

var PASS = Buffer.from("audit-tools-canonical-test-passphrase");
var ZERO = "0".repeat(128);

var _seq = 0;
function _freshOut(root, name) { _seq += 1; return path.join(root, name + "-" + _seq); }

async function _expectCode(fn, code) {
  var threw = null;
  try { await fn(); } catch (e) { threw = e; }
  return threw && threw.code === code;
}

function _copyBundle(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  var entries = fs.readdirSync(src);
  for (var i = 0; i < entries.length; i++) {
    fs.copyFileSync(path.join(src, entries[i]), path.join(dst, entries[i]));
  }
  return dst;
}

function _flipByte(file) {
  var buf = fs.readFileSync(file);
  buf[0] = buf[0] ^ 0xff;
  fs.writeFileSync(file, buf);
}

function _editManifest(dir, mutate) {
  var p = path.join(dir, "manifest.json");
  var m = JSON.parse(fs.readFileSync(p, "utf8"));
  mutate(m);
  fs.writeFileSync(p, JSON.stringify(m));
}

// ---------------------------------------------------------------------------
// Pure / no-db branches: input validation, date coercion, CADF mapping,
// withRecordedAtIso, the reader-injection error paths that throw before any
// filesystem or db touch.
// ---------------------------------------------------------------------------
async function runInputValidation(root) {
  // _requirePassphrase — missing (not Buffer/string), and empty.
  check("archive: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({}); }, "audit-tools/no-passphrase"));
  check("archive: empty-string passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: "" }); }, "audit-tools/no-passphrase"));
  check("archive: empty-Buffer passphrase rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: Buffer.alloc(0) }); }, "audit-tools/no-passphrase"));

  // _requireOutDir — not a string, and already-exists.
  check("archive: missing out (no returnBytes) rejected",
    await _expectCode(function () { return b.auditTools.archive({ passphrase: PASS, before: Date.now() }); }, "audit-tools/no-outdir"));
  var existing = _freshOut(root, "already-there");
  fs.mkdirSync(existing, { recursive: true });
  check("archive: refuses to overwrite an existing out dir",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, before: Date.now(), out: existing });
    }, "audit-tools/outdir-exists"));

  // out + returnBytes are mutually exclusive on every verb that offers both.
  check("archive: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x"), before: Date.now() });
    }, "audit-tools/out-and-return-bytes"));
  check("exportSlice: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x") });
    }, "audit-tools/out-and-return-bytes"));
  check("forensicSnapshot: out + returnBytes rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, out: _freshOut(root, "x"), since: Date.now(), reason: "x" });
    }, "audit-tools/out-and-return-bytes"));

  // exportSlice missing out.
  check("exportSlice: missing out rejected",
    await _expectCode(function () { return b.auditTools.exportSlice({ passphrase: PASS }); }, "audit-tools/no-outdir"));

  // archive: before is required (date coercion of undefined → null).
  check("archive: missing before rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "nb") });
    }, "audit-tools/no-before"));

  // _toMs adversarial via archive (bad string / bad type).
  check("archive: unparseable before string rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "bd"), before: "not-a-date" });
    }, "audit-tools/bad-date"));
  check("archive: non-date-typed before rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "bt"), before: true });
    }, "audit-tools/bad-date"));

  // forensicSnapshot required-opt branches (returnBytes skips the out check).
  check("forensicSnapshot: missing since rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, reason: "x" });
    }, "audit-tools/no-since"));
  check("forensicSnapshot: missing/empty reason rejected",
    await _expectCode(function () {
      return b.auditTools.forensicSnapshot({ passphrase: PASS, returnBytes: true, since: Date.now() });
    }, "audit-tools/no-reason"));

  // verifyBundle / purge entry-point validation.
  check("verifyBundle: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.verifyBundle({ in: "/nope" }); }, "audit-tools/no-passphrase"));
  check("verifyBundle: missing in rejected",
    await _expectCode(function () { return b.auditTools.verifyBundle({ passphrase: PASS }); }, "audit-tools/no-indir"));
  check("purge: confirm must be exactly true",
    await _expectCode(function () { return b.auditTools.purge({ archive: "/x", passphrase: PASS }); }, "audit-tools/no-confirm"));
  check("purge: missing archive path rejected",
    await _expectCode(function () { return b.auditTools.purge({ confirm: true, passphrase: PASS }); }, "audit-tools/no-archive"));
  check("purge: missing passphrase rejected",
    await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: "/x" }); }, "audit-tools/no-passphrase"));
}

async function runReaderInjectedErrors(root) {
  async function empty() { return []; }
  // archive: no rows match.
  check("archive: no matching rows rejected",
    await _expectCode(function () {
      return b.auditTools.archive({ passphrase: PASS, out: _freshOut(root, "e"), before: Date.now(), readRows: empty });
    }, "audit-tools/empty"));
  // archive: no covering checkpoint.
  var oneRow = [{ _id: "r1", monotonicCounter: 1, recordedAt: 1, action: "a", prevHash: ZERO, rowHash: "aa", nonce: Buffer.from("nn") }];
  check("archive: no covering checkpoint rejected",
    await _expectCode(function () {
      return b.auditTools.archive({
        passphrase: PASS, out: _freshOut(root, "nc"), before: Date.now(),
        readRows: function () { return Promise.resolve(oneRow); },
        readCoveringCheckpoint: function () { return Promise.resolve(null); },
      });
    }, "audit-tools/no-covering-checkpoint"));

  // exportSlice: empty + non-contiguous.
  check("exportSlice: no matching rows rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({ passphrase: PASS, out: _freshOut(root, "ee"), readRows: empty });
    }, "audit-tools/empty"));
  check("exportSlice: non-contiguous slice rejected",
    await _expectCode(function () {
      return b.auditTools.exportSlice({
        passphrase: PASS, out: _freshOut(root, "ncg"),
        readRows: function () { return Promise.resolve([{ monotonicCounter: 1 }, { monotonicCounter: 3 }]); },
      });
    }, "audit-tools/non-contiguous"));

  // archive witness path: covering checkpoint anchors a counter beyond the
  // purgeable slice tip, so the in-between rows ride as verification
  // witnesses. Fake rows suffice — the build only reads counters/hashes.
  function fakeRow(c) {
    return { _id: "w" + c, monotonicCounter: c, recordedAt: c * 10, action: "seed", prevHash: ZERO, rowHash: "hh" + c, nonce: Buffer.from("n" + c) };
  }
  var witnessBuilt = await b.auditTools.archive({
    passphrase: PASS, returnBytes: true, before: Date.now(),
    readRows: function (crit) {
      if (crit.beforeMs != null) return Promise.resolve([fakeRow(1), fakeRow(2), fakeRow(3)]);
      return Promise.resolve([fakeRow(4), fakeRow(5)]);   // witnesses 4..5
    },
    readCoveringCheckpoint: function () {
      return Promise.resolve({ atMonotonicCounter: 5, atRowHash: "hh5", publicKeyFingerprint: "fp", _id: "ck" });
    },
    readPredecessorRowHash: function () { return Promise.resolve(ZERO); },
  });
  check("archive witness path: purgeable rowCount excludes witnesses", witnessBuilt.rowCount === 3);
  var wPlain = (await backupCrypto.decryptWithPassphrase(
    witnessBuilt.files["rows.enc"], PASS, witnessBuilt.manifest.salts.rows)).toString("utf8");
  check("archive witness path: rows.enc carries slice + witness lines",
    wPlain.split("\n").filter(Boolean).length === 5);

  // archive: witnesses required by the checkpoint anchor are not all
  // available → the slice cannot be proven to chain to the signed anchor.
  check("archive: missing anchor witnesses rejected",
    await _expectCode(function () {
      return b.auditTools.archive({
        passphrase: PASS, returnBytes: true, before: Date.now(),
        readRows: function (crit) {
          if (crit.beforeMs != null) return Promise.resolve([fakeRow(1), fakeRow(2), fakeRow(3)]);
          return Promise.resolve([fakeRow(4)]);   // tip 4 ≠ anchor 5
        },
        readCoveringCheckpoint: function () {
          return Promise.resolve({ atMonotonicCounter: 5, atRowHash: "hh5", publicKeyFingerprint: "fp", _id: "ck" });
        },
        readPredecessorRowHash: function () { return Promise.resolve(ZERO); },
      });
    }, "audit-tools/anchor-rows-missing"));
}

async function runCadfMapping() {
  var base = Date.UTC(2026, 4, 1, 0, 0, 0);
  var rows = [
    { _id: "e1", monotonicCounter: 1, recordedAt: base, action: "auth.login", outcome: "success",
      actorUserIdHash: "h-alice", actorIp: "10.0.0.5", actorSessionId: "s-1", resourceKind: "session", resourceId: "r1",
      reason: "policy allow", metadata: { k: 1 }, prevHash: ZERO, rowHash: "aa" },
    { _id: "e2", monotonicCounter: 2, recordedAt: base + 1, action: "auth.fail", outcome: "failure",
      actorUserId: "bob", resourceId: "r2", metadata: '{"j":2}', prevHash: "aa", rowHash: "bb" },
    { _id: "e3", monotonicCounter: 3, recordedAt: base + 2, action: "policy.deny", outcome: "denied",
      metadata: "{not json", prevHash: "bb", rowHash: "cc" },
    { _id: "e4", monotonicCounter: 4, recordedAt: base + 3, action: "sys.warn", outcome: "warning",
      metadata: null, prevHash: "cc", rowHash: "dd" },
    { _id: "e5", monotonicCounter: 5, recordedAt: base + 4, action: "sys.odd", outcome: "quantum",
      prevHash: "dd", rowHash: "ee" },
    { _id: "e6", monotonicCounter: 6, recordedAt: base + 5, action: "sys.blank", prevHash: "ee", rowHash: "ff" },
  ];
  async function readRows() { return rows; }

  // Range with explicit from/to (ISO round-trip) via exportAudit default dispatch.
  var batch = await b.auditTools.exportAudit({ from: new Date(base), to: base + 100, readRows: readRows });
  check("exportAudit: defaults to cadf batch envelope",
    batch.typeURI.indexOf("event-batch") !== -1 && batch.events.length === 6);
  check("cadf: range.from is ISO", batch.range.from === new Date(base).toISOString());
  check("cadf: success outcome preserved", batch.events[0].outcome === "success");
  check("cadf: object metadata attached", batch.events[0].attachments && batch.events[0].attachments.length === 1);
  check("cadf: actorIp mapped to initiator address",
    batch.events[0].initiator.addresses && batch.events[0].initiator.addresses[0].url === "10.0.0.5");
  check("cadf: reason mapped", batch.events[0].reason && batch.events[0].reason.reasonCode === "policy allow");
  check("cadf: resourceKind → target typeURI", /session$/.test(batch.events[0].target.typeURI));
  check("cadf: failure outcome preserved", batch.events[1].outcome === "failure");
  check("cadf: string metadata parsed", batch.events[1].attachments && /"j":2/.test(batch.events[1].attachments[0].content));
  check("cadf: actorUserId fallback initiator id", batch.events[1].initiator.id === "bob");
  check("cadf: resourceId fallback target id", batch.events[1].target.id === "r2");
  check("cadf: no actorIp → no addresses", batch.events[1].initiator.addresses === undefined);
  check("cadf: denied → failure outcome", batch.events[2].outcome === "failure");
  check("cadf: unparseable metadata falls back to raw",
    batch.events[2].attachments && /not json/.test(batch.events[2].attachments[0].content));
  check("cadf: unknown initiator id when no actor fields", batch.events[2].initiator.id === "unknown");
  check("cadf: n/a target when no resource fields", batch.events[2].target.id === "n/a");
  check("cadf: warning → unknown outcome", batch.events[3].outcome === "unknown");
  check("cadf: null metadata → no attachments", batch.events[3].attachments === undefined);
  check("cadf: unrecognized outcome passes through", batch.events[4].outcome === "quantum");
  check("cadf: absent outcome → unknown", batch.events[5].outcome === "unknown");
  check("cadf: no reason → undefined", batch.events[5].reason === undefined);

  // Range with no from/to → both null; _toMs(undefined) → null branch.
  var openBatch = await b.auditTools.exportCadf({ readRows: readRows });
  check("cadf: open range yields null bounds",
    openBatch.range.from === null && openBatch.range.to === null);

  // exportCadf / exportAudit bad-format rejections.
  check("exportCadf: non-cadf format rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ format: "cef", readRows: readRows }); }, "audit-tools/bad-format"));
  check("exportAudit: unknown format rejected",
    await _expectCode(function () { return b.auditTools.exportAudit({ format: "xml", readRows: readRows }); }, "audit-tools/bad-format"));

  // _toMs Date-instance + parseable-string positive paths, and adversarial.
  var isoBatch = await b.auditTools.exportCadf({ from: "2026-01-01T00:00:00Z", readRows: readRows });
  check("cadf: parseable ISO string from-bound applied",
    isoBatch.range.from === new Date("2026-01-01T00:00:00Z").toISOString());
  check("exportCadf: unparseable from string rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ from: "nonsense", readRows: readRows }); }, "audit-tools/bad-date"));
  check("exportCadf: non-date-typed from rejected",
    await _expectCode(function () { return b.auditTools.exportCadf({ from: {}, readRows: readRows }); }, "audit-tools/bad-date"));
}

async function runForensicSuccess(root) {
  // Fake but contiguous rows starting at counter 1 → the default predecessor
  // reader short-circuits to ZERO_HASH without any db touch.
  function frow(c) {
    return { _id: "f" + c, monotonicCounter: c, recordedAt: c * 1000, action: "sys.evt", outcome: "success", prevHash: ZERO, rowHash: "rr" + c, nonce: Buffer.from("n" + c) };
  }
  async function readRows() { return [frow(1), frow(2), frow(3)]; }

  // returnBytes: assembles the slice files plus the IR wrapper in memory.
  var snap = await b.auditTools.forensicSnapshot({
    returnBytes: true, since: 0, passphrase: PASS, reason: "IR drill", incidentId: "inc-1",
    actor: { id: "alice", role: "incident-commander" }, readRows: readRows,
  });
  check("forensicSnapshot: returnBytes yields the IR wrapper file", Buffer.isBuffer(snap.files["forensic-snapshot.json"]));
  check("forensicSnapshot: returnBytes yields the slice rows.enc", Buffer.isBuffer(snap.files["rows.enc"]));
  check("forensicSnapshot: snapshotKind is forensic", snap.snapshotKind === "forensic");
  check("forensicSnapshot: incidentId + actor carried", snap.incidentId === "inc-1" && snap.actor.role === "incident-commander");
  check("forensicSnapshot: runtime fingerprint captured", snap.runtime && snap.runtime.nodeVersion === process.version);
  check("forensicSnapshot: no disk manifestPath in returnBytes mode", snap.manifestPath === undefined);

  // on-disk: writes rows.enc + manifest.json + forensic-snapshot.json.
  var fdir = _freshOut(root, "forensic");
  var snap2 = await b.auditTools.forensicSnapshot({ out: fdir, since: 0, passphrase: PASS, reason: "IR onto disk", readRows: readRows });
  check("forensicSnapshot: on-disk returns a manifestPath", typeof snap2.manifestPath === "string" && /forensic-snapshot\.json$/.test(snap2.manifestPath));
  check("forensicSnapshot: on-disk wrote the IR wrapper", fs.existsSync(snap2.manifestPath));
  check("forensicSnapshot: omitted incidentId/actor default to null", snap2.incidentId === null && snap2.actor === null);
}

function runWithRecordedAtIso() {
  check("withRecordedAtIso: null passes through", b.auditTools.withRecordedAtIso(null) === null);
  check("withRecordedAtIso: undefined passes through", b.auditTools.withRecordedAtIso(undefined) === undefined);
  var n = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: 1762560000000 });
  check("withRecordedAtIso: number recordedAt → ISO added", n.recordedAtIso === new Date(1762560000000).toISOString());
  var big = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: 1762560000000n });
  check("withRecordedAtIso: bigint recordedAt → ISO added", big.recordedAtIso === new Date(1762560000000).toISOString());
  var inf = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: Infinity });
  check("withRecordedAtIso: non-finite recordedAt → no ISO", inf.recordedAtIso === undefined);
  var str = b.auditTools.withRecordedAtIso({ _id: "x", recordedAt: "2025" });
  check("withRecordedAtIso: non-numeric recordedAt → unchanged", str.recordedAtIso === undefined);
}

// ---------------------------------------------------------------------------
// Integrated: real encrypted db + audit chain + signed checkpoint.
// ---------------------------------------------------------------------------
async function _seedAuditRows(count) {
  b.audit.registerNamespace("test");
  for (var i = 0; i < count; i++) {
    await b.audit.record({ actor: { userId: "u-" + i }, action: "test.seeded", outcome: "success", metadata: { i: i } });
  }
  await b.audit.flush();
}

async function runIntegrated(root) {
  var dir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-db-"));
  var archiveDir = _freshOut(root, "archive");
  var tornDown = false;
  try {
    await setupTestDb(dir);
    await _seedAuditRows(6);
    await b.audit.checkpoint();

    var realRows = await b.clusterStorage.executeAll("SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    check("seeded a real audit chain", realRows.length >= 6);
    var firstCounter = Number(realRows[0].monotonicCounter);
    var lastCounter  = Number(realRows[realRows.length - 1].monotonicCounter);

    // ---- archive happy path (default readers + signer + writer) ----
    var arch = await b.auditTools.archive({ out: archiveDir, before: new Date(Date.now() + 3600000), passphrase: PASS });
    check("archive: wrote a bundle with rowCount", arch.rowCount === realRows.length);
    check("archive: manifest is archive kind", arch.manifest.kind === "archive");

    // ---- verifyBundle happy variants ----
    var ok = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS });
    check("verifyBundle: archive verifies ok", ok.ok === true && ok.kind === "archive");
    check("verifyBundle: rowsVerified matches", ok.rowsVerified === realRows.length);
    var okRows = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, includeRows: true });
    check("verifyBundle: includeRows attaches decrypted rows", Array.isArray(okRows.rows) && okRows.rows.length === realRows.length);
    var okNoSig = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: signature check can be skipped", okNoSig.ok === true);
    var badSig = await b.auditTools.verifyBundle({ in: archiveDir, passphrase: PASS, verifySignature: function () { return false; } });
    check("verifyBundle: failing signature verifier → not ok", badSig.ok === false && /signature/.test(badSig.reason));

    // ---- exportSlice happy (default readers, predecessor at chain origin) ----
    var exportDir = _freshOut(root, "export");
    var exp = await b.auditTools.exportSlice({ out: exportDir, from: 0, to: Date.now() + 3600000, passphrase: PASS });
    check("exportSlice: wrote an export bundle", exp.manifest.kind === "export" && exp.rowCount === realRows.length);
    var okExp = await b.auditTools.verifyBundle({ in: exportDir, passphrase: PASS });
    check("verifyBundle: export bundle verifies ok", okExp.ok === true && okExp.kind === "export");

    // ---- exportSlice with a predecessor beyond the chain origin (firstCounter>1) ----
    if (realRows.length >= 3) {
      var midDir = _freshOut(root, "mid");
      var midRows = realRows.slice(2);   // starts at counter firstCounter+2
      var midExp = await b.auditTools.exportSlice({
        out: midDir, passphrase: PASS,
        readRows: function () { return Promise.resolve(midRows); },
      });
      check("exportSlice: mid-chain slice records a real predecessor hash",
        midExp.manifest.range.predecessorRowHash === String(realRows[1].rowHash));
      var okMid = await b.auditTools.verifyBundle({ in: midDir, passphrase: PASS });
      check("verifyBundle: mid-chain slice verifies against its predecessor", okMid.ok === true);
    }

    // ---- rowHash break: a row whose content was mutated after hashing ----
    var tamperedRows = realRows.map(function (r, idx) {
      return idx === 1 ? Object.assign({}, r, { action: "TAMPERED-" + r.action }) : r;
    });
    var rhDir = _freshOut(root, "rowhash-break");
    await b.auditTools.exportSlice({
      out: rhDir, passphrase: PASS,
      readRows: function () { return Promise.resolve(tamperedRows); },
      readPredecessorRowHash: function () { return Promise.resolve(String(realRows[0].prevHash)); },
    });
    var rhRes = await b.auditTools.verifyBundle({ in: rhDir, passphrase: PASS });
    check("verifyBundle: mutated row content → rowHash mismatch", rhRes.ok === false && /rowHash mismatch/.test(rhRes.reason));

    // ---- prevHash break via tampered manifest predecessor witness ----
    var pbDir = _copyBundle(archiveDir, _freshOut(root, "prevhash-break"));
    _editManifest(pbDir, function (m) { m.range.predecessorRowHash = "f".repeat(128); });
    var pbRes = await b.auditTools.verifyBundle({ in: pbDir, passphrase: PASS });
    check("verifyBundle: wrong predecessor witness → prevHash mismatch", pbRes.ok === false && /prevHash mismatch/.test(pbRes.reason));

    // ---- first/last rowHash disagreement with the manifest ----
    var frDir = _copyBundle(archiveDir, _freshOut(root, "first-mismatch"));
    _editManifest(frDir, function (m) { m.range.firstRowHash = "e".repeat(128); });
    var frRes = await b.auditTools.verifyBundle({ in: frDir, passphrase: PASS });
    check("verifyBundle: firstRowHash disagreement flagged", frRes.ok === false && /firstRowHash/.test(frRes.reason));
    var lrDir = _copyBundle(archiveDir, _freshOut(root, "last-mismatch"));
    _editManifest(lrDir, function (m) { m.range.lastRowHash = "e".repeat(128); });
    var lrRes = await b.auditTools.verifyBundle({ in: lrDir, passphrase: PASS });
    check("verifyBundle: lastRowHash disagreement flagged", lrRes.ok === false && /lastRowHash/.test(lrRes.reason));

    // ---- checkpoint atMonotonicCounter below the slice tip (build-time inject) ----
    if (realRows.length >= 2) {
      var lowDir = _freshOut(root, "ckpt-low");
      await b.auditTools.archive({
        out: lowDir, before: new Date(Date.now() + 3600000), passphrase: PASS,
        readRows: function () { return Promise.resolve(realRows); },
        readCoveringCheckpoint: function () {
          return Promise.resolve({ atMonotonicCounter: firstCounter, atRowHash: String(realRows[0].rowHash), publicKeyFingerprint: "fp", _id: "ck-low" });
        },
      });
      var lowRes = await b.auditTools.verifyBundle({ in: lowDir, passphrase: PASS });
      check("verifyBundle: checkpoint below lastCounter flagged", lowRes.ok === false && /atMonotonicCounter/.test(lowRes.reason));
    }

    // ---- checkpoint atRowHash not bound to the anchored slice row ----
    var bindDir = _freshOut(root, "ckpt-unbound");
    await b.auditTools.archive({
      out: bindDir, before: new Date(Date.now() + 3600000), passphrase: PASS,
      readRows: function () { return Promise.resolve(realRows); },
      readCoveringCheckpoint: function () {
        return Promise.resolve({ atMonotonicCounter: lastCounter, atRowHash: "f".repeat(128), publicKeyFingerprint: "fp", _id: "ck-unbound" });
      },
    });
    var bindRes = await b.auditTools.verifyBundle({ in: bindDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: checkpoint atRowHash not bound to slice flagged", bindRes.ok === false && /atRowHash does not match/.test(bindRes.reason));

    // ---- checkpoint anchoring a counter NOT present in the bundle ----
    // An attacker pairs a checkpoint claiming a high anchor counter with a
    // slice that omits that row. Re-encrypt checkpoint.enc on a written copy
    // with an anchor counter beyond every bundle row and refresh the manifest
    // checksum so the read passes to the binding step.
    var absentDir = _copyBundle(archiveDir, _freshOut(root, "anchor-absent"));
    var forgedCkpt = await backupCrypto.encryptWithFreshSalt(
      JSON.stringify({ atMonotonicCounter: lastCounter + 5, atRowHash: "a".repeat(128) }), PASS);
    fs.writeFileSync(path.join(absentDir, "checkpoint.enc"), forgedCkpt.encrypted);
    _editManifest(absentDir, function (m) {
      m.salts.checkpoint = forgedCkpt.salt;
      m.checksum.checkpointSha3_512 = backupCrypto.checksum(forgedCkpt.encrypted);
      m.checkpoint.atMonotonicCounter = lastCounter + 5;
    });
    var absentRes = await b.auditTools.verifyBundle({ in: absentDir, passphrase: PASS, verifyCheckpointSignature: false });
    check("verifyBundle: checkpoint anchoring an absent counter is unbound",
      absentRes.ok === false && /no such row is present/.test(absentRes.reason));

    // ---- _readBundle corrupt-blob rejections (tamper written copies) ----
    var rcDir = _copyBundle(archiveDir, _freshOut(root, "rows-checksum"));
    _flipByte(path.join(rcDir, "rows.enc"));
    check("verifyBundle: tampered rows.enc → checksum mismatch",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: rcDir, passphrase: PASS }); }, "audit-tools/rows-checksum-mismatch"));

    var nrDir = _copyBundle(archiveDir, _freshOut(root, "no-rows"));
    fs.rmSync(path.join(nrDir, "rows.enc"));
    check("verifyBundle: missing rows.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: nrDir, passphrase: PASS }); }, "audit-tools/no-rows-blob"));

    var nmDir = _freshOut(root, "no-manifest");
    fs.mkdirSync(nmDir, { recursive: true });
    check("verifyBundle: missing manifest rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: nmDir, passphrase: PASS }); }, "audit-tools/no-manifest"));

    var tmDir = _freshOut(root, "manifest-too-large");
    fs.mkdirSync(tmDir, { recursive: true });
    fs.writeFileSync(path.join(tmDir, "manifest.json"), Buffer.alloc(5242880, 0x61));   // 5 MiB > 4 MiB cap
    check("verifyBundle: oversized manifest rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: tmDir, passphrase: PASS }); }, "audit-tools/bad-format"));

    var bfDir = _copyBundle(archiveDir, _freshOut(root, "bad-format"));
    _editManifest(bfDir, function (m) { m.format = "not-a-blamejs-bundle"; });
    check("verifyBundle: wrong manifest format rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: bfDir, passphrase: PASS }); }, "audit-tools/bad-format"));

    var bkDir = _copyBundle(archiveDir, _freshOut(root, "bad-kind"));
    _editManifest(bkDir, function (m) { m.kind = "bogus"; });
    check("verifyBundle: unknown manifest kind rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: bkDir, passphrase: PASS }); }, "audit-tools/bad-kind"));

    var ncDir = _copyBundle(archiveDir, _freshOut(root, "no-ckpt"));
    fs.rmSync(path.join(ncDir, "checkpoint.enc"));
    check("verifyBundle: archive missing checkpoint.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ncDir, passphrase: PASS }); }, "audit-tools/no-checkpoint-blob"));

    var ccDir = _copyBundle(archiveDir, _freshOut(root, "ckpt-checksum"));
    _flipByte(path.join(ccDir, "checkpoint.enc"));
    check("verifyBundle: tampered checkpoint.enc → checksum mismatch",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ccDir, passphrase: PASS }); }, "audit-tools/checkpoint-checksum-mismatch"));

    var ctDir = _copyBundle(archiveDir, _freshOut(root, "ckpt-too-large"));
    fs.writeFileSync(path.join(ctDir, "checkpoint.enc"), Buffer.alloc(5242880, 0x62));   // 5 MiB > 4 MiB cap
    check("verifyBundle: oversized checkpoint.enc rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: ctDir, passphrase: PASS }); }, "audit-tools/checkpoint-too-large"));

    check("verifyBundle: nonexistent bundle dir rejected",
      await _expectCode(function () { return b.auditTools.verifyBundle({ in: path.join(root, "does-not-exist"), passphrase: PASS }); }, "audit-tools/no-bundle"));

    // ---- _defaultReadPredecessorRowHash: ungrounded predecessor throws ----
    check("exportSlice: ungrounded predecessor rejected",
      await _expectCode(function () {
        return b.auditTools.exportSlice({
          out: _freshOut(root, "ungrounded"), passphrase: PASS,
          readRows: function () { return Promise.resolve([Object.assign({}, realRows[0], { monotonicCounter: 999999 })]); },
        });
      }, "audit-tools/no-predecessor"));

    // ---- purge refusal paths (no db mutation) ----
    check("purge: unverified archive rejected",
      await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: pbDir, passphrase: PASS }); }, "audit-tools/archive-not-ok"));
    check("purge: non-archive bundle kind rejected",
      await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: exportDir, passphrase: PASS }); }, "audit-tools/wrong-kind"));
    check("purge: predecessor not matching prior anchor rejected",
      await _expectCode(function () {
        return b.auditTools.purge({
          confirm: true, archive: archiveDir, passphrase: PASS,
          readAnchor: function () { return Promise.resolve({ lastPurgedCounter: firstCounter - 1, lastPurgedRowHash: "d".repeat(128) }); },
          apply: function () { return Promise.resolve({ rowsDeleted: 0, checkpointsDeleted: 0, archiveBundleId: "x" }); },
        });
      }, "audit-tools/anchor-mismatch"));

    // ---- dual-control gate refusals + a consumed-grant success (injected apply) ----
    var gate = function () { return { m: 2, n: 3 }; };
    check("purge: dual control without a grant rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate });
      }, "audit-tools/dual-control-required"));
    check("purge: not-ready grant rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate, dualControlGrant: { ready: false, action: "auditTools.purge" } });
      }, "audit-tools/dual-control-grant-not-ready"));
    check("purge: grant bound to a different action rejected",
      await _expectCode(function () {
        return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate, dualControlGrant: { ready: true, action: "db.eraseHard" } });
      }, "audit-tools/dual-control-grant-mismatch"));
    var gateOk = await b.auditTools.purge({
      confirm: true, archive: archiveDir, passphrase: PASS, checkDualControlGate: gate,
      dualControlGrant: { ready: true, action: "auditTools.purge" },
      readAnchor: function () { return Promise.resolve(null); },
      apply: function () { return Promise.resolve({ rowsDeleted: realRows.length, checkpointsDeleted: 1, archiveBundleId: "gid" }); },
    });
    check("purge: consumed dual-control grant proceeds", gateOk.purged === true && gateOk.dualControlConsumed === true);

    // ---- real purge (default anchor read + apply) mutates the chain ----
    var purged = await b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS });
    check("purge: real purge deletes live rows", purged.purged === true && purged.rowsDeleted > 0);
    check("purge: reports no dual-control consumed (gate not declared)", purged.dualControlConsumed === false);

    // ---- second purge of the same bundle is now non-monotonic ----
    check("purge: replay against a set anchor is non-monotonic",
      await _expectCode(function () { return b.auditTools.purge({ confirm: true, archive: archiveDir, passphrase: PASS }); }, "audit-tools/non-monotonic-purge"));

    // ---- _defaultReadPredecessorRowHash anchor branch: predecessor purged ----
    await _seedAuditRows(2);
    var postRows = await b.clusterStorage.executeAll("SELECT * FROM audit_log ORDER BY monotonicCounter ASC");
    if (postRows.length) {
      var pDir = _freshOut(root, "post-purge");
      var postExp = await b.auditTools.exportSlice({
        out: pDir, passphrase: PASS,
        readRows: function () { return Promise.resolve(postRows); },
      });
      // The predecessor for a slice whose first row sits right after a purged
      // range resolves through the purge anchor's lastPurgedRowHash rather than
      // a (now-deleted) predecessor row — the branch under test here.
      check("exportSlice: predecessor resolves via the purge anchor",
        postExp.manifest.range.predecessorRowHash === String(purged.lastPurgedRowHash));
      // documents current behavior: after an in-process purge empties audit_log,
      // subsequently-recorded rows restart their prevHash at ZERO_HASH (the live
      // chain resumes from an empty table), so a slice of those rows chain-walks
      // to a prevHash discontinuity against the anchor predecessor. The chain
      // resume semantics live in the audit module, not audit-tools.
      var okPost = await b.auditTools.verifyBundle({ in: pDir, passphrase: PASS });
      check("verifyBundle: post-purge live rows restart the chain (discontinuity surfaced)",
        okPost.ok === false && /prevHash mismatch/.test(okPost.reason));
    }

    // ---- teardown, then verify without a live signer: default verifier
    // catches the un-initialized audit-sign keypair and reports not-ok. ----
    await teardownTestDb(dir);
    tornDown = true;
    var noSigner = await b.auditTools.verifyBundle({ in: exportDir, passphrase: PASS });
    check("verifyBundle: export still verifies with no live signer", noSigner.ok === true);
  } finally {
    if (!tornDown) { try { await teardownTestDb(dir); } catch (_e) {} }
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function run() {
  var root = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-at-"));
  try {
    await runInputValidation(root);
    await runReaderInjectedErrors(root);
    await runCadfMapping();
    await runForensicSuccess(root);
    runWithRecordedAtIso();
    await runIntegrated(root);
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_e) {}
  }
  console.log("OK — audit-tools tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { process.exitCode = 1; throw err; });
}
