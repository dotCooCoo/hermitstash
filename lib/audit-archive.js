"use strict";

/**
 * HermitStash-native encrypted audit archival.
 *
 * When audit_log grows past the configured row threshold, the oldest entries are
 * serialized in their sealed at-rest form, passphrase-encrypted (Argon2id +
 * XChaCha20-Poly1305 — the same crypto as backups, via b.backupCrypto), signed
 * with a post-quantum key (b.auditSign, SLH-DSA / ML-DSA), and written to
 * data/audit-archives/ as a single JSON envelope. The archived rows are then
 * pruned from the DB with the tamper chain re-anchored so verifyChain still
 * passes on the live rows.
 *
 * The bundle stores the SEALED rows (ciphertext in the vault-sealed columns) plus
 * the chain proof, so:
 *   - verification recomputes each rowHash over the sealed form (matches the chain)
 *     and checks the PQC signature — needs only the bundle passphrase;
 *   - reading the content (export) additionally unseals with the vault key, which
 *     the server already holds.
 *
 * This is deliberately HS-native rather than b.auditTools: HermitStash runs its
 * own standalone SQLite substrate and uses none of blamejs's data layer, so the
 * audit-tools archive/purge path (which assumes that layer) does not apply.
 */

var b = require("./vendor/blamejs");
var C = require("./constants");
var config = require("./config");
var logger = require("../app/shared/logger");
var nodeFs = require("node:fs");
var nodePath = require("node:path");

// Lazy to avoid the vault -> config -> audit -> db circular import.
var db = b.lazyRequire(function () { return require("./db"); });
var fieldCryptoLazy = b.lazyRequire(function () { return require("./field-crypto"); });
var auditLazy = b.lazyRequire(function () { return require("./audit"); });

var BUNDLE_VERSION = "hs-audit-archive-v1";

// ---- Purge serializer (shared with retention cleanup) ----
//
// Retention cleanup (lib/audit.js) and archival (this module) BOTH move the
// tamper-chain purge anchor and DELETE the oldest audit rows. With no lock, a
// retention delete that fires while an archival is mid-await (Argon2id encrypt +
// verify) can raise the anchor to Y and delete rows [1..Y], after which archival's
// _pruneArchived would lower the anchor back to X (< Y) — leaving the live floor at
// Y+1 while the anchor claims X, a permanent, self-perpetuating verifyChain
// "prevHash mismatch". One process-wide async mutex serializes both mutating paths
// so their anchor-read → delete → anchor-write windows can never interleave.
var _purgeMutex = new b.safeAsync.Mutex();
function runExclusivePurge(fn) { return _purgeMutex.runExclusive(fn); }

// Move the purge anchor FORWARD only — never lower it. Both retention and archival
// advance the chain-origin anchor; a stale writer lowering it below a newer floor
// is the exact corruption above. Re-read the live anchor immediately before writing
// and keep MAX(existing, new). Defense-in-depth alongside the mutex: even a future
// out-of-band anchor writer can only move it forward.
function upsertPurgeAnchorNeverLower(counter, rowHash, bundleId) {
  if (counter == null || rowHash == null) return;
  var cur = db().rawGet("SELECT lastPurgedCounter FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
  if (cur && cur.lastPurgedCounter != null && Number(cur.lastPurgedCounter) >= Number(counter)) return;
  db().rawExec(
    "INSERT INTO _blamejs_audit_purge_anchor (scope, lastPurgedCounter, lastPurgedRowHash, archiveBundleId, purgedAt) " +
    "VALUES ('audit', ?, ?, ?, ?) " +
    "ON CONFLICT(scope) DO UPDATE SET lastPurgedCounter = excluded.lastPurgedCounter, " +
    "lastPurgedRowHash = excluded.lastPurgedRowHash, archiveBundleId = excluded.archiveBundleId, purgedAt = excluded.purgedAt",
    counter, rowHash, bundleId, Date.now()
  );
}

// Deterministic hash of the FULL top-level manifest, bound into the archive
// signature so an on-disk edit of ANY manifest field (count / firstCounter /
// lastCounter / fingerprint / …) breaks verification — not only the three fields
// the checksum+stamp covered. Canonical JSON so key order can't shift the bytes.
function _manifestHash(manifest) {
  return b.crypto.sha3Hash(b.canonicalJson.stringify(manifest));
}

// ---- Signing (lazy, non-interactive plaintext by default) ----
var _signReady = null;
function _ensureSigning() {
  if (!_signReady) {
    _signReady = b.auditSign.init({
      dataDir: C.PATHS.DATA_DIR,
      mode: config.auditSigningMode === "wrapped" ? "wrapped" : "plaintext",
      algorithm: "slh-dsa-shake-256f",
    });
  }
  return _signReady;
}

function _archiveDir() {
  var dir = C.PATHS.AUDIT_ARCHIVE_DIR;
  try { nodeFs.mkdirSync(dir, { recursive: true }); } catch (_e) { /* exists */ }
  return dir;
}

// ---- Wire form (JSON-safe) for the sealed rows ----
// nonce is a BLOB (Buffer); render it as base64 so the row round-trips through
// JSON. Every other column is already a string / number / null.
function _rowToWire(row) {
  var out = {};
  for (var k in row) {
    if (!Object.prototype.hasOwnProperty.call(row, k)) continue;
    var v = row[k];
    // nonce is a BLOB returned as a Buffer OR Uint8Array (b.crypto.generateBytes);
    // base64 it so it survives JSON intact instead of becoming a numeric-key object.
    if (Buffer.isBuffer(v) || v instanceof Uint8Array) out[k] = "b64:" + Buffer.from(v).toString("base64");
    else out[k] = v;
  }
  return out;
}
function _wireToRow(w) {
  var out = {};
  for (var k in w) {
    if (!Object.prototype.hasOwnProperty.call(w, k)) continue;
    var v = w[k];
    if (typeof v === "string" && v.indexOf("b64:") === 0) out[k] = Buffer.from(v.slice(4), "base64");
    else out[k] = v;
  }
  return out;
}

// ---- Archive the oldest rows down to the threshold ----
// Runs the whole archive (anchor read → encrypt → sign → verify → prune) under the
// shared purge mutex so a retention cleanup can't move the anchor mid-await.
function archiveNow(opts) {
  return runExclusivePurge(function () { return _archiveNowLocked(opts); });
}

async function _archiveNowLocked(opts) {
  opts = opts || {};
  var passphrase = opts.passphrase || config.auditArchivePassphrase;
  if (!passphrase) throw new Error("Audit archive passphrase is not configured.");

  var threshold = parseInt(config.auditArchiveThresholdRows, 10) || 0;
  var keep = (opts.keep != null) ? opts.keep : threshold;

  var countRow = db().rawGet("SELECT COUNT(*) AS c FROM audit_log");
  var total = countRow ? Number(countRow.c) : 0;
  var toArchive = opts.all ? total : Math.max(0, total - keep);
  if (toArchive <= 0) return { archived: 0, total: total, id: null };

  // Oldest rows first. Chained rows order by counter; any pre-chain NULL-counter
  // rows sort first (by createdAt) and are archived/pruned by _id too.
  var rawRows = db().rawQuery(
    "SELECT * FROM audit_log ORDER BY (monotonicCounter IS NULL) DESC, monotonicCounter ASC, createdAt ASC LIMIT ?",
    toArchive
  );
  if (!rawRows.length) return { archived: 0, total: total, id: null };

  var chained = rawRows.filter(function (r) { return r.monotonicCounter != null; });
  var chainOn = !!config.auditChainEnabled && chained.length > 0;
  var first = rawRows[0], last = rawRows[rawRows.length - 1];

  // Chain continuity: the predecessor of the first archived chained row is the
  // current purge anchor's rowHash (or the chain origin if none yet).
  var predecessorRowHash = null;
  if (chainOn) {
    var anchor = db().rawGet("SELECT lastPurgedRowHash FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    predecessorRowHash = (anchor && anchor.lastPurgedRowHash) ? anchor.lastPurgedRowHash : b.auditChain.ZERO_HASH;
  }

  var stamp = new Date().toISOString();
  var lastCounter = chained.length ? Number(chained[chained.length - 1].monotonicCounter) : null;
  var id = "audit-" + stamp.replace(/[:.]/g, "-") + (lastCounter != null ? "-c" + lastCounter : "");

  var manifest = {
    version: BUNDLE_VERSION,
    id: id,
    createdAt: stamp,
    count: rawRows.length,
    firstCreatedAt: first.createdAt || null,
    lastCreatedAt: last.createdAt || null,
    chainEnabled: chainOn,
    firstCounter: chained.length ? Number(chained[0].monotonicCounter) : null,
    lastCounter: lastCounter,
    firstRowHash: chained.length ? chained[0].rowHash : null,
    lastRowHash: chained.length ? chained[chained.length - 1].rowHash : null,
    predecessorRowHash: predecessorRowHash,
  };

  // Encrypt { manifest, rows } with the passphrase, sign the ciphertext checksum.
  var plaintext = Buffer.from(JSON.stringify({ manifest: manifest, rows: rawRows.map(_rowToWire) }), "utf8");
  var saltHex = b.crypto.generateToken(C.BYTES.bytes(32));
  var encrypted = await b.backupCrypto.encryptWithPassphrase(plaintext, passphrase, saltHex);
  var checksum = b.backupCrypto.checksum(encrypted);

  await _ensureSigning();
  var sigPayload = Buffer.from(BUNDLE_VERSION + "\n" + checksum + "\n" + stamp + "\n" + _manifestHash(manifest), "utf8");
  var signature = b.auditSign.sign(sigPayload);

  var envelope = {
    v: BUNDLE_VERSION,
    salt: saltHex,
    checksum: checksum,
    signature: Buffer.isBuffer(signature) ? signature.toString("base64") : String(signature),
    fingerprint: b.auditSign.getPublicKeyFingerprint(),
    publicKey: b.auditSign.getPublicKey(),
    manifest: manifest,
    data: encrypted.toString("base64"),
  };

  var file = nodePath.join(_archiveDir(), id + ".json");
  if (nodeFs.existsSync(file)) throw new Error("Archive already exists: " + id);
  b.atomicFile.writeSync(file, JSON.stringify(envelope), { fileMode: 0o600 });

  // Safety: read the freshly written bundle back and verify it end-to-end
  // (decrypt + checksum + PQC signature + chain recompute) BEFORE pruning the live
  // rows. A bad write / encrypt / sign therefore never deletes unrecoverable data.
  var check = await verifyArchive(id, passphrase);
  if (!check.ok) {
    try { nodeFs.unlinkSync(file); } catch (_e) { /* best-effort cleanup */ }
    throw new Error("Refusing to prune — the written archive failed verification: " + check.reason);
  }

  _pruneArchived(rawRows, manifest);

  auditLazy().log(auditLazy().ACTIONS.AUDIT_ARCHIVED, {
    performedBy: opts.performedBy || "system",
    details: "Archived " + rawRows.length + " entries to " + id +
      (chainOn ? " (chain re-anchored at counter " + lastCounter + ")" : ""),
    req: opts.req,
  });
  return { archived: rawRows.length, total: total - rawRows.length, id: id };
}

// Re-anchor the chain to the last archived row, then delete the archived rows by
// _id (exact). Re-anchor BEFORE deleting so verifyChain resumes from the next live
// row rather than breaking on a missing prefix.
function _pruneArchived(rows, manifest) {
  if (manifest.chainEnabled && manifest.lastCounter != null && manifest.lastRowHash) {
    upsertPurgeAnchorNeverLower(manifest.lastCounter, manifest.lastRowHash, manifest.id);
  }
  var ids = rows.map(function (r) { return r._id; });
  for (var i = 0; i < ids.length; i += 500) {
    var batch = ids.slice(i, i + 500);
    var placeholders = batch.map(function () { return "?"; }).join(",");
    db().rawExec.apply(null, ["DELETE FROM audit_log WHERE _id IN (" + placeholders + ")"].concat(batch));
  }
}

// ---- Read / list / verify / export ----
function _bundlePath(id) {
  // id is operator-supplied — confine it to the archive dir, basename only.
  var safe = nodePath.basename(String(id || ""));
  if (!/^audit-[A-Za-z0-9_-]+\.json$/.test(safe) && !/^audit-[A-Za-z0-9_-]+$/.test(safe)) {
    throw new Error("Invalid archive id.");
  }
  if (safe.slice(-5) !== ".json") safe += ".json";
  return nodePath.join(_archiveDir(), safe);
}

function _readEnvelope(id) {
  var file = _bundlePath(id);
  if (!nodeFs.existsSync(file)) throw new Error("Archive not found: " + id);
  return b.safeJson.parse(nodeFs.readFileSync(file, "utf8"));
}

function listArchives() {
  var dir = _archiveDir();
  var files;
  try { files = nodeFs.readdirSync(dir); } catch (_e) { return []; }
  var out = [];
  for (var i = 0; i < files.length; i++) {
    if (files[i].slice(-5) !== ".json") continue;
    try {
      var env = b.safeJson.parse(nodeFs.readFileSync(nodePath.join(dir, files[i]), "utf8"));
      var m = env.manifest || {};
      var stat = nodeFs.statSync(nodePath.join(dir, files[i]));
      out.push({
        id: m.id || files[i].slice(0, -5),
        createdAt: m.createdAt || null,
        count: m.count || 0,
        firstCreatedAt: m.firstCreatedAt || null,
        lastCreatedAt: m.lastCreatedAt || null,
        chainEnabled: !!m.chainEnabled,
        firstCounter: m.firstCounter,
        lastCounter: m.lastCounter,
        fingerprint: env.fingerprint || null,
        sizeBytes: stat.size,
      });
    } catch (_e) { /* skip an unreadable / malformed bundle */ }
  }
  out.sort(function (a, b2) { return String(b2.createdAt).localeCompare(String(a.createdAt)); });
  return out;
}

// Decrypt + integrity-check a bundle: PQC signature over the checksum, checksum
// over the ciphertext, then recompute the chain rowHashes over the sealed rows and
// confirm contiguity + the manifest's first/last hashes. Returns { ok, ... }.
async function verifyArchive(id, passphrase) {
  var env = _readEnvelope(id);
  var encrypted = Buffer.from(env.data, "base64");

  if (b.backupCrypto.checksum(encrypted) !== env.checksum) {
    return { ok: false, reason: "checksum mismatch (bundle corrupted or altered)" };
  }
  // Reconstruct the exact signed payload: v \n checksum \n createdAt \n
  // hash(top-level manifest). The manifest hash is recomputed over the on-disk
  // env.manifest, so any edit to a plaintext manifest field (count, counters,
  // fingerprint, …) yields a different payload and the signature no longer verifies.
  var sigPayload = Buffer.from(env.v + "\n" + env.checksum + "\n" + env.manifest.createdAt + "\n" + _manifestHash(env.manifest), "utf8");
  // Pin the verifying key to THIS server's own key history (the current key, or a
  // rotated-out key resolved by fingerprint) — NEVER the envelope's embedded
  // publicKey. An attacker who rewrote the bundle on disk could otherwise re-sign
  // with their own keypair and embed it, which would defeat the tamper-evidence.
  // A fingerprint this server never held is rejected.
  await _ensureSigning();
  // Constant-time fingerprint compare (project convention: timing-safe for ALL
  // digest/MAC values). b.crypto.timingSafeEqual is length-safe (false, no throw,
  // on a length mismatch), so a differing-length fingerprint simply falls through
  // to the by-fingerprint history lookup below.
  var _curFp = b.auditSign.getPublicKeyFingerprint();
  var _isCurrentKey = !!env.fingerprint &&
    b.crypto.timingSafeEqual(Buffer.from(String(env.fingerprint)), Buffer.from(String(_curFp)));
  var trustedPub = _isCurrentKey
    ? b.auditSign.getPublicKey()
    : (env.fingerprint ? b.auditSign.getPublicKeyByFingerprint(env.fingerprint) : null);
  if (!trustedPub) return { ok: false, reason: "signature key is not trusted (unknown fingerprint)" };
  var sigOk = false;
  try { sigOk = b.auditSign.verify(sigPayload, Buffer.from(env.signature, "base64"), trustedPub); } catch (_e) { sigOk = false; }
  if (!sigOk) return { ok: false, reason: "signature verification failed" };

  var decrypted = await b.backupCrypto.decryptWithPassphrase(encrypted, passphrase, env.salt);
  var payload = b.safeJson.parse(decrypted.toString("utf8"));
  var rows = (payload.rows || []).map(_wireToRow);
  var manifest = payload.manifest || env.manifest;

  var rowsVerified = rows.length;
  if (manifest.chainEnabled) {
    // Delegate the chain walk to the SAME audited primitive the live chain uses
    // (b.auditChain.verifyChain) instead of re-implementing it: feed it the
    // bundle's chained rows and a synthetic purge anchor carrying the slice's
    // predecessor rowHash, so it walks from the correct origin without the live DB.
    var chainRows = rows
      .filter(function (r) { return r.monotonicCounter != null; })
      .map(function (r) { return Object.assign({}, r, { nonce: Buffer.isBuffer(r.nonce) ? r.nonce : Buffer.from(r.nonce) }); })
      .sort(function (a, c) { return Number(a.monotonicCounter) - Number(c.monotonicCounter); });
    var pred = manifest.predecessorRowHash;
    function bundleQueryAll(sqlText) {
      if (/_blamejs_audit_purge_anchor/i.test(String(sqlText))) {
        if (pred && pred !== b.auditChain.ZERO_HASH && manifest.firstCounter != null) {
          return Promise.resolve([{ lastPurgedCounter: manifest.firstCounter - 1, lastPurgedRowHash: pred }]);
        }
        return Promise.resolve([]);
      }
      return Promise.resolve(chainRows);
    }
    var walk = await b.auditChain.verifyChain(bundleQueryAll, "audit_log", {});
    if (!walk.ok) {
      return { ok: false, reason: walk.reason || "chain mismatch", breakAt: walk.breakAt, rowsVerified: walk.rowsVerified || 0 };
    }
    rowsVerified = walk.rowsVerified;
    if (manifest.lastRowHash && walk.lastHash && walk.lastHash !== manifest.lastRowHash) {
      return { ok: false, reason: "final rowHash does not match the manifest" };
    }
  }
  return { ok: true, id: manifest.id, count: rows.length, rowsVerified: rowsVerified, range: { firstCounter: manifest.firstCounter, lastCounter: manifest.lastCounter }, fingerprint: env.fingerprint };
}

// Decrypt + unseal a bundle's rows for export (server holds the vault key).
async function readArchiveEntries(id, passphrase) {
  // Verify the archive's PQC signature (pinned to THIS server's key history) and
  // tamper chain BEFORE returning any row for export — the checksum alone proves
  // only non-corruption, not authenticity, so a rewritten bundle's rows would
  // otherwise be exported to the auditor as genuine. verifyArchive performs the
  // pinned-key signature verify + chain walk and refuses an unknown-fingerprint
  // or altered bundle.
  var check = await verifyArchive(id, passphrase);
  if (!check.ok) throw new Error("Archive verification failed: " + (check.reason || "unknown"));
  var env = _readEnvelope(id);
  var encrypted = Buffer.from(env.data, "base64");
  if (b.backupCrypto.checksum(encrypted) !== env.checksum) throw new Error("Archive checksum mismatch.");
  var decrypted = await b.backupCrypto.decryptWithPassphrase(encrypted, passphrase, env.salt);
  var payload = b.safeJson.parse(decrypted.toString("utf8"));
  var rows = (payload.rows || []).map(_wireToRow);
  // Unseal the vault-sealed columns to plaintext for the auditor.
  return rows.map(function (r) { return fieldCryptoLazy().unsealDoc("audit_log", Object.assign({}, r)); });
}

// ---- Scheduled, size-triggered archival ----
function startAuditArchival() {
  function tick() {
    if (!config.auditArchiveEnabled) return;
    if (!config.auditArchivePassphrase) return;
    try {
      var threshold = parseInt(config.auditArchiveThresholdRows, 10) || 0;
      if (threshold <= 0) return;
      var countRow = db().rawGet("SELECT COUNT(*) AS c FROM audit_log");
      var total = countRow ? Number(countRow.c) : 0;
      if (total <= threshold) return;
      archiveNow({ performedBy: "system" }).catch(function (e) {
        logger.error("[audit-archive] scheduled archival failed", { err: e && e.message });
      });
    } catch (e) {
      logger.error("[audit-archive] scheduled archival check failed", { err: e && e.message });
    }
  }
  // First check shortly after boot, then hourly. unref so it never holds the
  // process open.
  setTimeout(tick, C.TIME.seconds(30));
  var timer = setInterval(tick, C.TIME.hours(1));
  if (timer.unref) timer.unref();
}

// ---- PQC-signed chain checkpoints ----
//
// The row-hash chain (lib/audit.js) is keyless: a DB-write adversary who can edit
// every row can recompute a self-consistent chain and defeat verifyChain. A
// periodic checkpoint signs the current chain tip { counter, tipHash } with the
// server's post-quantum audit-signing key (the SAME key archival uses), so a later
// verify catches a full-chain rewrite the private key can't forge. Checkpoints are
// linked (each carries the previous tipHash) so a truncation / reorder of the
// stored sequence is caught too. Runs whenever the chain is enabled — no separate
// opt-in — since a signed checkpoint is pure additional evidence.
var CHECKPOINT_FORMAT = "hs-audit-chain-checkpoint-v1";
var CHECKPOINT_MAX = 1000; // allow:raw-byte-literal — checkpoint-count cap, not a byte size
var CHECKPOINT_FILE = nodePath.join(C.PATHS.DATA_DIR, "audit-chain-checkpoints.json");

function _readCheckpoints() {
  try {
    if (!nodeFs.existsSync(CHECKPOINT_FILE)) return [];
    var doc = b.safeJson.parse(nodeFs.readFileSync(CHECKPOINT_FILE, "utf8"));
    return Array.isArray(doc && doc.anchors) ? doc.anchors : [];
  } catch (_e) { return []; }
}

function _writeCheckpoints(anchors) {
  var doc = { v: CHECKPOINT_FORMAT, anchors: anchors };
  b.atomicFile.writeSync(CHECKPOINT_FILE, JSON.stringify(doc), { fileMode: 0o600 });
}

function _liveChainTip() {
  return db().rawGet(
    "SELECT monotonicCounter, rowHash FROM audit_log WHERE monotonicCounter IS NOT NULL ORDER BY monotonicCounter DESC LIMIT 1"
  );
}

// Sign the current chain tip and append it to the checkpoint store. No-op when the
// chain is off, when there are no chained rows, or when the tip hasn't advanced past
// the last checkpoint (a same-counter checkpoint would break the strictly-increasing
// invariant verifyAnchorChain enforces).
async function checkpointNow(opts) {
  opts = opts || {};
  if (!config.auditChainEnabled && !opts.force) return { skipped: true, reason: "chain disabled" };
  var tip = _liveChainTip();
  if (!tip || tip.rowHash == null) return { skipped: true, reason: "no chained rows" };

  var anchors = _readCheckpoints();
  var prev = anchors.length ? anchors[anchors.length - 1] : null;
  if (prev && Number(tip.monotonicCounter) <= Number(prev.counter)) {
    return { skipped: true, reason: "tip has not advanced", counter: Number(tip.monotonicCounter) };
  }

  await _ensureSigning();
  var a = b.auditSign.anchor(
    { counter: Number(tip.monotonicCounter), tipHash: String(tip.rowHash), prevTipHash: prev ? prev.tipHash : null },
    { format: CHECKPOINT_FORMAT }
  );
  anchors.push(a);
  if (anchors.length > CHECKPOINT_MAX) anchors = anchors.slice(anchors.length - CHECKPOINT_MAX);
  _writeCheckpoints(anchors);
  return { ok: true, counter: a.counter, tipHash: a.tipHash };
}

// Verify every stored checkpoint's signature + linkage, then confirm the LATEST
// checkpoint still matches the live chain: the row at its counter must carry the
// signed tipHash (a rewrite changes it), and a missing row is only acceptable when
// it sits at/below the purge anchor (archived away) rather than silently deleted.
async function verifyCheckpoints() {
  var anchors = _readCheckpoints();
  if (!anchors.length) return { ok: true, checkpoints: 0, reason: "no checkpoints yet" };

  await _ensureSigning();
  var chainRes = b.auditSign.verifyAnchorChain(anchors);
  if (!chainRes.ok) {
    return { ok: false, checkpoints: anchors.length, breakAt: chainRes.breakAt, reason: chainRes.reason };
  }

  var latest = anchors[anchors.length - 1];
  var liveRow = db().rawGet("SELECT rowHash FROM audit_log WHERE monotonicCounter = ?", latest.counter);
  if (liveRow && liveRow.rowHash != null) {
    if (String(liveRow.rowHash) !== String(latest.tipHash)) {
      return { ok: false, checkpoints: anchors.length, counter: latest.counter,
        reason: "live row at the checkpointed counter no longer matches the signed tip hash (chain rewritten)" };
    }
  } else {
    var anchorRow = db().rawGet("SELECT lastPurgedCounter FROM _blamejs_audit_purge_anchor WHERE scope = 'audit'");
    var anchored = (anchorRow && anchorRow.lastPurgedCounter != null) ? Number(anchorRow.lastPurgedCounter) : -1;
    if (Number(latest.counter) > anchored) {
      return { ok: false, checkpoints: anchors.length, counter: latest.counter,
        reason: "the checkpointed row was deleted without being archived (chain truncated)" };
    }
  }
  return { ok: true, checkpoints: anchors.length, counter: latest.counter, tipHash: latest.tipHash };
}

// Scheduled checkpointing — first shortly after boot, then hourly. Gated on the
// chain being enabled; unref'd so it never holds the process open.
function startCheckpointing() {
  function tick() {
    if (!config.auditChainEnabled) return;
    checkpointNow().catch(function (e) {
      logger.error("[audit-archive] scheduled checkpoint failed", { err: e && e.message });
    });
  }
  setTimeout(tick, C.TIME.minutes(1));
  var timer = setInterval(tick, C.TIME.hours(1));
  if (timer.unref) timer.unref();
}

module.exports = {
  archiveNow: archiveNow,
  listArchives: listArchives,
  verifyArchive: verifyArchive,
  readArchiveEntries: readArchiveEntries,
  startAuditArchival: startAuditArchival,
  // Chain-purge serializer + never-lower anchor write, shared with retention.
  runExclusivePurge: runExclusivePurge,
  upsertPurgeAnchorNeverLower: upsertPurgeAnchorNeverLower,
  // Exposed for the anchor-race regression test (drives prune-after-retention).
  _pruneArchived: _pruneArchived,
  // PQC-signed chain checkpoints.
  checkpointNow: checkpointNow,
  verifyCheckpoints: verifyCheckpoints,
  startCheckpointing: startCheckpointing,
};
