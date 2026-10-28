/**
 * The in-place swap of a vault-key rotation, shared by scripts/vault-key-rotate.js
 * and the boot recovery in lib/vault.js.
 *
 * The rotation tool builds the rotated copy in DATA_DIR/.rotation-staging and
 * then writes DATA_DIR/.rotation-swap.json, which lists the top-level entries of
 * DATA_DIR ("live") and of the staging directory ("staged") and names the
 * directory the live entries move into (".rotation-old-<timestamp>"). The swap
 * moves every live entry into that directory and every staged entry into
 * DATA_DIR, one rename per entry. DATA_DIR itself is never renamed, so the swap
 * works when DATA_DIR is a mount point.
 *
 * Each step can be repeated after a crash. Where an entry is follows from the
 * filesystem: a live entry has moved once it exists in the old directory, and a
 * staged entry has moved once it is missing from the staging directory. Both
 * directions use that rule, so recovery needs no record of how far the tool got.
 *
 * Entries named in C.DATA_DIR_INTERNAL are never moved.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");
var b = require("./vendor/blamejs");
var C = require("./constants");

var NAMES = C.DATA_DIR_INTERNAL;
var MARKER_FORMAT = 2;

function isInternal(name) {
  return name === NAMES.ROTATION_STAGING ||
    name === NAMES.ROTATION_MARKER ||
    name.indexOf(NAMES.ROTATION_MARKER + ".") === 0 ||
    name.indexOf(NAMES.ROTATION_OLD_PREFIX) === 0 ||
    name === NAMES.SERVER_LEASE ||
    name.indexOf(NAMES.SERVER_LEASE + ".") === 0;
}

function _lexists(p) {
  try { nodeFs.lstatSync(p); return true; }
  catch (e) { if (e && e.code === "ENOENT") return false; throw e; }
}

function _fsyncDir(dir) {
  try { b.atomicFile.fsyncDir(dir); }
  catch (_e) { /* directory fsync is unsupported on Windows */ }
}

function _move(from, to) {
  b.atomicFile.renameWithRetry(from, to);
}

function listLive(dataDir) {
  return nodeFs.readdirSync(dataDir).filter(function (n) { return !isInternal(n); }).sort();
}

function oldDirName(isoTimestamp) {
  return NAMES.ROTATION_OLD_PREFIX + String(isoTimestamp).replace(/[:.]/g, "-");
}

function _assertEntryName(name, field) {
  if (typeof name !== "string" || name === "" || name === "." || name === ".." ||
      name.indexOf("/") !== -1 || name.indexOf("\\") !== -1 || name.indexOf("\0") !== -1 ||
      isInternal(name)) {
    throw new Error("rotation marker " + field + " holds an invalid entry name: " + JSON.stringify(name));
  }
}

function _validate(marker) {
  if (!marker || marker.format !== MARKER_FORMAT) {
    throw new Error("rotation marker has an unknown format");
  }
  if (marker.direction !== "forward" && marker.direction !== "backward") {
    throw new Error("rotation marker direction is neither forward nor backward");
  }
  if (typeof marker.oldDir !== "string" || marker.oldDir.indexOf(NAMES.ROTATION_OLD_PREFIX) !== 0 ||
      marker.oldDir.indexOf("/") !== -1 || marker.oldDir.indexOf("\\") !== -1 || marker.oldDir.indexOf("..") !== -1) {
    throw new Error("rotation marker oldDir is not a " + NAMES.ROTATION_OLD_PREFIX + "<timestamp> name");
  }
  if (!Array.isArray(marker.live) || !Array.isArray(marker.staged)) {
    throw new Error("rotation marker is missing its live or staged entry list");
  }
  marker.live.forEach(function (n) { _assertEntryName(n, "live"); });
  marker.staged.forEach(function (n) { _assertEntryName(n, "staged"); });
  return marker;
}

function markerPath(dataDir) { return nodePath.join(dataDir, NAMES.ROTATION_MARKER); }
function stagingPath(dataDir) { return nodePath.join(dataDir, NAMES.ROTATION_STAGING); }

function writeMarker(dataDir, marker) {
  _validate(marker);
  b.atomicFile.writeSync(markerPath(dataDir), JSON.stringify(marker, null, 2), { fileMode: 0o600 });
  _fsyncDir(dataDir);
}

function readMarker(dataDir) {
  var raw = nodeFs.readFileSync(markerPath(dataDir), "utf8");
  return _validate(b.safeJson.parse(raw, { maxBytes: b.constants.BYTES.mib(1) }));
}

function hasMarker(dataDir) { return _lexists(markerPath(dataDir)); }

/**
 * Build the marker for a swap of the staging directory into dataDir.
 */
function planSwap(dataDir, isoTimestamp) {
  return _validate({
    format: MARKER_FORMAT,
    startedAt: new Date().toISOString(),
    direction: "forward",
    oldDir: oldDirName(isoTimestamp),
    live: listLive(dataDir),
    staged: nodeFs.readdirSync(stagingPath(dataDir)).sort(),
  });
}

/**
 * Move every live entry into marker.oldDir and every staged entry into dataDir,
 * then remove the empty staging directory. The marker is left in place.
 */
function rollForward(dataDir, marker) {
  _validate(marker);
  var staging = stagingPath(dataDir);
  var oldDir = nodePath.join(dataDir, marker.oldDir);
  try { nodeFs.mkdirSync(oldDir, { mode: 0o700 }); }
  catch (e) { if (!e || e.code !== "EEXIST") throw e; }

  var live = Object.create(null);
  marker.live.forEach(function (n) { live[n] = true; });
  var staged = Object.create(null);
  marker.staged.forEach(function (n) { staged[n] = true; });
  var names = Object.keys(Object.assign(Object.create(null), live, staged)).sort();

  for (var i = 0; i < names.length; i++) {
    var n = names[i];
    var inData = nodePath.join(dataDir, n);
    if (live[n] && _lexists(inData) && !_lexists(nodePath.join(oldDir, n))) {
      _move(inData, nodePath.join(oldDir, n));
    }
    var inStaging = nodePath.join(staging, n);
    if (staged[n] && _lexists(inStaging)) {
      if (_lexists(inData)) {
        throw new Error(inData + " exists but is not an entry the rotation moved aside; " +
          "the staged " + n + " cannot be moved into place");
      }
      _move(inStaging, inData);
    }
  }
  _fsyncDir(oldDir);

  var missing = marker.staged.filter(function (n) { return !_lexists(nodePath.join(dataDir, n)); });
  if (missing.length > 0) {
    throw new Error("staged entries are missing from both " + staging + " and " + dataDir + ": " + missing.join(", "));
  }
  if (_lexists(staging)) {
    var left = nodeFs.readdirSync(staging);
    if (left.length > 0) {
      throw new Error(staging + " still holds entries the marker does not list: " + left.join(", "));
    }
    nodeFs.rmdirSync(staging);
  }
  _fsyncDir(dataDir);
}

/**
 * Undo rollForward: move every staged entry that reached dataDir back into the
 * staging directory, move every live entry back from marker.oldDir, remove the
 * empty old directory, clear the marker, and then delete the staging directory.
 *
 * A staged entry whose name is also live has reached dataDir only while the
 * live original is in the old directory, so it is moved back only then. Once
 * the original is back, the entry in dataDir is the original, and a repeated
 * rollBack leaves it alone.
 */
function rollBack(dataDir, marker) {
  _validate(marker);
  var staging = stagingPath(dataDir);
  var oldDir = nodePath.join(dataDir, marker.oldDir);
  var live = Object.create(null);
  marker.live.forEach(function (n) { live[n] = true; });

  for (var s = 0; s < marker.staged.length; s++) {
    var sn = marker.staged[s];
    var stagedAt = nodePath.join(staging, sn);
    var inData = nodePath.join(dataDir, sn);
    var arrived = live[sn] ? _lexists(nodePath.join(oldDir, sn)) : true;
    if (arrived && !_lexists(stagedAt) && _lexists(inData)) {
      try { nodeFs.mkdirSync(staging, { mode: 0o700 }); }
      catch (e) { if (!e || e.code !== "EEXIST") throw e; }
      _move(inData, stagedAt);
    }
  }
  for (var l = 0; l < marker.live.length; l++) {
    var ln = marker.live[l];
    var movedAside = nodePath.join(oldDir, ln);
    if (_lexists(movedAside)) {
      var back = nodePath.join(dataDir, ln);
      if (_lexists(back)) {
        throw new Error(back + " exists, so the original " + ln + " cannot be moved back from " + oldDir);
      }
      _move(movedAside, back);
    }
  }
  _fsyncDir(dataDir);
  if (_lexists(oldDir)) {
    var leftOld = nodeFs.readdirSync(oldDir);
    if (leftOld.length > 0) {
      throw new Error(oldDir + " still holds entries the marker does not list: " + leftOld.join(", "));
    }
    nodeFs.rmdirSync(oldDir);
  }
  // Every original is back. Without the marker, the staging directory is an
  // unfinished rotated copy, which boot recovery deletes if this deletion stops.
  clearMarker(dataDir);
  nodeFs.rmSync(staging, { recursive: true, force: true });
  _fsyncDir(dataDir);
}

function clearMarker(dataDir) {
  nodeFs.rmSync(markerPath(dataDir), { force: true });
  _fsyncDir(dataDir);
}

/**
 * Names of the .rotation-old-<timestamp> directories in dataDir.
 */
function listOldDirs(dataDir) {
  return nodeFs.readdirSync(dataDir).filter(function (n) {
    return n.indexOf(NAMES.ROTATION_OLD_PREFIX) === 0;
  }).sort();
}

module.exports = {
  isInternal: isInternal,
  listLive: listLive,
  listOldDirs: listOldDirs,
  oldDirName: oldDirName,
  markerPath: markerPath,
  stagingPath: stagingPath,
  planSwap: planSwap,
  writeMarker: writeMarker,
  readMarker: readMarker,
  hasMarker: hasMarker,
  rollForward: rollForward,
  rollBack: rollBack,
  clearMarker: clearMarker,
};
