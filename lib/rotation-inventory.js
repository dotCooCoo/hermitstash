/**
 * This module lists what a vault-key rotation carries into the rotated copy of
 * the data directory unchanged.
 *
 * scripts/vault-key-rotate.js builds the rotated copy with b.vaultRotate.rotate
 * and then renames it into place of the data directory, so anything the copy
 * does not contain stays behind in the old directory. The copy receives every
 * file, directory and symbolic link under the data directory except:
 *   - the files b.vaultRotate.rotate writes itself (the encrypted database, the
 *     sealed database key, the vault key, every additionalSealed file, and the
 *     derived-hash salt and MAC key), and
 *   - transient files: locks, atomic-write temp files, the pending markers of
 *     the passphrase tools, and a plaintext working database, which sits in the
 *     data directory only when no tmpfs is configured.
 *
 * A directory is copied whole unless something below it is a symbolic link.
 * b.atomicFile.copyDirRecursive skips symbolic links, so such a directory is
 * listed file by file, and its symbolic links are returned for recreateSymlinks
 * to write into the rotated copy. A re-sealed file inside a directory copied
 * whole is replaced when b.vaultRotate.rotate writes the re-sealed version.
 * A link at a rewritten path is not carried, and a linked directory that holds
 * a rewritten file is listed file by file into a real directory.
 */
var nodeFs = require("node:fs");
var nodePath = require("node:path");

// b.vaultRotate.rotate writes these into the rotated copy itself, in addition
// to the paths the caller names.
var FRAMEWORK_WRITTEN = ["vault.derived-hash-salt", "vault.derived-hash-mac.sealed"];

var TRANSIENT_RE = /(?:\.lock|\.tmp|\.tmp-[A-Za-z0-9_-]+|\.migration-pending|\.unseal-pending)$/;
var WORKING_DB_RE = /^hermitstash-.+\.db(?:-wal|-shm|\.owner)?$/;
// File names on ext4, XFS, Btrfs and NTFS are at most 255 UTF-16 code units
// long, which is what String length counts.
var NAME_MAX = 255;

function _slash(p) { return String(p).split(nodePath.sep).join("/"); }

/**
 * @param {string} dataDir - the data directory being rotated
 * @param {object} paths - the b.vaultRotate.rotate `paths` option, without
 *   verbatimFiles and verbatimDirs
 * @returns {{ verbatimFiles: object[], verbatimDirs: object[],
 *   symlinks: { relativePath: string, target: string }[] }}
 */
function carriedEntries(dataDir, paths) {
  var written = Object.create(null);
  [paths.encryptedDb, paths.dbKeySealed, paths.vaultKeyPlain, paths.vaultKeySealed]
    .concat(FRAMEWORK_WRITTEN)
    .concat((paths.additionalSealed || []).map(function (e) { return e.relativePath; }))
    .forEach(function (p) { if (p) written[_slash(p)] = true; });

  var out = { verbatimFiles: [], verbatimDirs: [], symlinks: [] };

  function isTransient(relPath, name) {
    if (name.length > NAME_MAX) return false;
    if (TRANSIENT_RE.test(name)) return true;
    return relPath.indexOf("/") === -1 && WORKING_DB_RE.test(name);
  }

  function holdsSymlink(relDir) {
    var entries = nodeFs.readdirSync(nodePath.join(dataDir, relDir), { withFileTypes: true });
    return entries.some(function (ent) {
      if (ent.isSymbolicLink()) return true;
      return ent.isDirectory() && holdsSymlink(relDir + "/" + ent.name);
    });
  }

  function holdsWritten(relDir) {
    var prefix = relDir + "/";
    return Object.keys(written).some(function (w) { return w.indexOf(prefix) === 0; });
  }

  function isLinkedDirectory(rel) {
    try { return nodeFs.statSync(nodePath.join(dataDir, rel)).isDirectory(); }
    catch (_e) { return false; }   // a dangling link is carried as a link
  }

  function visit(relDir) {
    var abs = relDir ? nodePath.join(dataDir, relDir) : dataDir;
    nodeFs.readdirSync(abs, { withFileTypes: true }).forEach(function (ent) {
      var rel = relDir ? relDir + "/" + ent.name : ent.name;
      // b.vaultRotate.rotate writes a regular file at a rewritten path, so a
      // link there is not recreated.
      if (written[rel] || isTransient(rel, ent.name)) return;
      if (ent.isSymbolicLink()) {
        // A linked directory that holds a rewritten file becomes a real
        // directory in the rotated copy, because b.vaultRotate.rotate writes
        // the re-sealed file inside it.
        if (holdsWritten(rel) && isLinkedDirectory(rel)) visit(rel);
        else out.symlinks.push({ relativePath: rel, target: nodeFs.readlinkSync(nodePath.join(dataDir, rel)) });
      } else if (ent.isDirectory()) {
        if (holdsSymlink(rel)) visit(rel);
        else out.verbatimDirs.push({ relativePath: rel, required: false });
      } else if (ent.isFile()) {
        out.verbatimFiles.push({ relativePath: rel, required: false });
      }
    });
  }

  visit("");
  return out;
}

/**
 * recreateSymlinks writes each symbolic link that carriedEntries returned into
 * the rotated copy, with the same target string.
 *
 * @param {string} stagingDir - the rotated copy
 * @param {{ relativePath: string, target: string }[]} symlinks
 */
function recreateSymlinks(stagingDir, symlinks) {
  (symlinks || []).forEach(function (s) {
    var dest = nodePath.join(stagingDir, s.relativePath);
    nodeFs.mkdirSync(nodePath.dirname(dest), { recursive: true, mode: 0o700 });
    nodeFs.symlinkSync(s.target, dest);
  });
}

module.exports = { carriedEntries: carriedEntries, recreateSymlinks: recreateSymlinks };
