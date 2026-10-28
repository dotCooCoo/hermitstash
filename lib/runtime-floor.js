/**
 * The runtime versions HermitStash starts on. server.js calls check() before it
 * loads anything else, so this module requires nothing.
 *
 * Node.js: 24.22.1 or later on the 24 line, 26.12.1 or later on the 26 line,
 * or 27 and later. Those releases carry the OpenSSL 3.5 post-quantum bindings
 * (ML-KEM-1024, SLH-DSA-SHAKE-256f, ML-DSA-87), the TLS 1.3 no-cert resumption
 * fix from 24.21.0, and the patched bundled Brotli decoder (CVE-2026-111497).
 * Odd-numbered lines and lines before 24 are refused.
 *
 * Brotli: a Node built against the system Brotli library (node_shared_brotli,
 * as in the container image) does not use the bundled decoder, so the library
 * itself must be 1.2.1 or later. The bundled decoder keeps reporting 1.2.0
 * after its patch, so the library version is checked only on such a build.
 *
 * OpenSSL: 3.5.9, 3.6.5 or 4.0.3 or later on those lines, or 4.1 and later
 * (CVE-2026-35189: a crafted peer certificate makes an older OpenSSL allocate
 * hundreds of MiB during the handshake). Lines before 3.5 have no ML-KEM and
 * are refused.
 */
"use strict";

var VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(\S*)/;

// Negative, zero or positive as "major.minor.patch" a sorts before, with or
// after b.
function compareParts(a, b) {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

function parts(m) {
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

// true when version is below the floor "major.minor.patch". A version that does
// not parse, or a prerelease at the floor itself (24.22.1-pre, 3.5.9-dev),
// counts as below.
function below(version, floor) {
  var m = VERSION_RE.exec(String(version || ""));
  if (!m) return true;
  var order = compareParts(parts(m), parts(VERSION_RE.exec(floor)));
  if (order !== 0) return order < 0;
  return /^-/.test(m[4]);
}

// Floor per Node.js release line; a later line than every key is accepted
// from its first release.
var NODE_FLOORS = { "24": "24.22.1", "26": "26.12.1" };
var NODE_OPEN_FROM = "27.0.0";

function nodeFloor(version) {
  var major = String(version || "").split(".")[0];
  if (Object.prototype.hasOwnProperty.call(NODE_FLOORS, major)) return NODE_FLOORS[major];
  return below(major + ".0.0", NODE_OPEN_FROM) ? null : NODE_OPEN_FROM;
}

// Floor per OpenSSL release line; lines after 3.6 and before 4.0 have no
// patch floor, and 4.1 and later are accepted.
var OPENSSL_FLOORS = { "3.5": "3.5.9", "3.6": "3.6.5", "4.0": "4.0.3" };

function opensslFloor(version) {
  var m = VERSION_RE.exec(String(version || ""));
  if (!m) return null;
  var line = m[1] + "." + m[2];
  if (Object.prototype.hasOwnProperty.call(OPENSSL_FLOORS, line)) return OPENSSL_FLOORS[line];
  if (!below(version, "4.1.0")) return "4.1.0";
  if (!below(version, "3.7.0") && below(version, "4.0.0")) return line + ".0";
  return null;
}

/**
 * @param {{ versions: object, config?: object }} proc - process, or a stand-in
 * @returns {string[]|null} the lines of a FATAL message, or null when supported
 */
function check(proc) {
  var versions = proc.versions || {};
  var node = versions.node;
  var nf = nodeFloor(node);
  if (!nf || below(node, nf)) {
    return [
      "FATAL: HermitStash requires Node.js 24.22.1 or later on the 24 line, 26.12.1 or later on the 26 line,",
      "  or 27 and later (found v" + node + "). Earlier releases on those lines carry the Brotli decoder",
      "  flaw CVE-2026-111497, and other lines are not supported. Upgrade Node and re-run.",
      "  Install: https://nodejs.org/  |  Linux/systemd: deploy/install.sh",
    ];
  }
  var shared = proc.config && proc.config.variables && proc.config.variables.node_shared_brotli;
  if ((shared === true || shared === "true") && below(versions.brotli, "1.2.1")) {
    return [
      "FATAL: this Node.js uses the system Brotli library " + versions.brotli + ", which is affected by",
      "  CVE-2026-111497. Upgrade the Brotli library (libbrotlidec) to 1.2.1 or newer and re-run.",
    ];
  }
  var openssl = String(versions.openssl || "").replace(/^OpenSSL\s+/i, "");
  var of = opensslFloor(openssl);
  if (!of || below(openssl, of)) {
    return [
      "FATAL: HermitStash requires OpenSSL 3.5.9, 3.6.5 or 4.0.3 or later on those lines, or 4.1 and later",
      "  (this Node.js uses OpenSSL " + (openssl || "unknown") + "). Older releases are affected by CVE-2026-35189,",
      "  and lines before 3.5 have no ML-KEM. Upgrade Node.js, or the system OpenSSL it is built against.",
    ];
  }
  return null;
}

module.exports = { check: check, below: below };
