// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.publicSuffix
 * @nav        Validation
 * @title      Public Suffix
 * @order      140
 * @card       Mozilla Public Suffix List substrate — exposes
 *             `b.publicSuffix.publicSuffix(domain)` /
 *             `b.publicSuffix.organizationalDomain(domain)` /
 *             `b.publicSuffix.isPublicSuffix(domain)` for the
 *             "registrable domain" derivation that DMARCbis,
 *             BIMI, cookie-scope, and same-site policies all need.
 *
 * @intro
 *   The Public Suffix List (PSL) is Mozilla's published catalog of
 *   "effective top-level domains" — labels under which independent
 *   parties can register names (`com`, `co.uk`, `s3.amazonaws.com`,
 *   …). It is the canonical reference for deriving the
 *   "organizational domain" of a hostname: the registrable label one
 *   level below its public suffix. Several upstream specs lean on it
 *   directly:
 *
 *     - RFC 9989 (DMARC) replaces RFC 7489's heuristic
 *       organizational-domain derivation with a PSL lookup, including
 *       the `psd=` (public-suffix-domain policy) and `np=`
 *       (non-public-suffix policy) tags
 *     - BIMI (draft-blank-ietf-bimi) uses the same organizational-domain
 *       logic to scope brand indicators
 *     - Same-site cookie scoping (RFC 6265bis) refers to the PSL when
 *       deciding whether `Domain=co.uk` is a "public suffix" attempt
 *
 *   This module ships the PSL as a vendored data file
 *   (`lib/vendor/public-suffix-list.dat`) and parses it once at
 *   module-load. The algorithm is the canonical one published at
 *   https://publicsuffix.org/list/: an exception rule outranks every
 *   other match, and otherwise the matching rule with the MOST LABELS
 *   prevails whether it is exact or a wildcard. Ranking by kind instead
 *   would hand `x.kawasaki.jp` to `jp` rather than to
 *   `*.kawasaki.jp`.
 *
 *   Surface:
 *
 *     b.publicSuffix.publicSuffix("example.co.uk")
 *       // → "co.uk"
 *
 *     b.publicSuffix.organizationalDomain("foo.bar.example.co.uk")
 *       // → "example.co.uk"
 *
 *     b.publicSuffix.isPublicSuffix("co.uk")
 *       // → true
 *
 *     b.publicSuffix.lookupSource()
 *       // → { vendoredAt: "2026-05-09", entries: <n>, sha256: "..." }
 *
 *   IDN inputs are punycode-normalized via Node's `url.domainToASCII`
 *   before lookup. Bad inputs throw `PublicSuffixError`.
 */

var nodeUrl  = require("node:url");
var lazyRequire = require("./lazy-require");
var codepointClass = require("./codepoint-class");
// guard-domain owns the ACE-label rule. Deferred because the guard family
// pulls the gate contract, which this module sits below in the load order.
var guardDomain = lazyRequire(function () { return require("./guard-domain"); });
var vendorData = require("./vendor-data");
var pslDataModule = require("./vendor/public-suffix-list.data");
var { PublicSuffixError } = require("./framework-error");

function _err(code, message) {
  return new PublicSuffixError(code, message);
}

function _firstNonHostCharacter(name) {
  for (var i = 0; i < name.length; i += 1) {
    var cp = name.charCodeAt(i);
    if (cp < 0x21 || cp === 0x7f ||
        cp === 0x2f || cp === 0x3f || cp === 0x23 || cp === 0x5c ||
        cp === 0x3a || cp === 0x40 || cp === 0x5b || cp === 0x5d) {
      return i;
    }
  }
  return -1;
}

var _DOMAIN_CHARS = codepointClass.ASCII_ALNUM + "-._";

function _isLdhDomain(ascii) {
  return codepointClass.isRunOf(ascii, _DOMAIN_CHARS, 1, ascii.length);
}

function _isRootMarker(ch) {
  return ch === "." || ch === "。" || ch === "．" || ch === "｡";
}

function _normalizeInput(domain) {
  if (typeof domain !== "string") {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain must be a string");
  }
  if (domain.length === 0) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain must not be empty");
  }
  var s = domain.toLowerCase();
  var rootStripped = false;
  if (_isRootMarker(s.charAt(s.length - 1))) {
    s = s.slice(0, -1);
    rootStripped = true;
    if (s.length === 0) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain must not be a bare dot");
    }
  }
  if (s.length > 253) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain exceeds 253-octet RFC 1035 limit");
  }
  if (_firstNonHostCharacter(s) !== -1) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains a control byte or URL delimiter");
  }
  var ascii = nodeUrl.domainToASCII(s);
  if (!ascii) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain failed IDN normalization");
  }
  if (ascii.indexOf("..") !== -1 || ascii.charCodeAt(0) === 46) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains empty label");
  }
  if (!_isLdhDomain(ascii)) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain contains a character that is not a letter, digit, " +
      "hyphen, dot or underscore; domainToASCII MAPS such a name without " +
      "validating it as a host, so `ex*ample.com` arrives here looking canonical");
  }
  if (!guardDomain().aceLabelsCarryPayload(ascii)) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain carries an `xn--` label with no Punycode payload; " +
      "domainToASCII returns such a label unchanged on some Node versions and " +
      "the empty string on others, so the mapper's output is not the verdict");
  }
  var withoutRoot = ascii.charCodeAt(ascii.length - 1) === 46
    ? ascii.length - 1 : ascii.length;
  if (withoutRoot > 253) {
    throw _err("public-suffix/invalid-domain",
      "publicSuffix: domain exceeds 253-octet RFC 1035 limit once converted " +
      "to A-labels (" + withoutRoot + " octets)");
  }
  var labelSpan = ascii.slice(0, withoutRoot);
  var labels = labelSpan.split(".");
  for (var li = 0; li < labels.length; li += 1) {
    if (labels[li].length > 63) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: label " + JSON.stringify(labels[li].slice(0, 16) + "...") +
        " is " + labels[li].length + " octets once converted to an A-label, over " +
        "the 63-octet RFC 1035 limit");
    }
  }
  if (ascii.charCodeAt(ascii.length - 1) === 46 ) {
    if (rootStripped) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain contains empty label");
    }
    ascii = ascii.slice(0, -1);
    if (ascii.length === 0) {
      throw _err("public-suffix/invalid-domain",
        "publicSuffix: domain must not be a bare dot");
    }
  }
  return ascii;
}

function _parsePsl(text) {
  var exact     = Object.create(null);
  var wildcard  = Object.create(null);
  var exception = Object.create(null);
  var lines = text.split(/\r?\n/);
  var entries = 0;

  for (var i = 0; i < lines.length; i += 1) {
    var line = lines[i];
    if (!line) continue;
    var sp = line.indexOf(" ");
    if (sp !== -1) line = line.slice(0, sp);
    if (!line) continue;
    if (line.charCodeAt(0) === 47  &&
        line.charCodeAt(1) === 47) continue;

    var rule = line.toLowerCase();
    var asciiRule = nodeUrl.domainToASCII(rule);
    if (!asciiRule) continue;

    if (asciiRule.charCodeAt(0) === 33 ) {
      exception[asciiRule.slice(1)] = true;
    } else if (asciiRule.charCodeAt(0) === 42  &&
               asciiRule.charCodeAt(1) === 46 ) {
      wildcard[asciiRule.slice(2)] = true;
    } else {
      exact[asciiRule] = true;
    }
    entries += 1;
  }

  return { exact: exact, wildcard: wildcard, exception: exception, entries: entries };
}

var _data;
var _sourceMeta;
(function _init() {
  var raw;
  try {
    raw = vendorData.get("public-suffix-list");
  } catch (e) {
    throw _err("public-suffix/not-loaded",
      "publicSuffix: vendored PSL data not loadable via b.vendorData " +
      "(" + (e && e.message ? e.message : "unknown error") + ")");
  }
  var parsed = _parsePsl(raw.toString("utf8"));
  _data = parsed;
  var meta = pslDataModule.metadata;
  _sourceMeta = Object.freeze({
    vendoredAt: meta.fetchedAt,
    entries: parsed.entries,
    sha256: meta.sha256,
    signedBy: meta.publicKeyFingerprint,
  });
})();

function _lookupAscii(ascii) {
  var labels = ascii.split(".");

  var exceptionMatch = null;
  var exactMatch     = null;
  var wildcardMatch  = null;

  for (var i = 0; i < labels.length; i += 1) {
    var candidate = labels.slice(i).join(".");
    if (_data.exception[candidate]) {
      var parentLabels = labels.slice(i + 1);
      if (parentLabels.length > 0) {
        exceptionMatch = parentLabels.join(".");
      } else {
        exceptionMatch = "";
      }
      break;
    }
    if (!exactMatch && _data.exact[candidate]) {
      exactMatch = candidate;
    }
    if (!wildcardMatch && i > 0) {
      if (_data.wildcard[candidate]) {
        wildcardMatch = labels.slice(i - 1).join(".");
      }
    }
  }

  if (exceptionMatch !== null) return exceptionMatch === "" ? null : exceptionMatch;
  if (exactMatch !== null && wildcardMatch !== null) {
    return wildcardMatch.split(".").length > exactMatch.split(".").length
      ? wildcardMatch
      : exactMatch;
  }
  if (exactMatch    !== null) return exactMatch;
  if (wildcardMatch !== null) return wildcardMatch;
  if (labels.length >= 2) return labels[labels.length - 1];
  return null;
}

/**
 * @primitive b.publicSuffix.publicSuffix
 * @signature b.publicSuffix.publicSuffix(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.organizationalDomain, b.publicSuffix.isPublicSuffix
 *
 * Returns the longest matching public suffix for `domain`, per the
 * Mozilla PSL algorithm (https://publicsuffix.org/list/). An exception
 * rule outranks every other match; otherwise the matching rule with
 * the most labels prevails, whether it is exact or a wildcard, and the
 * implicit "*" rule applies when nothing matches. So `x.kawasaki.jp`
 * resolves to itself under `*.kawasaki.jp` rather than to `jp`. Input
 * is lowercased and IDN-normalized (punycode) before lookup. Returns
 * `null` for inputs that have no registrable parent (single-label
 * TLDs, public-suffix-only inputs).
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) for
 * non-string / empty / overlong / control-byte-bearing inputs.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.publicSuffix("example.co.uk");
 *   // → "co.uk"
 *   b.publicSuffix.publicSuffix("foo.bar.example.com");
 *   // → "com"
 */
function publicSuffix(domain) {
  var ascii = _normalizeInput(domain);
  return _lookupAscii(ascii);
}

/**
 * @primitive b.publicSuffix.organizationalDomain
 * @signature b.publicSuffix.organizationalDomain(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix, b.publicSuffix.isPublicSuffix
 *
 * Returns the registrable "organizational domain" — the public
 * suffix plus exactly one label to its left. This is the value
 * DMARCbis, BIMI, and cookie-scope policies operate on when they
 * decide whether two hostnames belong to the same registered party.
 *
 * Returns `null` when `domain` IS a public suffix (no organizational
 * parent exists — `co.uk` has no registrable owner, only the labels
 * registered under it do).
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) on bad
 * input shape.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.organizationalDomain("foo.bar.example.co.uk");
 *   // → "example.co.uk"
 *   b.publicSuffix.organizationalDomain("example.com");
 *   // → "example.com"
 *   b.publicSuffix.organizationalDomain("co.uk");
 *   // → null
 */
function organizationalDomain(domain) {
  var ascii = _normalizeInput(domain);
  var suffix = _lookupAscii(ascii);
  if (suffix === null) return null;
  if (suffix === ascii) return null;
  var suffixLabels = suffix.split(".").length;
  var labels = ascii.split(".");
  if (labels.length <= suffixLabels) return null;
  return labels.slice(labels.length - suffixLabels - 1).join(".");
}

/**
 * @primitive b.publicSuffix.isPublicSuffix
 * @signature b.publicSuffix.isPublicSuffix(domain)
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix, b.publicSuffix.organizationalDomain
 *
 * Returns `true` when `domain` is itself a public suffix (e.g.
 * `"co.uk"`, `"com"`, `"s3.amazonaws.com"`), `false` otherwise.
 * DMARCbis uses this distinction for its `psd=` (public-suffix-
 * domain) policy: a TLD operator publishing a record on `co.uk`
 * itself is a different actor than `example.co.uk` publishing one.
 *
 * Throws `PublicSuffixError` (`public-suffix/invalid-domain`) on bad
 * input shape.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.isPublicSuffix("co.uk");
 *   // → true
 *   b.publicSuffix.isPublicSuffix("example.co.uk");
 *   // → false
 */
function isPublicSuffix(domain) {
  var ascii = _normalizeInput(domain);
  var suffix = _lookupAscii(ascii);
  return suffix !== null && suffix === ascii;
}

/**
 * @primitive b.publicSuffix.lookupSource
 * @signature b.publicSuffix.lookupSource()
 * @since     0.8.53
 * @status    stable
 * @related   b.publicSuffix.publicSuffix
 *
 * Returns transparency metadata for the loaded PSL: the date the
 * file was vendored (`vendoredAt`, ISO 8601 from
 * `lib/vendor/MANIFEST.json`), the parsed-rule count (`entries`),
 * and the SHA-256 hash of the raw file contents (`sha256`, hex). Use
 * to surface in operator dashboards / forensic logs so a snapshot of
 * the PSL the framework was making decisions against is reproducible
 * after the fact.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var src = b.publicSuffix.lookupSource();
 *   // → { vendoredAt: "2026-05-09", entries: 9000, sha256: "a008..." }
 */
function lookupSource() {
  return _sourceMeta;
}

/**
 * @primitive b.publicSuffix.canonicalDomain
 * @signature b.publicSuffix.canonicalDomain(domain)
 * @since     0.15.50
 * @status    stable
 * @related   b.publicSuffix.organizationalDomain, b.publicSuffix.publicSuffix
 *
 * Returns the bare canonical host form of `domain` for identity
 * comparison: lowercase, a single trailing dot stripped, and IDN
 * labels normalized to their A-label (punycode) form. Unlike
 * `organizationalDomain` it does NOT walk the public-suffix list — it
 * returns the input host itself in canonical form.
 *
 * Two values that denote the same host in different encodings (case,
 * trailing dot, U-label vs A-label) return the SAME string, so an
 * equality compare is encoding-stable — the building block for DMARC
 * alignment and certificate SAN-vs-domain authorization checks, where
 * one side normalizing differently from the other is a bypass.
 *
 * Non-throwing: returns `""` for any input that is not a valid host
 * (control bytes, empty labels, over the 253-octet limit), so a
 * hostile or garbage value canonicalizes to `""` and matches nothing.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.publicSuffix.canonicalDomain("Example.COM.");   // → "example.com"
 *   b.publicSuffix.canonicalDomain("a..b");             // → ""
 */
function canonicalDomain(domain) {
  try { return _normalizeInput(domain); } catch (_e) { return ""; }
}

module.exports = {
  publicSuffix:         publicSuffix,
  organizationalDomain: organizationalDomain,
  canonicalDomain:      canonicalDomain,
  isPublicSuffix:       isPublicSuffix,
  lookupSource:         lookupSource,
  _firstNonHostCharacter: _firstNonHostCharacter,
  _isRootMarker:          _isRootMarker,
};
