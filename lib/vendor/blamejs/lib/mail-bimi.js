"use strict";
/**
 * BIMI — Brand Indicators for Message Identification (RFC 9091).
 *
 * BIMI records publish a sender's brand logo URL in DNS so receiving
 * MTAs can render it next to the message in supported clients
 * (Gmail, Yahoo, Apple Mail). The record format is:
 *
 *   default._bimi.<domain>  IN  TXT  "v=BIMI1; l=https://...; a=https://..."
 *
 * - `l=` URL to the SVG logo file (Tiny PS Profile per RFC 9091 §5)
 * - `a=` URL to the Verified Mark Certificate (VMC) — RFC 9091 §6
 *
 * BIMI is layered on a passing DMARC posture (the receiver requires
 * DMARC to be at quarantine or reject). No-op for senders without
 * DMARC enforcement.
 *
 * Surface:
 *   b.mail.bimi.recordShape({ logoUrl, vmcUrl?, selector? })  → string
 *   b.mail.bimi.fetchPolicy(domain, opts?)                    → { v, l, a } | null
 *   b.mail.bimi.parseRecord(text)                             → { v, l, a } | null
 *
 * The framework does NOT validate the SVG / VMC contents against the
 * RFC 9091 §5/§6 profiles — operators feed those to their own asset
 * pipeline. The fetch primitive is a thin DNS lookup that returns
 * the structured record so an operator dashboard or SMTP send-time
 * preflight can verify the publication.
 */

var dns = require("node:dns");
var dnsPromises = dns.promises;
var validateOpts = require("./validate-opts");
var safeUrl = require("./safe-url");
var C = require("./constants");
var { defineClass } = require("./framework-error");

var BimiError = defineClass("BimiError", { alwaysPermanent: true });

var BIMI_VERSION = "BIMI1";
var BIMI_DEFAULT_SELECTOR = "default";
var BIMI_RECORD_MAX_BYTES = C.BYTES.kib(2);

function _validateUrl(url, label) {
  // RFC 9091 §4.2 — `l=` and `a=` MUST be HTTPS URLs.
  try {
    safeUrl.parse(url, { allowedProtocols: ["https:"] });
  } catch (e) {
    throw new BimiError("mail-bimi/bad-" + label,
      "bimi: " + label + " must be an https:// URL — got '" + url + "': " +
      ((e && e.message) || String(e)));
  }
}

function recordShape(opts) {
  validateOpts.requireObject(opts, "bimi.recordShape", BimiError);
  validateOpts(opts, ["logoUrl", "vmcUrl", "selector"], "bimi.recordShape");
  validateOpts.requireNonEmptyString(opts.logoUrl,
    "bimi.recordShape: logoUrl", BimiError, "mail-bimi/no-logo");
  _validateUrl(opts.logoUrl, "logoUrl");
  if (opts.vmcUrl !== undefined && opts.vmcUrl !== null) {
    validateOpts.requireNonEmptyString(opts.vmcUrl,
      "bimi.recordShape: vmcUrl", BimiError, "mail-bimi/bad-vmc");
    _validateUrl(opts.vmcUrl, "vmcUrl");
  }
  // No CR/LF/NUL/semicolon — defense-in-depth so a hostile URL can't
  // inject a record-separator sequence into the published TXT.
  if (/[\r\n\0;]/.test(opts.logoUrl)) {
    throw new BimiError("mail-bimi/bad-logo",
      "bimi.recordShape: logoUrl contains forbidden control / record-separator characters");
  }
  if (opts.vmcUrl && /[\r\n\0;]/.test(opts.vmcUrl)) {
    throw new BimiError("mail-bimi/bad-vmc",
      "bimi.recordShape: vmcUrl contains forbidden control / record-separator characters");
  }

  var fields = ["v=" + BIMI_VERSION, "l=" + opts.logoUrl];
  if (opts.vmcUrl) fields.push("a=" + opts.vmcUrl);
  return fields.join("; ");
}

function parseRecord(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  if (text.length > BIMI_RECORD_MAX_BYTES) return null;                          // bound BEFORE parse — TXT-record sanity cap
  // RFC 9091 §4 — semicolon-separated, key=value, leading "v=BIMI1".
  var parts = text.split(";");
  var rv = { v: null, l: null, a: null };
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var k = p.slice(0, eq).trim().toLowerCase();
    var v = p.slice(eq + 1).trim();
    if (k === "v" || k === "l" || k === "a") rv[k] = v;
  }
  if (rv.v !== BIMI_VERSION || !rv.l) return null;
  return rv;
}

async function fetchPolicy(domain, opts) {
  validateOpts.requireNonEmptyString(domain,
    "bimi.fetchPolicy: domain", BimiError, "mail-bimi/bad-domain");
  opts = opts || {};
  var selector = opts.selector || BIMI_DEFAULT_SELECTOR;
  var qname = selector + "._bimi." + domain;
  var records;
  try {
    if (opts.dnsLookup) records = await opts.dnsLookup(qname, "TXT");
    else records = await dnsPromises.resolveTxt(qname);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new BimiError("mail-bimi/lookup-failed",
      "bimi.fetchPolicy: TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  // RFC 9091 §4.1 — a TXT lookup may return multiple chunks; pick
  // the first record that begins with v=BIMI1.
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    var parsed = parseRecord(s);
    if (parsed) return parsed;
  }
  return null;
}

module.exports = {
  recordShape:  recordShape,
  parseRecord:  parseRecord,
  fetchPolicy:  fetchPolicy,
  BIMI_VERSION: BIMI_VERSION,
  BimiError:    BimiError,
};
