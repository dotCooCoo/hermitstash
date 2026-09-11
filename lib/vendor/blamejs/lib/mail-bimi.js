// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.mail.bimi
 * @nav    Mail
 * @title  BIMI
 *
 * @intro
 *   Brand Indicators for Message Identification (draft-blank-ietf-bimi). BIMI
 *   records publish a sender's brand-logo URL in DNS so receiving
 *   MTAs can render it next to the message in supported clients
 *   (Gmail, Yahoo, Apple Mail). The TXT record format is:
 *
 *     default._bimi.<domain>  IN  TXT  "v=BIMI1; l=https://...; a=https://..."
 *
 *   - `l=` URL to the SVG logo file (Tiny PS Profile per draft-blank-ietf-bimi)
 *   - `a=` URL to the Verified Mark Certificate (VMC / CMC) — §6
 *
 *   BIMI is layered on a passing DMARC posture (the receiver requires
 *   DMARC at quarantine or reject). No-op for senders without DMARC
 *   enforcement.
 *
 *   Surface:
 *
 *     b.mail.bimi.recordShape({ logoUrl, vmcUrl?, selector? })  -> string
 *     b.mail.bimi.fetchPolicy(domain, opts?)                    -> record | null
 *     b.mail.bimi.parseRecord(text)                             -> record | null
 *     b.mail.bimi.fetchAndVerifyMark({ domain, vmcUrl, ... })   -> verified mark
 *     b.mail.bimi.validateTinyPsSvg(svgBytes)                   -> { ok, violations }
 *
 *   `fetchAndVerifyMark` fetches a VMC / CMC over HTTPS via b.httpClient,
 *   parses it as X.509, validates the chain against the BIMI Group
 *   trust anchors (vendored at lib/vendor/bimi-trust-anchors.pem,
 *   operator-overridable via `trustAnchorsPem`), confirms the cert's
 *   subjectAltName URI matches the BIMI domain, and confirms the
 *   cert carries the BIMI mark-verification policy OID
 *   (1.3.6.1.5.5.7.3.31). The verified mark is returned as
 *   { svg, evidenceDocument } — `svg` pulled from the RFC 3709
 *   logotype extension when present, `evidenceDocument` echoed from the
 *   operator-supplied opts.evidenceDocument.
 *
 *   `validateTinyPsSvg` enforces the AuthIndicators-WG Tiny PS subset:
 *   single root <svg>, version="1.2", baseProfile="tiny-ps", viewBox
 *   present, no script / style / foreignObject / animate / filter /
 *   image, no external href / xlink:href references (only #fragment
 *   permitted), bounded byte size (32 KiB cap).
 *
 * @card
 *   BIMI (draft-blank-ietf-bimi) policy lookup, VMC + CMC fetch + chain validation, and Tiny-PS SVG profile enforcement for inbox brand-mark rendering.
 */

var nodeCrypto = require("node:crypto");

var asn1 = require("./asn1-der");
var C = require("./constants");
var codepointClass = require("./codepoint-class");
var pick = require("./pick");
var httpClient = require("./http-client");
var lazyRequire = require("./lazy-require");
var networkDnsResolver = lazyRequire(function () { return require("./network-dns-resolver"); });
var safeBuffer = require("./safe-buffer");
var markupTokenizer = require("./markup-tokenizer");
var x509Chain = require("./x509-chain");
var structuredFields = require("./structured-fields");
var safeUrl = require("./safe-url");
var publicSuffix = require("./public-suffix");
var validateOpts = require("./validate-opts");
var { defineClass, MailBimiError } = require("./framework-error");

// Audit emitter — lazy to avoid pulling the audit dispatcher into the
// module load graph until the first verify call. fetchAndVerifyMark is
// the only path that emits.
var audit = lazyRequire(function () { return require("./audit"); });

var BimiError = defineClass("BimiError", { alwaysPermanent: true });

var BIMI_VERSION = "BIMI1";
var BIMI_DEFAULT_SELECTOR = "default";
var BIMI_RECORD_MAX_BYTES = C.BYTES.kib(2);

var TINY_PS_MAX_BYTES = C.BYTES.kib(32);

var SVG_NAMESPACE = "http://www.w3.org/2000/svg";

var NCNAME_START_RANGES = [
  [0x41, 0x5A], 0x5F, [0x61, 0x7A],
  [0xC0, 0xD6], [0xD8, 0xF6], [0xF8, 0x2FF],
  [0x370, 0x37D], [0x37F, 0x1FFF],
  [0x200C, 0x200D], [0x2070, 0x218F], [0x2C00, 0x2FEF],
  [0x3001, 0xD7FF], [0xF900, 0xFDCF], [0xFDF0, 0xFFFD],
  [0x10000, 0xEFFFF],
];

var NCNAME_TAIL_RANGES = [
  0x2D, 0x2E, [0x30, 0x39], 0xB7, [0x300, 0x36F], [0x203F, 0x2040],
];

function _isNcName(s) {
  if (s.length === 0) return false;
  var started = false;
  for (var i = 0; i < s.length; ) {
    var cp = s.codePointAt(i);
    i += cp > 0xFFFF ? 2 : 1;
    var ok = codepointClass.inRanges(cp, NCNAME_START_RANGES) ||
             (started && codepointClass.inRanges(cp, NCNAME_TAIL_RANGES));
    if (!ok) return false;
    started = true;
  }
  return true;
}

var VMC_DEFAULT_MAX_BYTES = C.BYTES.kib(256);

var VMC_DEFAULT_TIMEOUT_MS = C.TIME.seconds(15);

var BIMI_EKU_MARK_VERIFICATION = "1.3.6.1.5.5.7.3.31";
var VMC_POLICY_OID = "1.3.6.1.4.1.53087.1.1";
var CMC_POLICY_OID = "1.3.6.1.4.1.53087.1.2";

var ID_PE_LOGOTYPE = "1.3.6.1.5.5.7.1.12";

var vendorData = require("./vendor-data");
var _vendoredTrustAnchorsPem = "";
try {
  _vendoredTrustAnchorsPem = vendorData.getAsString("bimi-trust-anchors");
} catch (_e) {
  _vendoredTrustAnchorsPem = "";
}

function _validateUrl(url, label) {
  try {
    safeUrl.parse(url, { allowedProtocols: ["https:"] });
  } catch (e) {
    throw new BimiError("mail-bimi/bad-" + label,
      "bimi: " + label + " must be an https:// URL - got '" + url + "': " +
      ((e && e.message) || String(e)));
  }
}

/**
 * @primitive b.mail.bimi.recordShape
 * @signature b.mail.bimi.recordShape(opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.parseRecord, b.mail.bimi.fetchPolicy
 *
 * Builds the canonical draft-blank-ietf-bimi BIMI TXT-record string from a logo
 * URL and optional VMC URL. Throws on missing or non-https URLs and
 * on control / record-separator characters in the URLs. Operators
 * publish the returned string at `default._bimi.<domain>` (or the
 * selector subdomain if they're using non-default selectors).
 *
 * @opts
 *   {
 *     logoUrl:   string,    // required - https:// URL to Tiny-PS SVG
 *     vmcUrl:    string?,   // optional - https:// URL to VMC / CMC PEM
 *     selector:  string?,   // unused at record-shape time; reserved
 *                           //   for future per-selector behavior
 *   }
 *
 * @example
 *   var rec = b.mail.bimi.recordShape({
 *     logoUrl: "https://example.com/bimi/logo.svg",
 *     vmcUrl:  "https://example.com/bimi/cert.pem",
 *   });
 *   // -> "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/cert.pem"
 */
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

/**
 * @primitive b.mail.bimi.parseRecord
 * @signature b.mail.bimi.parseRecord(text)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.fetchPolicy
 *
 * Parses a BIMI TXT record into `{ v, l, a }`. Returns null when the
 * text is not a v=BIMI1 record, the `l=` URL is missing, or the
 * total bytes exceed the 2 KiB sanity cap. Use this when the operator
 * already has the TXT bytes in hand (e.g. an inbound auth-results
 * pipeline carrying the resolved record).
 *
 * @example
 *   var rv = b.mail.bimi.parseRecord("v=BIMI1; l=https://example.com/logo.svg");
 *   // -> { v: "BIMI1", l: "https://example.com/logo.svg", a: null }
 */
function parseRecord(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  if (text.length > BIMI_RECORD_MAX_BYTES) return null;
  var pairs = structuredFields.parseTagList(text);
  var rv = { v: null, l: null, a: null };
  for (var i = 0; i < pairs.length; i += 1) {
    var k = pairs[i][0];
    if (k === "v" || k === "l" || k === "a") rv[k] = pairs[i][1];
  }
  if (rv.v !== BIMI_VERSION || !rv.l) return null;
  return rv;
}

/**
 * @primitive b.mail.bimi.fetchPolicy
 * @signature b.mail.bimi.fetchPolicy(domain, opts?)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.fetchAndVerifyMark
 *
 * Resolves `default._bimi.<domain>` (or `<selector>._bimi.<domain>`
 * if `opts.selector` is set) and returns the parsed `{ v, l, a }`.
 * Returns null when no TXT record exists or no record on the
 * resolved name parses as v=BIMI1. Operators feed the returned
 * `l=` / `a=` URLs into `fetchAndVerifyMark` to retrieve the
 * verified mark.
 *
 * @opts
 *   {
 *     selector:  string?,                       // default "default"
 *     dnsLookup: async (qname, type) => rows?,  // operator-supplied resolver
 *                                               //   (DoH / cache / fixture);
 *                                               //   default: node:dns.resolveTxt
 *   }
 *
 * @example
 *   // requires: outbound DNS for the BIMI record and HTTPS for the mark
 *   var pol = await b.mail.bimi.fetchPolicy("example.com");
 *   if (pol && pol.a) {
 *     var verified = await b.mail.bimi.fetchAndVerifyMark({
 *       domain:  "example.com",
 *       vmcUrl:  pol.a,
 *     });
 *   }
 */
async function fetchPolicy(domain, opts) {
  validateOpts.requireNonEmptyString(domain,
    "bimi.fetchPolicy: domain", BimiError, "mail-bimi/bad-domain");
  opts = opts || {};
  var selector = opts.selector || BIMI_DEFAULT_SELECTOR;
  var qname = selector + "._bimi." + domain;
  var records = await networkDnsResolver().safeResolveTxt(qname, {
    dnsLookup:    opts.dnsLookup,
    errorFactory: function (code, msg) { return new BimiError(code, msg); },
    code:         "mail-bimi/lookup-failed",
  });
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    var parsed = parseRecord(s);
    if (parsed) return parsed;
  }
  return null;
}

var TINY_PS_FORBIDDEN_TAGS = {
  "script": true,
  "style": true,
  "foreignobject": true,
  "animate": true,
  "animatetransform": true,
  "animatemotion": true,
  "set": true,
  "filter": true,
  "image": true,
};

/**
 * @primitive b.mail.bimi.validateTinyPsSvg
 * @signature b.mail.bimi.validateTinyPsSvg(svgBytes)
 * @since     0.8.53
 * @status    stable
 * @related   b.mail.bimi.fetchAndVerifyMark, b.guardSvg
 *
 * Validates a brand-mark SVG against the AuthIndicators-WG Tiny PS
 * profile (draft-blank-ietf-bimi). Tiny-PS is a strict subset of SVG 1.2:
 * single <svg> root with `version="1.2"` and `baseProfile="tiny-ps"`,
 * `viewBox` required, byte size up to 32 KiB, no scripts / styles /
 * foreign content / animation / filters / external image refs, no
 * external references in `href` / `xlink:href` attributes (only
 * `#fragment` permitted), no `<!DOCTYPE>` / `<!ENTITY>` / processing
 * instructions other than the XML prolog. Returns
 * `{ ok, violations }` where each violation is `{ code, message }`.
 * Throws `MailBimiError` (`bimi/svg-too-large`) when the input
 * exceeds the byte cap; throws (`bimi/svg-tiny-ps-violation` with
 * `parse-failed`) on tokenizer failure.
 *
 * @example
 *   var rv = b.mail.bimi.validateTinyPsSvg('<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1" xmlns="http://www.w3.org/2000/svg"></svg>');
 *   // -> { ok: true, violations: [] }
 */
function validateTinyPsSvg(svgBytes) {
  var s;
  if (Buffer.isBuffer(svgBytes) || svgBytes instanceof Uint8Array) {
    if (svgBytes.length > TINY_PS_MAX_BYTES) {
      throw new MailBimiError("bimi/svg-too-large",
        "bimi.validateTinyPsSvg: input " + svgBytes.length + " bytes exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES);
    }
    s = safeBuffer.normalizeText(Buffer.from(svgBytes), {
      maxBytes:    TINY_PS_MAX_BYTES,
      errorClass:  MailBimiError,
      typeCode:    "bimi/svg-tiny-ps-violation",
      sizeCode:    "bimi/svg-too-large",
      typeMessage: "bimi.validateTinyPsSvg: input must be Buffer / Uint8Array / string",
      sizeMessage: "bimi.validateTinyPsSvg: input exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES + " bytes",
    });
  } else if (typeof svgBytes === "string") {
    if (Buffer.byteLength(svgBytes, "utf8") > TINY_PS_MAX_BYTES) {
      throw new MailBimiError("bimi/svg-too-large",
        "bimi.validateTinyPsSvg: input " + Buffer.byteLength(svgBytes, "utf8") + " bytes exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES);
    }
    s = svgBytes;
  } else {
    throw new MailBimiError("bimi/svg-tiny-ps-violation",
      "bimi.validateTinyPsSvg: input must be Buffer / Uint8Array / string");
  }

  var violations = [];
  function _vio(code, message) { violations.push({ code: code, message: message }); }

  var tokens;
  try { tokens = _tokenizeTinyPsSvg(s); }
  catch (e) {
    throw new MailBimiError("bimi/svg-tiny-ps-violation",
      "bimi.validateTinyPsSvg: parse-failed: " + ((e && e.message) || String(e)));
  }

  var rootSvg = null;
  var depth = 0;
  var sawSecondRoot = false;
  for (var i = 0; i < tokens.length; i += 1) {
    var t = tokens[i];

    if (t.type === "doctype") {
      _vio("doctype-forbidden", "<!DOCTYPE> is forbidden in Tiny-PS (entity-expansion / DTD class)");
      continue;
    }
    if (t.type === "declaration") {
      _vio("declaration-forbidden",
        "<!" + (t.raw || "").slice(2, 30) + "...> declaration is forbidden in Tiny-PS");
      continue;
    }
    if (t.type === "processingInstruction") {
      var pir = (t.raw || "").trim();
      if (!/^<\?xml\b/i.test(pir)) {
        _vio("pi-forbidden", "processing instruction is forbidden in Tiny-PS: " + pir.slice(0, 40))   ;
      }
      continue;
    }
    if (t.type === "comment" || t.type === "text" || t.type === "cdata") continue;

    if (t.type === "endTag") {
      depth -= 1;
      continue;
    }

    if (t.type === "tag") {
      var name = t.name;
      if (Object.prototype.hasOwnProperty.call(TINY_PS_FORBIDDEN_TAGS, name)) {
        _vio("element-forbidden",
          "<" + name + "> is forbidden in Tiny-PS (script / style / animation / filter / image / foreign-content class)");
      }
      if (name.indexOf("animate") === 0 && !Object.prototype.hasOwnProperty.call(TINY_PS_FORBIDDEN_TAGS, name)) {
        _vio("element-forbidden",
          "<" + name + "> animation element is forbidden in Tiny-PS");
      }

      if (depth === 0) {
        if (rootSvg === null) {
          if (name !== "svg") {
            _vio("root-not-svg",
              "Tiny-PS root element must be <svg> - got <" + name + ">");
          }
          rootSvg = t;
        } else if (!sawSecondRoot) {
          _vio("multiple-root-elements",
            "Tiny-PS document must have exactly one root <svg> element");
          sawSecondRoot = true;
        }
      }

      var attrs = t.attrs || {};
      for (var aname in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, aname)) continue;
        var aval = String(attrs[aname]);
        var lname = aname.toLowerCase();

        if (lname.indexOf("on") === 0 && lname.length > 2) {
          _vio("event-handler-forbidden",
            "event-handler attribute `" + aname + "` is forbidden in Tiny-PS");
        }

        if (lname === "href" || lname === "xlink:href") {
          if (aval.length > 0 && aval.charAt(0) !== "#") {
            _vio("external-ref-forbidden",
              "external reference in `" + aname + "='" + aval.slice(0, 60) /* allow:raw-time-literal — display truncation char-count 60; coincidental multiple-of-60, not a duration, C.TIME N/A */ + "...'` " +
              "is forbidden in Tiny-PS (only `#fragment` permitted)");
          }
        }

        if (lname === "style") {
          _vio("style-attr-forbidden",
            "`style` attribute is forbidden in Tiny-PS (CSS @import / url() class)");
        }
      }

      if (!t.selfClosing) depth += 1;
    }
  }

  if (rootSvg !== null) {
    var rootAttrs = rootSvg.attrs || {};
    if (rootAttrs.version !== "1.2") {
      _vio("bad-version",
        "Tiny-PS requires version=\"1.2\" on root <svg> - got `" +
        (rootAttrs.version === undefined ? "(missing)" : rootAttrs.version) + "`");
    }
    if (rootAttrs.baseProfile !== "tiny-ps" && rootAttrs.baseprofile !== "tiny-ps") {
      _vio("bad-base-profile",
        "Tiny-PS requires baseProfile=\"tiny-ps\" on root <svg> - got `" +
        (rootAttrs.baseProfile || rootAttrs.baseprofile || "(missing)") + "`");
    }
    if (!rootAttrs.viewBox && !rootAttrs.viewbox) {
      _vio("missing-viewbox",
        "Tiny-PS requires viewBox attribute on root <svg>");
    }
  }

  return { ok: violations.length === 0, violations: violations };
}

function _tokenizeTinyPsSvg(s) {
  var tokens = [];
  var len = s.length;
  var pos = 0;

  while (pos < len) {
    var lt = s.indexOf("<", pos);
    if (lt === -1) {
      if (pos < len) tokens.push({ type: "text", raw: s.slice(pos, len) });
      break;
    }
    if (lt > pos) tokens.push({ type: "text", raw: s.slice(pos, lt) });

    if (s.startsWith("<!--", lt)) {
      var endC = markupTokenizer.htmlCommentEnd(s, lt);
      if (endC === -1) throw new Error("unterminated comment");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "comment", raw: s.slice(lt, endC) });
      pos = endC;
      continue;
    }
    if (s.startsWith("<![CDATA[", lt)) {
      var endX = s.indexOf("]]>", lt + 9);
      if (endX === -1) throw new Error("unterminated CDATA");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "cdata", raw: s.slice(lt, endX + 3) });
      pos = endX + 3;
      continue;
    }
    if (s.startsWith("<!DOCTYPE", lt) || s.startsWith("<!doctype", lt)) {
      var endD = s.indexOf(">", lt);
      if (endD === -1) throw new Error("unterminated doctype");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "doctype", raw: s.slice(lt, endD + 1) });
      pos = endD + 1;
      continue;
    }
    if (s.charAt(lt + 1) === "?") {
      var endP = s.indexOf("?>", lt + 2);
      if (endP === -1) throw new Error("unterminated processing instruction");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "processingInstruction", raw: s.slice(lt, endP + 2) });
      pos = endP + 2;
      continue;
    }
    if (s.charAt(lt + 1) === "!") {
      var endDecl = s.indexOf(">", lt);
      if (endDecl === -1) throw new Error("unterminated declaration");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "declaration", raw: s.slice(lt, endDecl + 1) });
      pos = endDecl + 1;
      continue;
    }
    if (s.charAt(lt + 1) === "/") {
      var endE = s.indexOf(">", lt);
      if (endE === -1) throw new Error("unterminated end tag");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      var ename = s.slice(lt + 2, endE).trim().toLowerCase().split(/\s/)[0];
      tokens.push({ type: "endTag", name: ename });
      pos = endE + 1;
      continue;
    }

    var pp = markupTokenizer.scanToTagEnd(s, lt + 1, len);
    if (pp >= len) throw new Error("unterminated start tag");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
    var raw = s.slice(lt, pp + 1);
    var inner = raw.slice(1, raw.length - 1);
    var selfClosing = inner.endsWith("/");
    if (selfClosing) inner = inner.slice(0, inner.length - 1);

    var bimiParts = markupTokenizer.splitTagNameAttrs(inner, markupTokenizer.XML_TAG_NAME_TAIL);

    tokens.push({
      type:        "tag",
      name:        bimiParts.tagName,
      attrs:       _parseTinyPsAttrs(bimiParts.attrSrc),
      raw:         raw,
      selfClosing: selfClosing,
    });
    pos = pp + 1;
  }
  return tokens;
}

function _parseTinyPsAttrs(src) {
  var attrs = {};
  var re = /(?<![A-Za-z0-9:._-])([A-Za-z_:][A-Za-z0-9:._-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g;
  var m;
  while ((m = re.exec(src)) !== null) {
    var name = m[1];
    var value = m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : (m[5] || ""));
    if (!pick.isPoisonedKey(name)) attrs[name] = value;
  }
  return attrs;
}

/**
 * @primitive b.mail.bimi.fetchAndVerifyMark
 * @signature b.mail.bimi.fetchAndVerifyMark(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.mail.bimi.fetchPolicy, b.mail.bimi.validateTinyPsSvg
 *
 * Fetches a VMC / CMC PEM from `opts.vmcUrl` (or `opts.cmcUrl`) over
 * HTTPS, parses it as X.509, validates the chain against the BIMI
 * Group trust anchors (vendored at lib/vendor/bimi-trust-anchors.pem,
 * operator-overridable via `trustAnchorsPem`), confirms the cert's
 * subjectAltName URI matches the BIMI domain, and confirms the cert
 * carries the BIMI mark-verification ExtendedKeyUsage OID
 * (1.3.6.1.5.5.7.3.31). Returns
 * `{ ok, mark, certificate, vmcType }` where `vmcType` is `"vmc"`
 * or `"cmc"` derived from the cert's policyOIDs, and `mark` carries
 * the SVG bytes when the cert's RFC 3709 logotype extension is
 * present (or null when not). Throws `MailBimiError` with one of
 * the documented codes on any failure.
 *
 * @opts
 *   {
 *     domain:            string,       // required - BIMI domain to assert
 *                                      //   matches subjectAltName URI
 *     vmcUrl:            string?,      // VMC PEM URL (https://); operator
 *                                      //   passes one of vmcUrl / cmcUrl
 *     cmcUrl:            string?,      // CMC PEM URL (https://); same
 *     trustAnchorsPem:   string?,      // operator-supplied PEM bundle;
 *                                      //   defaults to the vendored
 *                                      //   bimi-trust-anchors.pem
 *     timeoutMs:         number?,      // default 15s
 *     maxResponseBytes:  number?,      // default 256 KiB
 *     audit:             { safeEmit }, // operator-supplied audit dispatcher
 *     httpClient:        object?,      // default b.httpClient - test-only
 *                                      //   override for unit tests that
 *                                      //   want to stub the network call
 *     evidenceDocument:  string?,      // operator-supplied trademark
 *                                      //   evidence URL; surfaced on
 *                                      //   the result for audit logging
 *   }
 *
 * @example
 *   var rv = await b.mail.bimi.fetchAndVerifyMark({
 *     domain:           "example.com",
 *     vmcUrl:           "https://example.com/bimi/cert.pem",
 *     trustAnchorsPem:  "-----BEGIN CERTIFICATE-----\n...",
 *   });
 *   // -> { ok, mark: { svg, evidenceDocument }, certificate, vmcType: "vmc" }
 */
async function fetchAndVerifyMark(opts) {
  validateOpts.requireObject(opts, "bimi.fetchAndVerifyMark", MailBimiError, "bimi/bad-opts");
  validateOpts(opts, [
    "domain", "vmcUrl", "cmcUrl",
    "trustAnchorsPem", "timeoutMs", "maxResponseBytes",
    "audit", "httpClient", "evidenceDocument",
  ], "bimi.fetchAndVerifyMark");
  validateOpts.requireNonEmptyString(opts.domain,
    "bimi.fetchAndVerifyMark: domain", MailBimiError, "bimi/bad-opts");

  var url = opts.vmcUrl || opts.cmcUrl;
  if (typeof url !== "string" || url.length === 0) {
    throw new MailBimiError("bimi/bad-opts",
      "bimi.fetchAndVerifyMark: one of vmcUrl / cmcUrl is required");
  }
  try { safeUrl.parse(url, { allowedProtocols: ["https:"] }); }
  catch (e) {
    throw new MailBimiError("bimi/bad-opts",
      "bimi.fetchAndVerifyMark: cert URL must be https - got `" + url + "`: " +
      ((e && e.message) || String(e)));
  }

  var timeoutMs = opts.timeoutMs !== undefined ? opts.timeoutMs : VMC_DEFAULT_TIMEOUT_MS;
  var maxBytes  = opts.maxResponseBytes !== undefined ? opts.maxResponseBytes : VMC_DEFAULT_MAX_BYTES;

  var hc = opts.httpClient || httpClient;

  var rsp;
  try {
    rsp = await hc.request({
      method:           "GET",
      url:              url,
      timeoutMs:        timeoutMs,
      maxResponseBytes: maxBytes,
      allowedProtocols: ["https:"],
      headers:          { "Accept": "application/x-pem-file, application/pem-certificate-chain, text/plain" },
      errorClass:       MailBimiError,
    });
  } catch (e) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, reason: (e && e.message) || String(e) });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: GET " + url + " failed: " + ((e && e.message) || String(e)));
  }
  if (rsp.statusCode !== C.HTTP.STATUS.OK) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, status: rsp.statusCode });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: GET " + url + " returned status " + rsp.statusCode);
  }
  var pemBytes = Buffer.isBuffer(rsp.body) ? rsp.body.toString("utf8") : String(rsp.body || "");
  if (pemBytes.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, reason: "no-pem" });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: response body is not a PEM-encoded CERTIFICATE chain");
  }

  var certPems = _splitPemChain(pemBytes);
  if (certPems.length === 0) {
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: no CERTIFICATE blocks in PEM body");
  }
  var leaf;
  var intermediates = [];
  try {
    leaf = new nodeCrypto.X509Certificate(certPems[0]);
    for (var i = 1; i < certPems.length; i += 1) {
      intermediates.push(new nodeCrypto.X509Certificate(certPems[i]));
    }
  } catch (e) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: X.509 parse failed: " + ((e && e.message) || String(e)));
  }

  var trustAnchorsPem = typeof opts.trustAnchorsPem === "string" && opts.trustAnchorsPem.length > 0
    ? opts.trustAnchorsPem
    : _vendoredTrustAnchorsPem;
  var anchorPems = _splitPemChain(trustAnchorsPem);
  if (anchorPems.length === 0) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: no trust anchors configured - populate " +
      "lib/vendor/bimi-trust-anchors.pem or pass `trustAnchorsPem` " +
      "(see draft-blank-ietf-bimi / BIMI Group VMC issuer list)");
  }
  var anchors;
  try {
    anchors = anchorPems.map(function (p) { return new nodeCrypto.X509Certificate(p); });
  } catch (e) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: trust-anchor PEM parse failed: " + ((e && e.message) || String(e)));
  }
  var chainOk = _verifyCertChain(leaf, intermediates, anchors);
  if (!chainOk.ok) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: chainOk.reason });
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: chain validation failed: " + chainOk.reason);
  }

  var sanMatch = _subjectAltNameMatchesDomain(leaf, opts.domain);
  if (!sanMatch.ok) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: "san-mismatch", san: sanMatch.found });
    throw new MailBimiError("bimi/vmc-domain-mismatch",
      "bimi.fetchAndVerifyMark: subjectAltName does not include BIMI domain `" +
      opts.domain + "` - found: " + (sanMatch.found.length === 0 ? "(none)" : sanMatch.found.join(", ")));
  }

  var policyInfo = _extractBimiCertPolicy(leaf);
  if (!policyInfo.hasMarkVerificationEku) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: "missing-eku" });
    throw new MailBimiError("bimi/vmc-policy-oid-missing",
      "bimi.fetchAndVerifyMark: certificate is missing the BIMI mark-verification " +
      "ExtendedKeyUsage OID (" + BIMI_EKU_MARK_VERIFICATION + ") - draft-blank-ietf-bimi");
  }

  var vmcType = "vmc";
  if (policyInfo.policyOids.indexOf(CMC_POLICY_OID) !== -1 &&
      policyInfo.policyOids.indexOf(VMC_POLICY_OID) === -1) {
    vmcType = "cmc";
  }

  var mark = {
    svg:               policyInfo.logoSvg,
    evidenceDocument:  typeof opts.evidenceDocument === "string" ? opts.evidenceDocument : null,
  };

  _emitAudit(opts, "mail.bimi.vmc.verified", "success", {
    url:      url,
    domain:   opts.domain,
    vmcType:  vmcType,
    issuer:   leaf.issuer,
    subject:  leaf.subject,
    notAfter: leaf.validTo,
  });

  return {
    ok: true,
    mark: mark,
    certificate: {
      issuer:     leaf.issuer,
      subject:    leaf.subject,
      notAfter:   leaf.validTo,
      notBefore:  leaf.validFrom,
      policyOids: policyInfo.policyOids.slice(),
    },
    vmcType: vmcType,
  };
}

function _splitPemChain(pemText) {
  if (typeof pemText !== "string") return [];
  var BEGIN = "-----BEGIN CERTIFICATE-----";
  var END = "-----END CERTIFICATE-----";
  var out = [];
  var from = 0;
  for (;;) {
    var b = pemText.indexOf(BEGIN, from);
    if (b === -1) break;
    var e = pemText.indexOf(END, b + BEGIN.length);
    if (e === -1) break;
    out.push(pemText.slice(b, e + END.length));
    from = e + END.length;
  }
  return out;
}

function _verifyCertChain(leaf, intermediates, anchors) {
  var now = Date.now();
  var current = leaf;
  var depth = 0;
  var MAX_DEPTH = 8;

  while (depth < MAX_DEPTH) {
    var notBefore = Date.parse(current.validFrom);
    var notAfter  = Date.parse(current.validTo);
    if (!isFinite(notBefore) || !isFinite(notAfter)) {
      return { ok: false, reason: "cert validity dates unparseable" };
    }
    if (isFinite(notBefore) && now < notBefore) {
      return { ok: false, reason: "cert not-yet-valid (notBefore=" + current.validFrom + ")" };
    }
    if (isFinite(notAfter) && now > notAfter) {
      return { ok: false, reason: "cert expired (notAfter=" + current.validTo + ")" };
    }

    for (var ai = 0; ai < anchors.length; ai += 1) {
      var anchor = anchors[ai];
      if (x509Chain.issuerValidlyIssued(anchor, current)) return { ok: true };
    }
    if (current.checkIssued(current)) {
      return { ok: false, reason: "self-signed root not in trust-anchor bundle" };
    }

    var nextIssuer = null;
    for (var ii = 0; ii < intermediates.length; ii += 1) {
      var cand = intermediates[ii];
      if (cand === current) continue;
      if (x509Chain.issuerValidlyIssued(cand, current)) {
        nextIssuer = cand;
        break;
      }
    }
    if (nextIssuer === null) {
      return { ok: false, reason: "no issuer found for `" + current.subject + "` in chain or trust anchors" };
    }
    current = nextIssuer;
    depth += 1;
  }
  return { ok: false, reason: "chain depth exceeded " + MAX_DEPTH };
}

function _canonBimiHost(host) {
  return publicSuffix.canonicalDomain(host == null ? "" : host);
}

function _subjectAltNameMatchesDomain(cert, domain) {
  var raw = cert.subjectAltName || "";
  var parts = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  var found = parts.slice();
  var dom = _canonBimiHost(domain);
  if (dom.length === 0) return { ok: false, found: found };
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    var lp = p.toLowerCase();
    if (lp.indexOf("dns:") === 0) {
      if (_canonBimiHost(p.slice(4)) === dom) return { ok: true, found: found };
    } else if (lp.indexOf("uri:") === 0) {
      try {
        var u = safeUrl.parse(p.slice(4), { allowedProtocols: ["https:", "http:"] });
        if (_canonBimiHost(u.hostname) === dom) return { ok: true, found: found };
      } catch (_e) {
        // A URI SAN the URL parser refuses (userinfo / malformed / homograph)
        // is not a usable host binding — FAIL CLOSED. No substring fallback:
        // the old `lp.indexOf(dom) !== -1` matched the domain anywhere in the
        // raw SAN string (userinfo / path), so a CA-chained cert whose real
        // host differed could vouch for an arbitrary victim domain.
      }
    }
  }
  return { ok: false, found: found };
}

function _extractBimiCertPolicy(cert) {
  var rv = { hasMarkVerificationEku: false, policyOids: [], logoSvg: null };
  var rawDer = cert.raw;
  if (!rawDer || rawDer.length === 0) return rv;

  var outer;
  try { outer = asn1.readNode(rawDer, 0); }
  catch (_e) { return rv; }
  if (!outer || !outer.constructed) return rv;
  var topChildren;
  try { topChildren = asn1.readSequence(outer.value); }
  catch (_e) { return rv; }
  if (!topChildren || topChildren.length < 1) return rv;
  var tbs = topChildren[0];
  if (!tbs || !tbs.constructed) return rv;
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return rv; }
  var extsNode = null;
  for (var ti = 0; ti < tbsChildren.length; ti += 1) {
    var n = tbsChildren[ti];
    if (n.tagClass === 2 && n.tag === 3) { extsNode = n; break; }
  }
  if (!extsNode) return rv;
  var seqNode;
  try { seqNode = asn1.readNode(extsNode.value, 0); }
  catch (_e) { return rv; }
  if (!seqNode || !seqNode.constructed) return rv;
  var extList;
  try { extList = asn1.readSequence(seqNode.value); }
  catch (_e) { return rv; }
  for (var ei = 0; ei < extList.length; ei += 1) {
    var ext = extList[ei];
    if (!ext.constructed) continue;
    var extChildren;
    try { extChildren = asn1.readSequence(ext.value); }
    catch (_e) { continue; }
    if (!extChildren || extChildren.length < 2) continue;
    var oid;
    try { oid = asn1.readOid(extChildren[0]); }
    catch (_e) { continue; }
    var octet = extChildren[extChildren.length - 1];
    var inner;
    try { inner = asn1.readNode(octet.value, 0); }
    catch (_e) { continue; }

    if (oid === "2.5.29.37") {
      if (!inner || !inner.constructed) continue;
      var ekuList;
      try { ekuList = asn1.readSequence(inner.value); }
      catch (_e) { continue; }
      for (var ek = 0; ek < ekuList.length; ek += 1) {
        var ekuOid;
        try { ekuOid = asn1.readOid(ekuList[ek]); }
        catch (_e) { continue; }
        if (ekuOid === BIMI_EKU_MARK_VERIFICATION) rv.hasMarkVerificationEku = true;
      }
    } else if (oid === "2.5.29.32") {
      if (!inner || !inner.constructed) continue;
      var polList;
      try { polList = asn1.readSequence(inner.value); }
      catch (_e) { continue; }
      for (var pi = 0; pi < polList.length; pi += 1) {
        var polItem = polList[pi];
        if (!polItem.constructed) continue;
        var polChildren;
        try { polChildren = asn1.readSequence(polItem.value); }
        catch (_e) { continue; }
        if (polChildren.length === 0) continue;
        try {
          var polOid = asn1.readOid(polChildren[0]);
          if (polOid) rv.policyOids.push(polOid);
        } catch (_e) { /* skip */ }
      }
    } else if (oid === ID_PE_LOGOTYPE) {
      var found = _scanForEmbeddedSvg(inner, 8); 
      if (found) rv.logoSvg = found;
    }
  }
  return rv;
}

function _skipQuotedLiteral(text, j) {
  var ch = text.charAt(j);
  if (ch !== "\"" && ch !== "'") return 0;
  var end = text.indexOf(ch, j + 1);
  return end === -1 ? -1 : end + 1;
}

function _skipCommentOrPi(text, j) {
  if (text.startsWith("<!--", j)) {
    var endComment = markupTokenizer.xmlCommentEnd(text, j);
    return endComment === -1 ? -1 : endComment;
  }
  if (text.startsWith("<?", j)) {
    var endPi = text.indexOf("?>", j + 2);
    return endPi === -1 ? -1 : endPi + 2;
  }
  return 0;
}

function _endOfDoctype(text, at) {
  var j = at + 9;
  while (j < text.length) {
    if (text.charAt(j) === ">") return j + 1;
    if (text.charAt(j) === "[") {
      var endSubset = _endOfInternalSubset(text, j);
      if (endSubset === -1) return -1;
      j = endSubset + 1;
      continue;
    }
    var skipped = _skipQuotedLiteral(text, j);
    if (skipped === 0) skipped = _skipCommentOrPi(text, j);
    if (skipped === -1) return -1;
    j = skipped === 0 ? j + 1 : skipped;
  }
  return -1;
}

function _endOfInternalSubset(text, at) {
  var j = at + 1;
  while (j < text.length) {
    if (text.charAt(j) === "]") return j;
    var skipped = _skipQuotedLiteral(text, j);
    if (skipped === 0) skipped = _skipCommentOrPi(text, j);
    if (skipped === -1) return -1;
    j = skipped === 0 ? j + 1 : skipped;
  }
  return -1;
}

function _endsTagName(text, at) {
  var ch = text.charAt(at);
  return ch === ">" || ch === "/" || markupTokenizer.isMarkupSpace(text.charCodeAt(at));
}

function _tagBodyIsWellFormed(text, from, tagEnd) {
  var quote = "";
  for (var i = from; i < tagEnd; i += 1) {
    var ch = text.charAt(i);
    if (quote) { if (ch === quote) quote = ""; continue; }
    if (ch === "\"" || ch === "'") { quote = ch; continue; }
    if (ch !== "/") continue;
    return i + 1 === tagEnd;
  }
  return quote === "";
}

function _svgRootFollowsPrologue(text) {
  var i = 0;
  for (;;) {
    i = markupTokenizer.skipMarkupSpace(text, i);

    var aside = _skipCommentOrPi(text, i);
    if (aside === -1) return false;
    if (aside !== 0) { i = aside; continue; }

    if (text.startsWith("<!DOCTYPE", i) || text.startsWith("<!doctype", i)) {
      var endDoctype = _endOfDoctype(text, i);
      if (endDoctype === -1) return false;
      i = endDoctype;
      continue;
    }
    break;
  }

  if (text.charAt(i) !== "<") return false;

  var nameEnd = i + 1;
  while (nameEnd < text.length && !_endsTagName(text, nameEnd)) nameEnd += 1;
  if (nameEnd >= text.length) return false;
  var tagEnd = markupTokenizer.scanToTagEnd(text, nameEnd, text.length);
  if (tagEnd >= text.length) return false;
  if (!_tagBodyIsWellFormed(text, nameEnd, tagEnd)) return false;

  var parts = text.slice(i + 1, nameEnd).split(":");
  if (parts.length > 2 || parts[parts.length - 1] !== "svg") return false;
  if (parts.length === 2 && !_isNcName(parts[0])) return false;
  if (parts.length === 1) return true;

  var attrs = markupTokenizer.parseAttrs(text.slice(nameEnd, tagEnd));
  var wanted = "xmlns:" + parts[0];
  for (var a = 0; a < attrs.length; a += 1) {
    if (attrs[a].name === wanted) {
      return markupTokenizer.decodeCharRefs(attrs[a].value) === SVG_NAMESPACE;
    }
  }
  return false;
}

function _scanForEmbeddedSvg(node, depthBudget) {
  if (!node) return null;
  if (depthBudget < 0) return null;

  if (!node.constructed) {
    if (!node.value || node.value.length < 4) return null;
    var text = node.value.toString("utf8");
    return _svgRootFollowsPrologue(text) ? text : null;
  }

  var children;
  try { children = asn1.readSequence(node.value); }
  catch (_e) {
    try {
      var sub = asn1.readNode(node.value, 0);
      return _scanForEmbeddedSvg(sub, depthBudget - 1);
    } catch (_ee) { return null; }
  }
  for (var i = 0; i < children.length; i += 1) {
    var f = _scanForEmbeddedSvg(children[i], depthBudget - 1);
    if (f) return f;
  }
  return null;
}

function _emitAudit(opts, action, outcome, metadata) {
  var sink = opts && opts.audit;
  try {
    if (sink && typeof sink.safeEmit === "function") {
      sink.safeEmit({ action: action, outcome: outcome, metadata: metadata });
      return;
    }
    var defaultSink = audit();
    if (defaultSink && typeof defaultSink.safeEmit === "function") {
      defaultSink.safeEmit({ action: action, outcome: outcome, metadata: metadata });
    }
  } catch (_e) {
    // drop-silent - by design. Audit failure must not break the
    // BIMI-verify hot path; observability counter takes care of the
    // signal upstream.
  }
}

module.exports = {
  recordShape:                recordShape,
  parseRecord:                parseRecord,
  fetchPolicy:                fetchPolicy,
  fetchAndVerifyMark:         fetchAndVerifyMark,
  validateTinyPsSvg:          validateTinyPsSvg,
  BIMI_VERSION:               BIMI_VERSION,
  BIMI_EKU_MARK_VERIFICATION: BIMI_EKU_MARK_VERIFICATION,
  VMC_POLICY_OID:             VMC_POLICY_OID,
  CMC_POLICY_OID:             CMC_POLICY_OID,
  TINY_PS_MAX_BYTES:          TINY_PS_MAX_BYTES,
  BimiError:                  BimiError,
  MailBimiError:              MailBimiError,
};
