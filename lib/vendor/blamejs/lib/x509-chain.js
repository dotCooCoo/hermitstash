// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var nodeCrypto = require("node:crypto");
var asn1 = require("./asn1-der");
var numericBounds = require("./numeric-bounds");
var codepointClass = require("./codepoint-class");

var OID_BASIC_CONSTRAINTS = "2.5.29.19";
var OID_SUBJECT_ALT_NAME = "2.5.29.17";
var OID_NAME_CONSTRAINTS = "2.5.29.30";

function _certLike(cert) {
  return cert instanceof nodeCrypto.X509Certificate;
}

/**
 * @module b.x509Chain
 * @nav    Crypto
 * @title  X.509 chain (CA-bit issuer test)
 *
 * @intro
 *   The basicConstraints-enforcing issuer test the framework's own
 *   certificate-chain walkers route through (<code>b.tsa.verifyToken</code>,
 *   <code>b.mail.bimi</code> VMC/CMC, <code>b.mail.crypto.smime</code>,
 *   <code>b.mdoc</code>, <code>b.contentCredentials</code>,
 *   <code>b.auth.fidoMds3</code>). It exists because node:crypto's
 *   <code>X509Certificate.checkIssued()</code> validates the issuer/subject
 *   DN match, the AKI/SKI linkage, and — only when a keyUsage extension is
 *   present — keyCertSign, but it does <strong>not</strong> enforce
 *   basicConstraints cA:TRUE. A leaf / end-entity certificate (cA:FALSE)
 *   that omits keyUsage is therefore wrongly accepted as a signing CA for
 *   the next certificate in the chain — the classic basicConstraints bypass
 *   (CVE-2002-0862 class). Every in-tree walker routes its issuer test
 *   through these helpers so the cA enforcement can never be forgotten in
 *   one walker but present in another.
 *
 *   Exposed so a consumer validating an X.509 chain <em>outside</em> a TLS
 *   handshake — an operator-uploaded CA bundle, a non-handshake PQ-signed
 *   certificate — has the same hardened, fail-closed test instead of being
 *   pushed toward the raw <code>checkIssued()</code> path this module
 *   exists to prevent. Both helpers fail closed: any malformed input or
 *   unsupported key type returns false rather than throwing.
 *
 * @card
 *   basicConstraints cA:TRUE-enforcing X.509 issuer test, fail-closed —
 *   the hardened alternative to node's checkIssued() for chains built
 *   outside a TLS handshake.
 */

/**
 * @primitive b.x509Chain.isCaCert
 * @signature b.x509Chain.isCaCert(cert)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued
 *
 * True only when <code>cert</code> asserts basicConstraints cA:TRUE.
 * node's <code>X509Certificate</code> exposes <code>.ca</code> (a boolean);
 * a certificate with no basicConstraints extension or with cA:FALSE
 * returns false. A missing cert or a non-boolean <code>.ca</code> (parse
 * failure / unsupported runtime) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var ca = new crypto.X509Certificate(caPem);
 *   b.x509Chain.isCaCert(ca);   // → true only if basicConstraints cA:TRUE
 */
function isCaCert(cert) {
  return !!cert && cert.ca === true;
}

/**
 * @primitive b.x509Chain.issuerValidlyIssued
 * @signature b.x509Chain.issuerValidlyIssued(issuer, subject)
 * @since     0.15.15
 * @status    stable
 * @related   b.x509Chain.isCaCert
 *
 * True when <code>issuer</code> validly issued <code>subject</code> AND is
 * itself a CA: the DN / AKI-SKI / keyUsage linkage (checkIssued), the
 * cryptographic signature (verify), and basicConstraints cA:TRUE
 * (isCaCert). The cA check runs first so a non-CA certificate is rejected
 * before the expensive signature verification. Any exception (malformed
 * cert, unsupported key type) fails closed to false.
 *
 * @example
 *   var crypto = require("crypto");
 *   var issuer  = new crypto.X509Certificate(issuerPem);
 *   var subject = new crypto.X509Certificate(leafPem);
 *   b.x509Chain.issuerValidlyIssued(issuer, subject);   // → boolean
 */
function issuerValidlyIssued(issuer, subject) {
  try {
    return isCaCert(issuer) &&
      subject.checkIssued(issuer) &&
      subject.verify(issuer.publicKey);
  } catch (_e) {
    return false;
  }
}

function _certExtensionValue(certDer, oid) {
  var tbsKids = asn1.readCertificateTbsFields(certDer).tbsKids;
  var extsWrapper = null;
  for (var i = 0; i < tbsKids.length; i += 1) {
    if (tbsKids[i].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && tbsKids[i].tag === 3) {
      extsWrapper = tbsKids[i];
      break;
    }
  }
  if (!extsWrapper) return { value: null, duplicate: false };
  var exts = asn1.readSequence(asn1.readNode(extsWrapper.value, 0).value);
  var value = null;
  var count = 0;
  for (var j = 0; j < exts.length; j += 1) {
    if (exts[j].tag !== asn1.TAG.SEQUENCE) continue;
    var extKids = asn1.readSequence(exts[j].value);
    if (extKids.length < 2) continue;
    var extOid;
    try { extOid = asn1.readOid(extKids[0]); } catch (_e) { continue; }
    if (extOid !== oid) continue;
    count += 1;
    if (value === null) value = asn1.readOctetString(extKids[extKids.length - 1]);
  }
  return { value: value, duplicate: count > 1 };
}

function basicConstraintsPathLen(cert) {
  if (!cert || !Buffer.isBuffer(cert.raw)) return null;
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_BASIC_CONSTRAINTS); }
  catch (_e) { return null; }
  if (ext.duplicate) return -1;
  var extnValue = ext.value;
  if (!extnValue) return null;
  try {
    var bc = asn1.readNode(extnValue, 0);
    if (bc.tag !== asn1.TAG.SEQUENCE) return null;
    var kids = asn1.readSequence(bc.value);
    for (var k = 0; k < kids.length; k += 1) {
      if (kids[k].tag === asn1.TAG.INTEGER && kids[k].tagClass === asn1.TAG_CLASS.UNIVERSAL) {
        var intBuf = kids[k].value;
        if (!intBuf || intBuf.length === 0 || (intBuf[0] & 0x80)) return -1;
        return asn1.readUnsignedInt(kids[k]);
      }
    }
    return null;
  } catch (_e) {
    return null;
  }
}

var CASE_IGNORE_OIDS = {
  "2.5.4.3": 1, "2.5.4.4": 1, "2.5.4.5": 1, "2.5.4.6": 1, "2.5.4.7": 1,
  "2.5.4.8": 1, "2.5.4.9": 1, "2.5.4.10": 1, "2.5.4.11": 1, "2.5.4.12": 1,
  "2.5.4.13": 1, "2.5.4.15": 1, "2.5.4.17": 1, "2.5.4.18": 1, "2.5.4.19": 1,
  "2.5.4.27": 1, "2.5.4.41": 1, "2.5.4.42": 1, "2.5.4.43": 1, "2.5.4.44": 1,
  "2.5.4.46": 1, "2.5.4.51": 1, "2.5.4.65": 1,
  "0.9.2342.19200300.100.1.1": 1, "0.9.2342.19200300.100.1.25": 1,
  "1.2.840.113549.1.9.1": 1,
};

// allow:dynamic-regex — fixed ASCII literal naming the RFC 4518 separators by escape, so U+2028 and U+2029 are never a line terminator in this source
var RFC4518_MAP_TO_SPACE = new RegExp(
  "[\\t\\n\\v\\f\\r\\u0085\\u2028\\u2029\\p{Zs}]", "gu");
var RFC4518_DELETED_RANGES = [
  [0x0000, 0x0008], [0x000e, 0x001f], [0x007f, 0x0084], [0x0086, 0x009f],
  [0x00ad, 0x00ad], [0x034f, 0x034f], [0x06dd, 0x06dd], [0x070f, 0x070f],
  [0x1806, 0x1806], [0x180b, 0x180e],
  [0x200b, 0x200f], [0x202a, 0x202e], [0x2060, 0x2063], [0x206a, 0x206f],
  [0xfe00, 0xfe0f], [0xfeff, 0xfeff], [0xfff9, 0xfffb], [0xfffc, 0xfffc],
  [0x1d173, 0x1d17a], [0xe0001, 0xe0001], [0xe0020, 0xe007f],
];

var RFC4518_PROHIBITED = /\p{C}/u;

function _rfc4518Deleted(cp) {
  for (var i = 0; i < RFC4518_DELETED_RANGES.length; i += 1) {
    var r = RFC4518_DELETED_RANGES[i];
    if (cp >= r[0] && cp <= r[1]) return true;
  }
  return false;
}

function _rfc4518DropMappedToNothing(s) {
  var out = "";
  for (var i = 0; i < s.length; ) {
    var cp = s.codePointAt(i);
    var width = cp > 0xffff ? 2 : 1;
    var ch = s.slice(i, i + width);
    i += width;
    if (_rfc4518Deleted(cp)) continue;
    if (RFC4518_PROHIBITED.test(ch)) return null;
    out += ch;
  }
  return out;
}

var DOTLESS_I = String.fromCharCode(0x0131);
var RFC4518_PREPARE_PASSES = 8;
var RFC4518_NORMAL_FORM = "NFC";

function _caseFoldOnce(s) {
  return s.split(DOTLESS_I).map(function (seg) {
    return seg.toUpperCase().toLowerCase();
  }).join(DOTLESS_I);
}

function _rfc4518SettleMapAndNormalize(s) {
  var cur = s;
  for (var i = 0; i < RFC4518_PREPARE_PASSES; i += 1) {
    var next = _rfc4518DropMappedToNothing(
      cur.normalize(RFC4518_NORMAL_FORM).replace(RFC4518_MAP_TO_SPACE, " "));
    if (next === null) return null;
    if (next === cur) return cur;
    cur = next;
  }
  return cur;
}

function _rfc4518Prepare(s) {
  var cur = s;
  for (var i = 0; i < RFC4518_PREPARE_PASSES; i += 1) {
    var settled = _rfc4518SettleMapAndNormalize(cur);
    if (settled === null) return null;
    var next = _caseFoldOnce(settled).normalize(RFC4518_NORMAL_FORM);
    if (next === cur) break;
    cur = next;
  }
  return cur.replace(/ +/g, " ").trim();
}

function _opaqueValueKey(node) {
  return "b:" + node.tagClass + ":" + (node.constructed ? "c" : "p") + ":" +
    node.tag.toString(16) + ":" + node.value.toString("hex");
}

var PRINTABLE_STRING_EXTRA = " '()+,-./:=?";
var ASCII_PRINTABLE_FIRST = 0x20;
var ASCII_PRINTABLE_LAST  = 0x7e;
var TAG_PRINTABLE_STRING  = 0x13;

function _legacyRepertoireText(buf, tag) {
  var out = "";
  for (var i = 0; i < buf.length; i += 1) {
    var b = buf[i];
    if (b < ASCII_PRINTABLE_FIRST || b > ASCII_PRINTABLE_LAST) return null;
    var ch = String.fromCharCode(b);
    if (tag === TAG_PRINTABLE_STRING &&
        !/[A-Za-z0-9]/.test(ch) && PRINTABLE_STRING_EXTRA.indexOf(ch) === -1) {
      return null;
    }
    out += ch;
  }
  return out;
}

function _attrValueKey(node, caseIgnore) {
  var buf = node.value;
  if (!caseIgnore) return _opaqueValueKey(node);
  var universalPrimitive = node.tagClass === asn1.TAG_CLASS.UNIVERSAL &&
    node.constructed !== true;
  var s = null;
  if (!universalPrimitive) {
    s = null;
  } else if (node.tag === 0x13 || node.tag === 0x16 || node.tag === 0x14) {
    s = _legacyRepertoireText(buf, node.tag);
  } else if (node.tag === 0x0c) {
    s = buf.toString("utf8");
    if (!Buffer.from(s, "utf8").equals(buf)) s = null;
  } else if (node.tag === 0x1e && buf.length % 2 === 0) {
    var b2 = Buffer.from(buf); b2.swap16(); s = b2.toString("utf16le");
  } else if (node.tag === 0x1c && buf.length % 4 === 0) {
    s = "";
    for (var i = 0; i < buf.length; i += 4) s += String.fromCodePoint(buf.readUInt32BE(i));
  }
  if (s === null) return _opaqueValueKey(node);
  var prepared = null;
  try { prepared = _rfc4518Prepare(s); } catch (_e) { prepared = null; }
  if (prepared === null) {
    _refuseName("attribute value holds a code point RFC 4518 prohibits");
  }
  return "s:" + prepared;
}

function _refuseName(why) { throw new Error("x509-chain: " + why); }

function _isUniversalConstructed(node, tag) {
  return !!node && node.tag === tag && node.constructed === true &&
    node.tagClass === asn1.TAG_CLASS.UNIVERSAL;
}

function _isUniversalPrimitive(node, tag) {
  return !!node && node.tag === tag && node.constructed !== true &&
    node.tagClass === asn1.TAG_CLASS.UNIVERSAL;
}

function _canonicalName(nameNode) {
  if (!_isUniversalConstructed(nameNode, asn1.TAG.SEQUENCE)) {
    _refuseName("name is not a constructed universal SEQUENCE");
  }
  return asn1.readSequence(nameNode.value).map(function (rdn) {
    if (!_isUniversalConstructed(rdn, asn1.TAG.SET)) {
      _refuseName("relative distinguished name is not a constructed universal SET");
    }
    var atvs = asn1.readSequence(rdn.value);
    if (atvs.length === 0) _refuseName("relative distinguished name has no attribute");
    var entries = atvs.map(function (atv) {
      if (!_isUniversalConstructed(atv, asn1.TAG.SEQUENCE)) {
        _refuseName("attribute is not a constructed universal SEQUENCE");
      }
      var kids = asn1.readSequence(atv.value);
      if (kids.length !== 2 || !_isUniversalPrimitive(kids[0], asn1.TAG.OID)) {
        _refuseName("attribute is not exactly a primitive OID and one value");
      }
      var oid = asn1.readOid(kids[0]);
      return oid + "=" + _attrValueKey(kids[1], Object.prototype.hasOwnProperty.call(CASE_IGNORE_OIDS, oid));
    });
    entries.sort();
    return entries;
  });
}

/**
 * @primitive b.x509Chain.canonicalNameKey
 * @signature b.x509Chain.canonicalNameKey(nameNode)
 * @since     0.20.37
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued, b.x509Chain.nameConstraintsSatisfied
 *
 * One comparable string for an X.501 <code>Name</code> node, the shape a
 * certificate's issuer and subject fields carry, so two encodings of the same
 * name compare equal. Distinguished-name equality is not DER
 * equality: RFC 5280 section 7.1 compares <code>PrintableString</code> and
 * <code>UTF8String</code> attributes after normalization, so the same issuer
 * spelled in either type, in either case, or with repeated inner spaces is one
 * name. Attribute order within a relative distinguished name does not change
 * the key, and attributes whose type is case-sensitive keep their case.
 *
 * A case-insensitive attribute is prepared per RFC 4518: the soft hyphen, the
 * combining grapheme joiner, the variation selectors, the zero width space and
 * the control and format code points Unicode 3.2 defined are removed; tab, the
 * line and page separators and every space-separator character become one space;
 * the value is case FOLDED, not merely lowercased, so
 * <code>Stra&szlig;e CA</code> and <code>STRASSE CA</code> are one name and so
 * are the final and medial forms of sigma; and the value is normalized, to form
 * C for the reason given below.
 *
 * The removed set is a fixed table, not a category test against the Unicode
 * version the runtime happens to ship, and any other code point in category
 * Other refuses the whole name with <code>null</code>. Removing a character is
 * the one mapping that can make two DIFFERENT names equal, so a character the
 * RFC never listed must not be removed merely because a later Unicode gave it a
 * format category: U+061C, added in Unicode 6.3, made an issuer
 * <code>A&lt;U+061C&gt;B</code> take the key of <code>AB</code>. RFC 4518
 * section 2.4 prohibits the code points unassigned in Unicode 3.2, and refusing
 * is the safe answer for one this cannot classify, since no conformant peer
 * sends it.
 *
 * That refusal reads the runtime's own category table, so which names are
 * refused follows the Unicode version the Node release ships: a code point
 * assigned a category after that release was built is refused there and may key
 * on a newer one. The names this affects are the ones no conformant peer sends,
 * and a name of letters, digits, spaces and punctuation keys identically on
 * every release, but a deployment that compares verdicts across Node versions
 * should pin one.
 *
 * Normalization is to form C, not the form KC RFC 4518 names, and that is a
 * deliberate narrowing. Compatibility normalization maps one character onto a
 * DIFFERENT one, which under form KC gave 24,355 pairs of unrelated code points
 * the same key: every superscript, subscript, circled, fullwidth and mathematical
 * variant collapsed onto its ASCII base, so <code>A&lt;U+1D2C&gt;B</code> took
 * the key of <code>AAB</code> and a SignerInfo could name a certificate it did
 * not. The RFC bounds that hazard by prohibiting every code point unassigned in
 * Unicode 3.2, which needs that repertoire to implement. Canonical normalization
 * only composes and reorders, so it never maps a character onto another one: every
 * set of code points that shares a key is a single Unicode case class, which is
 * what a case-insensitive attribute is defined to unify. U+03D1 and U+03F4 share
 * one because case folding takes both to theta. Two canonically equivalent
 * spellings still key alike; two compatibility variants no longer do.
 *
 * What that costs: a name spelled with a compatibility variant keys apart from
 * the same name in ASCII. <code>&lt;U+FF21&gt;CME CA</code>, which is
 * fullwidth A followed by CME CA, does not take the key of
 * <code>ACME CA</code>, and the same holds for the Roman numeral
 * <code>&lt;U+2160&gt;</code> against <code>I</code> and the
 * <code>&lt;U+FB00&gt;</code> ligature against <code>ff</code>. A SignerInfo
 * that names its issuer in one spelling and a certificate that names it in the
 * other therefore do not match, and the verify reports the certificate as not
 * named rather than accepting it. Both spellings are valid under RFC 4518,
 * which asks for form KC so they unify. Form KC unifies them by mapping one
 * character onto another, and bounding that to the characters the RFC allows
 * needs the Unicode 3.2 repertoire; form C refuses the pair instead of risking
 * the collapse. Vendoring that repertoire is what would let this use form KC,
 * and until it does, a peer that mixes the two spellings of one name is
 * refused rather than guessed at.
 *
 * The steps run to a fixed point rather than in a chosen order, because no single
 * order settles every name. Case mapping can hand back a decomposed sequence,
 * which only a normalization that follows it recomposes. And the fold is the one
 * step that cannot be undone: U+0345 becomes a base letter, so a mark run folded
 * before it is canonically ordered puts the accent on a different letter for
 * good, which removing a combining grapheme joiner can expose. So the mapping and
 * the normalization settle together first, the fold runs once on the settled
 * value, and that repeats until nothing changes, so the result keys to itself.
 *
 * A <code>PrintableString</code>, <code>IA5String</code> or
 * <code>TeletexString</code> is read only within its own repertoire: printable
 * ASCII, and for <code>PrintableString</code> the letters, digits and
 * <code>'()+,-./:=?</code> that type permits. Decoding bytes outside it as
 * Latin-1 fed preparation characters that were never in the input, so the bytes
 * <code>41 00 42</code> became A, NUL, B and the NUL was then removed, taking the
 * key of the valid <code>AB</code>. Such a value now keys by its bytes.
 *
 * Folding stops at the default rules: U+0131 is left alone, since Unicode folds
 * it onto an ASCII <code>i</code> only under the Turkic rules, and merging the
 * two would let one issuer read as another.
 *
 * Case mapping is the runtime's, so a character Unicode assigned after 3.2 folds
 * onto its case partner as that version defines: U+1C90 GEORGIAN MTAVRULI CAPITAL
 * AN keys as U+10D0, the Mkhedruli letter it is the capital of. RFC 4518 would
 * prohibit the newer character outright, which needs the Unicode 3.2 repertoire to
 * implement, so this deviates from the RFC and matches the pair instead. It does
 * not merge two DIFFERENT letters: every set of code points that shares a key is
 * one Unicode case class, which is what a case-insensitive attribute is defined to
 * do, and `x509-chain-canonical-name.test.js` asserts that over every code point.
 *
 * An empty <code>RDNSequence</code> is a name and keys like any other, because
 * RFC 5280 section 4.1.2.6 permits an empty subject when the identity is
 * carried in <code>subjectAltName</code>. A structure that only resembles a
 * name returns <code>null</code> instead: every node is checked for its tag,
 * its class and whether it is constructed, so a relative distinguished name
 * written as a <code>SEQUENCE</code>, one holding no attribute, an attribute
 * that is not exactly a primitive object identifier and one value refuses
 * rather than keying, each of which would otherwise key the same as the
 * well-formed encoding and compare equal to it. A value whose tag number
 * matches a string type under another class is not read as text: it keys by
 * its bytes together with its full tag identity, which is also what a value
 * this function cannot read as text does, so two such values are equal only
 * when their bytes and their tag identity both are.
 *
 * Two <code>null</code>s are not a match: compare for equality only after
 * checking that neither side is <code>null</code>, or two names you could not
 * read would appear to equal each other.
 *
 * @example
 *   var issuerKey  = b.x509Chain.canonicalNameKey(issuerNameNode);
 *   var subjectKey = b.x509Chain.canonicalNameKey(subjectNameNode);
 *   issuerKey !== null && issuerKey === subjectKey;
 *   // → true when the two names are the same name, however each was encoded
 */
function canonicalNameKey(nameNode) {
  try { return JSON.stringify(_canonicalName(nameNode)); }
  catch (_e) { return null; }
}

/**
 * @primitive b.x509Chain.sameName
 * @signature b.x509Chain.sameName(aNameNode, bNameNode)
 * @since     0.20.37
 * @status    stable
 * @related   b.x509Chain.canonicalNameKey, b.x509Chain.pathLenSatisfied
 *
 * Are these two X.501 <code>Name</code> nodes the same name? Answers from
 * <code>canonicalNameKey</code> when both names can be prepared, so two
 * encodings of one name match however each was written.
 *
 * When the preparation refuses a name, the two are compared by their bytes
 * instead of being called different. A refused name still equals itself, and
 * the alternative refuses conforming input: a SignerInfo whose sid issuer field
 * is copied verbatim from its own certificate stopped binding to it, and a
 * self-issued rollover whose subject bytes equal its issuer bytes stopped
 * counting as self-issued, so a chain RFC 5280 section 6.1.4 exempts from the
 * path-length count was rejected. Byte equality is the strictest comparison
 * there is, so it cannot make two different names match.
 *
 * Returns false when either argument is missing, and false when one name
 * prepares and the other does not.
 *
 * @example
 *   b.x509Chain.sameName(subjectNameNode, issuerNameNode);
 *   // → true when the two names are the same name, and when neither can be
 *   //   prepared but their bytes are identical
 */
function sameName(aNameNode, bNameNode) {
  if (!aNameNode || !bNameNode) return false;
  var aKey = canonicalNameKey(aNameNode);
  var bKey = canonicalNameKey(bNameNode);
  if (aKey !== null && bKey !== null) return aKey === bKey;
  var useRaw = !!(aNameNode.raw && bNameNode.raw);
  var aRaw = useRaw ? aNameNode.raw : aNameNode.value;
  var bRaw = useRaw ? bNameNode.raw : bNameNode.value;
  if (!aRaw || !bRaw) return false;
  return Buffer.from(aRaw).equals(Buffer.from(bRaw));
}

function _isSelfIssued(cert) {
  if (!cert || !Buffer.isBuffer(cert.raw)) return false;
  var f;
  try { f = asn1.readCertificateTbsFields(cert.raw); }
  catch (_e) { return false; }
  return sameName(f.subject, f.issuer);
}

/**
 * @primitive b.x509Chain.pathLenSatisfied
 * @signature b.x509Chain.pathLenSatisfied(chain)
 * @since     0.20.21
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued
 *
 * True when every CA in an ordered certificate chain honors its
 * basicConstraints pathLenConstraint (RFC 5280 §4.2.1.9 / §6.1.4).
 * <code>chain</code> is an array of node <code>X509Certificate</code>
 * objects ordered leaf-first (index 0 is the end-entity, the last element
 * is the topmost CA), the same order the framework's chain walkers build.
 * A CA that asserts pathLenConstraint N permits at most N non-self-issued
 * intermediate CAs between it and the end-entity; a chain that exceeds any
 * such limit returns false. node's <code>X509Certificate</code> does not
 * expose pathLenConstraint, so a chain built from otherwise-valid links can
 * silently exceed it; this reads the constraint from each certificate's DER
 * and enforces it. A chain shorter than two certificates has no CA link to
 * constrain and returns true. A missing certificate in the array fails
 * closed to false; a certificate with no pathLenConstraint imposes no limit.
 *
 * @example
 *   var crypto = require("crypto");
 *   var chain = [leafCert, intermediateCert, rootCert].map(function (pem) {
 *     return new crypto.X509Certificate(pem);
 *   });
 *   b.x509Chain.pathLenSatisfied(chain);   // → boolean
 */
function pathLenSatisfied(chain) {
  if (!Array.isArray(chain)) return false;
  for (var k = 0; k < chain.length; k += 1) {
    if (!_certLike(chain[k])) return false;
  }
  if (chain.length < 2) return true;
  var maxPathLen = Infinity;
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    var cert = chain[i];
    if (i >= 1 && !_isSelfIssued(cert)) {
      if (maxPathLen <= 0) return false;
      maxPathLen -= 1;
    }
    if (isCaCert(cert)) {
      var pl = basicConstraintsPathLen(cert);
      if (pl !== null) {
        if (pl < 0) return false;
        if (pl < maxPathLen) maxPathLen = pl;
      }
    }
  }
  return true;
}

function _certInPath(path, fp) {
  for (var i = 0; i < path.length; i += 1) {
    if (path[i].fingerprint256 === fp) return true;
  }
  return false;
}

function _hasPoolParent(current, path, pool, issued) {
  for (var p = 0; p < pool.length; p += 1) {
    var cand = pool[p];
    if (!_certLike(cand)) continue;
    if (_certInPath(path, cand.fingerprint256)) continue;
    if (issued(cand, current)) return true;
  }
  return false;
}

function _searchChain(current, path, anchors, pool, issued, validAt, maxDepth, state) {
  state.visits += 1;
  if (state.visits > state.maxVisits) return false;
  if (!validAt(current)) {
    if (!state.invalidCert) state.invalidCert = current;
    return false;
  }
  for (var a = 0; a < anchors.length; a += 1) {
    if (!_certLike(anchors[a])) continue;
    var isIssuer = issued(anchors[a], current);
    var isSelf = current.fingerprint256 === anchors[a].fingerprint256;
    if (!isIssuer && !isSelf) continue;
    var full = isIssuer ? path.concat([anchors[a]]) : path;
    if (!pathLenSatisfied(full)) {
      state.pathLen = true;
      continue;
    }
    if (!nameConstraintsSatisfied(full)) {
      state.nameBlocked = true;
      continue;
    }
    if (isIssuer && !validAt(anchors[a])) {
      if (!state.invalidCert) state.invalidCert = anchors[a];
      continue;
    }
    return true;
  }
  if (path.length >= maxDepth) {
    if (_hasPoolParent(current, path, pool, issued)) state.depthLimited = true;
    return false;
  }
  for (var p = 0; p < pool.length; p += 1) {
    var cand = pool[p];
    if (!_certLike(cand)) continue;
    if (_certInPath(path, cand.fingerprint256)) continue;
    if (!issued(cand, current)) continue;
    if (_searchChain(cand, path.concat([cand]), anchors, pool, issued, validAt, maxDepth, state)) return true;
  }
  return false;
}

/**
 * @primitive b.x509Chain.resolveChain
 * @signature b.x509Chain.resolveChain(leaf, pool, anchors, opts?)
 * @since     0.20.21
 * @status    stable
 * @related   b.x509Chain.issuerValidlyIssued, b.x509Chain.pathLenSatisfied
 *
 * Searches for a certification path from <code>leaf</code> through the candidate
 * certificates in <code>pool</code> to any certificate in <code>anchors</code>,
 * honoring basicConstraints pathLenConstraint. Every node on an accepted path
 * passes <code>opts.validAt</code>, every adjacent pair passes
 * <code>opts.issued</code>, and the assembled path satisfies
 * <code>pathLenSatisfied</code>. When one candidate issuer overruns a
 * path-length constraint the search tries the remaining candidates, so an
 * interchangeable issuer (same subject and key, different pathLenConstraint)
 * that completes a within-limit path is not preempted by a stricter one that
 * appears earlier in the pool. A certificate already on the path under
 * construction is never revisited, and the search stops after
 * <code>opts.maxVisits</code> node expansions to bound work on a crafted pool.
 *
 * The result carries <code>reason</code> "anchored" on success, "pathlen" when a
 * matching anchor was rejected only for path length, "nameconstraint" when it was
 * rejected only for a CA nameConstraints violation, otherwise "untrusted".
 * <code>invalidCert</code> is the first certificate that failed
 * <code>validAt</code> (null when none did). <code>depthLimited</code> is true
 * when a branch was cut at <code>maxDepth</code> with an issuer still available.
 *
 * @opts
 *   issued:    function,  // (issuer, subject) → boolean; default issuerValidlyIssued
 *   validAt:   function,  // (cert) → boolean; default () => true
 *   maxDepth:  number,    // default: pool.length + 1; caps the path length
 *   maxVisits: number,    // default: 4096; caps node expansions
 *
 * @example
 *   var res = b.x509Chain.resolveChain(leaf, [subCa, issuer], [root]);
 *   // → { ok: true, reason: "anchored", invalidCert: null, depthLimited: false }
 */
function resolveChain(leaf, pool, anchors, opts) {
  opts = opts || {};
  var issued = typeof opts.issued === "function" ? opts.issued : issuerValidlyIssued;
  var validAt = typeof opts.validAt === "function" ? opts.validAt : function () { return true; };
  var candidates = Array.isArray(pool) ? pool : [];
  var trust = Array.isArray(anchors) ? anchors : [];
  var maxDepth = numericBounds.isPositiveFiniteInt(opts.maxDepth) ? opts.maxDepth : candidates.length + 1;
  var state = {
    pathLen: false,
    nameBlocked: false,
    invalidCert: null,
    depthLimited: false,
    visits: 0,
    maxVisits: numericBounds.isPositiveFiniteInt(opts.maxVisits) ? opts.maxVisits : 4096,
  };
  var ok = _certLike(leaf) &&
    _searchChain(leaf, [leaf], trust, candidates, issued, validAt, maxDepth, state);
  var reason = "untrusted";
  if (ok) reason = "anchored";
  else if (state.pathLen) reason = "pathlen";
  else if (state.nameBlocked) reason = "nameconstraint";
  return {
    ok: ok,
    reason: reason,
    invalidCert: state.invalidCert,
    depthLimited: state.depthLimited,
  };
}

function _isSequence(node) {
  return node.tag === asn1.TAG.SEQUENCE && node.tagClass === asn1.TAG_CLASS.UNIVERSAL && node.constructed;
}

function _isAscii(buf) {
  for (var i = 0; i < buf.length; i += 1) {
    if (buf[i] > 0x7f) return false;
  }
  return true;
}

function _validDnsLabel(label) {
  if (label.length === 0 || label.length > 63) return false;
  for (var i = 0; i < label.length; i += 1) {
    var c = label.charCodeAt(i);
    if (!codepointClass.isAsciiAlnum(c) && c !== 0x2d && c !== 0x5f && c !== 0x2a) return false;
  }
  return label.charAt(0) !== "-" && label.charAt(label.length - 1) !== "-";
}

function _validSanDnsName(s) {
  if (s.length === 0 || s.length > 253) return false;
  var labels = s.split(".");
  for (var i = 0; i < labels.length; i += 1) {
    if (!_validDnsLabel(labels[i])) return false;
  }
  return true;
}

function _validConstraintDnsBase(s) {
  if (s.charAt(0) === ".") return _validSanDnsName(s.slice(1));
  return _validSanDnsName(s);
}

function _validSkippedGeneralName(node) {
  try {
    if (node.tag === 1 || node.tag === 6) return node.value.length > 0 && _isAscii(node.value);
    if (node.tag === 8) return node.value.length > 0;
    if (node.tag === 4) return _isSequence(asn1.readNodeStrict(node.value));
    var kids = asn1.readSequence(node.value);
    if (node.tag === 0) {
      return kids.length === 2 &&
        kids[0].tag === asn1.TAG.OID && kids[0].tagClass === asn1.TAG_CLASS.UNIVERSAL &&
        kids[1].tagClass === asn1.TAG_CLASS.CONTEXT_SPECIFIC && kids[1].tag === 0;
    }
    return kids.length >= 1;
  } catch (_e) {
    return false;
  }
}

function _constraintName(node) {
  if (node.tagClass !== asn1.TAG_CLASS.CONTEXT_SPECIFIC) return { type: "malformed" };
  if (node.tag === 2) {
    if (node.constructed || node.value.length === 0 || !_isAscii(node.value)) return { type: "malformed" };
    return { type: "dns", value: node.value.toString("latin1") };
  }
  if (node.tag === 7) return node.constructed ? { type: "malformed" } : { type: "ip", value: Buffer.from(node.value) };
  if (node.tag === 0 || node.tag === 3 || node.tag === 4 || node.tag === 5) {
    if (!node.constructed) return { type: "malformed" };
    return _validSkippedGeneralName(node) ? { type: "other" } : { type: "malformed" };
  }
  if (node.tag === 1 || node.tag === 6 || node.tag === 8) {
    if (node.constructed) return { type: "malformed" };
    return _validSkippedGeneralName(node) ? { type: "other" } : { type: "malformed" };
  }
  return { type: "malformed" };
}

function _subjectAltConstraintNames(cert) {
  var out = [];
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_SUBJECT_ALT_NAME); } catch (_e) { return { names: out, malformed: true }; }
  if (ext.duplicate) return { names: out, malformed: true };
  var extnValue = ext.value;
  if (!extnValue) return { names: out, malformed: false };
  try {
    var seq = asn1.readNodeStrict(extnValue);
    if (!_isSequence(seq)) return { names: out, malformed: true };
    var names = asn1.readSequence(seq.value);
    if (!names.length) return { names: out, malformed: true };
    for (var i = 0; i < names.length; i += 1) {
      var gn = _constraintName(names[i]);
      if (gn.type === "malformed") return { names: out, malformed: true };
      if (gn.type === "other") continue;
      if (gn.type === "ip" && gn.value.length !== 4 && gn.value.length !== 16) return { names: out, malformed: true };
      if (gn.type === "dns" && !_validSanDnsName(gn.value)) return { names: out, malformed: true };
      out.push(gn);
    }
  } catch (_e) { return { names: out, malformed: true }; }
  return { names: out, malformed: false };
}

function _nameConstraintsOf(cert) {
  var ext;
  try { ext = _certExtensionValue(cert.raw, OID_NAME_CONSTRAINTS); } catch (_e) { return { error: true }; }
  if (ext.duplicate) return { error: true };
  var extnValue = ext.value;
  if (!extnValue) return null;
  try {
    var seq = asn1.readNodeStrict(extnValue);
    if (!_isSequence(seq)) return { error: true };
    var fields = asn1.readSequence(seq.value);
    if (!fields.length) return { error: true };
    var res = { permitted: null, excluded: null, unsupported: false };
    var prevTag = -1;
    for (var i = 0; i < fields.length; i += 1) {
      var f = fields[i];
      if (f.tagClass !== asn1.TAG_CLASS.CONTEXT_SPECIFIC || !f.constructed || (f.tag !== 0 && f.tag !== 1)) return { error: true };
      if (f.tag <= prevTag) return { error: true };
      prevTag = f.tag;
      var subtrees = asn1.readSequence(f.value);
      if (!subtrees.length) return { error: true };
      var bucket = { dns: [], ip: [] };
      for (var s = 0; s < subtrees.length; s += 1) {
        if (!_isSequence(subtrees[s])) return { error: true };
        var gsKids = asn1.readSequence(subtrees[s].value);
        if (!gsKids.length) return { error: true };
        if (gsKids.length > 1) { res.unsupported = true; continue; }
        var gn = _constraintName(gsKids[0]);
        if (gn.type !== "dns" && gn.type !== "ip") { res.unsupported = true; continue; }
        if (gn.type === "ip" && gn.value.length !== 8 && gn.value.length !== 32) { res.unsupported = true; continue; }
        if (gn.type === "ip" && !_validIpConstraintMask(gn.value)) { res.unsupported = true; continue; }
        if (gn.type === "dns" && !_validConstraintDnsBase(gn.value)) { res.unsupported = true; continue; }
        bucket[gn.type].push(gn.value);
      }
      if (f.tag === 0) res.permitted = bucket; else res.excluded = bucket;
    }
    return res;
  } catch (_e) { return { error: true }; }
}

function _withinDnsSubtree(name, base) {
  var n = String(name).toLowerCase();
  var b = String(base).toLowerCase();
  if (b === "") return false;
  if (b.charAt(0) === ".") {
    return n.length > b.length && n.slice(n.length - b.length) === b;
  }
  if (n === b) return true;
  return n.length > b.length && n.slice(n.length - b.length - 1) === "." + b;
}

function _validIpConstraintMask(baseBuf) {
  var addrLen = baseBuf.length / 2;
  var seenZero = false;
  for (var i = addrLen; i < baseBuf.length; i += 1) {
    for (var bit = 7; bit >= 0; bit -= 1) {
      if ((baseBuf[i] >> bit) & 1) {
        if (seenZero) return false;
      } else {
        seenZero = true;
      }
    }
  }
  return true;
}

function _withinIpSubtree(nameBuf, baseBuf) {
  if (!Buffer.isBuffer(nameBuf) || !Buffer.isBuffer(baseBuf)) return false;
  if (baseBuf.length !== nameBuf.length * 2) return false;
  for (var i = 0; i < nameBuf.length; i += 1) {
    var mask = baseBuf[nameBuf.length + i];
    if ((nameBuf[i] & mask) !== (baseBuf[i] & mask)) return false;
  }
  return true;
}

function _nameWithin(name, base) {
  if (name.type === "dns") return _withinDnsSubtree(name.value, base);
  if (name.type === "ip") return _withinIpSubtree(name.value, base);
  return false;
}

function _certNamesSatisfy(cert, permittedReqs, excluded) {
  var hasConstraint = permittedReqs.dns.length || permittedReqs.ip.length ||
    excluded.dns.length || excluded.ip.length;
  var san = _subjectAltConstraintNames(cert);
  if (san.malformed) return !hasConstraint;
  var names = san.names;
  for (var n = 0; n < names.length; n += 1) {
    var name = names[n];
    var ex = excluded[name.type];
    for (var e = 0; e < ex.length; e += 1) if (_nameWithin(name, ex[e])) return false;
    var reqs = permittedReqs[name.type];
    for (var r = 0; r < reqs.length; r += 1) {
      var within = false;
      for (var g = 0; g < reqs[r].length; g += 1) if (_nameWithin(name, reqs[r][g])) { within = true; break; }
      if (!within) return false;
    }
  }
  return true;
}

/**
 * @primitive b.x509Chain.nameConstraintsSatisfied
 * @signature b.x509Chain.nameConstraintsSatisfied(chain)
 * @since     0.20.22
 * @status    stable
 * @related   b.x509Chain.pathLenSatisfied, b.x509Chain.resolveChain
 *
 * Enforces X.509 nameConstraints (RFC 5280 §4.2.1.10 / §6.1.4) over an ordered
 * chain <code>[leaf, …intermediates, anchor]</code>. Each CA's permittedSubtrees
 * and excludedSubtrees accumulate down the chain (permitted intersect, excluded
 * union) and are applied to the subjectAltName of every certificate below it
 * (self-issued intermediates are exempt; the leaf is always checked). A
 * dNSName is matched by the add-labels rule (base <code>example.com</code> is
 * satisfied by <code>example.com</code> and <code>host.example.com</code>, not
 * <code>notexample.com</code>); an iPAddress by the address/mask CIDR.
 *
 * dNSName and iPAddress constraints are evaluated. A nameConstraints extension
 * carrying any other subtree form (directoryName, rfc822Name, URI, otherName) or
 * a non-default minimum/maximum, or one that does not parse, fails CLOSED (the
 * chain is rejected) rather than being ignored. Returns a boolean; a non-array,
 * or any entry that is not an X509Certificate, is false.
 *
 * @example
 *   b.x509Chain.nameConstraintsSatisfied([leaf, intermediate, root]);
 *   // → false when the leaf SAN is outside the intermediate's permitted subtree
 */
function nameConstraintsSatisfied(chain) {
  if (!Array.isArray(chain)) return false;
  for (var k = 0; k < chain.length; k += 1) {
    if (!_certLike(chain[k])) return false;
  }
  var permittedReqs = { dns: [], ip: [] };
  var excluded = { dns: [], ip: [] };
  for (var i = chain.length - 1; i >= 0; i -= 1) {
    var cert = chain[i];
    if (i !== chain.length - 1 && (i === 0 || !_isSelfIssued(cert))) {
      if (!_certNamesSatisfy(cert, permittedReqs, excluded)) return false;
    }
    var nc = _nameConstraintsOf(cert);
    if (nc && nc.error) return false;
    if (nc) {
      if (nc.unsupported) return false;
      if (nc.permitted) {
        if (nc.permitted.dns.length) permittedReqs.dns.push(nc.permitted.dns);
        if (nc.permitted.ip.length) permittedReqs.ip.push(nc.permitted.ip);
      }
      if (nc.excluded) {
        excluded.dns = excluded.dns.concat(nc.excluded.dns);
        excluded.ip = excluded.ip.concat(nc.excluded.ip);
      }
    }
  }
  return true;
}

module.exports = {
  isCaCert:                isCaCert,
  issuerValidlyIssued:     issuerValidlyIssued,
  pathLenSatisfied:        pathLenSatisfied,
  resolveChain:            resolveChain,
  nameConstraintsSatisfied: nameConstraintsSatisfied,
  canonicalNameKey:        canonicalNameKey,
  sameName:                sameName,
};
