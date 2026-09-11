// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.crypto.httpSig — RFC 9421 HTTP Message Signatures.
 *
 * RFC 9421 (April 2024) standardizes message-level integrity for HTTP
 * requests and responses. Two headers carry the signature:
 *
 *   Signature-Input: <label>=("@method" "@target-uri" "content-digest");
 *                    created=1718000000;keyid="key-1";alg="ed25519"
 *   Signature:       <label>=:<base64-of-signature>:
 *
 * Per RFC 9421 §2.5, the signature base is the canonicalized list of
 * covered components plus the signature parameters; the signing
 * algorithm runs over those bytes.
 *
 * Derived components implemented here (RFC 9421 §2.2):
 *   @method, @target-uri, @authority, @scheme, @request-target,
 *   @path, @query, @query-param
 *
 * Signature parameters (RFC 9421 §2.3):
 *   created, expires, nonce, keyid, alg, tag
 *
 * Algorithms (RFC 9421 §3.3 + §A.2 IANA registry):
 *   "ed25519"      — Edwards-curve digital signature, classical
 *                    backward-compat default for non-PQC peers
 *   "ml-dsa-65"    — FIPS 204 lattice signatures, PQC default when
 *                    both peers PQC-aware
 *
 * The framework does NOT expose RSA / ECDSA-P256 / ECDSA-P384 / HMAC
 * variants from RFC 9421 §3.3 — same crypto-policy stance as the rest
 * of the framework (no SHA-256-only hashes, no classical-only
 * primitives where a PQC alternative is shipping).
 *
 * Operator API:
 *
 *   var sig = b.crypto.httpSig.sign({
 *     method:  "POST",
 *     url:     "https://api.example.com/orders",
 *     headers: { "content-type": "application/json", "host": "api.example.com" },
 *     body:    bodyBuffer,                 // for content-digest header
 *   }, {
 *     keyid:   "service-a-2026-05",
 *     alg:     "ed25519",                  // or "ml-dsa-65"
 *     privateKey: privateKeyPem,
 *     covered: ["@method", "@target-uri", "content-digest"],
 *     created: Math.floor(Date.now()/1000),
 *     expires: Math.floor(Date.now()/1000) + 300,
 *     label:   "sig1",                     // optional — defaults to "sig1"
 *   });
 *   // → { headers: { "Signature-Input": "...", "Signature": "...",
 *                     "Content-Digest": "..." } }
 *
 *   var ok = b.crypto.httpSig.verify({
 *     method, url, headers, body
 *   }, {
 *     keyResolver: function (keyid, alg) { return publicKeyPem; },
 *     toleranceMs: b.constants.TIME.minutes(5),
 *     // requiredComponents (RFC 9421 §3.2): components the covered set MUST
 *     // include, else verify refuses with reason "missing-required-component".
 *     // Omitted → secure default: @method + @target-uri, plus content-digest
 *     // when the request has a body. [] explicitly waives the coverage floor.
 *     requiredComponents: ["@method", "@target-uri", "content-digest"],
 *   });
 *   // → { valid, label, keyid, alg, covered, reason?, missing? }
 */

var nodeCrypto       = require("node:crypto");
var bCrypto          = require("./crypto");
var safeUrl          = require("./safe-url");
var safeBuffer       = require("./safe-buffer");
var C                = require("./constants");
var lazyRequire      = require("./lazy-require");
var structuredFields = require("./structured-fields");
var validateOpts     = require("./validate-opts");
var { HttpSigError } = require("./framework-error");

var _err = HttpSigError.factory;

var observability = lazyRequire(function () { return require("./observability"); });

var SUPPORTED_ALGS = Object.freeze(["ed25519", "ml-dsa-65"]);

var DEFAULT_TOLERANCE_MS  = C.TIME.minutes(5);
var DEFAULT_CLOCK_SKEW_MS = C.TIME.minutes(1);

function _sfQuotedString(s) {
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7E) {
      throw _err("http-message-signature/bad-param",
        "httpSig: parameter string contains non-printable byte at offset " + i);
    }
  }
  return safeBuffer.quoteString(s);
}

function _serializeCovered(covered) {
  var parts = covered.map(function (c) {
    var semi = c.indexOf(";");
    if (semi === -1) return _sfQuotedString(c);
    var bare = c.slice(0, semi);
    var paramSuffix = c.slice(semi);
    return _sfQuotedString(bare) + paramSuffix;
  });
  return "(" + parts.join(" ") + ")";
}

function _serializeSigParams(p) {
  var out = "";
  if (typeof p.created === "number") out += ";created=" + p.created;
  if (typeof p.expires === "number") out += ";expires=" + p.expires;
  if (typeof p.nonce === "string") out += ";nonce=" + _sfQuotedString(p.nonce);
  if (typeof p.alg === "string") out += ";alg=" + _sfQuotedString(p.alg);
  if (typeof p.keyid === "string") out += ";keyid=" + _sfQuotedString(p.keyid);
  if (typeof p.tag === "string") out += ";tag=" + _sfQuotedString(p.tag);
  return out;
}

function _resolveDerivedComponent(name, msg) {
  var parsed = msg._parsedUrl;
  switch (name) {
    case "@method":         return msg.method.toUpperCase();
    case "@target-uri":     return msg.url;
    case "@authority":      return parsed.host;
    case "@scheme":         return parsed.protocol.replace(/:$/, "");
    case "@request-target": return parsed.pathname + (parsed.search || "");
    case "@path":           return parsed.pathname;
    case "@query":          return parsed.search || "?";
    case "@status":
      if (typeof msg.status !== "number") {
        throw _err("http-message-signature/missing-status",
          "httpSig: @status referenced but message has no numeric status");
      }
      return String(msg.status);
    default:
      throw _err("http-message-signature/unknown-derived",
        "httpSig: unknown derived component " + JSON.stringify(name));
  }
}

var _QP_SURVIVORS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._";

function _canonQueryParamPart(rawToken) {
  var decoded;
  try {
    decoded = new URLSearchParams("k=" + rawToken.replace(/&/g, "%26")).get("k");
    if (decoded === null) decoded = "";
  } catch (_e) {
    return rawToken;
  }
  var bytes = Buffer.from(decoded, "utf8");
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    var b = bytes[i];
    var ch = String.fromCharCode(b);
    out += _QP_SURVIVORS.indexOf(ch) !== -1
      ? ch
      : "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

function _resolveQueryParam(msg, paramName) {
  var search = (msg._parsedUrl.search || "").replace(/^\?/, "");
  if (search.length === 0) {
    throw _err("http-message-signature/missing-query",
      "httpSig: @query-param;name=" + JSON.stringify(paramName) + " but URL has no query");
  }
  var pairs = search.split("&");
  var wantName = _canonQueryParamPart(paramName);
  for (var i = 0; i < pairs.length; i++) {
    var eq = pairs[i].indexOf("=");
    var rawName = eq === -1 ? pairs[i] : pairs[i].slice(0, eq);
    if (_canonQueryParamPart(rawName) === wantName) {
      return _canonQueryParamPart(eq === -1 ? "" : pairs[i].slice(eq + 1));
    }
  }
  throw _err("http-message-signature/missing-query-param",
    "httpSig: @query-param;name=" + JSON.stringify(paramName) + " not present in URL");
}

var _QP_NAME_PARAM_RE = /;name="((?:[^"\\]|\\.)*)"/;

function _canonicalizeQueryParamIdentifiers(covered) {
  return covered.map(function (raw) {
    if (raw.indexOf("@query-param;") !== 0) return raw;
    return raw.replace(_QP_NAME_PARAM_RE, function (_m, body) {
      var nameVal = structuredFields.unescapeSfStringBody(body);
      return ";name=" + _sfQuotedString(_canonQueryParamPart(nameVal));
    });
  });
}

function _resolveHeader(headers, name) {
  var lower = name.toLowerCase();
  var keys = Object.keys(headers);
  for (var i = 0; i < keys.length; i++) {
    if (keys[i].toLowerCase() === lower) {
      var v = headers[keys[i]];
      if (Array.isArray(v)) return v.map(function (s) { return String(s).trim(); }).join(", ");
      return String(v).trim();
    }
  }
  return null;
}

function _buildSignatureBase(coveredList, params, msg) {
  var lines = [];
  for (var i = 0; i < coveredList.length; i++) {
    var raw = coveredList[i];
    var semicolon = raw.indexOf(";");
    var bare = semicolon === -1 ? raw : raw.slice(0, semicolon);
    var paramSuffix = semicolon === -1 ? "" : raw.slice(semicolon);
    var value;
    if (bare === "@query-param") {
      var nameMatch = paramSuffix.match(/;name="([^"]+)"/);
      if (!nameMatch) {
        throw _err("http-message-signature/bad-query-param",
          "httpSig: @query-param requires ;name=\"...\" parameter");
      }
      value = _resolveQueryParam(msg, nameMatch[1]);
    } else if (bare.charAt(0) === "@") {
      value = _resolveDerivedComponent(bare, msg);
    } else {
      value = _resolveHeader(msg.headers, bare);
      if (value === null) {
        throw _err("http-message-signature/missing-header",
          "httpSig: covered header " + JSON.stringify(bare) + " not present");
      }
    }
    lines.push(_sfQuotedString(bare) + paramSuffix + ": " + value);
  }
  lines.push("\"@signature-params\": " + _serializeCovered(coveredList) +
             _serializeSigParams(params));
  return Buffer.from(lines.join("\n"), "utf8");
}

function contentDigest(body) {
  var buf;
  if (Buffer.isBuffer(body)) buf = body;
  else if (typeof body === "string") buf = Buffer.from(body, "utf8");
  else throw _err("http-message-signature/bad-body",
    "httpSig.contentDigest: body must be a string or Buffer");
  var h = nodeCrypto.createHash("sha3-512").update(buf).digest("base64");
  return "sha3-512=:" + h + ":";
}

function _parseUrl(url) {
  var parsed = safeUrl.parse(url, {
    allowedProtocols: safeUrl.ALLOW_HTTP_TLS,
    errorClass:       HttpSigError,
  });
  return {
    protocol: parsed.protocol,
    host:     parsed.host,
    pathname: parsed.pathname || "/",
    search:   parsed.search || "",
  };
}

function _normalizeMessage(msg) {
  validateOpts.requireObject(msg, "httpSig: message", HttpSigError);
  validateOpts.requireNonEmptyString(msg.method,
    "httpSig: message.method", HttpSigError, "http-message-signature/bad-opt");
  validateOpts.requireNonEmptyString(msg.url,
    "httpSig: message.url", HttpSigError, "http-message-signature/bad-opt");
  if (!msg.headers || typeof msg.headers !== "object") {
    throw _err("http-message-signature/bad-opt", "httpSig: message.headers required");
  }
  return {
    method:  msg.method,
    url:     msg.url,
    headers: msg.headers,
    body:    msg.body,
    status:  msg.status,
    _parsedUrl: _parseUrl(msg.url),
  };
}

function sign(msg, opts) {
  var m = _normalizeMessage(msg);
  validateOpts.requireObject(opts, "httpSig.sign", HttpSigError);
  validateOpts.requireNonEmptyString(opts.keyid,
    "httpSig.sign: keyid", HttpSigError, "http-message-signature/bad-opt");
  if (typeof opts.alg !== "string" || SUPPORTED_ALGS.indexOf(opts.alg) === -1) {
    throw _err("http-message-signature/bad-opt",
      "httpSig.sign: alg must be one of " + SUPPORTED_ALGS.join(", ") +
      " (got " + JSON.stringify(opts.alg) + ")");
  }
  validateOpts.requireNonEmptyString(opts.privateKey,
    "httpSig.sign: privateKey (PEM)", HttpSigError, "http-message-signature/bad-opt");
  var signKeyType = null;
  try { signKeyType = nodeCrypto.createPrivateKey(opts.privateKey).asymmetricKeyType; }
  catch (_e) { signKeyType = null; }
  if (signKeyType !== null && signKeyType !== opts.alg) {
    throw _err("http-message-signature/bad-opt",
      "httpSig.sign: alg '" + opts.alg + "' does not match the private key's type '" +
      signKeyType + "' (the alg label must be bound to the key's real algorithm)");
  }
  if (!Array.isArray(opts.covered) || opts.covered.length === 0) {
    throw _err("http-message-signature/bad-opt", "httpSig.sign: covered must be a non-empty array");
  }
  var label = typeof opts.label === "string" && opts.label.length > 0
    ? opts.label : "sig1";
  var nowSec = Math.floor((opts.now ? opts.now() : Date.now()) / C.TIME.seconds(1));
  var params = {
    created: typeof opts.created === "number" ? opts.created : nowSec,
    expires: typeof opts.expires === "number" ? opts.expires : undefined,
    nonce:   typeof opts.nonce === "string" ? opts.nonce : undefined,
    alg:     opts.alg,
    keyid:   opts.keyid,
    tag:     typeof opts.tag === "string" ? opts.tag : undefined,
  };

  var emittedHeaders = {};
  var coveredLower = opts.covered.map(function (c) { return c.split(";")[0].toLowerCase(); });  // allow:bare-split-on-quoted-header-token-grammar — opts.covered is operator-supplied component-id list (e.g. "content-digest;sf"); component identifiers are RFC 9421 §2.1 derived-field names with token-only grammar; no quoted-string
  if (coveredLower.indexOf("content-digest") !== -1 &&
      _resolveHeader(m.headers, "content-digest") === null) {
    if (m.body == null) {
      throw _err("http-message-signature/bad-opt",
        "httpSig.sign: covered includes content-digest but message.body is missing");
    }
    var digest = contentDigest(m.body);
    emittedHeaders["Content-Digest"] = digest;
    m.headers = Object.assign({}, m.headers, { "content-digest": digest });
  }

  var covered = _canonicalizeQueryParamIdentifiers(opts.covered);
  var base = _buildSignatureBase(covered, params, m);
  var sig;
  try {
    sig = nodeCrypto.sign(null, base, opts.privateKey);
  } catch (e) {
    throw _err("http-message-signature/sign-failed", "httpSig.sign: " + e.message);
  }
  var sigB64 = sig.toString("base64");

  emittedHeaders["Signature-Input"] = label + "=" + _serializeCovered(covered) +
                                      _serializeSigParams(params);
  emittedHeaders["Signature"] = label + "=:" + sigB64 + ":";

  try { observability().safeEvent("httpSig.sign", 1, { outcome: "success", alg: opts.alg }); }
  catch (_e) { /* drop-silent */ }

  return {
    headers:    emittedHeaders,
    label:      label,
    signature:  sigB64,
    base:       base,
  };
}

function _parseSignatureInput(headerValue) {
  var eq = headerValue.indexOf("=");
  if (eq === -1) {
    throw _err("http-message-signature/bad-header", "httpSig: Signature-Input: missing '=' separator");
  }
  var label = headerValue.slice(0, eq).trim();
  var rest = headerValue.slice(eq + 1).trim();
  if (rest.charAt(0) !== "(") {
    throw _err("http-message-signature/bad-header",
      "httpSig: Signature-Input: covered list must start with '('");
  }
  var closeIdx = rest.indexOf(")");
  if (closeIdx === -1) {
    throw _err("http-message-signature/bad-header",
      "httpSig: Signature-Input: covered list missing ')'");
  }
  var coveredRaw = rest.slice(1, closeIdx).trim();
  var paramsRaw = rest.slice(closeIdx + 1);
  var covered = [];
  var i2 = 0;
  while (i2 < coveredRaw.length) {
    while (i2 < coveredRaw.length && /\s/.test(coveredRaw.charAt(i2))) i2++;
    if (i2 >= coveredRaw.length) break;
    if (coveredRaw.charAt(i2) !== "\"") {
      var endTok = i2;
      while (endTok < coveredRaw.length && !/[\s]/.test(coveredRaw.charAt(endTok))) endTok++;
      covered.push(coveredRaw.slice(i2, endTok));
      i2 = endTok;
      continue;
    }
    var qStart = i2 + 1;
    var qEnd = qStart;
    while (qEnd < coveredRaw.length && coveredRaw.charAt(qEnd) !== "\"") {
      if (coveredRaw.charAt(qEnd) === "\\" && qEnd + 1 < coveredRaw.length) qEnd += 2;
      else qEnd++;
    }
    if (qEnd >= coveredRaw.length) {
      throw _err("http-message-signature/bad-header",
        "httpSig: Signature-Input: unterminated quoted token");
    }
    var bareName = structuredFields.unescapeSfStringBody(coveredRaw.slice(qStart, qEnd));
    i2 = qEnd + 1;
    var suffixStart = i2;
    while (i2 < coveredRaw.length && /[^\s]/.test(coveredRaw.charAt(i2))) i2++;
    var suffix = coveredRaw.slice(suffixStart, i2);
    covered.push(bareName + suffix);
  }

  var params = {};
  if (paramsRaw.length > 0) {
    var paramParts = structuredFields.splitTopLevel(paramsRaw, ";");
    for (var j = 0; j < paramParts.length; j++) {
      var part = paramParts[j].trim();
      if (part.length === 0) continue;
      var pEq = part.indexOf("=");
      if (pEq === -1) continue;
      var k = part.slice(0, pEq).trim();
      var vv = part.slice(pEq + 1).trim();
      if (vv.charAt(0) === "\"" && vv.charAt(vv.length - 1) === "\"") {
        var _unq = structuredFields.unquoteSfString(vv);
        params[k] = _unq === null ? vv : _unq;
      } else {
        var num = Number(vv);
        params[k] = isFinite(num) ? num : vv;
      }
    }
  }
  return { label: label, covered: covered, params: params };
}

function _parseSignature(headerValue, label) {
  var prefix = label + "=:";
  if (headerValue.indexOf(prefix) !== 0) {
    var parts = headerValue.split(",");                                                        // allow:bare-split-on-quoted-header-token-grammar — RFC 9421 §2.4 Signature header values are `label=:b64:` form; base64 alphabet excludes `,` and the label tokens are RFC 8941 §3.3.4 sf-token (no DQUOTE in practice)
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (p.indexOf(prefix) === 0) {
        return p.slice(prefix.length).replace(/:$/, "");
      }
    }
    throw _err("http-message-signature/bad-header",
      "httpSig: Signature header has no entry for label " + JSON.stringify(label));
  }
  return headerValue.slice(prefix.length).replace(/:$/, "");
}

function verify(msg, opts) {
  var m = _normalizeMessage(msg);
  opts = opts || {};
  if (typeof opts.keyResolver !== "function") {
    throw _err("http-message-signature/bad-opt",
      "httpSig.verify: keyResolver(keyid, alg) → publicKeyPem required");
  }
  validateOpts.optionalNonEmptyStringArray(opts.requiredComponents,
    "httpSig.verify: requiredComponents", HttpSigError, "http-message-signature/bad-opt");
  var toleranceMs = (typeof opts.toleranceMs === "number" && isFinite(opts.toleranceMs) && opts.toleranceMs >= 0)
    ? opts.toleranceMs : DEFAULT_TOLERANCE_MS;
  var clockSkewMs = (typeof opts.clockSkewMs === "number" && isFinite(opts.clockSkewMs) && opts.clockSkewMs >= 0)
    ? opts.clockSkewMs : DEFAULT_CLOCK_SKEW_MS;
  var nowMs = opts.now ? opts.now() : Date.now();

  var sigInput = _resolveHeader(m.headers, "signature-input");
  var sig = _resolveHeader(m.headers, "signature");
  if (!sigInput) {
    return { valid: false, reason: "missing-signature-input" };
  }
  if (!sig) {
    return { valid: false, reason: "missing-signature" };
  }

  var parsedInput;
  try { parsedInput = _parseSignatureInput(sigInput); }
  catch (e) { return { valid: false, reason: "bad-signature-input", error: e.message }; }

  var p = parsedInput.params;
  if (typeof p.alg !== "string" || SUPPORTED_ALGS.indexOf(p.alg) === -1) {
    return { valid: false, reason: "unsupported-alg", alg: p.alg };
  }
  if (typeof p.keyid !== "string" || p.keyid.length === 0) {
    return { valid: false, reason: "missing-keyid" };
  }
  if (typeof p.created === "number") {
    var ageMs = nowMs - p.created * C.TIME.seconds(1);
    if (ageMs > toleranceMs) {
      return { valid: false, reason: "expired", ageMs: ageMs };
    }
    if (-ageMs > clockSkewMs) {
      return { valid: false, reason: "future", skewMs: -ageMs };
    }
  }
  if (typeof p.expires === "number" && nowMs > p.expires * C.TIME.seconds(1)) {
    return { valid: false, reason: "expires-passed" };
  }

  var publicKeyPem;
  try { publicKeyPem = opts.keyResolver(p.keyid, p.alg); }
  catch (e) { return { valid: false, reason: "key-resolver-threw", error: e.message }; }
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    return { valid: false, reason: "unknown-keyid", keyid: p.keyid };
  }
  var verifyKeyType = null;
  try { verifyKeyType = nodeCrypto.createPublicKey(publicKeyPem).asymmetricKeyType; }
  catch (_e) { verifyKeyType = null; }
  if (verifyKeyType !== null && verifyKeyType !== p.alg) {
    return { valid: false, reason: "alg-key-mismatch", alg: p.alg, keyType: verifyKeyType };
  }

  var coveredLower = parsedInput.covered.map(function (c) { return c.split(";")[0].toLowerCase(); });  // allow:bare-split-on-quoted-header-token-grammar — same as sign() above: covered items are RFC 9421 §2.1 component-ids, token grammar

  function _componentKey(c) {
    var semi = c.indexOf(";");
    return semi === -1 ? c.toLowerCase() : c.slice(0, semi).toLowerCase() + c.slice(semi);
  }
  var requiredComponents;
  if (opts.requiredComponents !== undefined && opts.requiredComponents !== null) {
    requiredComponents = opts.requiredComponents.map(_componentKey);
  } else {
    requiredComponents = ["@method", "@target-uri"];
    if (m.body != null) requiredComponents.push("content-digest");
  }
  var coveredKeys = parsedInput.covered.map(_componentKey);
  var missingComponents = [];
  for (var rci = 0; rci < requiredComponents.length; rci += 1) {
    if (coveredKeys.indexOf(requiredComponents[rci]) === -1) missingComponents.push(requiredComponents[rci]);
  }
  if (missingComponents.length > 0) {
    return { valid: false, reason: "missing-required-component", missing: missingComponents };
  }

  if (coveredLower.indexOf("content-digest") !== -1) {
    if (m.body == null) {
      return { valid: false, reason: "content-digest-no-body" };
    }
    var presented = _resolveHeader(m.headers, "content-digest");
    if (!presented) {
      return { valid: false, reason: "content-digest-header-missing" };
    }
    var expectedDigest = contentDigest(m.body);
    var digestMembers  = structuredFields.splitTopLevel(presented, ",");
    var offeredDigests = [];
    for (var di = 0; di < digestMembers.length; di++) {
      var member = digestMembers[di].trim();
      var deq = member.indexOf("=");
      if (deq < 1) continue;
      var dkv = structuredFields.parseKeyValuePiece(member);
      if (dkv.key !== "sha3-512") continue;
      offeredDigests.push("sha3-512=" + dkv.value.trim());
    }
    var matchedDigest = bCrypto.timingSafeEqualAny(expectedDigest, offeredDigests);
    if (!matchedDigest) {
      return { valid: false, reason: "content-digest-mismatch" };
    }
  }

  var sigB64;
  try { sigB64 = _parseSignature(sig, parsedInput.label); }
  catch (e) { return { valid: false, reason: "bad-signature-header", error: e.message }; }
  if (!safeBuffer.isCanonicalBase64(sigB64)) {
    return { valid: false, reason: "bad-signature-encoding" };
  }
  var sigBuf;
  try { sigBuf = Buffer.from(sigB64, "base64"); }
  catch (_e) { return { valid: false, reason: "bad-signature-encoding" }; }

  var paramsForBase = {
    created: p.created,
    expires: p.expires,
    nonce:   p.nonce,
    alg:     p.alg,
    keyid:   p.keyid,
    tag:     p.tag,
  };
  var base;
  try { base = _buildSignatureBase(parsedInput.covered, paramsForBase, m); }
  catch (e) { return { valid: false, reason: "build-base-failed", error: e.message }; }

  var ok;
  try { ok = nodeCrypto.verify(null, base, publicKeyPem, sigBuf); }
  catch (e) { return { valid: false, reason: "verify-threw", error: e.message }; }

  try { observability().safeEvent("httpSig.verify", 1, { outcome: ok ? "success" : "failure", alg: p.alg }); }
  catch (_e) { /* drop-silent */ }

  if (!ok) {
    return { valid: false, reason: "bad-signature", keyid: p.keyid, alg: p.alg };
  }
  return {
    valid:   true,
    label:   parsedInput.label,
    keyid:   p.keyid,
    alg:     p.alg,
    covered: parsedInput.covered,
    created: p.created,
    expires: p.expires,
    nonce:   p.nonce,
  };
}

module.exports = {
  sign:           sign,
  verify:         verify,
  contentDigest:  contentDigest,
  SUPPORTED_ALGS: SUPPORTED_ALGS,
  HttpSigError:   HttpSigError,
};
