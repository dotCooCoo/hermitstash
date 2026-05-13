"use strict";
/**
 * @module     b.auth.saml
 * @nav        Identity
 * @title      SAML 2.0 SP
 * @order      370
 * @card       SAML 2.0 Service Provider primitive — builds AuthnRequests,
 *             parses + verifies IdP-signed Responses, validates the
 *             assertion's SubjectConfirmation / Conditions, and
 *             defends against XML signature-wrapping via
 *             `b.xmlC14n.canonicalizeElementById`'s single-match
 *             invariant.
 *
 * @intro
 *   SAML 2.0 (OASIS) is the federation protocol financial /
 *   government / enterprise IdPs still ship — operators can't always
 *   require an OIDC IdP. This primitive implements the SP side
 *   only:
 *
 *     - AuthnRequest builder (HTTP-Redirect + HTTP-POST bindings)
 *     - Response parser:
 *         * Verify Response or Assertion XMLDSig (whichever the IdP
 *           signed) using the IdP's signing certificate
 *         * Refuse signature-wrapping by enforcing single-element-
 *           match on the Reference URI (via xml-c14n)
 *         * Validate `NotOnOrAfter` / `NotBefore` / `Recipient` /
 *           `InResponseTo` on SubjectConfirmation
 *         * Validate `Conditions/NotBefore`/`NotOnOrAfter`/
 *           `AudienceRestriction`
 *     - SP metadata XML emitter
 *     - MDQ (RFC 8414-style metadata-query) fetch with strict
 *       server-identity per RFC 9525
 *
 *   Operators wire two routes:
 *
 *     /saml/login   → returns the AuthnRequest URL (Redirect binding)
 *                     OR an HTML form (POST binding) the user-agent
 *                     submits to the IdP's SSO endpoint.
 *     /saml/acs     → AssertionConsumerService — receives the IdP's
 *                     SAMLResponse, calls verifyResponse, hydrates
 *                     the user session.
 *
 *   Storage of `InResponseTo` / RelayState pre-image / nonce is
 *   operator-side via b.cache or b.session — the framework gives the
 *   parsing + verification primitive; operators wire freshness +
 *   replay defense.
 */

var lazyRequire  = require("../lazy-require");
var validateOpts = require("../validate-opts");
var nodeCrypto   = require("node:crypto");
var { generateToken, timingSafeEqual } = require("../crypto");
var { AuthError } = require("../framework-error");

var xmlC14n   = lazyRequire(function () { return require("../xml-c14n"); });
var httpClient = lazyRequire(function () { return require("../http-client"); });
var audit     = lazyRequire(function () { return require("../audit"); });
var observability = lazyRequire(function () { return require("../observability"); });
var emit = validateOpts.makeNamespacedEmitters("auth.saml", { audit: audit, observability: observability });

var SUPPORTED_DIGEST = { "http://www.w3.org/2001/04/xmlenc#sha256": "sha256",
                         "http://www.w3.org/2001/04/xmlenc#sha384": "sha384",
                         "http://www.w3.org/2001/04/xmlenc#sha512": "sha512" };
var SUPPORTED_SIG    = { "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   { hash: "sha256", padding: "pkcs1" },
                         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   { hash: "sha384", padding: "pkcs1" },
                         "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   { hash: "sha512", padding: "pkcs1" },
                         "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": { hash: "sha256", ec: true },
                         "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": { hash: "sha384", ec: true },
                         "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": { hash: "sha512", ec: true } };
var SAML_NS = {
  protocol:  "urn:oasis:names:tc:SAML:2.0:protocol",
  assertion: "urn:oasis:names:tc:SAML:2.0:assertion",
  metadata:  "urn:oasis:names:tc:SAML:2.0:metadata",
};

var _emitAudit  = emit.audit;
var _emitMetric = emit.metric;

function _findChild(node, localName, namespace) {
  if (!node || !node.children) return null;
  for (var i = 0; i < node.children.length; i++) {
    var c = node.children[i];
    if (c.type !== "element") continue;
    var colon = c.name.indexOf(":");
    var local = colon !== -1 ? c.name.substring(colon + 1) : c.name;
    if (local !== localName) continue;
    if (namespace) {
      var prefix = colon !== -1 ? c.name.substring(0, colon) : "";
      var ns = _namespaceForPrefix(c, prefix);
      if (ns !== namespace) continue;
    }
    return c;
  }
  return null;
}

function _findAllChildren(node, localName, namespace) {
  var out = [];
  if (!node || !node.children) return out;
  for (var i = 0; i < node.children.length; i++) {
    var c = node.children[i];
    if (c.type !== "element") continue;
    var colon = c.name.indexOf(":");
    var local = colon !== -1 ? c.name.substring(colon + 1) : c.name;
    if (local !== localName) continue;
    if (namespace) {
      var prefix = colon !== -1 ? c.name.substring(0, colon) : "";
      var ns = _namespaceForPrefix(c, prefix);
      if (ns !== namespace) continue;
    }
    out.push(c);
  }
  return out;
}

function _namespaceForPrefix(node, prefix) {
  var cur = node;
  while (cur) {
    if (cur.attrs) {
      for (var i = 0; i < cur.attrs.length; i++) {
        var a = cur.attrs[i];
        if (prefix === "" && a.name === "xmlns") return a.value;
        if (a.name === "xmlns:" + prefix) return a.value;
      }
    }
    cur = cur.parent;
  }
  return null;
}

function _attr(node, name) {
  if (!node || !node.attrs) return null;
  for (var i = 0; i < node.attrs.length; i++) {
    if (node.attrs[i].name === name) return node.attrs[i].value;
  }
  return null;
}

function _textContent(node) {
  if (!node || !node.children) return "";
  var out = "";
  for (var i = 0; i < node.children.length; i++) {
    var c = node.children[i];
    if (c.type === "text") out += c.text;
    else if (c.type === "element") out += _textContent(c);
  }
  return out.trim();
}

function _verifyXmldsig(envelope, signatureNode, certPem) {
  // Parse SignedInfo + extract canonicalization, signature, and
  // reference algorithms. Then:
  //   1. Locate the referenced element by its ID attribute (single-
  //      match invariant from xml-c14n.canonicalizeElementById)
  //   2. C14n + hash that element, compare to Reference DigestValue
  //   3. C14n SignedInfo, verify the signature against the cert pubkey
  var signedInfo = _findChild(signatureNode, "SignedInfo");
  if (!signedInfo) {
    throw new AuthError("auth-saml/no-signed-info", "Signature missing SignedInfo");
  }
  var canonMethodNode = _findChild(signedInfo, "CanonicalizationMethod");
  var canonAlgo = canonMethodNode && _attr(canonMethodNode, "Algorithm");
  if (canonAlgo !== "http://www.w3.org/2001/10/xml-exc-c14n#" &&
      canonAlgo !== "http://www.w3.org/2001/10/xml-exc-c14n#WithComments") {
    throw new AuthError("auth-saml/unsupported-c14n",
      "Unsupported CanonicalizationMethod: " + canonAlgo + " (only xml-exc-c14n supported)");
  }
  var sigMethodNode = _findChild(signedInfo, "SignatureMethod");
  var sigAlgo = sigMethodNode && _attr(sigMethodNode, "Algorithm");
  if (!SUPPORTED_SIG[sigAlgo]) {
    throw new AuthError("auth-saml/unsupported-sig-alg",
      "Unsupported SignatureMethod: " + sigAlgo);
  }
  var refNode = _findChild(signedInfo, "Reference");
  if (!refNode) throw new AuthError("auth-saml/no-reference", "SignedInfo missing Reference");
  var refUri = _attr(refNode, "URI") || "";
  if (refUri.charAt(0) !== "#") {
    throw new AuthError("auth-saml/external-reference",
      "Reference URI must be a same-document fragment (got \"" + refUri + "\")");
  }
  var refId = refUri.substring(1);
  var digestMethodNode = _findChild(refNode, "DigestMethod");
  var digestAlgo = digestMethodNode && _attr(digestMethodNode, "Algorithm");
  if (!SUPPORTED_DIGEST[digestAlgo]) {
    throw new AuthError("auth-saml/unsupported-digest",
      "Unsupported DigestMethod: " + digestAlgo);
  }
  var digestValueNode = _findChild(refNode, "DigestValue");
  var expectedDigestB64 = _textContent(digestValueNode);
  if (!expectedDigestB64) {
    throw new AuthError("auth-saml/no-digest-value", "Reference missing DigestValue");
  }
  var withComments = canonAlgo.indexOf("#WithComments") !== -1;

  // XMLDSig Reference Transforms — applied in order before the digest.
  // SAML responses commonly use:
  //   1. http://www.w3.org/2000/09/xmldsig#enveloped-signature  (strip
  //      the <Signature> child of the referenced element)
  //   2. http://www.w3.org/2001/10/xml-exc-c14n#                (canonicalize)
  // Without the enveloped-signature transform, the digest is computed
  // over the assertion-including-signature, which never matches the
  // signed-then-signature-injected reality.
  var transformsNode = _findChild(refNode, "Transforms");
  var transformList = transformsNode ? _findAllChildren(transformsNode, "Transform") : [];
  var stripSignature = false;
  var refC14nWithComments = withComments;
  for (var ti = 0; ti < transformList.length; ti++) {
    var algo = _attr(transformList[ti], "Algorithm");
    switch (algo) {
      case "http://www.w3.org/2000/09/xmldsig#enveloped-signature":
        stripSignature = true;
        break;
      case "http://www.w3.org/2001/10/xml-exc-c14n#":
        refC14nWithComments = false;
        break;
      case "http://www.w3.org/2001/10/xml-exc-c14n#WithComments":
        refC14nWithComments = true;
        break;
      default:
        throw new AuthError("auth-saml/unsupported-transform",
          "Unsupported Transform: " + algo + " (supported: enveloped-signature, xml-exc-c14n)");
    }
  }

  // Locate the referenced element with the single-match invariant
  // (anti-wrapping defense) — if zero or duplicate IDs match, refuse.
  // We then optionally strip its <Signature> child(ren) per the
  // enveloped-signature transform and canonicalize the result.
  var c14n = xmlC14n();
  var rootForRef = c14n.parse(envelope);
  var matches = [];
  (function _walk(node) {
    if (node.type !== "element") return;
    if (node.attrs) {
      for (var ai = 0; ai < node.attrs.length; ai++) {
        if (node.attrs[ai].name === "ID" && node.attrs[ai].value === refId) {
          matches.push(node);
          break;
        }
      }
    }
    for (var ci = 0; ci < node.children.length; ci++) _walk(node.children[ci]);
  })(rootForRef);
  if (matches.length === 0) {
    throw new AuthError("auth-saml/no-id-match",
      "Reference URI #" + refId + " resolves to no element");
  }
  if (matches.length > 1) {
    throw new AuthError("auth-saml/duplicate-id",
      "Reference URI #" + refId + " matches " + matches.length +
      " elements — refused (signature-wrapping defense)");
  }
  var refTarget = matches[0];
  if (stripSignature) {
    refTarget.children = refTarget.children.filter(function (c) {
      if (c.type !== "element") return true;
      var colon = c.name.indexOf(":");
      var local = colon !== -1 ? c.name.substring(colon + 1) : c.name;
      return local !== "Signature";
    });
  }
  var canonical = c14n.canonicalize(refTarget, { withComments: refC14nWithComments });
  var actualDigest = nodeCrypto.createHash(SUPPORTED_DIGEST[digestAlgo]).update(canonical).digest();
  // Constant-time compare — Buffer.compare short-circuits per byte and
  // leaks the matching-prefix length when the operator's audit/log
  // captures verify-failure timing. timingSafeEqual returns false for
  // length-mismatched inputs without leaking length.
  if (!timingSafeEqual(Buffer.from(expectedDigestB64, "base64"), actualDigest)) {
    throw new AuthError("auth-saml/digest-mismatch",
      "Reference DigestValue does not match canonicalized referenced element (signature-wrapping or tampered content)");
  }

  // C14n SignedInfo as a parsed-tree node — we need to canonicalize
  // the SignedInfo element ITSELF, not look it up by ID. Slice the
  // serialized SignedInfo from the parsed tree.
  var signedInfoCanonical = xmlC14n().canonicalize(signedInfo, { withComments: withComments });

  // Resolve signer key from cert
  var cert = nodeCrypto.createPublicKey({ key: certPem, format: "pem" });

  var sigValueNode = _findChild(signatureNode, "SignatureValue");
  var sigB64 = _textContent(sigValueNode).replace(/\s+/g, "");
  if (!sigB64) throw new AuthError("auth-saml/no-signature-value", "Signature missing SignatureValue");
  var sigBytes = Buffer.from(sigB64, "base64");

  var sigSpec = SUPPORTED_SIG[sigAlgo];
  var verifyOpts = { key: cert };
  if (sigSpec.padding === "pkcs1") verifyOpts.padding = nodeCrypto.constants.RSA_PKCS1_PADDING;
  if (sigSpec.ec) verifyOpts.dsaEncoding = "der";
  var ok = nodeCrypto.verify(sigSpec.hash, signedInfoCanonical, verifyOpts, sigBytes);
  if (!ok) {
    throw new AuthError("auth-saml/bad-signature", "SAML signature verification failed");
  }
  return { refId: refId };
}

/**
 * @primitive b.auth.saml.sp.create
 * @signature b.auth.saml.sp.create(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.xmlC14n.canonicalizeElementById, b.network.tls.checkServerIdentity9525
 *
 * Build a SAML 2.0 SP. Operators supply:
 *   - the SP entityId (this RP's URL)
 *   - assertionConsumerServiceUrl (the /saml/acs route)
 *   - idpEntityId + idpSsoUrl + idpCertPem (the trust anchor for
 *     this SP — typically rotated quarterly via MDQ)
 *
 * @opts
 *   {
 *     entityId:                    string,    // this SP's entityID URL
 *     assertionConsumerServiceUrl: string,    // SP /saml/acs endpoint
 *     idpEntityId:                 string,
 *     idpSsoUrl:                   string,    // IdP single-sign-on endpoint
 *     idpCertPem:                  string,    // IdP signing cert (PEM)
 *     audience?:                   string,    // default = entityId
 *     clockSkewSec?:               number,    // default 60
 *     nameIdFormat?:               string,    // optional NameIDPolicy/Format
 *   }
 *
 * @example
 *   var sp = b.auth.saml.sp.create({
 *     entityId:                    "https://sp.example",
 *     assertionConsumerServiceUrl: "https://sp.example/saml/acs",
 *     idpEntityId:                 "https://idp.example",
 *     idpSsoUrl:                   "https://idp.example/sso",
 *     idpCertPem:                  process.env.IDP_CERT_PEM,
 *   });
 */
function create(opts) {
  validateOpts.requireObject(opts, "auth.saml.sp.create", AuthError);
  validateOpts.requireNonEmptyString(opts.entityId, "entityId", AuthError, "auth-saml/no-entity-id");
  validateOpts.requireNonEmptyString(opts.assertionConsumerServiceUrl, "assertionConsumerServiceUrl",
    AuthError, "auth-saml/no-acs");
  validateOpts.requireNonEmptyString(opts.idpEntityId, "idpEntityId", AuthError, "auth-saml/no-idp-entity-id");
  validateOpts.requireNonEmptyString(opts.idpSsoUrl, "idpSsoUrl", AuthError, "auth-saml/no-idp-sso");
  validateOpts.requireNonEmptyString(opts.idpCertPem, "idpCertPem", AuthError, "auth-saml/no-idp-cert");

  var audience = opts.audience || opts.entityId;
  var clockSkewSec = typeof opts.clockSkewSec === "number" ? opts.clockSkewSec : 60;             // allow:raw-time-literal — clock-skew default

  /**
   * @primitive b.auth.saml.sp.buildAuthnRequest
   * @signature b.auth.saml.sp.buildAuthnRequest(opts)
   * @since     0.8.62
   *
   * Build a SAMLRequest XML + the URL-safe deflate-base64 encoding
   * for the HTTP-Redirect binding. Returns `{ id, redirectUrl, raw }`
   * where `id` is the AuthnRequest ID the SP must remember (binds to
   * the response's `InResponseTo`).
   *
   * @opts
   *   { relayState?: string }
   *
   * @example
   *   var ar = sp.buildAuthnRequest({ relayState: "/dashboard" });
   *   res.statusCode = 302;
   *   res.setHeader("Location", ar.redirectUrl);
   *   res.end();
   *   // remember ar.id; expect it back in the Response InResponseTo
   */
  function buildAuthnRequest(bopts) {
    bopts = bopts || {};
    var id = "_" + generateToken(20);
    var issueInstant = new Date().toISOString();
    // RFC 3741 §1.3.2 attribute-value + §1.3.1 element-text escaping
    // for every operator-supplied string interpolated into the
    // AuthnRequest XML. Without escaping, a `"` or `<` in any of the
    // four fields (idpSsoUrl, assertionConsumerServiceUrl, entityId,
    // nameIdFormat) produces malformed XML and can break out of the
    // attribute / element context, injecting unsigned content the IdP
    // canonicalizer would never honor but the consumer's signed XML
    // baseline relies on. (Surfaced by the 2026-05-11 SAML audit.)
    var c14n = xmlC14n();
    var nameIdPolicy = "";
    if (opts.nameIdFormat) {
      nameIdPolicy = "<samlp:NameIDPolicy Format=\"" + c14n.escapeAttrValue(opts.nameIdFormat) +
                     "\" AllowCreate=\"true\"/>";
    }
    var xml =
      "<samlp:AuthnRequest xmlns:samlp=\"" + SAML_NS.protocol + "\" " +
      "xmlns:saml=\"" + SAML_NS.assertion + "\" " +
      "ID=\"" + id + "\" " +
      "Version=\"2.0\" " +
      "IssueInstant=\"" + issueInstant + "\" " +
      "Destination=\"" + c14n.escapeAttrValue(opts.idpSsoUrl) + "\" " +
      "AssertionConsumerServiceURL=\"" + c14n.escapeAttrValue(opts.assertionConsumerServiceUrl) + "\" " +
      "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">" +
      "<saml:Issuer>" + c14n.escapeText(opts.entityId) + "</saml:Issuer>" +
      nameIdPolicy +
      "</samlp:AuthnRequest>";
    var zlib = require("node:zlib");
    var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"));
    var samlRequest = encodeURIComponent(deflated.toString("base64"));
    var url = opts.idpSsoUrl + (opts.idpSsoUrl.indexOf("?") === -1 ? "?" : "&") +
              "SAMLRequest=" + samlRequest;
    if (bopts.relayState) {
      url += "&RelayState=" + encodeURIComponent(bopts.relayState);
    }
    _emitAudit("authnrequest_built", "success", { id: id, idp: opts.idpEntityId });
    _emitMetric("authn-request-built");
    return { id: id, redirectUrl: url, raw: xml };
  }

  /**
   * @primitive b.auth.saml.sp.verifyResponse
   * @signature b.auth.saml.sp.verifyResponse(samlResponseB64, vopts)
   * @since     0.8.62
   *
   * Parse + verify the IdP's SAMLResponse (the base64-encoded XML
   * the user-agent POSTs to /saml/acs). Validates the XMLDSig
   * (Response-level OR Assertion-level signature), the assertion's
   * SubjectConfirmation Bearer constraints, and Conditions audience
   * + time bounds. Returns `{ nameId, nameIdFormat, sessionIndex,
   * attributes, audience, inResponseTo }`.
   *
   * @opts
   *   {
   *     expectedInResponseTo?: string,   // the AuthnRequest ID this is responding to
   *     now?:                  number,   // timestamp override for tests
   *   }
   *
   * @example
   *   app.post("/saml/acs", function (req, res) {
   *     var info = sp.verifyResponse(req.body.SAMLResponse, {
   *       expectedInResponseTo: req.session.samlRequestId,
   *     });
   *     // → { nameId, nameIdFormat, sessionIndex, attributes, audience, issuer }
   *   });
   */
  function verifyResponse(samlResponseB64, vopts) {
    vopts = vopts || {};
    if (typeof samlResponseB64 !== "string" || samlResponseB64.length === 0) {
      throw new AuthError("auth-saml/no-response", "verifyResponse: SAMLResponse required");
    }
    var xml = Buffer.from(samlResponseB64, "base64").toString("utf8");
    if (!xml || xml.indexOf("<") === -1) {
      throw new AuthError("auth-saml/bad-response-decode",
        "verifyResponse: SAMLResponse base64 decode produced no XML");
    }
    var c14n = xmlC14n();
    var root = c14n.parse(xml);
    // Root must be Response
    var rootColon = root.name.indexOf(":");
    var rootLocal = rootColon !== -1 ? root.name.substring(rootColon + 1) : root.name;
    if (rootLocal !== "Response") {
      throw new AuthError("auth-saml/wrong-root",
        "verifyResponse: root element must be Response, got " + rootLocal);
    }

    // XSW defense — refuse duplicate top-level security-critical
    // elements. SAML XML signature wrapping (XSW) attacks shuffle
    // signed elements alongside unsigned siblings; the parser's
    // first-match `_findChild` lookup combined with the signed-
    // element-ID check at L479 was vulnerable to a multi-Assertion
    // payload where the verifier signed one but the consumer read
    // attributes from another. Reject any Response with more than
    // one of these structural children (Audit 2026-05-11).
    var statusChildren = _findAllChildren(root, "Status", SAML_NS.protocol);
    if (statusChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-status",
        "verifyResponse: Response has multiple <Status> children — XSW shape refused");
    }
    var status = statusChildren[0] || null;
    var statusCodeChildren = status ? _findAllChildren(status, "StatusCode", SAML_NS.protocol) : [];
    if (statusCodeChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-status-code",
        "verifyResponse: <Status> has multiple <StatusCode> children — XSW shape refused");
    }
    var statusCode = statusCodeChildren[0] || null;
    var statusValue = statusCode && _attr(statusCode, "Value");
    if (statusValue !== "urn:oasis:names:tc:SAML:2.0:status:Success") {
      throw new AuthError("auth-saml/bad-status",
        "verifyResponse: SAML Status is not Success: " + statusValue);
    }

    // Validate signature: prefer Assertion-level (most secure — the
    // assertion is the security-critical element). Fall back to
    // Response-level when the IdP signs the envelope only.
    var assertionChildren = _findAllChildren(root, "Assertion", SAML_NS.assertion);
    if (assertionChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-assertion",
        "verifyResponse: Response has multiple <Assertion> children — XSW shape refused");
    }
    var assertion = assertionChildren[0] || null;
    if (!assertion) {
      throw new AuthError("auth-saml/no-assertion", "verifyResponse: Response has no Assertion");
    }

    var assertionSignature = _findChild(assertion, "Signature");
    var responseSignature = _findChild(root, "Signature");

    if (!assertionSignature && !responseSignature) {
      throw new AuthError("auth-saml/unsigned",
        "verifyResponse: neither Response nor Assertion is signed — SAML SP refuses unsigned responses");
    }
    var signed;
    if (assertionSignature) {
      signed = _verifyXmldsig(xml, assertionSignature, opts.idpCertPem);
      if (signed.refId !== _attr(assertion, "ID")) {
        throw new AuthError("auth-saml/signed-different-element",
          "verifyResponse: assertion signature references a different element ID");
      }
    } else {
      signed = _verifyXmldsig(xml, responseSignature, opts.idpCertPem);
      if (signed.refId !== _attr(root, "ID")) {
        throw new AuthError("auth-saml/signed-different-element",
          "verifyResponse: response signature references a different element ID");
      }
    }

    // Issuer must match the configured IdP entityID
    var issuerEl = _findChild(assertion, "Issuer", SAML_NS.assertion);
    var issuer = _textContent(issuerEl);
    if (issuer !== opts.idpEntityId) {
      throw new AuthError("auth-saml/wrong-issuer",
        "verifyResponse: Assertion Issuer \"" + issuer + "\" does not match expected \"" +
        opts.idpEntityId + "\"");
    }

    // Subject + SubjectConfirmation — XSW: refuse duplicate <Subject>.
    var subjectChildren = _findAllChildren(assertion, "Subject", SAML_NS.assertion);
    if (subjectChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-subject",
        "verifyResponse: Assertion has multiple <Subject> children — XSW shape refused");
    }
    var subject = subjectChildren[0] || null;
    if (!subject) throw new AuthError("auth-saml/no-subject", "verifyResponse: missing Subject");
    var nameIdChildren = _findAllChildren(subject, "NameID", SAML_NS.assertion);
    if (nameIdChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-nameid",
        "verifyResponse: <Subject> has multiple <NameID> children — XSW shape refused");
    }
    var nameIdEl = nameIdChildren[0] || null;
    if (!nameIdEl) throw new AuthError("auth-saml/no-nameid", "verifyResponse: missing NameID");
    var nameId = _textContent(nameIdEl);
    var nameIdFormat = _attr(nameIdEl, "Format");

    var nowSec = Math.floor((vopts.now || Date.now()) / 1000);                                  // allow:raw-byte-literal — ms→s
    var confirmations = _findAllChildren(subject, "SubjectConfirmation", SAML_NS.assertion);
    var bearerOk = false;
    for (var i = 0; i < confirmations.length; i++) {
      var sc = confirmations[i];
      if (_attr(sc, "Method") !== "urn:oasis:names:tc:SAML:2.0:cm:bearer") continue;
      var scd = _findChild(sc, "SubjectConfirmationData", SAML_NS.assertion);
      if (!scd) continue;
      var notOnOrAfter = _attr(scd, "NotOnOrAfter");
      if (notOnOrAfter) {
        var t = Date.parse(notOnOrAfter) / 1000;                                                // allow:raw-byte-literal — ms→s
        if (!isFinite(t) || t < nowSec - clockSkewSec) {
          continue; // expired confirmation — try next
        }
      }
      var notBefore = _attr(scd, "NotBefore");
      if (notBefore) {
        var nb = Date.parse(notBefore) / 1000;                                                  // allow:raw-byte-literal — ms→s
        if (isFinite(nb) && nb > nowSec + clockSkewSec) continue;
      }
      var recipient = _attr(scd, "Recipient");
      if (recipient && recipient !== opts.assertionConsumerServiceUrl) {
        continue;
      }
      var inResponseTo = _attr(scd, "InResponseTo");
      if (vopts.expectedInResponseTo) {
        // Constant-time compare against the AuthnRequest ID the
        // operator stored — protects against timing-based InResponseTo
        // probing. timingSafeEqual returns false for missing /
        // length-mismatch without leaking. (Audit 2026-05-11.)
        if (inResponseTo === null || inResponseTo === undefined ||
            !timingSafeEqual(inResponseTo, vopts.expectedInResponseTo)) {
          throw new AuthError("auth-saml/bad-in-response-to",
            "SubjectConfirmation InResponseTo does not match expected " +
            "AuthnRequest ID (replay defense)");
        }
      }
      bearerOk = true;
      break;
    }
    if (!bearerOk) {
      throw new AuthError("auth-saml/no-valid-bearer",
        "verifyResponse: no Bearer SubjectConfirmation passed time/recipient checks");
    }

    // Conditions
    var conditions = _findChild(assertion, "Conditions", SAML_NS.assertion);
    if (conditions) {
      var cNotBefore = _attr(conditions, "NotBefore");
      var cNotOnOrAfter = _attr(conditions, "NotOnOrAfter");
      if (cNotBefore) {
        var cnb = Date.parse(cNotBefore) / 1000;                                                // allow:raw-byte-literal — ms→s
        if (isFinite(cnb) && cnb > nowSec + clockSkewSec) {
          throw new AuthError("auth-saml/conditions-not-yet-valid",
            "Conditions NotBefore is in the future");
        }
      }
      if (cNotOnOrAfter) {
        var cnoa = Date.parse(cNotOnOrAfter) / 1000;                                            // allow:raw-byte-literal — ms→s
        if (isFinite(cnoa) && cnoa < nowSec - clockSkewSec) {
          throw new AuthError("auth-saml/conditions-expired",
            "Conditions NotOnOrAfter has passed");
        }
      }
      var ar = _findChild(conditions, "AudienceRestriction", SAML_NS.assertion);
      if (ar) {
        var audiences = _findAllChildren(ar, "Audience", SAML_NS.assertion).map(_textContent);
        if (audiences.indexOf(audience) === -1) {
          throw new AuthError("auth-saml/wrong-audience",
            "Audience \"" + audience + "\" not in assertion's AudienceRestriction (got " +
            JSON.stringify(audiences) + ")");
        }
      }
    }

    // AuthnStatement.SessionIndex (for SLO)
    var sessionIndex = null;
    var authnStmt = _findChild(assertion, "AuthnStatement", SAML_NS.assertion);
    if (authnStmt) {
      sessionIndex = _attr(authnStmt, "SessionIndex");
    }

    // AttributeStatement → flat map
    var attributes = {};
    var attrStmt = _findChild(assertion, "AttributeStatement", SAML_NS.assertion);
    if (attrStmt) {
      var attrEls = _findAllChildren(attrStmt, "Attribute", SAML_NS.assertion);
      for (var ai = 0; ai < attrEls.length; ai++) {
        var n = _attr(attrEls[ai], "Name");
        var values = _findAllChildren(attrEls[ai], "AttributeValue", SAML_NS.assertion).map(_textContent);
        attributes[n] = values.length === 1 ? values[0] : values;
      }
    }

    _emitAudit("response_verified", "success", { issuer: issuer });
    _emitMetric("response-verified");
    return {
      nameId:          nameId,
      nameIdFormat:    nameIdFormat,
      sessionIndex:    sessionIndex,
      attributes:      attributes,
      audience:        audience,
      inResponseTo:    bearerOk ? _attr(_findChild(_findChild(subject, "SubjectConfirmation", SAML_NS.assertion),
                                       "SubjectConfirmationData", SAML_NS.assertion), "InResponseTo") : null,
      issuer:          issuer,
    };
  }

  /**
   * @primitive b.auth.saml.sp.metadata
   * @signature b.auth.saml.sp.metadata()
   * @since     0.8.62
   *
   * Emit the SP's `EntityDescriptor` XML for IdP-side configuration.
   * Operators serve this verbatim at /saml/metadata.
   *
   * @example
   *   app.get("/saml/metadata", function (req, res) {
   *     res.setHeader("Content-Type", "application/samlmetadata+xml");
   *     res.end(sp.metadata());
   *   });
   */
  function metadata() {
    // RFC 3741 attr/text escaping for operator-supplied URLs / IDs —
    // same audit-finding shape as buildAuthnRequest above.
    var c14n = xmlC14n();
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
      "<md:EntityDescriptor xmlns:md=\"" + SAML_NS.metadata + "\" entityID=\"" + c14n.escapeAttrValue(opts.entityId) + "\">" +
      "<md:SPSSODescriptor protocolSupportEnumeration=\"" + SAML_NS.protocol + "\" " +
      "AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">" +
      "<md:AssertionConsumerService " +
      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " +
      "Location=\"" + c14n.escapeAttrValue(opts.assertionConsumerServiceUrl) + "\" index=\"0\"/>" +
      "</md:SPSSODescriptor>" +
      "</md:EntityDescriptor>";
  }

  return {
    buildAuthnRequest: buildAuthnRequest,
    verifyResponse:    verifyResponse,
    metadata:          metadata,
    entityId:          opts.entityId,
    idpEntityId:       opts.idpEntityId,
  };
}

/**
 * @primitive b.auth.saml.fetchMdq
 * @signature b.auth.saml.fetchMdq(opts)
 * @since     0.8.62
 * @status    stable
 * @related   b.auth.saml.sp.create, b.network.tls.checkServerIdentity9525
 *
 * Fetch an entity's signed metadata from a Metadata Query (MDQ)
 * server per SAML 2.0 MDQ. Composes b.httpClient with strict server-
 * identity (RFC 9525) and verifies the metadata XMLDSig against the
 * operator-supplied trust cert. Returns the raw metadata XML on
 * success.
 *
 * The MDQ URL pattern is `<baseUrl>/entities/{sha1(entityId)}` per
 * the spec — operators with a federation MDQ deployment supply the
 * baseUrl + their pinned trust cert.
 *
 * @opts
 *   {
 *     baseUrl:        string,
 *     entityId:       string,
 *     trustCertPem?:  string,    // PEM of the federation operator's signing cert
 *   }
 *
 * @example
 *   var xml = await b.auth.saml.fetchMdq({
 *     baseUrl:      "https://mdq.federation.example",
 *     entityId:     "https://idp.example",
 *     trustCertPem: process.env.FEDERATION_TRUST_CERT_PEM,
 *   });
 */
async function fetchMdq(opts) {
  validateOpts.requireObject(opts, "auth.saml.fetchMdq", AuthError);
  validateOpts.requireNonEmptyString(opts.baseUrl, "baseUrl", AuthError, "auth-saml/no-mdq-base");
  validateOpts.requireNonEmptyString(opts.entityId, "entityId", AuthError, "auth-saml/no-mdq-entity");
  var hash = nodeCrypto.createHash("sha1").update(opts.entityId, "utf8").digest("hex");
  var url = opts.baseUrl.replace(/\/$/, "") + "/entities/%7Bsha1%7D" + hash;
  var hc = httpClient();
  var res = await hc.request({
    url:    url,
    method: "GET",
    headers: { Accept: "application/samlmetadata+xml" },
  });
  if (res.statusCode < 200 || res.statusCode >= 300) {
    throw new AuthError("auth-saml/mdq-fetch-failed",
      "fetchMdq " + url + " returned " + res.statusCode);
  }
  if (!res.body || res.body.length === 0) {
    throw new AuthError("auth-saml/mdq-empty",
      "fetchMdq " + url + " returned empty body");
  }
  var xml = res.body.toString("utf8");
  if (opts.trustCertPem) {
    var c14n = xmlC14n();
    var root = c14n.parse(xml);
    var sig = _findChild(root, "Signature");
    if (!sig) {
      throw new AuthError("auth-saml/mdq-unsigned",
        "fetchMdq: metadata is unsigned but trustCertPem was supplied");
    }
    _verifyXmldsig(xml, sig, opts.trustCertPem);
  }
  _emitAudit("mdq_fetched", "success", { entityId: opts.entityId });
  _emitMetric("mdq-fetched");
  return xml;
}

module.exports = {
  sp:        { create: create },
  fetchMdq:  fetchMdq,
};
