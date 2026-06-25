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
var zlib         = require("node:zlib");
var nodeCrypto   = require("node:crypto");
var pqcSoftware  = require("../pqc-software");
var bCrypto      = require("../crypto");
var { generateToken, timingSafeEqual } = bCrypto;
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
  if (!Object.prototype.hasOwnProperty.call(SUPPORTED_SIG, sigAlgo)) {
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
  if (!Object.prototype.hasOwnProperty.call(SUPPORTED_DIGEST, digestAlgo)) {
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
  validateOpts.shape(opts, {
    entityId:                    { rule: "required-string", label: "entityId",                    code: "auth-saml/no-entity-id" },
    assertionConsumerServiceUrl: { rule: "required-string", label: "assertionConsumerServiceUrl", code: "auth-saml/no-acs" },
    idpEntityId:                 { rule: "required-string", label: "idpEntityId",                 code: "auth-saml/no-idp-entity-id" },
    idpSsoUrl:                   { rule: "required-string", label: "idpSsoUrl",                    code: "auth-saml/no-idp-sso" },
    idpCertPem:                  { rule: "required-string", label: "idpCertPem",                   code: "auth-saml/no-idp-cert" },
    audience:                    "optional-string",
    clockSkewSec:                "optional-non-negative",
    nameIdFormat:                "optional-string",
    singleLogoutServiceUrl:      "optional-string",
    idpSloUrl:                   "optional-string",
  }, "auth.saml.sp.create", AuthError);

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
   * attributes, audience, inResponseTo, issuer }`.
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
   *     // → { nameId, nameIdFormat, sessionIndex, attributes, audience, inResponseTo, issuer }
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
    // signed elements alongside unsigned siblings; a first-match
    // child lookup combined with a signed-element-ID check is
    // vulnerable to a multi-Assertion payload where the verifier
    // signs one element but the consumer reads attributes from
    // another. This is the class behind CVE-2024-45409 (ruby-saml,
    // CVSS 10.0, actively exploited) and CVE-2025-25291/25292
    // (omniauth-saml / ruby-saml namespace-confusion XSW). Reject
    // any Response with more than one of these structural children.
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

    // EncryptedAssertion (SAML 2.0 §2.5) — operator supplies their
    // SP decryption key via vopts.spPrivateKeyPem. Decrypt the
    // EncryptedAssertion → re-parse the cleartext → splice the
    // resulting <Assertion> back into the document tree before
    // signature validation. The signature check then runs against
    // the cleartext element exactly as if the IdP had emitted it
    // unencrypted (the IdP signs the cleartext, then encrypts).
    var encAssertionChildren = _findAllChildren(root, "EncryptedAssertion", SAML_NS.assertion);
    if (encAssertionChildren.length > 1) {
      throw new AuthError("auth-saml/duplicate-encrypted-assertion",
        "verifyResponse: Response has multiple <EncryptedAssertion> children — XSW shape refused");
    }
    var encAssertion = encAssertionChildren[0] || null;
    if (encAssertion) {
      if (typeof vopts.spPrivateKeyPem !== "string" || vopts.spPrivateKeyPem.length === 0) {
        throw new AuthError("auth-saml/encrypted-no-sp-key",
          "verifyResponse: Response carries EncryptedAssertion but " +
          "vopts.spPrivateKeyPem was not supplied");
      }
      var decryptedAssertionXml = _decryptEncryptedAssertion(encAssertion, vopts.spPrivateKeyPem);
      // Re-parse the cleartext + splice into root.children, replacing
      // the EncryptedAssertion node. The cleartext XML may carry its
      // own namespace declarations; we use the c14n parser to handle
      // that uniformly.
      var clearRoot;
      try { clearRoot = c14n.parse(decryptedAssertionXml); }
      catch (e) {
        throw new AuthError("auth-saml/encrypted-bad-cleartext",
          "verifyResponse: decrypted EncryptedAssertion is not parseable XML: " +
          ((e && e.message) || String(e)));
      }
      var clearRootLocal = clearRoot.name.split(":").pop();
      if (clearRootLocal !== "Assertion") {
        throw new AuthError("auth-saml/encrypted-not-assertion",
          "verifyResponse: decrypted EncryptedAssertion content is " + clearRootLocal +
          ", expected Assertion");
      }
      var encIdx = root.children.indexOf(encAssertion);
      if (encIdx !== -1) {
        root.children.splice(encIdx, 1, clearRoot);
      } else {
        root.children.push(clearRoot);
      }
      // Re-serialize the document with the cleartext Assertion inlined
      // so the downstream XMLDSig verifier (_verifyXmldsig) operates
      // on a coherent envelope. The signature reference still points
      // at the Assertion ID; since the cleartext Assertion's ID is
      // the IdP-signed one, the digest check matches.
      xml = Buffer.from(c14n.canonicalize(root)).toString("utf8");
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

    var nowSec = Math.floor((vopts.now || Date.now()) / 1000);                                  // ms→s
    var confirmations = _findAllChildren(subject, "SubjectConfirmation", SAML_NS.assertion);
    var bearerOk = false;
    var hokOk = false;
    // InResponseTo of the SubjectConfirmation that actually passed bearer
    // validation — captured so the returned value can't be sourced from a
    // different (non-validated) confirmation when several are present.
    var matchedInResponseTo = null;
    var hokFingerprint = null;
    // Holder-of-Key SubjectConfirmation per SAML 2.0 Profile §3.1
    // (urn:oasis:names:tc:SAML:2.0:cm:holder-of-key). The IdP binds
    // the assertion to the subject's key by embedding a KeyInfo
    // element inside SubjectConfirmationData; the SP MUST verify
    // that the requesting party demonstrated possession of that key.
    // Operators pass `vopts.holderOfKey: { presentedCertPem }` (the
    // mTLS client cert pinned by b.network.tls.peerCert, or any
    // operator-curated possession proof); we verify the embedded
    // KeyInfo's SubjectPublicKeyInfo matches.
    if (vopts.holderOfKey && typeof vopts.holderOfKey === "object" &&
        typeof vopts.holderOfKey.presentedCertPem === "string") {
      try {
        var presentedKey = nodeCrypto.createPublicKey({
          key: nodeCrypto.createPublicKey({
            key: vopts.holderOfKey.presentedCertPem, format: "pem",
          }).export({ type: "spki", format: "der" }),
          format: "der", type: "spki",
        });
        hokFingerprint = nodeCrypto.createHash("sha3-512")
          .update(presentedKey.export({ type: "spki", format: "der" })).digest("hex");
      } catch (eHk) {
        throw new AuthError("auth-saml/bad-hok-cert",
          "verifyResponse: holderOfKey.presentedCertPem could not be parsed: " +
          ((eHk && eHk.message) || String(eHk)));
      }
    }
    for (var i = 0; i < confirmations.length; i++) {
      var sc = confirmations[i];
      var method = _attr(sc, "Method");
      if (method === "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key") {
        // SP MUST refuse HoK without operator-supplied presented key
        // (RFC SAML-V2-Profile §3.1 — receiver of an HoK confirmation
        // can't honor it without proving possession).
        if (!hokFingerprint) {
          throw new AuthError("auth-saml/hok-no-presented-key",
            "Assertion uses holder-of-key SubjectConfirmation but " +
            "vopts.holderOfKey.presentedCertPem was not supplied");
        }
        var scdHok = _findChild(sc, "SubjectConfirmationData", SAML_NS.assertion);
        if (!scdHok) continue;
        var keyInfo = _findChild(scdHok, "KeyInfo");
        if (!keyInfo) {
          throw new AuthError("auth-saml/hok-no-keyinfo",
            "holder-of-key SubjectConfirmationData missing KeyInfo");
        }
        // Resolve KeyInfo → SubjectPublicKeyInfo. SAML 2.0 §2.4.1.3.1
        // permits X509Data/X509Certificate or KeyValue/RSAKeyValue
        // shapes; we accept X509Certificate (most common) + compute
        // its SPKI fingerprint to compare against the presented key.
        var x509Data = _findChild(keyInfo, "X509Data");
        var x509CertEl = x509Data ? _findChild(x509Data, "X509Certificate") : null;
        if (!x509CertEl) {
          throw new AuthError("auth-saml/hok-unsupported-keyinfo",
            "holder-of-key KeyInfo: only X509Data/X509Certificate is supported");
        }
        var certB64 = _textContent(x509CertEl).replace(/\s+/g, "");
        if (!certB64) {
          throw new AuthError("auth-saml/hok-no-cert",
            "holder-of-key KeyInfo/X509Certificate is empty");
        }
        var assertionCertPem =
          "-----BEGIN CERTIFICATE-----\n" + certB64.replace(/(.{64})/g, "$1\n") +
          "\n-----END CERTIFICATE-----\n";
        var assertionKey;
        try {
          assertionKey = nodeCrypto.createPublicKey({ key: assertionCertPem, format: "pem" });
        } catch (eAk) {
          throw new AuthError("auth-saml/hok-bad-cert",
            "holder-of-key X509Certificate could not be parsed: " +
            ((eAk && eAk.message) || String(eAk)));
        }
        var assertionFingerprint = nodeCrypto.createHash("sha3-512")
          .update(assertionKey.export({ type: "spki", format: "der" })).digest("hex");
        if (!timingSafeEqual(Buffer.from(assertionFingerprint, "hex"),
                              Buffer.from(hokFingerprint, "hex"))) {
          throw new AuthError("auth-saml/hok-key-mismatch",
            "holder-of-key: assertion's bound key fingerprint does not match " +
            "the presented mTLS / possession-proof cert (possession-proof failed)");
        }
        // HoK still requires the same time-window / Recipient checks
        // as Bearer (Profile §3.1 incorporates §3 by reference).
        var nbHok = _attr(scdHok, "NotBefore");
        var noaHok = _attr(scdHok, "NotOnOrAfter");
        if (!noaHok) continue;                                                                      // §3.1 (incorporates §3) — time-bound required
        var noaHokSec = Date.parse(noaHok) / 1000;                                                  // ms→s
        if (!isFinite(noaHokSec) || noaHokSec < nowSec - clockSkewSec) continue;                    // unparseable or expired
        if (nbHok) {
          // Fail CLOSED on a present-but-unparseable HoK NotBefore (same shape
          // as the Bearer path + NotOnOrAfter above) — an unparseable bound
          // can't establish the confirmation has begun, so skip this SCD.
          var nbHokSec = Date.parse(nbHok) / 1000;                                                  // ms→s
          if (!isFinite(nbHokSec) || nbHokSec > nowSec + clockSkewSec) continue;                    // unparseable or not-yet-valid
        }
        var recipHok = _attr(scdHok, "Recipient");
        if (!recipHok || recipHok !== opts.assertionConsumerServiceUrl) continue;   // §3.1→§4.1.4.2 — Recipient is mandatory; absent fails the endpoint binding
        hokOk = true;
        break;
      }
      if (method !== "urn:oasis:names:tc:SAML:2.0:cm:bearer") continue;
      var scd = _findChild(sc, "SubjectConfirmationData", SAML_NS.assertion);
      if (!scd) continue;
      var notOnOrAfter = _attr(scd, "NotOnOrAfter");
      if (!notOnOrAfter) continue;       // §4.1.4.2 — Bearer requires NotOnOrAfter (no unbounded freshness)
      var t = Date.parse(notOnOrAfter) / 1000;                                                  // ms→s
      if (!isFinite(t) || t < nowSec - clockSkewSec) continue;   // unparseable or expired confirmation — try next
      var notBefore = _attr(scd, "NotBefore");
      if (notBefore) {
        var nb = Date.parse(notBefore) / 1000;                                                  // ms→s
        // Fail CLOSED on a present-but-unparseable NotBefore (mirrors the
        // NotOnOrAfter line above + the Conditions block) — an unparseable
        // bound can't establish the confirmation has begun, so skip this SCD.
        if (!isFinite(nb) || nb > nowSec + clockSkewSec) continue;
      }
      // §4.1.4.2 — a Bearer SubjectConfirmationData delivered to an ACS MUST
      // carry a Recipient equal to this SP's ACS URL. Absent Recipient fails
      // the endpoint binding (treated as a mismatch), not silently skipped.
      var recipient = _attr(scd, "Recipient");
      if (!recipient || recipient !== opts.assertionConsumerServiceUrl) {
        continue;
      }
      var inResponseTo = _attr(scd, "InResponseTo");
      if (vopts.expectedInResponseTo) {
        // Constant-time compare against the AuthnRequest ID the
        // operator stored — protects against timing-based InResponseTo
        // probing. timingSafeEqual returns false for missing /
        // length-mismatch without leaking.
        if (inResponseTo === null || inResponseTo === undefined ||
            !timingSafeEqual(inResponseTo, vopts.expectedInResponseTo)) {
          throw new AuthError("auth-saml/bad-in-response-to",
            "SubjectConfirmation InResponseTo does not match expected " +
            "AuthnRequest ID (replay defense)");
        }
      }
      matchedInResponseTo = inResponseTo;
      bearerOk = true;
      break;
    }
    if (!bearerOk && !hokOk) {
      throw new AuthError("auth-saml/no-valid-confirmation",
        "verifyResponse: no Bearer or holder-of-key SubjectConfirmation " +
        "passed time/recipient/possession checks");
    }

    // Conditions
    var conditions = _findChild(assertion, "Conditions", SAML_NS.assertion);
    if (conditions) {
      var cNotBefore = _attr(conditions, "NotBefore");
      var cNotOnOrAfter = _attr(conditions, "NotOnOrAfter");
      if (cNotBefore) {
        var cnb = Date.parse(cNotBefore) / 1000;                                                // ms→s
        // Fail CLOSED on a present-but-unparseable bound (mirrors the Bearer
        // SCD path at line ~708) instead of skipping the window via isFinite().
        if (!isFinite(cnb)) {
          throw new AuthError("auth-saml/conditions-bad-timestamp",
            "Conditions NotBefore is present but unparseable");
        }
        if (cnb > nowSec + clockSkewSec) {
          throw new AuthError("auth-saml/conditions-not-yet-valid",
            "Conditions NotBefore is in the future");
        }
      }
      if (cNotOnOrAfter) {
        var cnoa = Date.parse(cNotOnOrAfter) / 1000;                                            // ms→s
        if (!isFinite(cnoa)) {
          throw new AuthError("auth-saml/conditions-bad-timestamp",
            "Conditions NotOnOrAfter is present but unparseable");
        }
        if (cnoa < nowSec - clockSkewSec) {
          throw new AuthError("auth-saml/conditions-expired",
            "Conditions NotOnOrAfter has passed");
        }
      }
    }
    // Audience binding — a signed assertion is bound to THIS SP via
    // AudienceRestriction. A missing Conditions or AudienceRestriction means
    // it is not bound here (audience-confusion: an assertion minted for another
    // SP). Fail closed when an audience is configured; opt out only via
    // vopts.requireAudienceRestriction === false.
    if (audience && vopts.requireAudienceRestriction !== false) {
      var ars = conditions
        ? _findAllChildren(conditions, "AudienceRestriction", SAML_NS.assertion) : [];
      if (ars.length === 0) {
        throw new AuthError("auth-saml/no-audience-restriction",
          "verifyResponse: assertion has no AudienceRestriction binding it to \"" +
          audience + "\" (audience-confusion defense; set requireAudienceRestriction:false to opt out)");
      }
      // SAML core §2.5.1.4: multiple <AudienceRestriction> elements are
      // AND-combined — the SP must be a member of the Audience set of EVERY
      // one. Checking only the first let an IdP that narrowed the assertion to
      // a DIFFERENT audience in a later restriction be accepted here.
      for (var ari = 0; ari < ars.length; ari += 1) {
        var audiences = _findAllChildren(ars[ari], "Audience", SAML_NS.assertion).map(_textContent);
        if (audiences.indexOf(audience) === -1) {
          throw new AuthError("auth-saml/wrong-audience",
            "Audience \"" + audience + "\" not in AudienceRestriction #" + (ari + 1) +
            " of " + ars.length + " (got " + JSON.stringify(audiences) + ")");
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
      inResponseTo:    bearerOk ? matchedInResponseTo : null,
      issuer:          issuer,
    };
  }

  /**
   * @primitive b.auth.saml.sp.metadata
   * @signature b.auth.saml.sp.metadata(metaOpts?)
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
  function metadata(metaOpts) {
    // RFC 3741 attr/text escaping for operator-supplied URLs / IDs —
    // same audit-finding shape as buildAuthnRequest above.
    metaOpts = metaOpts || {};
    var c14n = xmlC14n();
    // v0.10.16 — operator can supply SingleLogoutService URL +
    // additional ACS bindings (HTTP-Redirect / HTTP-Artifact). The
    // metadata XML now reflects what the SP actually supports.
    var sloUrl = metaOpts.singleLogoutServiceUrl || opts.singleLogoutServiceUrl;
    var sloXml = "";
    if (sloUrl) {
      sloXml =
        "<md:SingleLogoutService " +
        "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" " +
        "Location=\"" + c14n.escapeAttrValue(sloUrl) + "\"/>" +
        "<md:SingleLogoutService " +
        "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " +
        "Location=\"" + c14n.escapeAttrValue(sloUrl) + "\"/>";
    }
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
      "<md:EntityDescriptor xmlns:md=\"" + SAML_NS.metadata + "\" entityID=\"" + c14n.escapeAttrValue(opts.entityId) + "\">" +
      "<md:SPSSODescriptor protocolSupportEnumeration=\"" + SAML_NS.protocol + "\" " +
      "AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\">" +
      sloXml +
      "<md:AssertionConsumerService " +
      "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" " +
      "Location=\"" + c14n.escapeAttrValue(opts.assertionConsumerServiceUrl) + "\" index=\"0\"/>" +
      "</md:SPSSODescriptor>" +
      "</md:EntityDescriptor>";
  }

  // ---- Single Logout (RFC SAML Bindings §3.4 HTTP-Redirect) ----

  /**
   * @primitive b.auth.saml.sp.buildLogoutRequest
   * @signature b.auth.saml.sp.buildLogoutRequest(opts)
   * @since     0.10.16
   * @status    stable
   *
   * Build a SAML 2.0 LogoutRequest XML + the URL-safe deflate-base64
   * encoding for the HTTP-Redirect binding. When `signingKey` /
   * `signingAlg` are supplied, computes the binding-§3.4.4.1
   * canonical query-string signature so the IdP can verify the
   * request originated from a trusted SP. The signature is computed
   * over `SAMLRequest=<v>&[RelayState=<v>&]SigAlg=<v>` in that exact
   * order (no re-sorting per the spec).
   *
   * @opts
   *   nameId:         string,                          // user's NameID from the original AuthnResponse
   *   nameIdFormat:   string,                          // optional NameID Format URI
   *   sessionIndex:   string,                          // SessionIndex from the original Assertion AuthnStatement
   *   relayState:     string,                          // optional opaque blob round-tripped to LogoutResponse
   *   signingKey:     Uint8Array | string | KeyObject, // PQC private key (b.pqcSoftware.ml_dsa_*.keygen()) for ML-DSA;
   *                                                    // PEM string or node:crypto KeyObject for RSA / ECDSA / Ed25519
   *   signingAlg:     "rsa-sha256" | "rsa-sha384" | "rsa-sha512" |
   *                   "ecdsa-sha256" | "ecdsa-sha384" | "ecdsa-sha512" |
   *                   "ed25519" | "ml-dsa-65" | "ml-dsa-87",   // default omitted → unsigned
   *
   * @example
   *   var lr = sp.buildLogoutRequest({
   *     nameId: "alice@idp", sessionIndex: "_session-9876",
   *     signingKey: kp.secretKey, signingAlg: "ml-dsa-65",
   *   });
   *   res.statusCode = 302;
   *   res.setHeader("Location", lr.redirectUrl);
   */
  function buildLogoutRequest(bopts) {
    bopts = validateOpts.requireObject(bopts, "auth.saml.sp.buildLogoutRequest", AuthError, "auth-saml/bad-opts");
    validateOpts(bopts, ["nameId", "nameIdFormat", "sessionIndex", "relayState",
                          "signingKey", "signingAlg", "idpSloUrl"],
      "auth.saml.sp.buildLogoutRequest");
    validateOpts.requireNonEmptyString(bopts.nameId, "nameId", AuthError, "auth-saml/no-nameid");
    var idpSloUrl = bopts.idpSloUrl || opts.idpSloUrl || opts.idpSsoUrl;
    if (typeof idpSloUrl !== "string" || idpSloUrl.length === 0) {
      throw new AuthError("auth-saml/no-idp-slo",
        "buildLogoutRequest: opts.idpSloUrl (or sp.create's opts.idpSloUrl) required");
    }
    var id = "_" + generateToken(20);                                                                 // 20-byte SAML ID token
    var issueInstant = new Date().toISOString();
    var c14n = xmlC14n();
    var nameIdFormatAttr = bopts.nameIdFormat
      ? " Format=\"" + c14n.escapeAttrValue(bopts.nameIdFormat) + "\""
      : "";
    var sessionIndexXml = bopts.sessionIndex
      ? "<samlp:SessionIndex>" + c14n.escapeText(bopts.sessionIndex) + "</samlp:SessionIndex>"
      : "";
    var xml =
      "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_NS.protocol + "\" " +
      "xmlns:saml=\"" + SAML_NS.assertion + "\" " +
      "ID=\"" + id + "\" " +
      "Version=\"2.0\" " +
      "IssueInstant=\"" + issueInstant + "\" " +
      "Destination=\"" + c14n.escapeAttrValue(idpSloUrl) + "\">" +
      "<saml:Issuer>" + c14n.escapeText(opts.entityId) + "</saml:Issuer>" +
      "<saml:NameID" + nameIdFormatAttr + ">" + c14n.escapeText(bopts.nameId) + "</saml:NameID>" +
      sessionIndexXml +
      "</samlp:LogoutRequest>";
    var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"));
    var samlRequest = deflated.toString("base64");
    var query = "SAMLRequest=" + encodeURIComponent(samlRequest);
    if (bopts.relayState) {
      query += "&RelayState=" + encodeURIComponent(bopts.relayState);
    }
    // Signature path — per SAML Bindings §3.4.4.1 the signature is
    // computed over the URL-encoded query string with the SigAlg
    // parameter appended (no Signature parameter, no re-sorting).
    if (bopts.signingKey || bopts.signingAlg) {
      var sigAlgUrn = _sigAlgUrn(bopts.signingAlg);
      if (!sigAlgUrn) {
        throw new AuthError("auth-saml/bad-signing-alg",
          "buildLogoutRequest: signingAlg must be one of " +
          "'rsa-sha256' / 'rsa-sha384' / 'rsa-sha512' / " +
          "'ecdsa-sha256' / 'ecdsa-sha384' / 'ecdsa-sha512' / " +
          "'ed25519' (W3C XMLDSig Core 1.1 + RFC 9231) or " +
          "'ml-dsa-65' / 'ml-dsa-87' (framework-experimental — " +
          "urn:blamejs:experimental:saml-sig-alg:*)");
      }
      var isPqc = bopts.signingAlg === "ml-dsa-65" || bopts.signingAlg === "ml-dsa-87";
      if (isPqc && !(bopts.signingKey instanceof Uint8Array)) {
        throw new AuthError("auth-saml/bad-signing-key",
          "buildLogoutRequest: signingKey for " + bopts.signingAlg + " must be a Uint8Array");
      }
      if (!isPqc && bopts.signingAlg !== "ed25519" &&
          typeof bopts.signingKey !== "string" &&
          !(bopts.signingKey && typeof bopts.signingKey === "object" &&
            bopts.signingKey.type === "private")) {
        throw new AuthError("auth-saml/bad-signing-key",
          "buildLogoutRequest: signingKey for classical " + bopts.signingAlg +
          " must be a PEM string or node:crypto KeyObject");
      }
      query += "&SigAlg=" + encodeURIComponent(sigAlgUrn.urn);
      var sigBytes = sigAlgUrn.sign(Buffer.from(query, "utf8"), bopts.signingKey);
      query += "&Signature=" + encodeURIComponent(Buffer.from(sigBytes).toString("base64"));
    }
    var url = idpSloUrl + (idpSloUrl.indexOf("?") === -1 ? "?" : "&") + query;
    _emitAudit("logoutrequest_built", "success", {
      id: id, idp: opts.idpEntityId, signed: !!bopts.signingKey,
    });
    return { id: id, redirectUrl: url, raw: xml };
  }

  /**
   * @primitive b.auth.saml.sp.parseLogoutRequest
   * @signature b.auth.saml.sp.parseLogoutRequest(samlRequestB64, vopts?)
   * @since     0.10.16
   * @status    stable
   *
   * Parse an inbound LogoutRequest (IdP-initiated SLO). Returns
   * `{ id, nameId, nameIdFormat, sessionIndex, issuer, issueInstant }`.
   * When `vopts.idpVerifyKey` is supplied with `vopts.queryString`,
   * verifies the HTTP-Redirect-binding signature against the IdP key.
   *
   * @opts
   *   queryString:        string,             // raw query string (everything after `?` in the redirect URL)
   *   idpVerifyKey:       Uint8Array,         // IdP's PQC public key
   *   idpVerifyAlg:       "ml-dsa-65" | "ml-dsa-87" | "ed25519",
   *
   * @example
   *   var req = sp.parseLogoutRequest(req.query.SAMLRequest, {
   *     queryString: req.url.split("?")[1],
   *     idpVerifyKey: idpKp.publicKey,
   *     idpVerifyAlg: "ml-dsa-65",
   *   });
   */
  // _extractRedirectSignature(queryString) — split a SAML HTTP-Redirect
  // binding query string, pulling the URL-decoded `Signature=` value out and
  // collecting the remaining (signed) portion in order. Shared by
  // parseLogoutRequest / parseLogoutResponse so the two cannot drift on which
  // bytes the signature covers — a drift would be a signature-bypass.
  function _extractRedirectSignature(queryString) {
    var parts = queryString.split("&");
    var sigValue = null;
    var signedPortion = [];
    for (var i = 0; i < parts.length; i += 1) {
      if (parts[i].indexOf("Signature=") === 0) {
        sigValue = decodeURIComponent(parts[i].slice("Signature=".length));
      } else {
        signedPortion.push(parts[i]);
      }
    }
    return { sigValue: sigValue, signedPortion: signedPortion };
  }

  function parseLogoutRequest(samlRequestB64, vopts) {
    vopts = vopts || {};
    if (typeof samlRequestB64 !== "string" || samlRequestB64.length === 0) {
      throw new AuthError("auth-saml/no-saml-request",
        "parseLogoutRequest: samlRequestB64 must be a non-empty string");
    }
    var xml;
    try {
      var deflated = Buffer.from(samlRequestB64, "base64");
      xml = zlib.inflateRawSync(deflated, { maxOutputLength: 1024 * 1024 }).toString("utf8");        // allow:raw-byte-literal — 1 MiB max SAMLRequest decompressed
    } catch (e) {
      throw new AuthError("auth-saml/bad-saml-request",
        "parseLogoutRequest: inflate failed: " + ((e && e.message) || String(e)));
    }
    // Verify the redirect-binding signature when an IdP key is supplied.
    if (vopts.idpVerifyKey) {
      if (typeof vopts.queryString !== "string") {
        throw new AuthError("auth-saml/no-query-string",
          "parseLogoutRequest: idpVerifyKey requires queryString (raw URL query)");
      }
      var sigAlgUrn = _sigAlgUrn(vopts.idpVerifyAlg);
      if (!sigAlgUrn) {
        throw new AuthError("auth-saml/bad-verify-alg",
          "parseLogoutRequest: idpVerifyAlg must be 'ml-dsa-65' / 'ml-dsa-87' / 'ed25519'");
      }
      var sig = _extractRedirectSignature(vopts.queryString);
      var sigValue = sig.sigValue;
      var signedPortion = sig.signedPortion;
      if (!sigValue) {
        throw new AuthError("auth-saml/no-signature",
          "parseLogoutRequest: queryString lacks Signature parameter");
      }
      var sigBytes = Buffer.from(sigValue, "base64");
      var msgBytes = Buffer.from(signedPortion.join("&"), "utf8");
      var ok;
      try { ok = sigAlgUrn.verify(new Uint8Array(sigBytes), new Uint8Array(msgBytes), vopts.idpVerifyKey); }
      catch (eV) {
        throw new AuthError("auth-saml/verify-threw",
          "parseLogoutRequest: signature verify threw: " + ((eV && eV.message) || String(eV)));
      }
      if (!ok) {
        throw new AuthError("auth-saml/bad-signature",
          "parseLogoutRequest: HTTP-Redirect signature does not verify against idpVerifyKey");
      }
    }
    // Parse the inflated XML.
    var c14n = xmlC14n();
    var root = c14n.parse(xml);
    var rootLocal = root.name.indexOf(":") !== -1 ? root.name.split(":").pop() : root.name;
    if (rootLocal !== "LogoutRequest") {
      throw new AuthError("auth-saml/not-logout-request",
        "parseLogoutRequest: root element is " + rootLocal + ", expected LogoutRequest");
    }
    var nameIdEl = _findChild(root, "NameID", SAML_NS.assertion);
    if (!nameIdEl) {
      throw new AuthError("auth-saml/no-nameid",
        "parseLogoutRequest: missing NameID");
    }
    var issuerEl = _findChild(root, "Issuer", SAML_NS.assertion);
    var sessionIndexEl = _findChild(root, "SessionIndex", SAML_NS.protocol);
    return {
      id:             _attr(root, "ID"),
      issueInstant:   _attr(root, "IssueInstant"),
      destination:    _attr(root, "Destination"),
      nameId:         _textContent(nameIdEl),
      nameIdFormat:   _attr(nameIdEl, "Format"),
      sessionIndex:   sessionIndexEl ? _textContent(sessionIndexEl) : null,
      issuer:         issuerEl ? _textContent(issuerEl) : null,
    };
  }

  /**
   * @primitive b.auth.saml.sp.buildLogoutResponse
   * @signature b.auth.saml.sp.buildLogoutResponse(opts)
   * @since     0.10.16
   * @status    stable
   *
   * Build a SAML 2.0 LogoutResponse to an IdP-initiated LogoutRequest.
   * Status defaults to `urn:oasis:names:tc:SAML:2.0:status:Success`.
   * Same HTTP-Redirect binding + optional canonical-query signature
   * as buildLogoutRequest.
   *
   * @opts
   *   inResponseTo: string,                          // required — LogoutRequest ID being responded to
   *   destination:  string,                          // required — IdP SLO endpoint URL the response posts to
   *   statusCode:   string,                          // optional — SAML status URI; default Success
   *   relayState:   string,                          // optional — opaque blob from the matching LogoutRequest
   *   signingKey:   Uint8Array,                      // PQC private key (b.pqcSoftware.ml_dsa_*.keygen())
   *   signingAlg:   "ml-dsa-65" | "ml-dsa-87" | "ed25519",   // default omitted → unsigned
   *
   * @example
   *   var resp = sp.buildLogoutResponse({
   *     inResponseTo: incoming.id,
   *     destination:  "https://idp.example/slo",
   *     signingKey:   kp.secretKey,
   *     signingAlg:   "ml-dsa-65",
   *   });
   *   res.writeHead(302, { Location: resp.redirectUrl });
   */
  function buildLogoutResponse(bopts) {
    bopts = validateOpts.requireObject(bopts, "auth.saml.sp.buildLogoutResponse", AuthError, "auth-saml/bad-opts");
    validateOpts(bopts, ["inResponseTo", "destination", "statusCode", "relayState",
                          "signingKey", "signingAlg"],
      "auth.saml.sp.buildLogoutResponse");
    validateOpts.requireNonEmptyString(bopts.inResponseTo, "inResponseTo", AuthError, "auth-saml/no-in-response-to");
    validateOpts.requireNonEmptyString(bopts.destination, "destination", AuthError, "auth-saml/no-destination");
    var statusCode = bopts.statusCode || "urn:oasis:names:tc:SAML:2.0:status:Success";
    var id = "_" + generateToken(20);                                                                 // 20-byte SAML ID token
    var issueInstant = new Date().toISOString();
    var c14n = xmlC14n();
    var xml =
      "<samlp:LogoutResponse xmlns:samlp=\"" + SAML_NS.protocol + "\" " +
      "xmlns:saml=\"" + SAML_NS.assertion + "\" " +
      "ID=\"" + id + "\" " +
      "Version=\"2.0\" " +
      "IssueInstant=\"" + issueInstant + "\" " +
      "InResponseTo=\"" + c14n.escapeAttrValue(bopts.inResponseTo) + "\" " +
      "Destination=\"" + c14n.escapeAttrValue(bopts.destination) + "\">" +
      "<saml:Issuer>" + c14n.escapeText(opts.entityId) + "</saml:Issuer>" +
      "<samlp:Status><samlp:StatusCode Value=\"" + c14n.escapeAttrValue(statusCode) + "\"/></samlp:Status>" +
      "</samlp:LogoutResponse>";
    var deflated = zlib.deflateRawSync(Buffer.from(xml, "utf8"));
    var samlResponse = deflated.toString("base64");
    var query = "SAMLResponse=" + encodeURIComponent(samlResponse);
    if (bopts.relayState) {
      query += "&RelayState=" + encodeURIComponent(bopts.relayState);
    }
    if (bopts.signingKey || bopts.signingAlg) {
      var sigAlgUrn = _sigAlgUrn(bopts.signingAlg);
      if (!sigAlgUrn) {
        throw new AuthError("auth-saml/bad-signing-alg",
          "buildLogoutResponse: signingAlg must be one of " +
          "'rsa-sha256' / 'rsa-sha384' / 'rsa-sha512' / " +
          "'ecdsa-sha256' / 'ecdsa-sha384' / 'ecdsa-sha512' / " +
          "'ed25519' (W3C XMLDSig Core 1.1 + RFC 9231) or " +
          "'ml-dsa-65' / 'ml-dsa-87' (framework-experimental — " +
          "urn:blamejs:experimental:saml-sig-alg:*)");
      }
      var isPqcResp = bopts.signingAlg === "ml-dsa-65" || bopts.signingAlg === "ml-dsa-87";
      if (isPqcResp && !(bopts.signingKey instanceof Uint8Array)) {
        throw new AuthError("auth-saml/bad-signing-key",
          "buildLogoutResponse: signingKey for " + bopts.signingAlg + " must be a Uint8Array");
      }
      if (!isPqcResp && bopts.signingAlg !== "ed25519" &&
          typeof bopts.signingKey !== "string" &&
          !(bopts.signingKey && typeof bopts.signingKey === "object" &&
            bopts.signingKey.type === "private")) {
        throw new AuthError("auth-saml/bad-signing-key",
          "buildLogoutResponse: signingKey for classical " + bopts.signingAlg +
          " must be a PEM string or node:crypto KeyObject");
      }
      query += "&SigAlg=" + encodeURIComponent(sigAlgUrn.urn);
      var sigBytes = sigAlgUrn.sign(Buffer.from(query, "utf8"), bopts.signingKey);
      query += "&Signature=" + encodeURIComponent(Buffer.from(sigBytes).toString("base64"));
    }
    var url = bopts.destination + (bopts.destination.indexOf("?") === -1 ? "?" : "&") + query;
    _emitAudit("logoutresponse_built", "success", { id: id, inResponseTo: bopts.inResponseTo });
    return { id: id, redirectUrl: url, raw: xml };
  }

  /**
   * @primitive b.auth.saml.sp.parseLogoutResponse
   * @signature b.auth.saml.sp.parseLogoutResponse(samlResponseB64, vopts?)
   * @since     0.10.16
   * @status    stable
   *
   * Parse + verify an inbound SAML 2.0 LogoutResponse (the IdP's
   * acknowledgement of a previously-issued LogoutRequest). Returns
   * `{ id, inResponseTo, statusCode, issuer, success }` where
   * `success` is true when `statusCode` equals the spec's success
   * URN. When `vopts.idpVerifyKey` is supplied, verifies the
   * redirect-binding signature against the IdP key (same shape as
   * parseLogoutRequest).
   *
   * @opts
   *   queryString:   string,             // raw URL query (everything past `?`)
   *   idpVerifyKey:  Uint8Array,
   *   idpVerifyAlg:  "ml-dsa-65" | "ml-dsa-87" | "ed25519",
   *   expectedInResponseTo: string,      // optional — refuses on mismatch
   *
   * @example
   *   var resp = sp.parseLogoutResponse(req.query.SAMLResponse, {
   *     queryString: req.url.split("?")[1],
   *     idpVerifyKey: idpPub,
   *     idpVerifyAlg: "ml-dsa-65",
   *     expectedInResponseTo: storedLogoutRequestId,
   *   });
   *   resp.success;   // → true on Success status
   */
  function parseLogoutResponse(samlResponseB64, vopts) {
    vopts = vopts || {};
    if (typeof samlResponseB64 !== "string" || samlResponseB64.length === 0) {
      throw new AuthError("auth-saml/no-saml-response",
        "parseLogoutResponse: samlResponseB64 must be a non-empty string");
    }
    var xml;
    try {
      var deflated = Buffer.from(samlResponseB64, "base64");
      xml = zlib.inflateRawSync(deflated, { maxOutputLength: 1024 * 1024 }).toString("utf8");        // allow:raw-byte-literal — 1 MiB max SAMLResponse decompressed
    } catch (e) {
      throw new AuthError("auth-saml/bad-saml-response",
        "parseLogoutResponse: inflate failed: " + ((e && e.message) || String(e)));
    }
    if (vopts.idpVerifyKey) {
      if (typeof vopts.queryString !== "string") {
        throw new AuthError("auth-saml/no-query-string",
          "parseLogoutResponse: idpVerifyKey requires queryString");
      }
      var sigAlgUrn = _sigAlgUrn(vopts.idpVerifyAlg);
      if (!sigAlgUrn) {
        throw new AuthError("auth-saml/bad-verify-alg",
          "parseLogoutResponse: idpVerifyAlg must be 'ml-dsa-65' / 'ml-dsa-87' / 'ed25519'");
      }
      var sig = _extractRedirectSignature(vopts.queryString);
      var sigValue = sig.sigValue;
      var signedPortion = sig.signedPortion;
      if (!sigValue) {
        throw new AuthError("auth-saml/no-signature",
          "parseLogoutResponse: queryString lacks Signature parameter");
      }
      var ok;
      try {
        ok = sigAlgUrn.verify(new Uint8Array(Buffer.from(sigValue, "base64")),
          new Uint8Array(Buffer.from(signedPortion.join("&"), "utf8")),
          vopts.idpVerifyKey);
      } catch (eV) {
        throw new AuthError("auth-saml/verify-threw",
          "parseLogoutResponse: signature verify threw: " + ((eV && eV.message) || String(eV)));
      }
      if (!ok) {
        throw new AuthError("auth-saml/bad-signature",
          "parseLogoutResponse: HTTP-Redirect signature does not verify against idpVerifyKey");
      }
    }
    var c14n = xmlC14n();
    var root = c14n.parse(xml);
    var rootLocal = root.name.indexOf(":") !== -1 ? root.name.split(":").pop() : root.name;
    if (rootLocal !== "LogoutResponse") {
      throw new AuthError("auth-saml/not-logout-response",
        "parseLogoutResponse: root element is " + rootLocal + ", expected LogoutResponse");
    }
    var inResponseTo = _attr(root, "InResponseTo");
    if (vopts.expectedInResponseTo && inResponseTo !== vopts.expectedInResponseTo) {
      throw new AuthError("auth-saml/inresponseto-mismatch",
        "parseLogoutResponse: InResponseTo '" + inResponseTo + "' != expected '" +
        vopts.expectedInResponseTo + "'");
    }
    var statusEl = _findChild(root, "Status", SAML_NS.protocol);
    var statusCodeEl = statusEl && _findChild(statusEl, "StatusCode", SAML_NS.protocol);
    var statusCode = statusCodeEl ? _attr(statusCodeEl, "Value") : null;
    var issuerEl = _findChild(root, "Issuer", SAML_NS.assertion);
    return {
      id:           _attr(root, "ID"),
      inResponseTo: inResponseTo,
      destination:  _attr(root, "Destination"),
      statusCode:   statusCode,
      success:      statusCode === "urn:oasis:names:tc:SAML:2.0:status:Success",
      issuer:       issuerEl ? _textContent(issuerEl) : null,
    };
  }

  // ---- SLO HTTP-POST binding (SAML Bindings §3.5) ----

  /**
   * @primitive b.auth.saml.sp.buildLogoutRequestPost
   * @signature b.auth.saml.sp.buildLogoutRequestPost(opts)
   * @since     0.10.16
   * @status    stable
   *
   * HTTP-POST variant of buildLogoutRequest. Returns the
   * base64-encoded SAMLRequest body for the IdP's /slo POST endpoint
   * along with an embedded XMLDSig-Enveloped signature (when
   * signingKey is supplied). The signature is computed over the
   * canonical SignedInfo element per XMLDSig §4.5 — the referenced
   * LogoutRequest is canonicalized via exclusive-c14n, SHA3-512
   * digested, and that digest goes into the Reference's DigestValue
   * before SignedInfo itself is canonicalized + signed.
   *
   * @opts
   *   nameId, nameIdFormat, sessionIndex, relayState — same as buildLogoutRequest
   *   signingKey, signingAlg — PQC ml-dsa-65 / ml-dsa-87 (Ed25519 also
   *                            accepted; URN identifies the alg)
   *
   * @example
   *   var lr = sp.buildLogoutRequestPost({
   *     nameId: "alice@idp", signingKey: kp.secretKey, signingAlg: "ml-dsa-65",
   *   });
   *   res.statusCode = 200;
   *   res.setHeader("Content-Type", "text/html");
   *   res.end(lr.formHtml);   // auto-POSTs SAMLRequest to lr.action
   */
  function buildLogoutRequestPost(bopts) {
    bopts = validateOpts.requireObject(bopts, "auth.saml.sp.buildLogoutRequestPost",
      AuthError, "auth-saml/bad-opts");
    validateOpts(bopts, ["nameId", "nameIdFormat", "sessionIndex", "relayState",
                          "signingKey", "signingAlg", "idpSloUrl"],
      "auth.saml.sp.buildLogoutRequestPost");
    validateOpts.requireNonEmptyString(bopts.nameId, "nameId", AuthError, "auth-saml/no-nameid");
    var idpSloUrl = bopts.idpSloUrl || opts.idpSloUrl || opts.idpSsoUrl;
    if (typeof idpSloUrl !== "string" || idpSloUrl.length === 0) {
      throw new AuthError("auth-saml/no-idp-slo",
        "buildLogoutRequestPost: opts.idpSloUrl required");
    }
    var id = "_" + generateToken(20);                                                                 // 20-byte SAML ID token
    var issueInstant = new Date().toISOString();
    var c14n = xmlC14n();
    var nameIdFormatAttr = bopts.nameIdFormat
      ? " Format=\"" + c14n.escapeAttrValue(bopts.nameIdFormat) + "\""
      : "";
    var sessionIndexXml = bopts.sessionIndex
      ? "<samlp:SessionIndex>" + c14n.escapeText(bopts.sessionIndex) + "</samlp:SessionIndex>"
      : "";
    var bodyXml =
      "<samlp:LogoutRequest xmlns:samlp=\"" + SAML_NS.protocol + "\" " +
      "xmlns:saml=\"" + SAML_NS.assertion + "\" " +
      "ID=\"" + id + "\" " +
      "Version=\"2.0\" " +
      "IssueInstant=\"" + issueInstant + "\" " +
      "Destination=\"" + c14n.escapeAttrValue(idpSloUrl) + "\">" +
      "<saml:Issuer>" + c14n.escapeText(opts.entityId) + "</saml:Issuer>" +
      "<saml:NameID" + nameIdFormatAttr + ">" + c14n.escapeText(bopts.nameId) + "</saml:NameID>" +
      sessionIndexXml +
      "</samlp:LogoutRequest>";

    var signedXml = bodyXml;
    if (bopts.signingKey || bopts.signingAlg) {
      signedXml = _embedXmlDsig(bodyXml, id, bopts.signingKey, bopts.signingAlg);
    }
    var samlRequest = Buffer.from(signedXml, "utf8").toString("base64");
    var rs = bopts.relayState ? bopts.relayState : "";
    var formHtml =
      "<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">" +
      "<form method=\"POST\" action=\"" + c14n.escapeAttrValue(idpSloUrl) + "\">" +
      "<input type=\"hidden\" name=\"SAMLRequest\" value=\"" + c14n.escapeAttrValue(samlRequest) + "\"/>" +
      (rs ? "<input type=\"hidden\" name=\"RelayState\" value=\"" + c14n.escapeAttrValue(rs) + "\"/>" : "") +
      "<noscript><button type=\"submit\">Continue</button></noscript>" +
      "</form></body></html>";
    _emitAudit("logoutrequest_post_built", "success", {
      id: id, idp: opts.idpEntityId, signed: !!bopts.signingKey,
    });
    return { id: id, action: idpSloUrl, samlRequest: samlRequest, formHtml: formHtml, raw: signedXml };
  }

  /**
   * @primitive b.auth.saml.sp.parseLogoutRequestPost
   * @signature b.auth.saml.sp.parseLogoutRequestPost(samlRequestB64, vopts?)
   * @since     0.10.16
   * @status    stable
   *
   * HTTP-POST variant of parseLogoutRequest. Decodes the base64
   * SAMLRequest body, parses the XML, and (when `idpVerifyKey` /
   * `idpVerifyAlg` are supplied) verifies the embedded XMLDSig-
   * Enveloped signature against the IdP key. Refuses when the
   * signature element is missing, the Reference URI doesn't match
   * the document root ID, the digest doesn't match the canonicalized
   * referenced element (signature-wrapping defense), or the
   * SignedInfo signature doesn't verify.
   *
   * @opts
   *   idpVerifyKey: Uint8Array,                      // optional — verify embedded XMLDSig signature against this IdP key
   *   idpVerifyAlg: "ml-dsa-65" | "ml-dsa-87" | "ed25519",   // required when idpVerifyKey is supplied
   *
   * @example
   *   var req = sp.parseLogoutRequestPost(req.body.SAMLRequest, {
   *     idpVerifyKey: idpPubKey, idpVerifyAlg: "ml-dsa-65",
   *   });
   *   // req.nameId / req.sessionIndex / req.issuer
   */
  function parseLogoutRequestPost(samlRequestB64, vopts) {
    vopts = vopts || {};
    if (typeof samlRequestB64 !== "string" || samlRequestB64.length === 0) {
      throw new AuthError("auth-saml/bad-input",
        "parseLogoutRequestPost: samlRequestB64 must be a non-empty string");
    }
    var xml = Buffer.from(samlRequestB64, "base64").toString("utf8");
    if (vopts.idpVerifyKey || vopts.idpVerifyAlg) {
      _verifyEmbeddedXmlDsig(xml, vopts.idpVerifyKey, vopts.idpVerifyAlg, "LogoutRequest");
    }
    var c14n = xmlC14n();
    var root = c14n.parse(xml);
    var rootLocal = root.name.split(":").pop();
    if (rootLocal !== "LogoutRequest") {
      throw new AuthError("auth-saml/wrong-root",
        "parseLogoutRequestPost: root element is " + rootLocal + ", expected LogoutRequest");
    }
    var nameIdEl = _findChild(root, "NameID", SAML_NS.assertion);
    if (!nameIdEl) {
      throw new AuthError("auth-saml/no-nameid",
        "parseLogoutRequestPost: missing NameID");
    }
    var sessionIndexEl = _findChild(root, "SessionIndex", SAML_NS.protocol);
    var issuerEl       = _findChild(root, "Issuer", SAML_NS.assertion);
    return {
      id:           _attr(root, "ID"),
      destination:  _attr(root, "Destination"),
      nameId:       _textContent(nameIdEl),
      nameIdFormat: _attr(nameIdEl, "Format"),
      sessionIndex: sessionIndexEl ? _textContent(sessionIndexEl) : null,
      issuer:       issuerEl ? _textContent(issuerEl) : null,
    };
  }

  /**
   * @primitive b.auth.saml.sp.buildLogoutRequestSoap
   * @signature b.auth.saml.sp.buildLogoutRequestSoap(opts)
   * @since     0.10.16
   * @status    stable
   *
   * SOAP variant of buildLogoutRequest (SAML Bindings §3.2 — synchronous
   * back-channel binding). Wraps the LogoutRequest in
   * <soapenv:Envelope><soapenv:Body>...</> for an HTTP POST to the
   * IdP's SOAP endpoint. Embeds an XMLDSig-Enveloped signature on
   * the LogoutRequest itself (not the SOAP envelope) when signingKey
   * is supplied — matching the IdP-side parse expectation.
   *
   * @opts
   *   same as buildLogoutRequestPost
   *
   * @example
   *   var lr = sp.buildLogoutRequestSoap({ nameId: "alice@idp" });
   *   var resp = await b.httpClient.request(lr.action, {
   *     method:  "POST",
   *     body:    lr.body,
   *     headers: { "Content-Type": "text/xml; charset=utf-8" },
   *   });
   *   var result = sp.parseLogoutResponseSoap(resp.body);
   */
  function buildLogoutRequestSoap(bopts) {
    var post = buildLogoutRequestPost(bopts);
    var body =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
      "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
      "<soapenv:Body>" + post.raw + "</soapenv:Body>" +
      "</soapenv:Envelope>";
    return { id: post.id, action: post.action, body: body, raw: post.raw };
  }

  /**
   * @primitive b.auth.saml.sp.parseLogoutResponseSoap
   * @signature b.auth.saml.sp.parseLogoutResponseSoap(soapXml, vopts?)
   * @since     0.10.16
   * @status    stable
   *
   * Parse a SOAP-wrapped LogoutResponse from the IdP's synchronous
   * back-channel reply. Unwraps the soapenv:Body, optionally verifies
   * the XMLDSig signature, and returns the same shape as
   * parseLogoutResponse.
   *
   * @opts
   *   idpVerifyKey: Uint8Array,                      // optional — verify embedded XMLDSig signature against this IdP key
   *   idpVerifyAlg: "ml-dsa-65" | "ml-dsa-87" | "ed25519",   // required when idpVerifyKey is supplied
   *
   * @example
   *   var result = sp.parseLogoutResponseSoap(resp.body, {
   *     idpVerifyKey: idpPubKey, idpVerifyAlg: "ml-dsa-65",
   *   });
   *   // result.success / result.statusCode / result.inResponseTo
   */
  function parseLogoutResponseSoap(soapXml, vopts) {
    vopts = vopts || {};
    if (typeof soapXml !== "string" || soapXml.length === 0) {
      throw new AuthError("auth-saml/bad-input",
        "parseLogoutResponseSoap: soapXml must be a non-empty string");
    }
    var c14n = xmlC14n();
    var soapRoot;
    try { soapRoot = c14n.parse(soapXml); }
    catch (e) {
      throw new AuthError("auth-saml/bad-soap",
        "parseLogoutResponseSoap: XML parse failed: " + ((e && e.message) || String(e)));
    }
    var soapRootLocal = soapRoot.name.split(":").pop();
    if (soapRootLocal !== "Envelope") {
      throw new AuthError("auth-saml/bad-soap",
        "parseLogoutResponseSoap: root element is " + soapRootLocal + ", expected soap:Envelope");
    }
    var body = null;
    for (var ci = 0; ci < soapRoot.children.length; ci += 1) {
      var ch = soapRoot.children[ci];
      if (ch.type !== "element") continue;
      var local = ch.name.split(":").pop();
      if (local === "Body") { body = ch; break; }
    }
    if (!body) {
      throw new AuthError("auth-saml/bad-soap",
        "parseLogoutResponseSoap: missing soap:Body");
    }
    var inner = null;
    for (var bi = 0; bi < body.children.length; bi += 1) {
      var bc = body.children[bi];
      if (bc.type === "element") { inner = bc; break; }
    }
    if (!inner) {
      throw new AuthError("auth-saml/bad-soap",
        "parseLogoutResponseSoap: soap:Body is empty");
    }
    var innerXml = Buffer.from(c14n.canonicalize(inner)).toString("utf8");
    if (vopts.idpVerifyKey || vopts.idpVerifyAlg) {
      _verifyEmbeddedXmlDsig(innerXml, vopts.idpVerifyKey, vopts.idpVerifyAlg, "LogoutResponse");
    }
    var innerLocal = inner.name.split(":").pop();
    if (innerLocal !== "LogoutResponse") {
      throw new AuthError("auth-saml/wrong-root",
        "parseLogoutResponseSoap: body element is " + innerLocal + ", expected LogoutResponse");
    }
    var statusEl = _findChild(inner, "Status", SAML_NS.protocol);
    var statusCode = statusEl ? _attr(_findChild(statusEl, "StatusCode", SAML_NS.protocol), "Value") : null;
    var issuerEl = _findChild(inner, "Issuer", SAML_NS.assertion);
    return {
      id:           _attr(inner, "ID"),
      inResponseTo: _attr(inner, "InResponseTo"),
      destination:  _attr(inner, "Destination"),
      statusCode:   statusCode,
      success:      statusCode === "urn:oasis:names:tc:SAML:2.0:status:Success",
      issuer:       issuerEl ? _textContent(issuerEl) : null,
    };
  }

  return {
    buildAuthnRequest:       buildAuthnRequest,
    verifyResponse:          verifyResponse,
    metadata:                metadata,
    buildLogoutRequest:      buildLogoutRequest,
    parseLogoutRequest:      parseLogoutRequest,
    buildLogoutResponse:     buildLogoutResponse,
    parseLogoutResponse:     parseLogoutResponse,
    buildLogoutRequestPost:  buildLogoutRequestPost,
    parseLogoutRequestPost:  parseLogoutRequestPost,
    buildLogoutRequestSoap:  buildLogoutRequestSoap,
    parseLogoutResponseSoap: parseLogoutResponseSoap,
    entityId:                opts.entityId,
    idpEntityId:             opts.idpEntityId,
  };
}

// ---- SAML EncryptedAssertion decrypt (XMLEnc) ----

// XMLEnc Algorithm URIs we support.
//
// Currently-available standards (W3C XMLEnc 1.1, Recommendation 2013):
//   Symmetric content encryption:
//     http://www.w3.org/2009/xmlenc11#aes128-gcm   (XMLEnc 1.1 §5.2.4)
//     http://www.w3.org/2009/xmlenc11#aes256-gcm   (XMLEnc 1.1 §5.2.4)
//   Asymmetric key transport:
//     http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p   (XMLEnc 1.0 §5.4.2 + RFC 4055)
//     http://www.w3.org/2009/xmlenc11#rsa-oaep          (XMLEnc 1.1 §5.4.2)
//
// AES-CBC content encryption (xmlenc#aes128-cbc / aes256-cbc) is
// intentionally REFUSED: the XML-Encryption padding-oracle research
// (Jager & Somorovsky, "How to Break XML Encryption", CCS 2011)
// demonstrates that CBC mode under XMLEnc is exploitable without per-
// content MAC.
// Operators integrating with IdPs that default to CBC (older ADFS /
// Azure AD / Okta / Keycloak / OneLogin) MUST switch the IdP's
// content-encryption setting to AES-128-GCM or AES-256-GCM. The
// framework follows W3C's CR-2013 advice that GCM be used in new
// deployments; the framework's "never weaken security middleware"
// rule applies here.
//
// SHA-1 anywhere (rsa-oaep-mgf1p with SHA-1 OAEP DigestMethod,
// xmldsig#sha1 DigestMethod) is also refused — Bleichenbacher /
// collision risk plus CVE-2023-49141 class advisories outweigh
// "interop with stale IdPs". Operators upgrade the IdP's digest
// algorithm to SHA-256+ rather than relax the framework defense.
//
// Experimental (framework-private URNs — no IETF/W3C registration;
// these are clearly under `urn:blamejs:experimental:` so operators
// grep them in logs and know the framework owns them. Swap to the
// registered URI once the relevant IETF/W3C WG publishes one):
//   urn:blamejs:experimental:xmlenc:xchacha20-poly1305   (XChaCha20-Poly1305 content encryption)
//   urn:blamejs:experimental:xmlenc:ml-kem-1024          (ML-KEM-1024 key transport)
function _decryptEncryptedAssertion(encAssertion, spPrivateKeyPem) {
  var encData = _findChild(encAssertion, "EncryptedData");
  if (!encData) {
    throw new AuthError("auth-saml/encrypted-no-encrypted-data",
      "EncryptedAssertion missing EncryptedData");
  }
  var encMethod = _findChild(encData, "EncryptionMethod");
  var contentAlg = encMethod && _attr(encMethod, "Algorithm");
  if (!contentAlg) {
    throw new AuthError("auth-saml/encrypted-no-method",
      "EncryptedData missing EncryptionMethod/@Algorithm");
  }
  var keyInfo = _findChild(encData, "KeyInfo");
  if (!keyInfo) {
    throw new AuthError("auth-saml/encrypted-no-keyinfo",
      "EncryptedData missing KeyInfo (EncryptedKey transport required)");
  }
  var encKey = _findChild(keyInfo, "EncryptedKey");
  if (!encKey) {
    throw new AuthError("auth-saml/encrypted-no-encrypted-key",
      "EncryptedData/KeyInfo missing EncryptedKey");
  }
  var ekMethod = _findChild(encKey, "EncryptionMethod");
  var keyAlg = ekMethod && _attr(ekMethod, "Algorithm");
  if (!keyAlg) {
    throw new AuthError("auth-saml/encrypted-no-key-alg",
      "EncryptedKey missing EncryptionMethod/@Algorithm");
  }
  var ekCipherDataNode = _findChild(encKey, "CipherData");
  var ekCipherValueNode = ekCipherDataNode && _findChild(ekCipherDataNode, "CipherValue");
  if (!ekCipherValueNode) {
    throw new AuthError("auth-saml/encrypted-no-key-cipher-value",
      "EncryptedKey missing CipherData/CipherValue");
  }
  var wrappedKey = Buffer.from(_textContent(ekCipherValueNode).replace(/\s+/g, ""), "base64");
  // Unwrap the CEK.
  var cek;
  if (keyAlg === "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p" ||
      keyAlg === "http://www.w3.org/2009/xmlenc11#rsa-oaep") {
    var oaepHashName = "sha1";
    var digestMethodEk = _findChild(ekMethod, "DigestMethod");
    var oaepDigestUri = digestMethodEk && _attr(digestMethodEk, "Algorithm");
    if (oaepDigestUri) {
      if (oaepDigestUri === "http://www.w3.org/2001/04/xmlenc#sha256") oaepHashName = "sha256";
      else if (oaepDigestUri === "http://www.w3.org/2001/04/xmlenc#sha384") oaepHashName = "sha384";
      else if (oaepDigestUri === "http://www.w3.org/2001/04/xmlenc#sha512") oaepHashName = "sha512";
      else {
        throw new AuthError("auth-saml/encrypted-unsupported-oaep-digest",
          "EncryptedKey OAEP DigestMethod " + oaepDigestUri + " not supported");
      }
    }
    if (oaepHashName === "sha1") {
      throw new AuthError("auth-saml/encrypted-weak-oaep-digest",
        "EncryptedKey OAEP DigestMethod is SHA-1 — refused (CVE-2023-49141 class). " +
        "Require SHA-256+ on IdP side.");
    }
    var spKey;
    try { spKey = nodeCrypto.createPrivateKey({ key: spPrivateKeyPem, format: "pem" }); }
    catch (e) {
      throw new AuthError("auth-saml/encrypted-bad-sp-key",
        "spPrivateKeyPem parse failed: " + ((e && e.message) || String(e)));
    }
    try {
      cek = nodeCrypto.privateDecrypt({
        key:         spKey,
        padding:     nodeCrypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash:    oaepHashName,
      }, wrappedKey);
    } catch (eR) {
      throw new AuthError("auth-saml/encrypted-key-unwrap-failed",
        "OAEP unwrap failed: " + ((eR && eR.message) || String(eR)));
    }
  } else if (keyAlg === "urn:blamejs:experimental:xmlenc:ml-kem-1024") {
    // Framework PQC envelope — wrappedKey carries the ML-KEM
    // ciphertext concatenated with the AEAD-wrapped CEK. We invoke
    // b.pqcSoftware.ml_kem_1024.decapsulate to recover the shared
    // secret, then ChaCha20-Poly1305 unwrap. The exact wire shape is
    // the framework's `b.crypto.envelope` format.
    try {
      cek = bCrypto.decryptEnvelope({
        envelope:   wrappedKey,
        privateKey: nodeCrypto.createPrivateKey({ key: spPrivateKeyPem, format: "pem" }),
      });
    } catch (eM) {
      throw new AuthError("auth-saml/encrypted-key-unwrap-failed",
        "ML-KEM-1024 unwrap failed: " + ((eM && eM.message) || String(eM)));
    }
    if (!Buffer.isBuffer(cek)) cek = Buffer.from(cek);
  } else {
    throw new AuthError("auth-saml/encrypted-unsupported-key-alg",
      "EncryptedKey EncryptionMethod " + keyAlg + " not supported " +
      "(supported: W3C xmlenc#rsa-oaep-mgf1p, xmlenc11#rsa-oaep, " +
      "framework-experimental urn:blamejs:experimental:xmlenc:ml-kem-1024). " +
      "AES-CBC content encryption is refused — switch the IdP to AES-128-GCM " +
      "or AES-256-GCM.");
  }
  // Decrypt content with the CEK.
  var contentCipherDataNode = _findChild(encData, "CipherData");
  var contentCipherValueNode = contentCipherDataNode && _findChild(contentCipherDataNode, "CipherValue");
  if (!contentCipherValueNode) {
    throw new AuthError("auth-saml/encrypted-no-content-cipher-value",
      "EncryptedData missing CipherData/CipherValue");
  }
  var contentBlob = Buffer.from(_textContent(contentCipherValueNode).replace(/\s+/g, ""), "base64");
  var clearBytes;
  if (contentAlg === "http://www.w3.org/2009/xmlenc11#aes128-gcm" ||
      contentAlg === "http://www.w3.org/2009/xmlenc11#aes256-gcm") {
    var aesBits = contentAlg.indexOf("aes128") !== -1 ? 128 : 256;                                // AES key size
    var expectedKeyBytes = aesBits / 8;                                                            // bits→bytes
    if (cek.length !== expectedKeyBytes) {
      throw new AuthError("auth-saml/encrypted-wrong-cek-len",
        "AES-" + aesBits + "-GCM CEK length is " + cek.length + ", expected " + expectedKeyBytes);
    }
    if (contentBlob.length < 28) {                                                                 // 12 IV + 16 tag
      throw new AuthError("auth-saml/encrypted-content-too-short",
        "AES-GCM CipherValue too short to contain IV (12) + tag (16)");
    }
    var iv  = contentBlob.subarray(0, 12);                                                          // GCM IV size
    var tag = contentBlob.subarray(contentBlob.length - 16);                                       // GCM tag size
    var ct  = contentBlob.subarray(12, contentBlob.length - 16);
    var decipher = nodeCrypto.createDecipheriv("aes-" + aesBits + "-gcm", cek, iv);
    decipher.setAuthTag(tag);
    try { clearBytes = Buffer.concat([decipher.update(ct), decipher.final()]); }
    catch (eD) {
      throw new AuthError("auth-saml/encrypted-content-tag-mismatch",
        "AES-GCM authentication tag mismatch: " + ((eD && eD.message) || String(eD)));
    }
  } else if (contentAlg === "urn:blamejs:experimental:xmlenc:xchacha20-poly1305") {
    if (cek.length !== 32) {                                                                       // XChaCha20 key size
      throw new AuthError("auth-saml/encrypted-wrong-cek-len",
        "XChaCha20-Poly1305 CEK length is " + cek.length + ", expected 32");
    }
    if (contentBlob.length < 40) {                                                                 // 24 nonce + 16 tag
      throw new AuthError("auth-saml/encrypted-content-too-short",
        "XChaCha20-Poly1305 CipherValue too short");
    }
    var xnonce = contentBlob.subarray(0, 24);                                                       // XChaCha20 nonce size
    var xtag   = contentBlob.subarray(contentBlob.length - 16);                                    // Poly1305 tag size
    var xct    = contentBlob.subarray(24, contentBlob.length - 16);
    try {
      clearBytes = bCrypto.aeadDecrypt({
        alg:   "xchacha20-poly1305",
        key:   cek,
        nonce: xnonce,
        ct:    xct,
        tag:   xtag,
      });
    } catch (eX) {
      throw new AuthError("auth-saml/encrypted-content-tag-mismatch",
        "XChaCha20-Poly1305 tag mismatch: " + ((eX && eX.message) || String(eX)));
    }
  } else {
    throw new AuthError("auth-saml/encrypted-unsupported-content-alg",
      "EncryptedData EncryptionMethod " + contentAlg + " not supported " +
      "(supported: W3C xmlenc11#aes128-gcm, xmlenc11#aes256-gcm, " +
      "framework-experimental urn:blamejs:experimental:xmlenc:xchacha20-poly1305). " +
      "AES-CBC content encryption is refused — switch the IdP to AES-128-GCM or AES-256-GCM " +
      "(XMLEnc CBC padding-oracle class, Jager & Somorovsky CCS 2011).");
  }
  return clearBytes.toString("utf8");
}

// ---- SAML SLO XMLDSig-Enveloped (HTTP-POST/SOAP) ----

// PQC SignatureMethod URIs used by the embedded XMLDSig signatures.
// Standard XMLDSig vocabulary classical signing URIs (W3C XMLDSig
// Core 1.1 + RFC 9231 for Ed25519) are dispatched via _sigAlgUrn (sign
// side) and the SUPPORTED_SIG table (verify side). The framework adds two non-standard URNs for
// ML-DSA because no W3C/IETF XMLDSig URI registration exists for
// post-quantum signers yet (LAMPS WG has open drafts but none final).
// Operators integrating with PQC-aware IdPs that exchange those URNs
// out-of-band can use them; operators integrating with classical IdPs
// (the public SAML deployment baseline today) use the W3C URIs.

function _embedXmlDsig(bodyXml, refId, signingKey, signingAlg) {
  // XMLDSig-Enveloped over the LogoutRequest / LogoutResponse root.
  // Pipeline:
  //   1. exclusive-c14n digest the LogoutRequest element with the
  //      operator-supplied SignatureMethod's digest (SHA3-512 for
  //      PQC + Ed25519, SHA-256/384/512 for classical RSA/ECDSA).
  //   2. Build SignedInfo with that digest in the Reference.
  //   3. exclusive-c14n SignedInfo and sign it via the chosen alg.
  //   4. Emit the ds:Signature element inside the root.
  var sigAlgUrn = _sigAlgUrn(signingAlg);
  if (!sigAlgUrn) {
    throw new AuthError("auth-saml/bad-signing-alg",
      "_embedXmlDsig: signingAlg must be 'ml-dsa-65' / 'ml-dsa-87' / 'ed25519' / " +
      "'rsa-sha256' / 'rsa-sha384' / 'rsa-sha512' / " +
      "'ecdsa-sha256' / 'ecdsa-sha384' / 'ecdsa-sha512'");
  }
  // PQC requires a Uint8Array; classical accepts PEM string or
  // KeyObject. ed25519 accepts both raw Uint8Array (32 bytes) and
  // KeyObject/PEM. We validate the key shape per alg family.
  var isPqc = signingAlg === "ml-dsa-65" || signingAlg === "ml-dsa-87";
  if (isPqc && !(signingKey instanceof Uint8Array)) {
    throw new AuthError("auth-saml/bad-signing-key",
      "_embedXmlDsig: signingKey for " + signingAlg + " must be a Uint8Array");
  }
  if (!isPqc && signingAlg !== "ed25519" &&
      typeof signingKey !== "string" &&
      !(signingKey && typeof signingKey === "object" && signingKey.type === "private")) {
    throw new AuthError("auth-saml/bad-signing-key",
      "_embedXmlDsig: signingKey for classical " + signingAlg +
      " must be a PEM string or node:crypto KeyObject");
  }
  var sigMethodUri = sigAlgUrn.urn;
  // DigestMethod follows the SignatureMethod family:
  //   classical SHA-256 family → xmlenc#sha256/384/512 (W3C XMLDSig)
  //   PQC + Ed25519             → xmldsig-more#sha3-512 (framework default)
  var digestMethodUri;
  if (signingAlg === "rsa-sha256" || signingAlg === "ecdsa-sha256") {
    digestMethodUri = "http://www.w3.org/2001/04/xmlenc#sha256";
  } else if (signingAlg === "rsa-sha384" || signingAlg === "ecdsa-sha384") {
    digestMethodUri = "http://www.w3.org/2001/04/xmlenc#sha384";
  } else if (signingAlg === "rsa-sha512" || signingAlg === "ecdsa-sha512") {
    digestMethodUri = "http://www.w3.org/2001/04/xmlenc#sha512";
  } else {
    digestMethodUri = "http://www.w3.org/2007/05/xmldsig-more#sha3-512";
  }
  var c14n = xmlC14n();
  // Pick the digest function matching digestMethodUri.
  var digestNodeAlg;
  if (digestMethodUri === "http://www.w3.org/2001/04/xmlenc#sha256")      digestNodeAlg = "sha256";
  else if (digestMethodUri === "http://www.w3.org/2001/04/xmlenc#sha384") digestNodeAlg = "sha384";
  else if (digestMethodUri === "http://www.w3.org/2001/04/xmlenc#sha512") digestNodeAlg = "sha512";
  else                                                                    digestNodeAlg = "sha3-512";
  var refDigest = nodeCrypto.createHash(digestNodeAlg).update(c14n.canonicalize(c14n.parse(bodyXml))).digest();
  var signedInfo =
    "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
    "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
    "<ds:SignatureMethod Algorithm=\"" + sigMethodUri + "\"/>" +
    "<ds:Reference URI=\"#" + refId + "\">" +
    "<ds:Transforms>" +
    "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>" +
    "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>" +
    "</ds:Transforms>" +
    "<ds:DigestMethod Algorithm=\"" + digestMethodUri + "\"/>" +
    "<ds:DigestValue>" + refDigest.toString("base64") + "</ds:DigestValue>" +
    "</ds:Reference>" +
    "</ds:SignedInfo>";
  var signedInfoCanonical = c14n.canonicalize(c14n.parse(signedInfo));
  var sigBytes = sigAlgUrn.sign(signedInfoCanonical, signingKey);
  var sigEl =
    "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
    signedInfo +
    "<ds:SignatureValue>" + Buffer.from(sigBytes).toString("base64") + "</ds:SignatureValue>" +
    "</ds:Signature>";
  // Insert Signature as the second child after Issuer (per SAML 2.0
  // schema — saml:Issuer always precedes ds:Signature).
  var issuerCloseIdx = bodyXml.indexOf("</saml:Issuer>");
  if (issuerCloseIdx === -1) {
    throw new AuthError("auth-saml/no-issuer",
      "_embedXmlDsig: bodyXml missing saml:Issuer element");
  }
  var splitAt = issuerCloseIdx + "</saml:Issuer>".length;
  return bodyXml.substring(0, splitAt) + sigEl + bodyXml.substring(splitAt);
}

function _verifyEmbeddedXmlDsig(xml, idpVerifyKey, idpVerifyAlg, expectedRootLocal) {
  if (!idpVerifyKey || !idpVerifyAlg) return;
  var sigAlgUrn = _sigAlgUrn(idpVerifyAlg);
  if (!sigAlgUrn) {
    throw new AuthError("auth-saml/bad-verify-alg",
      "idpVerifyAlg must be 'ml-dsa-65' / 'ml-dsa-87' / 'ed25519' / " +
      "'rsa-sha256' / 'rsa-sha384' / 'rsa-sha512' / " +
      "'ecdsa-sha256' / 'ecdsa-sha384' / 'ecdsa-sha512'");
  }
  var expectedSigUri = sigAlgUrn.urn;
  var c14n = xmlC14n();
  var root = c14n.parse(xml);
  var rootLocal = root.name.split(":").pop();
  if (rootLocal !== expectedRootLocal) {
    throw new AuthError("auth-saml/wrong-root",
      "_verifyEmbeddedXmlDsig: root is " + rootLocal + ", expected " + expectedRootLocal);
  }
  var sigNode = _findChild(root, "Signature");
  if (!sigNode) {
    throw new AuthError("auth-saml/no-signature",
      "_verifyEmbeddedXmlDsig: " + expectedRootLocal + " has no embedded ds:Signature");
  }
  var signedInfo = _findChild(sigNode, "SignedInfo");
  if (!signedInfo) {
    throw new AuthError("auth-saml/no-signed-info",
      "_verifyEmbeddedXmlDsig: Signature missing SignedInfo");
  }
  // CanonicalizationMethod check (W3C XMLDSig Core 1.1 §4.5). Only
  // exclusive-c14n (with or without comments) is supported because the
  // framework's xml-c14n module canonicalizes via xml-exc-c14n. Older
  // SAML deployments using inclusive c14n
  // (http://www.w3.org/TR/2001/REC-xml-c14n-20010315) would silently
  // digest-mismatch — refuse explicitly with a clear error.
  var canonMethodNode = _findChild(signedInfo, "CanonicalizationMethod");
  var canonUri = canonMethodNode && _attr(canonMethodNode, "Algorithm");
  if (canonUri !== "http://www.w3.org/2001/10/xml-exc-c14n#" &&
      canonUri !== "http://www.w3.org/2001/10/xml-exc-c14n#WithComments") {
    throw new AuthError("auth-saml/unsupported-c14n",
      "_verifyEmbeddedXmlDsig: CanonicalizationMethod " + canonUri + " not supported " +
      "(only W3C exclusive xml-exc-c14n is supported; inclusive c14n is refused — " +
      "switch the IdP to exclusive canonicalization)");
  }
  var sigMethodNode = _findChild(signedInfo, "SignatureMethod");
  var sigUri = sigMethodNode && _attr(sigMethodNode, "Algorithm");
  if (sigUri !== expectedSigUri) {
    throw new AuthError("auth-saml/wrong-sig-alg",
      "_verifyEmbeddedXmlDsig: SignatureMethod " + sigUri + " != expected " + expectedSigUri +
      " (alg-confusion defense)");
  }
  var refNode = _findChild(signedInfo, "Reference");
  if (!refNode) {
    throw new AuthError("auth-saml/no-reference",
      "_verifyEmbeddedXmlDsig: SignedInfo missing Reference");
  }
  var refUri = _attr(refNode, "URI") || "";
  if (refUri.charAt(0) !== "#") {
    throw new AuthError("auth-saml/external-reference",
      "_verifyEmbeddedXmlDsig: Reference URI must be a same-document fragment");
  }
  var refId = refUri.substring(1);
  var rootId = _attr(root, "ID");
  if (rootId !== refId) {
    throw new AuthError("auth-saml/ref-mismatch",
      "_verifyEmbeddedXmlDsig: Reference URI '#" + refId + "' does not match root ID '" + rootId +
      "' (signature-wrapping defense)");
  }
  var digestMethodNode = _findChild(refNode, "DigestMethod");
  var digestUri = digestMethodNode && _attr(digestMethodNode, "Algorithm");
  // Allow either sha3-512 (framework default) or the SHA-2 family.
  var digestAlgName;
  if (digestUri === "http://www.w3.org/2007/05/xmldsig-more#sha3-512") digestAlgName = "sha3-512";
  else if (Object.prototype.hasOwnProperty.call(SUPPORTED_DIGEST, digestUri)) digestAlgName = SUPPORTED_DIGEST[digestUri];
  else {
    throw new AuthError("auth-saml/unsupported-digest",
      "_verifyEmbeddedXmlDsig: DigestMethod " + digestUri + " not supported");
  }
  var digestValueNode = _findChild(refNode, "DigestValue");
  var expectedDigestB64 = _textContent(digestValueNode);
  if (!expectedDigestB64) {
    throw new AuthError("auth-saml/no-digest-value",
      "_verifyEmbeddedXmlDsig: Reference missing DigestValue");
  }
  // Recompute the digest over the root with Signature stripped
  // (enveloped-signature transform). Clone root + filter out
  // ds:Signature children, then canonicalize.
  var rootForDigest = structuredClone(root);
  rootForDigest.children = rootForDigest.children.filter(function (c) {
    if (c.type !== "element") return true;
    return c.name.split(":").pop() !== "Signature";
  });
  var canonical = c14n.canonicalize(rootForDigest);
  var actualDigest = nodeCrypto.createHash(digestAlgName).update(canonical).digest();
  if (!timingSafeEqual(Buffer.from(expectedDigestB64, "base64"), actualDigest)) {
    throw new AuthError("auth-saml/digest-mismatch",
      "_verifyEmbeddedXmlDsig: Reference DigestValue does not match canonicalized root " +
      "(signature-wrapping or tampered content)");
  }
  // Canonicalize SignedInfo + PQC-verify signature.
  var signedInfoCanonical = c14n.canonicalize(signedInfo);
  var sigValueNode = _findChild(sigNode, "SignatureValue");
  var sigB64 = sigValueNode ? _textContent(sigValueNode).replace(/\s+/g, "") : "";
  if (!sigB64) {
    throw new AuthError("auth-saml/no-signature-value",
      "_verifyEmbeddedXmlDsig: Signature missing SignatureValue");
  }
  var sigBytes = Buffer.from(sigB64, "base64");
  var ok = false;
  try { ok = sigAlgUrn.verify(sigBytes, signedInfoCanonical, idpVerifyKey); }
  catch (e) {
    throw new AuthError("auth-saml/sig-verify-threw",
      "_verifyEmbeddedXmlDsig: signature verify threw: " + ((e && e.message) || String(e)));
  }
  if (!ok) {
    throw new AuthError("auth-saml/bad-signature",
      "_verifyEmbeddedXmlDsig: embedded XMLDSig signature does not verify against idpVerifyKey");
  }
}

// ---- SAML SLO signature-alg dispatch ----

function _sigAlgUrn(alg) {
  // PQC signers — framework-private experimental URIs. The `urn:`
  // prefix lives under `urn:blamejs:experimental:` so operators
  // grepping their IdP / SP logs immediately see the framework
  // ownership and know these are NOT IANA/W3C-registered. No IETF /
  // W3C XMLDSig assignment for ML-DSA exists yet; the IETF LAMPS WG
  // has open drafts (draft-ietf-lamps-x509-mldsa, -lamps-cms-mldsa)
  // but no XMLDSig URI registration. Once a registered URI exists,
  // we'll add it alongside and deprecate the experimental one.
  //
  // These URNs interop only with peers that share them out-of-band
  // (e.g. two SPs of the same vendor). Operators integrating with
  // real-world classical IdPs use the W3C XMLDSig URIs below.
  if (alg === "ml-dsa-65") {
    return {
      urn:    "urn:blamejs:experimental:saml-sig-alg:ml-dsa-65",
      sign:   function (bytes, sk) { return pqcSoftware.ml_dsa_65.sign(new Uint8Array(bytes), sk); },
      verify: function (sig, msg, pk) { return pqcSoftware.ml_dsa_65.verify(sig, msg, pk); },
      experimental: true,
    };
  }
  if (alg === "ml-dsa-87") {
    return {
      urn:    "urn:blamejs:experimental:saml-sig-alg:ml-dsa-87",
      sign:   function (bytes, sk) { return pqcSoftware.ml_dsa_87.sign(new Uint8Array(bytes), sk); },
      verify: function (sig, msg, pk) { return pqcSoftware.ml_dsa_87.verify(sig, msg, pk); },
      experimental: true,
    };
  }
  // Ed25519 — W3C XMLDSig URN registered in RFC 9231.
  if (alg === "ed25519") {
    return {
      urn:    "http://www.w3.org/2021/04/xmldsig-more#ed25519",
      sign:   function (bytes, sk) {
        var keyObj = (sk && typeof sk === "object" && sk.type === "private") ? sk
          : (typeof sk === "string" || (sk && sk.kty)) ? nodeCrypto.createPrivateKey(sk)
          : nodeCrypto.createPrivateKey({ key: Buffer.concat([
              Buffer.from("302e020100300506032b657004220420", "hex"),                                 // Ed25519 PKCS#8 prefix
              Buffer.from(sk),
            ]), format: "der", type: "pkcs8" });
        return nodeCrypto.sign(null, Buffer.from(bytes), keyObj);
      },
      verify: function (sig, msg, pk) {
        var keyObj = (pk && typeof pk === "object" && pk.type === "public") ? pk
          : (typeof pk === "string" || (pk && pk.kty)) ? nodeCrypto.createPublicKey(pk)
          : nodeCrypto.createPublicKey({ key: Buffer.concat([
              Buffer.from("302a300506032b6570032100", "hex"),                                         // Ed25519 SPKI prefix
              Buffer.from(pk),
            ]), format: "der", type: "spki" });
        return nodeCrypto.verify(null, Buffer.from(msg), keyObj, Buffer.from(sig));
      },
    };
  }
  // Classical XMLDSig algorithms registered in W3C XMLDSig Core 1.1 /
  // RFC 4051. Keys are PEM-formatted strings or node:crypto KeyObject
  // instances. Operators integrating with real-world IdPs that
  // haven't moved to PQC use these — RSA-SHA-256 is by far the most
  // common signing algorithm on the public SAML IdP wire today.
  var classical = {
    "rsa-sha256":   { urn: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",   hash: "sha256" },
    "rsa-sha384":   { urn: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",   hash: "sha384" },
    "rsa-sha512":   { urn: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",   hash: "sha512" },
    "ecdsa-sha256": { urn: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", hash: "sha256", ec: true },
    "ecdsa-sha384": { urn: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", hash: "sha384", ec: true },
    "ecdsa-sha512": { urn: "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", hash: "sha512", ec: true },
  };
  if (Object.prototype.hasOwnProperty.call(classical, alg)) {
    var spec = classical[alg];
    return {
      urn: spec.urn,
      sign: function (bytes, sk) {
        var keyObj = (sk && typeof sk === "object" && sk.type === "private") ? sk
          : nodeCrypto.createPrivateKey(sk);
        var opts2 = { key: keyObj };
        if (spec.ec) opts2.dsaEncoding = "der";
        return nodeCrypto.sign(spec.hash, Buffer.from(bytes), opts2);
      },
      verify: function (sig, msg, pk) {
        var keyObj = (pk && typeof pk === "object" && pk.type === "public") ? pk
          : nodeCrypto.createPublicKey(pk);
        var opts2 = { key: keyObj };
        if (spec.ec) opts2.dsaEncoding = "der";
        return nodeCrypto.verify(spec.hash, Buffer.from(msg), opts2, Buffer.from(sig));
      },
    };
  }
  return null;
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
