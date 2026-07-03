// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module     b.middleware.protectedResourceMetadata
 * @nav        Identity
 * @title      Protected Resource Metadata
 * @order      210
 * @slug       protected-resource-metadata
 *
 * @intro
 *   draft-ietf-oauth-resource-metadata: serves the
 *   `/.well-known/oauth-protected-resource` document so RFC 9728
 *   clients can auto-discover which authorization servers issue
 *   tokens for this resource, what scopes the resource accepts,
 *   what dpop algorithms the resource verifies, and which bearer-
 *   method binding (DPoP / mTLS cnf claim) is required. Pairs with
 *   b.middleware.bearerAuth so a 401 from the protected resource
 *   includes `WWW-Authenticate: Bearer resource_metadata=<url>` and
 *   the client can self-rediscover.
 *
 * @card
 *   `.well-known/oauth-protected-resource` discovery endpoint per
 *   draft-ietf-oauth-resource-metadata. Closes the gap that previously
 *   forced operators to hand-write the JSON.
 */

var framework_error = require("../framework-error");
var validateOpts    = require("../validate-opts");
var requestHelpers  = require("../request-helpers");
var safeUrl         = require("../safe-url");
var nodeCrypto      = require("node:crypto");

var H = requestHelpers.HTTP_STATUS;

var ProtectedResourceMetadataError = framework_error.defineClass(
  "ProtectedResourceMetadataError",
  "middleware/protected-resource-metadata"
);

var ALLOWED_BEARER_METHODS  = ["header", "body", "query"];
var ALLOWED_DPOP_ALGS       = ["ES256", "ES384", "RS256", "PS256", "EdDSA", "ML-DSA-65", "ML-DSA-87"];
// RFC 9728 §3.2 — signed_metadata signing algs. PQC-first per the
// framework's hard rule §2 (ML-DSA-* preferred); classical algs
// available for backwards-interop with relying parties without PQC
// libraries on hand.
var ALLOWED_SIGNED_METADATA_ALGS = ["ML-DSA-87", "ML-DSA-65", "EdDSA", "ES256", "ES384", "PS256", "PS384"];

function _b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

/**
 * @primitive b.middleware.protectedResourceMetadata
 * @signature b.middleware.protectedResourceMetadata(opts)
 * @since     0.8.77
 * @related   b.auth.oauth.introspectToken, b.middleware.bearerAuth
 *
 * Returns a request middleware that serves the protected-resource
 * metadata JSON document at `/.well-known/oauth-protected-resource`
 * (or operator-overridden path).
 *
 * @opts
 *   {
 *     resource:                       string,        // canonical resource URI (required)
 *     authorizationServers:           string[],      // issuer URLs that mint tokens for this resource (required, ≥1)
 *     scopesSupported?:               string[],
 *     bearerMethodsSupported?:        ("header"|"body"|"query")[],   // default ["header"]
 *     resourceSigningAlgValuesSupported?: string[], // for signed introspection / jwt-secured responses
 *     resourceDocumentation?:         string,        // URL to operator docs
 *     resourcePolicyUri?:             string,
 *     resourceTosUri?:                string,
 *     dpopSigningAlgValuesSupported?: string[],
 *     dpopBoundAccessTokensRequired?: boolean,
 *     mtlsBoundAccessTokensRequired?: boolean,
 *     path?:                          string,        // default "/.well-known/oauth-protected-resource"
 *   }
 *
 * @example
 *   var mw = b.middleware.protectedResourceMetadata({
 *     resource:             "https://api.example.com",
 *     authorizationServers: ["https://idp.example.com"],
 *     scopesSupported:      ["read", "write"],
 *     dpopBoundAccessTokensRequired: true,
 *   });
 *   app.use(mw);
 */
function create(opts) {
  validateOpts.requireObject(opts, "middleware.protectedResourceMetadata",
    ProtectedResourceMetadataError, "middleware/protected-resource-metadata/bad-opts");
  validateOpts.requireNonEmptyString(opts.resource, "resource",
    ProtectedResourceMetadataError, "middleware/protected-resource-metadata/no-resource");

  if (!Array.isArray(opts.authorizationServers) || opts.authorizationServers.length === 0) {
    throw new ProtectedResourceMetadataError(
      "middleware/protected-resource-metadata/no-as",
      "authorizationServers must be a non-empty array of issuer URLs");
  }
  // RFC 9728 §3 + RFC 8414 §3.1: authorizationServers entries
  // are issuer URLs and MUST be https://. Pre-v0.9.x only required
  // non-empty string, so an operator typo could ship `http://idp.test`
  // (or, worse, `javascript:` / `data:`) to clients via the well-known
  // document. allowHttp opts.allowHttp passes the framework's
  // safe-url loopback exception through (matches b.auth.oauth's
  // _validateUrl shape).
  var allowHttp = opts.allowHttp === true;
  opts.authorizationServers.forEach(function (u, i) {
    if (typeof u !== "string" || u.length === 0) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-as",
        "authorizationServers[" + i + "] must be a non-empty string");
    }
    try {
      safeUrl.parse(u, {
        allowedProtocols: allowHttp ? safeUrl.ALLOW_HTTP_ALL : safeUrl.ALLOW_HTTP_TLS,
      });
    } catch (_e) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-as-url",
        "authorizationServers[" + i + "] = '" + u + "' is not a valid " +
        (allowHttp ? "http(s)" : "https") + " URL (RFC 9728 §3 / RFC 8414 §3.1)");
    }
  });

  var bearerMethods = opts.bearerMethodsSupported || ["header"];
  bearerMethods.forEach(function (m, i) {
    if (ALLOWED_BEARER_METHODS.indexOf(m) === -1) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-bearer-method",
        "bearerMethodsSupported[" + i + "] must be one of: " + ALLOWED_BEARER_METHODS.join(", "));
    }
  });

  if (opts.dpopSigningAlgValuesSupported) {
    opts.dpopSigningAlgValuesSupported.forEach(function (a, i) {
      if (ALLOWED_DPOP_ALGS.indexOf(a) === -1) {
        throw new ProtectedResourceMetadataError(
          "middleware/protected-resource-metadata/bad-dpop-alg",
          "dpopSigningAlgValuesSupported[" + i + "] = '" + a +
          "' not in allowlist: " + ALLOWED_DPOP_ALGS.join(", "));
      }
    });
  }

  var path = opts.path || "/.well-known/oauth-protected-resource";

  var doc = {
    resource:                opts.resource,
    authorization_servers:   opts.authorizationServers,
    bearer_methods_supported: bearerMethods,
  };
  if (opts.scopesSupported)                       doc.scopes_supported = opts.scopesSupported;
  if (opts.resourceSigningAlgValuesSupported)     doc.resource_signing_alg_values_supported = opts.resourceSigningAlgValuesSupported;
  if (opts.resourceDocumentation)                 doc.resource_documentation = opts.resourceDocumentation;
  if (opts.resourcePolicyUri)                     doc.resource_policy_uri = opts.resourcePolicyUri;
  if (opts.resourceTosUri)                        doc.resource_tos_uri = opts.resourceTosUri;
  if (opts.dpopSigningAlgValuesSupported)         doc.dpop_signing_alg_values_supported = opts.dpopSigningAlgValuesSupported;
  if (opts.dpopBoundAccessTokensRequired === true) doc.dpop_bound_access_tokens_required = true;
  if (opts.mtlsBoundAccessTokensRequired === true) doc.tls_client_certificate_bound_access_tokens = true;

  // RFC 9728 §3.2 signed_metadata. Operators with an
  // anti-tamper requirement pass `signMetadata: { key, alg, kid }`;
  // the middleware emits `application/jwt` carrying the JWS-signed
  // metadata. Default output remains cleartext `application/json`.
  var signedJwt = null;
  var signedDoc = null;
  if (opts.signMetadata) {
    var sm = opts.signMetadata;
    if (!sm || typeof sm !== "object") {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-sign",
        "signMetadata must be an object { key, alg, kid? }");
    }
    if (!sm.alg || ALLOWED_SIGNED_METADATA_ALGS.indexOf(sm.alg) === -1) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-sign-alg",
        "signMetadata.alg '" + sm.alg + "' not in allowlist: " +
        ALLOWED_SIGNED_METADATA_ALGS.join(", "));
    }
    if (!sm.key) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-sign-key",
        "signMetadata.key is required (KeyObject, PEM string/Buffer, or JWK object)");
    }
    var signingKey;
    try {
      if (sm.key instanceof nodeCrypto.KeyObject) {
        signingKey = sm.key;
      } else if (typeof sm.key === "string" || Buffer.isBuffer(sm.key)) {
        signingKey = nodeCrypto.createPrivateKey({ key: sm.key, format: "pem" });
      } else if (typeof sm.key === "object") {
        signingKey = nodeCrypto.createPrivateKey({ key: sm.key, format: "jwk" });
      } else {
        throw new ProtectedResourceMetadataError(
          "middleware/protected-resource-metadata/bad-sign-key",
          "signMetadata.key must be KeyObject, PEM string/Buffer, or JWK object");
      }
    } catch (e) {
      if (e instanceof ProtectedResourceMetadataError) throw e;
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-sign-key",
        "signMetadata.key parse failed: " + ((e && e.message) || String(e)));
    }
    // RFC 9728 §3.2 — signed_metadata is a JWS carrying the same
    // metadata claims as the cleartext document plus iss + sub
    // (resource URI) for identification at consume-side.
    signedDoc = Object.assign({}, doc, { iss: opts.resource, sub: opts.resource });
    var jwsHeader = { alg: sm.alg, typ: "oauth-protected-resource+jwt" };
    if (sm.kid) jwsHeader.kid = sm.kid;
    var headerEnc  = _b64url(JSON.stringify(jwsHeader));
    var payloadEnc = _b64url(JSON.stringify(signedDoc));
    var input      = headerEnc + "." + payloadEnc;
    // PQC algs (ML-DSA-*) + EdDSA pass null hash; ES* / PS* / RS* use
    // their RFC 7518 hash + dsaEncoding shape.
    var signParams = { key: signingKey };
    var signAlgo   = null;
    if (sm.alg === "ES256") { signAlgo = "sha256"; signParams.dsaEncoding = "ieee-p1363"; }
    else if (sm.alg === "ES384") { signAlgo = "sha384"; signParams.dsaEncoding = "ieee-p1363"; }
    else if (sm.alg === "PS256") { signAlgo = "sha256"; signParams.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING; signParams.saltLength = 32; }   // RFC 7518 PS256 salt
    else if (sm.alg === "PS384") { signAlgo = "sha384"; signParams.padding = nodeCrypto.constants.RSA_PKCS1_PSS_PADDING; signParams.saltLength = 48; }   // RFC 7518 PS384 salt
    var sig = nodeCrypto.sign(signAlgo, Buffer.from(input, "ascii"), signParams);
    signedJwt = input + "." + _b64url(sig);
  }

  var bodyText  = JSON.stringify(doc);
  var bodyBytes = Buffer.byteLength(bodyText, "utf8");
  var signedBytes = signedJwt ? Buffer.byteLength(signedJwt, "utf8") : 0;

  function middleware(req, res, next) {
    if (req.url !== path && req.url.split("?")[0] !== path) {
      next();
      return;
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(H.METHOD_NOT_ALLOWED, {
        "Allow":         "GET, HEAD",
        "Cache-Control": "no-store",
      });
      res.end();
      return;
    }
    // RFC 9728 §3.2 — operators that wired signMetadata serve the JWS
    // form when the client advertises Accept: application/jwt (or via
    // the *.jwt path suffix). The cleartext document is still served
    // on the default path / Accept: application/json.
    var accept = (req.headers && req.headers.accept) || "";
    var wantsSigned = signedJwt && (accept.indexOf("application/jwt") !== -1);
    if (wantsSigned) {
      res.writeHead(H.OK, {
        "Content-Type":   "application/jwt",
        "Content-Length": String(signedBytes),
        "Cache-Control":  "public, max-age=3600",
      });
      if (req.method === "HEAD") { res.end(); return; }
      res.end(signedJwt);
      return;
    }
    res.writeHead(H.OK, {
      "Content-Type":   "application/json",
      "Content-Length": String(bodyBytes),
      "Cache-Control":  "public, max-age=3600",
    });
    if (req.method === "HEAD") { res.end(); return; }
    res.end(bodyText);
  }

  middleware.document      = doc;
  middleware.signedMetadata = signedJwt;
  middleware.path          = path;
  return middleware;
}

module.exports = {
  create:                        create,
  ProtectedResourceMetadataError: ProtectedResourceMetadataError,
  ALLOWED_BEARER_METHODS:        ALLOWED_BEARER_METHODS,
  ALLOWED_DPOP_ALGS:             ALLOWED_DPOP_ALGS,
  ALLOWED_SIGNED_METADATA_ALGS:  ALLOWED_SIGNED_METADATA_ALGS,
};
