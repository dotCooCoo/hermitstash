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

var H = requestHelpers.HTTP_STATUS;

var ProtectedResourceMetadataError = framework_error.defineClass(
  "ProtectedResourceMetadataError",
  "middleware/protected-resource-metadata"
);

var ALLOWED_BEARER_METHODS  = ["header", "body", "query"];
var ALLOWED_DPOP_ALGS       = ["ES256", "ES384", "RS256", "PS256", "EdDSA", "ML-DSA-65", "ML-DSA-87"];

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
  opts.authorizationServers.forEach(function (u, i) {
    if (typeof u !== "string" || u.length === 0) {
      throw new ProtectedResourceMetadataError(
        "middleware/protected-resource-metadata/bad-as",
        "authorizationServers[" + i + "] must be a non-empty string");
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

  var bodyText  = JSON.stringify(doc);
  var bodyBytes = Buffer.byteLength(bodyText, "utf8");

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
    res.writeHead(H.OK, {
      "Content-Type":   "application/json",
      "Content-Length": String(bodyBytes),
      "Cache-Control":  "public, max-age=3600",
    });
    if (req.method === "HEAD") { res.end(); return; }
    res.end(bodyText);
  }

  middleware.document = doc;
  middleware.path     = path;
  return middleware;
}

module.exports = {
  create:                        create,
  ProtectedResourceMetadataError: ProtectedResourceMetadataError,
  ALLOWED_BEARER_METHODS:        ALLOWED_BEARER_METHODS,
  ALLOWED_DPOP_ALGS:             ALLOWED_DPOP_ALGS,
};
