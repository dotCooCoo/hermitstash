// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * OpenAPI 3.1 — security-scheme builders.
 *
 * Each helper returns a JSON-Schema-compatible securityScheme object
 * the OpenAPI builder slots under `components.securitySchemes`.
 * Operators reference them by name in `security` requirements:
 *
 *   var openapi = b.openapi.create({ ... });
 *   openapi.security.add("bearerJwt", b.openapi.security.bearer({ jwtBearer: true }));
 *   openapi.path("get", "/me", { security: [{ bearerJwt: [] }] });
 *
 * Helpers cover every IANA-registered scheme operators reach for:
 *
 *   .bearer({ jwtBearer? })          → Bearer token
 *   .basic()                         → HTTP Basic auth
 *   .apiKey({ name, in })            → API key in header / query / cookie
 *   .oauth2({ flows })               → OAuth2 with AuthCode / ClientCreds /
 *                                       Implicit / Password flow specs
 *   .openIdConnect({ url })          → OIDC discovery URL
 *   .mtls()                          → mutual TLS (RFC 8705)
 *   .dpop()                          → DPoP-bound bearer (RFC 9449)
 *
 * The helpers throw at config-time on bad opts (config-time-throw discipline) so
 * an operator's typo in the OpenAPI document fails at the build step,
 * not at consumer-validation time.
 */

var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var OpenApiError = defineClass("OpenApiError", { alwaysPermanent: true });

function bearer(opts) {
  opts = opts || {};
  validateOpts(opts, ["jwtBearer", "description"], "openapi.security.bearer");
  var out = {
    type:   "http",
    scheme: "bearer",
  };
  if (opts.jwtBearer === true) out.bearerFormat = "JWT";
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

function basic(opts) {
  opts = opts || {};
  validateOpts(opts, ["description"], "openapi.security.basic");
  var out = { type: "http", scheme: "basic" };
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

function apiKey(opts) {
  opts = opts || {};
  validateOpts(opts, ["name", "in", "description"], "openapi.security.apiKey");
  validateOpts.requireNonEmptyString(opts.name, "apiKey: name",
    OpenApiError, "openapi/bad-security");
  var validIn = ["header", "query", "cookie"];
  if (validIn.indexOf(opts.in) === -1) {
    throw new OpenApiError("openapi/bad-security",
      "apiKey: in must be one of " + validIn.join(", ") +
      " — got " + JSON.stringify(opts.in));
  }
  var out = { type: "apiKey", name: opts.name, in: opts.in };
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

function _validateFlow(name, flow) {
  if (!flow || typeof flow !== "object") {
    throw new OpenApiError("openapi/bad-security",
      "oauth2." + name + ": flow must be an object");
  }
  if (typeof flow.scopes !== "object" || flow.scopes == null) {
    throw new OpenApiError("openapi/bad-security",
      "oauth2." + name + ": scopes must be an object (scopeName -> description)");
  }
  if (name === "authorizationCode" || name === "implicit") {
    validateOpts.requireNonEmptyString(flow.authorizationUrl,
      "oauth2." + name + ": authorizationUrl",
      OpenApiError, "openapi/bad-security");
  }
  if (name === "authorizationCode" || name === "password" || name === "clientCredentials") {
    validateOpts.requireNonEmptyString(flow.tokenUrl,
      "oauth2." + name + ": tokenUrl",
      OpenApiError, "openapi/bad-security");
  }
}

function oauth2(opts) {
  opts = opts || {};
  validateOpts(opts, ["flows", "description"], "openapi.security.oauth2");
  if (!opts.flows || typeof opts.flows !== "object") {
    throw new OpenApiError("openapi/bad-security",
      "oauth2: flows must be an object — at least one of authorizationCode / clientCredentials / implicit / password");
  }
  var validFlowNames = ["authorizationCode", "clientCredentials", "implicit", "password"];
  for (var k in opts.flows) {
    if (!Object.prototype.hasOwnProperty.call(opts.flows, k)) continue;
    if (validFlowNames.indexOf(k) === -1) {
      throw new OpenApiError("openapi/bad-security",
        "oauth2: unknown flow " + JSON.stringify(k) +
        " — valid: " + validFlowNames.join(", "));
    }
    _validateFlow(k, opts.flows[k]);
  }
  var out = { type: "oauth2", flows: opts.flows };
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

function openIdConnect(opts) {
  opts = opts || {};
  validateOpts(opts, ["url", "description"], "openapi.security.openIdConnect");
  validateOpts.requireNonEmptyString(opts.url,
    "openIdConnect: url", OpenApiError, "openapi/bad-security");
  var out = { type: "openIdConnect", openIdConnectUrl: opts.url };
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

// mTLS (RFC 8705) — modeled in OpenAPI 3.1 as `mutualTLS` security
// scheme type added in the 3.1 spec.
function mtls(opts) {
  opts = opts || {};
  validateOpts(opts, ["description"], "openapi.security.mtls");
  var out = { type: "mutualTLS" };
  if (typeof opts.description === "string" && opts.description.length > 0) {
    out.description = opts.description;
  }
  return out;
}

// DPoP-bound bearer — emitted as a Bearer scheme with a description
// noting the DPoP requirement; OpenAPI doesn't define a first-class
// DPoP scheme yet.
function dpop(opts) {
  opts = opts || {};
  validateOpts(opts, ["description"], "openapi.security.dpop");
  var desc = (typeof opts.description === "string" && opts.description.length > 0)
    ? opts.description
    : "Bearer token bound to a DPoP proof per RFC 9449. Client MUST send the access token in `Authorization: DPoP <token>` and the DPoP proof in the `DPoP` header.";
  return {
    type:        "http",
    scheme:      "dpop",
    description: desc,
  };
}

module.exports = {
  bearer:        bearer,
  basic:         basic,
  apiKey:        apiKey,
  oauth2:        oauth2,
  openIdConnect: openIdConnect,
  mtls:          mtls,
  dpop:          dpop,
  OpenApiError:  OpenApiError,
};
