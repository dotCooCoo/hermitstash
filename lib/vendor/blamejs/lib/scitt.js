"use strict";
/**
 * @module b.scitt
 * @nav    Crypto
 * @title  SCITT signed statements
 *
 * @intro
 *   A SCITT (Supply Chain Integrity, Transparency, and Trust) signed
 *   statement is a <code>b.cose</code> COSE_Sign1 that makes a signed,
 *   attributable claim <em>about an artifact</em> — a signed SBOM, a
 *   build attestation, a release approval. The artifact (or a hash /
 *   reference to it) is the payload; the issuer and the subject are
 *   carried in the integrity-protected <strong>CWT_Claims</strong>
 *   header (label 15, RFC 9597): <code>iss</code> (label 1) is who
 *   makes the statement, <code>sub</code> (label 2) is the artifact the
 *   statement is about. This module builds and verifies that envelope
 *   over <code>b.cose</code> + <code>b.cbor</code>.
 *
 *   <code>b.scitt.signStatement(payload, opts)</code> produces the
 *   COSE_Sign1, placing <code>iss</code> / <code>sub</code> (plus any
 *   extra CWT claims) in the protected CWT_Claims header and declaring
 *   the payload media type as the COSE content type.
 *   <code>b.scitt.verifyStatement(statement, opts)</code> verifies the
 *   signature (delegating the mandatory algorithm allowlist to
 *   <code>b.cose.verify</code>), then enforces that a CWT_Claims header
 *   with both <code>iss</code> and <code>sub</code> is present —
 *   refusing a statement that omits the issuer/subject binding — and
 *   optionally checks them against expected values.
 *
 *   The signing algorithms are exactly <code>b.cose</code>'s: the
 *   classical ES256/384/512 + EdDSA (final COSE ids, interoperable
 *   today) and ML-DSA-87 (PQC-forward, draft COSE id). Because the
 *   identity binding lives in the protected header it is covered by the
 *   signature and cannot be substituted without detection.
 *
 *   <strong>Scope.</strong> This is the <em>issuer half</em> of SCITT —
 *   producing and verifying signed statements, which is buildable today
 *   on finalized RFCs (RFC 9052 COSE, RFC 9597 CWT_Claims header, RFC
 *   8392 iss/sub). The <em>transparency receipt</em> (an inclusion proof
 *   from an append-only transparency service, COSE Receipts /
 *   draft-ietf-cose-merkle-tree-proofs) and the transparency-service
 *   registration protocol (draft-ietf-scitt-*) are deferred until those
 *   drafts publish — a signed statement produced here is the input a
 *   transparency service registers, and the receipt format is the part
 *   still in flux. Re-open on COSE-Receipts publication.
 *
 * @card
 *   SCITT signed statements (RFC 9052 COSE + RFC 9597 CWT_Claims) — a
 *   signed, issuer/subject-bound claim about an artifact (SBOM /
 *   attestation / approval). Composes b.cose; transparency receipts
 *   deferred to the COSE-Receipts draft.
 */

var cose = require("./cose");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ScittError = defineClass("ScittError", { alwaysPermanent: true });

// CWT_Claims header label (RFC 9597) and the two SCITT-required claim
// labels inside it (RFC 8392 §3.1.1): iss = who states, sub = about what.
var HDR_CWT_CLAIMS = 15;
var CLAIM_ISS = 1;
var CLAIM_SUB = 2;

function _requireNonEmptyString(v, name) {
  if (typeof v !== "string" || v.length === 0) {
    throw new ScittError("scitt/bad-" + name,
      "scitt.signStatement: opts." + name + " is required and must be a non-empty string");
  }
}

/**
 * @primitive b.scitt.signStatement
 * @signature b.scitt.signStatement(payload, opts)
 * @since     0.12.37
 * @status    experimental
 * @compliance soc2, cra
 * @related   b.scitt.verifyStatement, b.cose.sign
 *
 * Produce a SCITT signed statement: a COSE_Sign1 over
 * <code>payload</code> (the artifact bytes, or a hash / reference to
 * it) whose integrity-protected CWT_Claims header (label 15) binds the
 * issuer (<code>iss</code>) and subject (<code>sub</code>). Declare the
 * payload media type via <code>contentType</code> so a consumer knows
 * how to interpret it.
 *
 * @opts
 *   {
 *     alg:          string,        // b.cose alg: "ES256" | … | "ML-DSA-87"
 *     privateKey:   object,        // matching KeyObject or PEM
 *     issuer:       string,        // → CWT_Claims iss (label 1) — who makes the statement
 *     subject:      string,        // → CWT_Claims sub (label 2) — the artifact the statement is about
 *     contentType?: number|string, // payload media type (e.g. "application/spdx+json")
 *     claims?:      object,        // extra CWT claims by integer label, merged into CWT_Claims
 *     kid?:         string,        // → unprotected header label 4
 *     externalAad?: Buffer,        // bound into the signature
 *   }
 *
 * @example
 *   var stmt = await b.scitt.signStatement(sbomBytes, {
 *     alg: "ES256", privateKey: issuerKey,
 *     issuer: "https://builder.example", subject: "pkg:npm/widget@1.2.3",
 *     contentType: "application/spdx+json",
 *   });
 */
async function signStatement(payload, opts) {
  validateOpts.requireObject(opts, "scitt.signStatement", ScittError);
  validateOpts(opts,
    ["alg", "privateKey", "issuer", "subject", "contentType", "claims", "kid", "externalAad"],
    "scitt.signStatement");
  _requireNonEmptyString(opts.issuer, "issuer");
  _requireNonEmptyString(opts.subject, "subject");

  var cwtClaims = new Map();
  cwtClaims.set(CLAIM_ISS, opts.issuer);
  cwtClaims.set(CLAIM_SUB, opts.subject);
  // Extra CWT claims (e.g. iat = 6, a registration-policy claim) keyed
  // by their integer label. iss / sub are managed via opts.issuer /
  // opts.subject and cannot be overridden here.
  if (opts.claims && typeof opts.claims === "object") {
    var ck = opts.claims instanceof Map ? Array.from(opts.claims.keys()) : Object.keys(opts.claims);
    for (var i = 0; i < ck.length; i++) {
      var label = Number(ck[i]);
      if (!Number.isInteger(label)) {
        throw new ScittError("scitt/bad-claim-label",
          "scitt.signStatement: claims keys must be integer CWT claim labels");
      }
      if (label === CLAIM_ISS || label === CLAIM_SUB) {
        throw new ScittError("scitt/reserved-claim",
          "scitt.signStatement: set iss / sub via opts.issuer / opts.subject, not opts.claims");
      }
      var val = opts.claims instanceof Map ? opts.claims.get(ck[i]) : opts.claims[ck[i]];
      cwtClaims.set(label, val);
    }
  }

  var protectedHeaders = {};
  protectedHeaders[HDR_CWT_CLAIMS] = cwtClaims;

  return cose.sign(payload, {
    alg:              opts.alg,
    privateKey:       opts.privateKey,
    kid:              opts.kid,
    contentType:      opts.contentType,
    externalAad:      opts.externalAad,
    protectedHeaders: protectedHeaders,
  });
}

/**
 * @primitive b.scitt.verifyStatement
 * @signature b.scitt.verifyStatement(statement, opts)
 * @since     0.12.37
 * @status    experimental
 * @compliance soc2, cra
 * @related   b.scitt.signStatement, b.cose.verify
 *
 * Verify a SCITT signed statement and return its payload + identity
 * binding. The COSE signature is checked through
 * <code>b.cose.verify</code> (the algorithm allowlist is mandatory); a
 * statement that does not carry a CWT_Claims header with both
 * <code>iss</code> and <code>sub</code> is refused — that binding is
 * what makes it a SCITT statement rather than a bare COSE_Sign1.
 * <code>expectedIssuer</code> / <code>expectedSubject</code>, when
 * given, must match.
 *
 * @opts
 *   {
 *     algorithms:       string[],  // required — accepted alg names (allowlist)
 *     publicKey?:       object,    // verification key (KeyObject / PEM)
 *     keyResolver?:     function,  // (protectedHeaders, unprotectedHeaders) → key
 *     expectedIssuer?:  string,    // require iss === this
 *     expectedSubject?: string,    // require sub === this
 *     externalAad?:     Buffer,    // must match what was signed
 *     maxBytes?:        number,    // forwarded to b.cose.verify → b.cbor.decode
 *     maxDepth?:        number,
 *   }
 *
 * @example
 *   var out = await b.scitt.verifyStatement(stmt, {
 *     algorithms: ["ES256"], publicKey: issuerPub,
 *     expectedSubject: "pkg:npm/widget@1.2.3",
 *   });
 *   // → { payload: <Buffer>, issuer, subject, cwtClaims: Map, alg, protectedHeaders, unprotectedHeaders }
 */
async function verifyStatement(statement, opts) {
  validateOpts.requireObject(opts, "scitt.verifyStatement", ScittError);
  validateOpts(opts,
    ["algorithms", "publicKey", "keyResolver", "expectedIssuer", "expectedSubject",
     "externalAad", "maxBytes", "maxDepth"],
    "scitt.verifyStatement");

  var out = await cose.verify(statement, {
    algorithms:  opts.algorithms,
    publicKey:   opts.publicKey,
    keyResolver: opts.keyResolver,
    externalAad: opts.externalAad,
    maxBytes:    opts.maxBytes,
    maxDepth:    opts.maxDepth,
  });

  var cwtClaims = out.protectedHeaders.get(HDR_CWT_CLAIMS);
  if (!(cwtClaims instanceof Map)) {
    throw new ScittError("scitt/missing-cwt-claims",
      "scitt.verifyStatement: no CWT_Claims header (label 15) — not a SCITT signed statement");
  }
  var issuer = cwtClaims.get(CLAIM_ISS);
  var subject = cwtClaims.get(CLAIM_SUB);
  if (issuer === undefined || issuer === null) {
    throw new ScittError("scitt/missing-issuer",
      "scitt.verifyStatement: CWT_Claims has no iss (label 1)");
  }
  if (subject === undefined || subject === null) {
    throw new ScittError("scitt/missing-subject",
      "scitt.verifyStatement: CWT_Claims has no sub (label 2)");
  }
  if (opts.expectedIssuer !== undefined && issuer !== opts.expectedIssuer) {
    throw new ScittError("scitt/issuer-mismatch",
      "scitt.verifyStatement: iss does not match expectedIssuer");
  }
  if (opts.expectedSubject !== undefined && subject !== opts.expectedSubject) {
    throw new ScittError("scitt/subject-mismatch",
      "scitt.verifyStatement: sub does not match expectedSubject");
  }

  return {
    payload:            out.payload,
    issuer:             issuer,
    subject:            subject,
    cwtClaims:          cwtClaims,
    alg:                out.alg,
    protectedHeaders:   out.protectedHeaders,
    unprotectedHeaders: out.unprotectedHeaders,
  };
}

module.exports = {
  signStatement:   signStatement,
  verifyStatement: verifyStatement,
  CWT_CLAIMS_LABEL: HDR_CWT_CLAIMS,
  ScittError:      ScittError,
};
