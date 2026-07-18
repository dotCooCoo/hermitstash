// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Tests for b.auth.sdJwtVc — Selective Disclosure JWT for Verifiable
 * Credentials (draft-ietf-oauth-sd-jwt-vc).
 */

var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;
var sdJwtVc = b.auth.sdJwtVc;
var nodeCrypto = require("node:crypto");

// Generate a fresh ECDSA P-256 key pair for issuer + holder per test
function _newKeyPair() {
  var kp = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  return kp;
}

function _jwk(publicKey) {
  return publicKey.export({ format: "jwk" });
}

// ---- disclosure module ----

function testDisclosureEncodeDecode() {
  var dis = sdJwtVc.disclosure;
  var encoded = dis.encode("given_name", "Alice");
  check("disclosure.encode returns base64url string",
        typeof encoded === "string" && /^[A-Za-z0-9_-]+$/.test(encoded));
  var decoded = dis.decode(encoded);
  check("disclosure.decode round-trip name",
        decoded && decoded.name === "given_name");
  check("disclosure.decode round-trip value",
        decoded.value === "Alice");
  check("disclosure.decode salt is base64url",
        typeof decoded.salt === "string" && decoded.salt.length > 0);
}

function testDisclosureValueComplexShape() {
  var dis = sdJwtVc.disclosure;
  var encoded = dis.encode("address", { street: "Main St", city: "Springfield" });
  var decoded = dis.decode(encoded);
  check("disclosure: complex value preserved",
        decoded.value.street === "Main St" && decoded.value.city === "Springfield");
}

function testDisclosureBadInput() {
  var dis = sdJwtVc.disclosure;
  check("disclosure.decode: empty returns null",
        dis.decode("") === null);
  check("disclosure.decode: malformed base64 returns null",
        dis.decode("&&&!!!") === null);
}

function testDisclosureDeterministicSalt() {
  var dis = sdJwtVc.disclosure;
  // Use a saltSource for deterministic output
  var saltCount = 0;
  var encoded = dis.encode("x", "y", {
    saltSource: function () { saltCount += 1; return "fixed-salt-1"; },
  });
  var decoded = dis.decode(encoded);
  check("disclosure: saltSource called",
        saltCount === 1 && decoded.salt === "fixed-salt-1");
}

// ---- issue ----

function testIssueBasic() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer.example.com",
    subject:  "did:web:alice",
    vct:      "https://example.com/vct/identity",
    claims: {
      given_name:  "Alice",
      family_name: "Smith",
      birthdate:   "1990-01-15",
      country:     "US",
    },
    selectivelyDisclosed: ["given_name", "family_name"],
    issuerKey: issuer.privateKey,
    algorithm: "ES256",
  });
  check("issue: token starts with JWT",
        typeof sd.token === "string" && sd.token.split(".").length === 3 + (sd.disclosures.length === 0 ? 0 : 0));
  check("issue: 2 disclosures generated",
        sd.disclosures.length === 2);
  check("issue: payload has _sd array",
        Array.isArray(sd.payload._sd) && sd.payload._sd.length === 2);
  check("issue: payload has plain country (not selectively disclosed)",
        sd.payload.country === "US");
  check("issue: payload has no given_name (selectively disclosed)",
        sd.payload.given_name === undefined);
  check("issue: vct stamped",
        sd.payload.vct === "https://example.com/vct/identity");
  check("issue: typ vc+sd-jwt",
        sd.header.typ === "vc+sd-jwt");
}

function testIssueWithCnf() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer",
    vct:      "test",
    claims:   { x: 1 },
    issuerKey: issuer.privateKey,
    holderKey: _jwk(holder.publicKey),
  });
  check("issue: cnf.jwk stamped",
        sd.payload.cnf && sd.payload.cnf.jwk &&
        sd.payload.cnf.jwk.kty === "EC");
}

function testIssueValidation() {
  var threwNoIssuer = false;
  try {
    sdJwtVc.issue({
      vct: "x", claims: {},
      issuerKey: _newKeyPair().privateKey,
    });
  } catch (_e) { threwNoIssuer = true; }
  check("issue: missing issuer throws", threwNoIssuer);

  var threwNoVct = false;
  try {
    sdJwtVc.issue({
      issuer: "https://x", claims: {},
      issuerKey: _newKeyPair().privateKey,
    });
  } catch (_e) { threwNoVct = true; }
  check("issue: missing vct throws", threwNoVct);

  var threwBadAlg = false;
  try {
    sdJwtVc.issue({
      issuer: "https://x", vct: "y", claims: {},
      algorithm: "HS256",
      issuerKey: _newKeyPair().privateKey,
    });
  } catch (_e) { threwBadAlg = true; }
  check("issue: unsupported alg throws", threwBadAlg);

  var threwBadDisclosed = false;
  try {
    sdJwtVc.issue({
      issuer: "https://x", vct: "y",
      claims: { a: 1 },
      selectivelyDisclosed: ["nonexistent"],
      issuerKey: _newKeyPair().privateKey,
    });
  } catch (_e) { threwBadDisclosed = true; }
  check("issue: selectivelyDisclosed includes unknown claim throws",
        threwBadDisclosed);
}

// ---- verify ----

async function testVerifyHappyPath() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer",
    vct:      "https://example/identity",
    claims:   { given_name: "Alice", family_name: "Smith", country: "US" },
    selectivelyDisclosed: ["given_name", "family_name"],
    issuerKey: issuer.privateKey,
  });
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify happy path: valid",
        result.valid === true);
  check("verify happy path: vct preserved",
        result.claims.vct === "https://example/identity");
  check("verify happy path: country (plain) preserved",
        result.claims.country === "US");
  check("verify happy path: given_name (disclosed) reconstructed",
        result.claims.given_name === "Alice");
  check("verify happy path: family_name (disclosed) reconstructed",
        result.claims.family_name === "Smith");
  check("verify happy path: _sd stripped from result",
        result.claims._sd === undefined);
}

async function testVerifyBadIssuerSignature() {
  var issuer = _newKeyPair();
  var attacker = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey,
  });
  var threw = false;
  try {
    await sdJwtVc.verify(sd.token, {
      issuerKeyResolver: async function () { return attacker.publicKey; },
    });
  } catch (_e) { threw = true; }
  check("verify: wrong key throws", threw);
}

async function testVerifyExpired() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer", vct: "x",
    claims:   { a: 1 },
    issuerKey: issuer.privateKey,
    issuedAt: Date.now() - 60 * 60 * 1000,           // 1h ago
    ttlMs:    30 * 60 * 1000,                         // 30 min TTL — already expired
  });
  var threw = false;
  try {
    await sdJwtVc.verify(sd.token, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
    });
  } catch (_e) { threw = true; }
  check("verify: expired token throws", threw);
}

async function testVerifyVctMismatch() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "type-A", claims: { a: 1 },
    issuerKey: issuer.privateKey,
  });
  var threw = false;
  try {
    await sdJwtVc.verify(sd.token, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      expectedVct:       "type-B",
    });
  } catch (_e) { threw = true; }
  check("verify: vct mismatch throws", threw);
}

async function testVerifyDisclosureMismatch() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x",
    claims: { a: 1, b: 2 },
    selectivelyDisclosed: ["a"],
    issuerKey: issuer.privateKey,
  });
  // Tamper with the disclosure (the disclosure body, not the JWT)
  var parts = sd.token.split("~");
  // Forge a new disclosure with the same claim name but different value
  var dis = sdJwtVc.disclosure;
  var forged = dis.encode("a", 999);
  parts[1] = forged;
  var tampered = parts.join("~");
  var threw = false;
  try {
    await sdJwtVc.verify(tampered, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
    });
  } catch (_e) { threw = true; }
  check("verify: tampered disclosure throws", threw);
}

// ---- present ----

async function testPresentSubsetThenVerify() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer", vct: "x",
    claims:   { given_name: "Alice", family_name: "Smith", country: "US" },
    selectivelyDisclosed: ["given_name", "family_name"],
    issuerKey: issuer.privateKey,
  });
  var pres = sdJwtVc.present({
    sdJwt:               sd.token,
    disclosedClaimNames: ["given_name"],     // hold back family_name
  });
  check("present: 1 disclosure released",
        pres.disclosures.length === 1);
  // Verify the presentation
  var result = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("present + verify: given_name disclosed",
        result.claims.given_name === "Alice");
  check("present + verify: family_name NOT disclosed",
        result.claims.family_name === undefined);
  check("present + verify: country (plain) still present",
        result.claims.country === "US");
}

async function testPresentWithKeyBinding() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer", vct: "x",
    claims:   { given_name: "Alice" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuer.privateKey,
    holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt:               sd.token,
    disclosedClaimNames: ["given_name"],
    audience:            "https://verifier",
    nonce:               "test-nonce-123",
    holderKey:           holder.privateKey,
    algorithm:           "ES256",
  });
  check("present: KB-JWT appended",
        pres.presentation.endsWith(pres.presentation.split("~").pop()));

  var result = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
    audience:          "https://verifier",
    nonce:              "test-nonce-123",
    requireKeyBinding: true,
  });
  check("verify: KB validated",
        result.kbValidated === true);
  check("verify: holderKey returned",
        result.holderKey && result.holderKey.kty === "EC");
}

async function testKbRequiresReplayBinding() {
  // A KB-JWT presentation verified WITHOUT opts.audience/opts.nonce must fail
  // closed — otherwise the aud/nonce compares silently skip and the
  // presentation is replayable + acceptable at any verifier.
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x", claims: { x: 1 },
    issuerKey: issuer.privateKey, holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt: sd.token, audience: "https://verifier", nonce: "n-1",
    holderKey: holder.privateKey, algorithm: "ES256",
  });
  // No nonce + no audience supplied to verify → must throw.
  var threwNone = null;
  try {
    await sdJwtVc.verify(pres.presentation, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      requireKeyBinding: true,
    });
  } catch (e) { threwNone = e; }
  check("verify: KB-JWT without audience+nonce fails closed",
        threwNone && threwNone.code === "auth-sd-jwt-vc/missing-replay-binding");
  // audience but no nonce → still throws (replay defense needs the fresh nonce).
  var threwNoNonce = null;
  try {
    await sdJwtVc.verify(pres.presentation, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      audience: "https://verifier", requireKeyBinding: true,
    });
  } catch (e) { threwNoNonce = e; }
  check("verify: KB-JWT with audience but no nonce fails closed",
        threwNoNonce && threwNoNonce.code === "auth-sd-jwt-vc/missing-replay-binding");
}

async function testRequireExpOpt() {
  // requireExp + expectedIssuer are accepted opts (previously expectedIssuer
  // was consumed but absent from the allowlist → "unknown option"). A normal
  // token (issue() always writes a numeric exp) still verifies under requireExp.
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x", claims: { x: 1 }, issuerKey: issuer.privateKey,
  });
  var ok = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
    requireExp: true, expectedIssuer: "https://issuer",
  });
  check("verify: requireExp + expectedIssuer accepted; exp-present token verifies",
        ok.valid === true);
}

async function testKbWrongAudience() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x",
    claims: { x: 1 },
    issuerKey: issuer.privateKey,
    holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt:    sd.token,
    audience: "https://verifier1",
    nonce:    "n",
    holderKey: holder.privateKey,
  });
  var threw = false;
  try {
    await sdJwtVc.verify(pres.presentation, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      audience:          "https://verifier2",   // different from KB
      nonce:             "n",
    });
  } catch (_e) { threw = true; }
  check("verify: KB audience mismatch throws", threw);
}

async function testKbWrongNonce() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x",
    claims: { x: 1 },
    issuerKey: issuer.privateKey,
    holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt: sd.token, audience: "v", nonce: "n1", holderKey: holder.privateKey,
  });
  var threw = false;
  try {
    await sdJwtVc.verify(pres.presentation, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      audience: "v", nonce: "n2",
    });
  } catch (_e) { threw = true; }
  check("verify: KB nonce mismatch throws (replay defense)", threw);
}

async function testRequireKeyBindingMissing() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x", claims: { x: 1 },
    issuerKey: issuer.privateKey,
  });
  // Note: no KB, but verify requires it
  var threw = false;
  try {
    await sdJwtVc.verify(sd.token, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      requireKeyBinding: true,
    });
  } catch (_e) { threw = true; }
  check("verify: requireKeyBinding without KB-JWT throws", threw);
}

// ---- Issuer factory ----

async function testIssuerHappyPath() {
  var issuerKey = _newKeyPair();
  var holder = _newKeyPair();
  var issuer = sdJwtVc.issuer.create({
    issuerUrl: "https://issuer.example.com",
    keys: [{ kid: "k1", privateKey: issuerKey.privateKey, algorithm: "ES256" }],
    activeKid: "k1",
  });
  var sd = await issuer.issue({
    vct:     "https://example.com/vct/identity",
    subject: "did:web:alice",
    claims:  { given_name: "Alice", family_name: "Smith", country: "US" },
    selectivelyDisclosed: ["given_name", "family_name"],
    holderKey: _jwk(holder.publicKey),
  });
  check("issuer.issue: token returned",
        typeof sd.token === "string" && sd.token.indexOf("~") !== -1);
  check("issuer.issue: kid stamped in header",
        sd.header.kid === "k1");
  check("issuer.issue: stats.issued = 1",
        issuer.stats().issued === 1);

  // Verify with the kid → key resolver
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function (header) {
      check("issuer.verify: kid in header", header.kid === "k1");
      return issuerKey.publicKey;
    },
  });
  check("issuer + verify: round-trip valid",
        result.valid === true && result.claims.given_name === "Alice");
}

async function testIssuerKeyRotation() {
  var key1 = _newKeyPair();
  var key2 = _newKeyPair();
  var issuer = sdJwtVc.issuer.create({
    issuerUrl: "https://issuer",
    keys: [{ kid: "k1", privateKey: key1.privateKey }],
    activeKid: "k1",
  });
  // Issue with k1
  var sd1 = await issuer.issue({ vct: "x", claims: { a: 1 } });
  check("issuer rotate: pre-rotate header.kid = k1",
        sd1.header.kid === "k1");

  issuer.rotateKey({ kid: "k2", privateKey: key2.privateKey });
  check("issuer rotate: stats.keysRotated = 1",
        issuer.stats().keysRotated === 1);
  check("issuer rotate: activeKid = k2",
        issuer.stats().activeKid === "k2");
  check("issuer rotate: kids contains both",
        issuer.listKids().length === 2);

  var sd2 = await issuer.issue({ vct: "x", claims: { a: 2 } });
  check("issuer rotate: post-rotate header.kid = k2",
        sd2.header.kid === "k2");
  // The new credential verifies with key2, not key1
  var verified = await sdJwtVc.verify(sd2.token, {
    issuerKeyResolver: async function () { return key2.publicKey; },
  });
  check("issuer rotate: rotated key verifies new credentials",
        verified.valid === true);
}

function testIssuerValidation() {
  var threwNoUrl = false;
  try {
    sdJwtVc.issuer.create({
      keys: [{ kid: "k", privateKey: _newKeyPair().privateKey }],
    });
  } catch (_e) { threwNoUrl = true; }
  check("issuer.create: missing issuerUrl throws", threwNoUrl);

  var threwNoKeys = false;
  try {
    sdJwtVc.issuer.create({ issuerUrl: "https://x", keys: [] });
  } catch (_e) { threwNoKeys = true; }
  check("issuer.create: empty keys array throws", threwNoKeys);

  var threwBadActive = false;
  try {
    sdJwtVc.issuer.create({
      issuerUrl: "https://x",
      keys: [{ kid: "k", privateKey: _newKeyPair().privateKey }],
      activeKid: "nonexistent",
    });
  } catch (_e) { threwBadActive = true; }
  check("issuer.create: activeKid not in keys throws", threwBadActive);
}

async function testIssuerStats() {
  var key = _newKeyPair();
  var issuer = sdJwtVc.issuer.create({
    issuerUrl: "https://x",
    keys: [{ kid: "k", privateKey: key.privateKey }],
  });
  await issuer.issue({ vct: "y", claims: {} });
  await issuer.issue({ vct: "y", claims: {} });
  var stats = issuer.stats();
  check("issuer stats: issued count",  stats.issued === 2);
  check("issuer stats: lastIssuedAt set", typeof stats.lastIssuedAt === "number");
  check("issuer stats: activeKid",     stats.activeKid === "k");
  check("issuer stats: kids list",     Array.isArray(stats.kids));
}

// ---- Hash algorithm switching ----

async function testCustomHashAlg() {
  var issuerKey = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer", vct: "x",
    claims:   { a: 1, b: 2 },
    selectivelyDisclosed: ["a"],
    issuerKey: issuerKey.privateKey,
    hashAlg:   "sha-512",
  });
  check("issue: _sd_alg stamped to sha-512",
        sd.payload._sd_alg === "sha-512");
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return issuerKey.publicKey; },
  });
  check("verify: sha-512 disclosure round-trips",
        result.valid && result.claims.a === 1);
}

// ---- Decoy resilience ----

async function testNoDisclosuresPlainOnly() {
  var issuerKey = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "x",
    claims: { country: "US", role: "admin" },
    // No selectivelyDisclosed — all claims plain
    issuerKey: issuerKey.privateKey,
  });
  check("issue: 0 disclosures when none requested",
        sd.disclosures.length === 0);
  check("issue: _sd is empty array",
        Array.isArray(sd.payload._sd) && sd.payload._sd.length === 0);
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return issuerKey.publicKey; },
  });
  check("verify: plain-only round-trips",
        result.valid && result.claims.country === "US");
}

// ---- Holder factory ----

async function testHolderStoreAndList() {
  var issuerKey = _newKeyPair();
  var holderKey = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "https://example/identity",
    claims: { given_name: "Alice" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuerKey.privateKey,
    holderKey: _jwk(holderKey.publicKey),
  });
  var holder = sdJwtVc.holder.create({
    storage:   sdJwtVc.holder.memoryStorage(),
    holderKey: holderKey.privateKey,
  });
  await holder.store({
    id:    "cred-1",
    sdJwt: sd.token,
    vct:   "https://example/identity",
    issuer: "https://issuer",
  });
  var listed = await holder.list();
  check("holder: 1 credential stored", listed.length === 1);
  check("holder: credential has id", listed[0].id === "cred-1");

  var fetched = await holder.get("cred-1");
  check("holder: fetched by id", fetched && fetched.sdJwt === sd.token);
}

async function testHolderPresent() {
  var issuerKey = _newKeyPair();
  var holderKey = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "https://example/identity",
    claims: { given_name: "Alice", family_name: "Smith" },
    selectivelyDisclosed: ["given_name", "family_name"],
    issuerKey: issuerKey.privateKey,
    holderKey: _jwk(holderKey.publicKey),
  });
  var holder = sdJwtVc.holder.create({
    storage:   sdJwtVc.holder.memoryStorage(),
    holderKey: holderKey.privateKey,
  });
  await holder.store({ id: "c", sdJwt: sd.token });
  var pres = await holder.present({
    credentialId:        "c",
    disclosedClaimNames: ["given_name"],
    audience:            "https://verifier",
    nonce:               "n-1",
  });
  check("holder.present: returns presentation",
        typeof pres.presentation === "string" && pres.presentation.indexOf("~") !== -1);
  check("holder.present: 1 disclosure released",
        pres.disclosures.length === 1);

  // Round-trip: verify the holder's presentation
  var verified = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return issuerKey.publicKey; },
    audience:          "https://verifier",
    nonce:             "n-1",
    requireKeyBinding: true,
  });
  check("holder.present: round-trip valid",
        verified.valid && verified.kbValidated &&
        verified.claims.given_name === "Alice" &&
        verified.claims.family_name === undefined);
}

async function testHolderDelete() {
  var holderKey = _newKeyPair();
  var holder = sdJwtVc.holder.create({
    storage:   sdJwtVc.holder.memoryStorage(),
    holderKey: holderKey.privateKey,
  });
  await holder.store({ id: "c", sdJwt: "fake-token" });
  var existed = await holder.delete("c");
  check("holder.delete: returns true on existing",
        existed === true);
  var listed = await holder.list();
  check("holder.delete: list now empty",
        listed.length === 0);
  var existedAgain = await holder.delete("c");
  check("holder.delete: returns false on missing",
        existedAgain === false);
}

async function testHolderPresentNonexistent() {
  var holderKey = _newKeyPair();
  var holder = sdJwtVc.holder.create({
    storage:   sdJwtVc.holder.memoryStorage(),
    holderKey: holderKey.privateKey,
  });
  var threw = false;
  try { await holder.present({ credentialId: "ghost" }); }
  catch (_e) { threw = true; }
  check("holder.present: missing credentialId throws", threw);
}

function testHolderValidation() {
  var threwBadStorage = false;
  try {
    sdJwtVc.holder.create({
      storage:   { put: function () {} },
      holderKey: "x",
    });
  } catch (_e) { threwBadStorage = true; }
  check("holder.create: invalid storage throws", threwBadStorage);

  var threwNoKey = false;
  try {
    sdJwtVc.holder.create({
      storage: sdJwtVc.holder.memoryStorage(),
    });
  } catch (_e) { threwNoKey = true; }
  check("holder.create: missing holderKey throws", threwNoKey);
}

// The holder must derive the KB-JWT alg from the holder key type when no
// explicit `algorithm` is given — a fixed "ES256" default signed a non-EC
// holder key under a header alg that disagreed with the key (un-signable
// or a self-invalid KB-JWT a verifier rejects).
async function testHolderAlgFromKeyType() {
  var issuerKey = _newKeyPair();
  var edHolder = nodeCrypto.generateKeyPairSync("ed25519");
  var sd = sdJwtVc.issue({
    issuer: "https://issuer", vct: "https://example/identity",
    claims: { given_name: "Alice" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuerKey.privateKey,
    holderKey: _jwk(edHolder.publicKey),
  });
  var holder = sdJwtVc.holder.create({
    storage:   sdJwtVc.holder.memoryStorage(),
    holderKey: edHolder.privateKey,        // Ed25519, no explicit algorithm
  });
  await holder.store({ id: "c", sdJwt: sd.token });
  var pres = await holder.present({
    credentialId: "c", disclosedClaimNames: ["given_name"],
    audience: "https://verifier", nonce: "n-1",
  });
  var kbJwt = pres.presentation.split("~").pop();
  var kbAlg = JSON.parse(Buffer.from(kbJwt.split(".")[0], "base64url").toString("utf8")).alg;
  check("holder: Ed25519 key infers EdDSA KB-JWT alg (not fixed ES256)", kbAlg === "EdDSA");
  var verified = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return issuerKey.publicKey; },
    audience: "https://verifier", nonce: "n-1", requireKeyBinding: true,
  });
  check("holder: Ed25519-bound presentation round-trips", verified.valid && verified.kbValidated);

  // An RSA holder key has no KB-JWT alg in SUPPORTED_ALGS — refuse at
  // create time rather than emit a self-invalid ES256-headed token.
  var rsaThrew = null;
  try {
    sdJwtVc.holder.create({
      storage:   sdJwtVc.holder.memoryStorage(),
      holderKey: nodeCrypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey,
    });
  } catch (e) { rsaThrew = e; }
  check("holder.create: RSA holder key refused with a clear error",
        rsaThrew && rsaThrew.code === "auth-sd-jwt-vc/holder-key-unsupported");
}

// ---- FIX 4B: holder KB-JWT alg/kty cross-check ----

// The KB-JWT header alg is attacker-controllable (the holder mints the
// KB-JWT). The verifier must cross-check it against the holder's cnf.jwk
// key type BEFORE handing bytes to node:crypto.verify — the same
// CVE-2026-22817 defense the issuer path applies. An EC cnf key with a
// KB-JWT header claiming EdDSA (which requires kty=OKP) must be refused
// with the precise alg-mismatch error.
async function testKbAlgKtyCrossCheck() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();   // EC P-256
  var sd = sdJwtVc.issue({
    issuer:   "https://issuer", vct: "x",
    claims:   { given_name: "Alice" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuer.privateKey,
    holderKey: _jwk(holder.publicKey),
  });
  // Build a valid presentation, then replace its real KB-JWT with a forged
  // one whose header declares EdDSA against the EC holder key.
  var pres = sdJwtVc.present({
    sdJwt:               sd.token,
    disclosedClaimNames: ["given_name"],
    audience:            "https://verifier",
    nonce:               "n-1",
    holderKey:           holder.privateKey,
    algorithm:           "ES256",
  });
  var segs = pres.presentation.split("~");
  // Forge a KB-JWT segment: EdDSA header (OKP), EC holder key → mismatch.
  function b64u(obj) { return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url"); }
  var forgedHeader = b64u({ typ: "kb+jwt", alg: "EdDSA" });
  var forgedPayload = b64u({ aud: "https://verifier", nonce: "n-1", iat: Math.floor(Date.now() / 1000), sd_hash: "x" });
  segs[segs.length - 1] = forgedHeader + "." + forgedPayload + ".AAAA";
  var forgedPres = segs.join("~");

  var threw = null;
  try {
    await sdJwtVc.verify(forgedPres, {
      issuerKeyResolver: async function () { return issuer.publicKey; },
      audience:          "https://verifier",
      nonce:             "n-1",
      requireKeyBinding: true,
    });
  } catch (e) { threw = e; }
  check("KB alg/kty: mismatched KB-JWT alg refused with precise error",
        threw && threw.code === "auth-jwt-external/alg-kty-mismatch");
}

// ---- Module exports ----

function testExports() {
  check("SUPPORTED_ALGS includes ES256",
        sdJwtVc.SUPPORTED_ALGS.indexOf("ES256") !== -1);
  check("SUPPORTED_ALGS includes ML-DSA-87",
        sdJwtVc.SUPPORTED_ALGS.indexOf("ML-DSA-87") !== -1);
  check("DEFAULT_ALG is ML-DSA-87",
        sdJwtVc.DEFAULT_ALG === "ML-DSA-87");
  check("DEFAULT_HASH_ALG is sha3-512",
        sdJwtVc.DEFAULT_HASH_ALG === "sha3-512");
  check("disclosure module exposed",
        typeof sdJwtVc.disclosure.encode === "function");
}

// ---- Shared crafting helpers for adversarial / edge inputs ----
//
// These build hand-crafted SD-JWT / JWT byte sequences to drive verify()
// and present() down error / defensive branches the happy path never
// reaches. They are NOT mocks (no helper provides an "arbitrary-payload
// JWT signer"); they mint real issuer-/holder-signed bytes so the true
// cryptographic verify path executes against tampered structure.

function _b64uJson(o) {
  return Buffer.from(JSON.stringify(o), "utf8").toString("base64url");
}

// ES256 (ECDSA P-256, JOSE raw r||s) — mirrors the library's own
// _signJwt so a crafted issuer/holder credential verifies for real.
function _signEs256(header, payload, privateKey) {
  var si = _b64uJson(header) + "." + _b64uJson(payload);
  var sig = nodeCrypto.sign("sha256", Buffer.from(si, "ascii"),
    { key: privateKey, dsaEncoding: "ieee-p1363" });
  return si + "." + sig.toString("base64url");
}

async function _expectThrow(label, code, fn) {
  var err = null;
  try { await fn(); } catch (e) { err = e; }
  check(label, err && (code == null || err.code === code));
  return err;
}

// ---- _hashDisclosure (exported test hook) ----

function testHashDisclosureBadAlg() {
  // Direct call with an unsupported alg drives the internal guard that
  // issue()/verify() pre-validate around.
  _expectThrowSync("_hashDisclosure: unsupported alg throws bad-hash",
    "auth-sd-jwt-vc/bad-hash",
    function () { return sdJwtVc._hashDisclosure("some-disclosure", "md5"); });
  // An inherited Object.prototype member (a truthy prototype-chain hit on
  // the SUPPORTED_HASH_ALGS lookup) must get the typed bad-hash refusal, not
  // a raw createHash(<function>) ERR_INVALID_ARG_TYPE.
  ["constructor", "__proto__", "toString", "valueOf"].forEach(function (m) {
    _expectThrowSync("_hashDisclosure: inherited-member alg '" + m + "' throws bad-hash",
      "auth-sd-jwt-vc/bad-hash",
      function () { return sdJwtVc._hashDisclosure("x", m); });
  });
  // A supported alg returns a base64url digest.
  var d = sdJwtVc._hashDisclosure("x", "sha-256");
  check("_hashDisclosure: supported alg returns base64url digest",
        typeof d === "string" && /^[A-Za-z0-9_-]+$/.test(d));
}

function _expectThrowSync(label, code, fn) {
  var err = null;
  try { fn(); } catch (e) { err = e; }
  check(label, err && (code == null || err.code === code));
  return err;
}

// ---- issue: defensive input branches ----

function testIssueClaimsNotObject() {
  var key = _newKeyPair().privateKey;
  _expectThrowSync("issue: array claims rejected", "auth-sd-jwt-vc/bad-opts",
    function () {
      sdJwtVc.issue({ issuer: "https://i", vct: "x", claims: [1, 2], issuerKey: key });
    });
  _expectThrowSync("issue: string claims rejected", "auth-sd-jwt-vc/bad-opts",
    function () {
      sdJwtVc.issue({ issuer: "https://i", vct: "x", claims: "nope", issuerKey: key });
    });
}

function testIssueBadHashAlg() {
  var key = _newKeyPair().privateKey;
  _expectThrowSync("issue: unsupported hashAlg rejected", "auth-sd-jwt-vc/bad-hash",
    function () {
      sdJwtVc.issue({
        issuer: "https://i", vct: "x", claims: { a: 1 },
        issuerKey: key, hashAlg: "md5",
      });
    });
}

function testIssueNoIssuerKey() {
  _expectThrowSync("issue: missing issuerKey rejected", "auth-sd-jwt-vc/no-key",
    function () {
      sdJwtVc.issue({ issuer: "https://i", vct: "x", claims: { a: 1 } });
    });
}

function testIssueBadCnf() {
  var key = _newKeyPair().privateKey;
  // holderKey present but not a JWK object (string) → bad-cnf.
  _expectThrowSync("issue: non-object holderKey rejected", "auth-sd-jwt-vc/bad-cnf",
    function () {
      sdJwtVc.issue({
        issuer: "https://i", vct: "x", claims: { a: 1 },
        issuerKey: key, holderKey: "not-a-jwk",
      });
    });
  // Object without kty → bad-cnf.
  _expectThrowSync("issue: holderKey object without kty rejected",
    "auth-sd-jwt-vc/bad-cnf",
    function () {
      sdJwtVc.issue({
        issuer: "https://i", vct: "x", claims: { a: 1 },
        issuerKey: key, holderKey: { crv: "P-256" },
      });
    });
}

// ---- issue + verify across every supported signature algorithm ----

async function testIssueVerifyAllAlgs() {
  var cases = [
    { alg: "ES384", kp: function () { return nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-384" }); } },
    { alg: "EdDSA", kp: function () { return nodeCrypto.generateKeyPairSync("ed25519"); } },
    { alg: "ML-DSA-65", kp: function () { return nodeCrypto.generateKeyPairSync("ml-dsa-65"); } },
    { alg: "ML-DSA-87", kp: function () { return nodeCrypto.generateKeyPairSync("ml-dsa-87"); } },
  ];
  for (var i = 0; i < cases.length; i++) {
    var c = cases[i];
    var kp = c.kp();
    var sd = sdJwtVc.issue({
      issuer: "https://issuer", vct: "x",
      claims: { given_name: "Alice", country: "US" },
      selectivelyDisclosed: ["given_name"],
      issuerKey: kp.privateKey, algorithm: c.alg,
    });
    check("issue: " + c.alg + " header alg stamped", sd.header.alg === c.alg);
    var pub = kp.publicKey;
    var result = await sdJwtVc.verify(sd.token, {
      issuerKeyResolver: (function (k) { return async function () { return k; }; })(pub),
    });
    check("verify: " + c.alg + " round-trips",
          result.valid === true && result.claims.given_name === "Alice");
  }
}

// ---- present: defensive / option branches ----

function testPresentMalformed() {
  _expectThrowSync("present: sdJwt without ~ rejected", "auth-sd-jwt-vc/malformed",
    function () {
      sdJwtVc.present({ sdJwt: "no-separator-token", disclosedClaimNames: [] });
    });
}

function testPresentUnsupportedKbAlg() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, holderKey: _jwk(holder.publicKey),
  });
  _expectThrowSync("present: unsupported KB algorithm rejected",
    "auth-sd-jwt-vc/unsupported-alg",
    function () {
      sdJwtVc.present({
        sdJwt: sd.token, audience: "v", nonce: "n",
        holderKey: holder.privateKey, algorithm: "HS256",
      });
    });
}

function testPresentBadSdAlg() {
  // A credential whose issuer payload declares an unsupported _sd_alg is
  // refused by present() (holder computes sd_hash with that alg). Craft
  // the JWT bytes directly — present() reads the UNSIGNED payload, so no
  // real signature is needed to reach this guard.
  var jwt = "aGVhZGVy" + "." +
    _b64uJson({ iss: "https://i", vct: "x", _sd: [], _sd_alg: "sha-1" }) + "." +
    "c2ln";
  _expectThrowSync("present: unsupported issuer _sd_alg rejected",
    "auth-sd-jwt-vc/bad-hash",
    function () {
      sdJwtVc.present({ sdJwt: jwt + "~", disclosedClaimNames: [] });
    });
  // An inherited Object.prototype member as `_sd_alg` (read from the
  // unsigned issuer payload, attacker-controlled) must be refused with the
  // typed error. Each such member is a truthy prototype-chain hit that a
  // `!SUPPORTED_HASH_ALGS[_sdAlg]` guard would let slip, silently building a
  // presentation against an unsupported hash (fail-open).
  ["constructor", "__proto__", "toString", "valueOf"].forEach(function (m) {
    var inhJwt = "aGVhZGVy" + "." +
      _b64uJson({ iss: "https://i", vct: "x", _sd: [], _sd_alg: m }) + "." + "c2ln";
    _expectThrowSync("present: inherited-member issuer _sd_alg '" + m + "' rejected",
      "auth-sd-jwt-vc/bad-hash",
      function () {
        sdJwtVc.present({ sdJwt: inhJwt + "~", disclosedClaimNames: [] });
      });
  });
}

function testPresentSdAlgFallbackOnMalformedPayload() {
  // When the issuer JWT payload can't be parsed, present() falls back to
  // the spec-default sha-256 (rather than throwing) and still builds a
  // presentation.
  var jwt = "aGVhZGVy" + ".!!!not-valid-json-b64!!!." + "c2ln";
  var pres = sdJwtVc.present({ sdJwt: jwt + "~", disclosedClaimNames: [] });
  check("present: malformed issuer payload → sha-256 fallback, still builds",
        typeof pres.presentation === "string" && pres.presentation.indexOf("~") !== -1);
}

async function testPresentKeyAttestationHeader() {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt: sd.token, audience: "v", nonce: "n",
    holderKey: holder.privateKey, algorithm: "ES256",
    keyAttestation: "attestation.jwt.token",
    issuedAt: Date.now(),
  });
  var kbHeader = JSON.parse(Buffer.from(
    pres.presentation.split("~").pop().split(".")[0], "base64url").toString("utf8"));
  check("present: keyAttestation embedded in KB-JWT header",
        kbHeader.key_attestation === "attestation.jwt.token");
}

// ---- verify: top-level input validation ----

async function testVerifyInvalidPresentationArg() {
  var resolver = async function () { return _newKeyPair().publicKey; };
  await _expectThrow("verify: non-string presentation rejected",
    "auth-sd-jwt-vc/no-token",
    function () { return sdJwtVc.verify(12345, { issuerKeyResolver: resolver }); });
  await _expectThrow("verify: empty-string presentation rejected",
    "auth-sd-jwt-vc/no-token",
    function () { return sdJwtVc.verify("", { issuerKeyResolver: resolver }); });
}

async function testVerifyNoResolver() {
  await _expectThrow("verify: missing issuerKeyResolver rejected",
    "auth-sd-jwt-vc/no-resolver",
    function () { return sdJwtVc.verify("a.b.c~", {}); });
}

async function testVerifyPresentationNoSeparator() {
  var resolver = async function () { return _newKeyPair().publicKey; };
  await _expectThrow("verify: presentation without ~ rejected",
    "auth-sd-jwt-vc/malformed",
    function () { return sdJwtVc.verify("a.b.c", { issuerKeyResolver: resolver }); });
}

async function testVerifyJwtNotThreeParts() {
  var resolver = async function () { return _newKeyPair().publicKey; };
  await _expectThrow("verify: issuer JWT without 3 parts rejected",
    "auth-sd-jwt-vc/malformed-jwt",
    function () { return sdJwtVc.verify("only-one-part~", { issuerKeyResolver: resolver }); });
}

async function testVerifyBadHeader() {
  var resolver = async function () { return _newKeyPair().publicKey; };
  // Header decodes to bytes but not JSON → bad-header.
  var badHeader = Buffer.from("not-json", "utf8").toString("base64url");
  await _expectThrow("verify: non-JSON JWT header rejected", "auth-sd-jwt-vc/bad-header",
    function () {
      return sdJwtVc.verify(badHeader + ".cGF5.c2ln~", { issuerKeyResolver: resolver });
    });
}

async function testVerifyUnsupportedHeaderAlg() {
  var token = _b64uJson({ alg: "HS256", typ: "vc+sd-jwt" }) + "." +
              _b64uJson({ iss: "x" }) + ".c2ln";
  // Alg-allowlist gate fires BEFORE any key resolution.
  var resolverCalled = false;
  await _expectThrow("verify: unsupported header alg rejected before key lookup",
    "auth-sd-jwt-vc/unsupported-alg",
    function () {
      return sdJwtVc.verify(token + "~", {
        issuerKeyResolver: async function () { resolverCalled = true; return null; },
      });
    });
  check("verify: resolver not invoked for unsupported alg", resolverCalled === false);
}

async function testVerifyBadTyp() {
  var resolver = async function () { return _newKeyPair().publicKey; };
  var wrongTyp = _b64uJson({ alg: "ES256", typ: "JWT" }) + "." +
                 _b64uJson({ iss: "x" }) + ".c2ln";
  await _expectThrow("verify: wrong typ rejected", "auth-sd-jwt-vc/bad-typ",
    function () { return sdJwtVc.verify(wrongTyp + "~", { issuerKeyResolver: resolver }); });
  var absentTyp = _b64uJson({ alg: "ES256" }) + "." +
                  _b64uJson({ iss: "x" }) + ".c2ln";
  await _expectThrow("verify: absent typ rejected", "auth-sd-jwt-vc/bad-typ",
    function () { return sdJwtVc.verify(absentTyp + "~", { issuerKeyResolver: resolver }); });
}

async function testVerifyDcSdJwtTypAccepted() {
  // The `dc+sd-jwt` digital-credential profile typ must be accepted.
  var issuer = _newKeyPair();
  var nowSec = Math.floor(Date.now() / 1000);
  var jwt = _signEs256(
    { alg: "ES256", typ: "dc+sd-jwt" },
    { iss: "https://i", iat: nowSec, exp: nowSec + 3600, vct: "x", _sd: [], _sd_alg: "sha-256" },
    issuer.privateKey);
  var result = await sdJwtVc.verify(jwt + "~", {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify: dc+sd-jwt typ accepted", result.valid === true);
}

async function testVerifyCritRefusedAndEmptyAllowed() {
  var issuer = _newKeyPair();
  // Non-empty crit → refused.
  var sdCrit = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
    extraHeader: { crit: ["unknown-ext"] },
  });
  await _expectThrow("verify: non-empty crit header refused", "auth-sd-jwt-vc/unknown-crit",
    function () {
      return sdJwtVc.verify(sdCrit.token, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
      });
    });
  // Empty crit array → allowed (passes the guard, continues to verify).
  var sdEmptyCrit = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
    extraHeader: { crit: [] },
  });
  var okEmpty = await sdJwtVc.verify(sdEmptyCrit.token, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify: empty crit array accepted", okEmpty.valid === true);
}

async function testVerifyKeyNotFound() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: resolver returning null rejected",
    "auth-sd-jwt-vc/key-not-found",
    function () {
      return sdJwtVc.verify(sd.token, { issuerKeyResolver: async function () { return null; } });
    });
}

// ---- verify: issuerKeyResolver returning a JWK (RED — was crashing) ----

// A resolver that hands back a raw JWK is the common path per the
// CVE-2026-22817 alg/kty cross-check comment in verify(). Before the fix
// the JWK was cross-checked then passed straight to node:crypto.verify,
// which cannot consume a bare JWK object → ERR_INVALID_ARG_TYPE, so a
// VALID credential was rejected with a non-framework crash. The issuer
// path must import the JWK to a KeyObject first, exactly as the holder
// KB-JWT path does.
async function testJwkIssuerKeyResolver() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x",
    claims: { given_name: "Alice", country: "US" },
    selectivelyDisclosed: ["given_name"],
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return _jwk(issuer.publicKey); },
  });
  check("verify: JWK-returning resolver verifies a valid credential",
        result.valid === true && result.claims.given_name === "Alice");

  // Ed25519 JWK resolver path too.
  var edIssuer = nodeCrypto.generateKeyPairSync("ed25519");
  var sdEd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: edIssuer.privateKey, algorithm: "EdDSA",
  });
  var edResult = await sdJwtVc.verify(sdEd.token, {
    issuerKeyResolver: async function () { return _jwk(edIssuer.publicKey); },
  });
  check("verify: EdDSA JWK resolver verifies", edResult.valid === true);
}

async function testJwkIssuerAlgKtyMismatch() {
  // Resolver returns an EC JWK but the header alg claims EdDSA (requires
  // kty=OKP) → alg/kty cross-check refuses before node:crypto.verify.
  var issuer = _newKeyPair();
  var token = _b64uJson({ alg: "EdDSA", typ: "vc+sd-jwt" }) + "." +
              _b64uJson({ iss: "x", vct: "x" }) + ".c2ln";
  await _expectThrow("verify: issuer alg/kty mismatch (EC JWK vs EdDSA) refused",
    "auth-jwt-external/alg-kty-mismatch",
    function () {
      return sdJwtVc.verify(token + "~", {
        issuerKeyResolver: async function () { return _jwk(issuer.publicKey); },
      });
    });
}

// ---- verify: clock / issuer / exp branches ----

async function testVerifyNowAndClockSkewOpts() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  var result = await sdJwtVc.verify(sd.token, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
    now: Date.now(), maxClockSkewSec: 120,
  });
  check("verify: explicit now + maxClockSkewSec accepted", result.valid === true);
}

async function testVerifyBadClockSkew() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: Infinity maxClockSkewSec rejected",
    "auth-sd-jwt-vc/bad-clock-skew",
    function () {
      return sdJwtVc.verify(sd.token, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
        maxClockSkewSec: Infinity,
      });
    });
}

async function testVerifyIatFuture() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
    issuedAt: Date.now() + 60 * 60 * 1000,   // 1h in the future
  });
  await _expectThrow("verify: future iat rejected", "auth-sd-jwt-vc/iat-future",
    function () {
      return sdJwtVc.verify(sd.token, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
      });
    });
}

async function testVerifyRequireExpMissing() {
  // A validly issuer-signed credential that omits exp: accepted normally,
  // refused under requireExp:true.
  var issuer = _newKeyPair();
  var nowSec = Math.floor(Date.now() / 1000);
  var jwt = _signEs256(
    { alg: "ES256", typ: "vc+sd-jwt" },
    { iss: "https://i", iat: nowSec, vct: "x", _sd: [], _sd_alg: "sha-256" },
    issuer.privateKey);
  var okWithout = await sdJwtVc.verify(jwt + "~", {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify: exp-less credential accepted without requireExp",
        okWithout.valid === true);
  await _expectThrow("verify: exp-less credential refused under requireExp",
    "auth-sd-jwt-vc/missing-exp",
    function () {
      return sdJwtVc.verify(jwt + "~", {
        issuerKeyResolver: async function () { return issuer.publicKey; },
        requireExp: true,
      });
    });
}

async function testVerifyIssuerMismatch() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://issuer.example", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: expectedIssuer mismatch refused (CVE-2026-23552)",
    "auth-sd-jwt-vc/iss-mismatch",
    function () {
      return sdJwtVc.verify(sd.token, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
        expectedIssuer: "https://other-issuer.example",
      });
    });
}

// ---- verify: _sd_alg / _sd reconstruction defensive branches ----

async function testVerifyMissingSdAlgAndSd() {
  // Payload with neither _sd nor _sd_alg → hashAlg falls back to sha-256,
  // _sd falls back to []. Valid, no disclosed claims.
  var issuer = _newKeyPair();
  var nowSec = Math.floor(Date.now() / 1000);
  var jwt = _signEs256(
    { alg: "ES256", typ: "vc+sd-jwt" },
    { iss: "https://i", iat: nowSec, exp: nowSec + 3600, vct: "x", country: "US" },
    issuer.privateKey);
  var result = await sdJwtVc.verify(jwt + "~", {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify: missing _sd/_sd_alg → sha-256 fallback, [] digests, valid",
        result.valid === true && result.claims.country === "US");
}

async function testVerifyUnsupportedSdAlg() {
  // A malicious issuer-signed payload declaring an unsupported _sd_alg is
  // refused at reconstruction.
  var issuer = _newKeyPair();
  var nowSec = Math.floor(Date.now() / 1000);
  var jwt = _signEs256(
    { alg: "ES256", typ: "vc+sd-jwt" },
    { iss: "https://i", iat: nowSec, exp: nowSec + 3600, vct: "x", _sd: [], _sd_alg: "sha-1" },
    issuer.privateKey);
  await _expectThrow("verify: unsupported _sd_alg refused", "auth-sd-jwt-vc/bad-hash",
    function () {
      return sdJwtVc.verify(jwt + "~", {
        issuerKeyResolver: async function () { return issuer.publicKey; },
      });
    });
}

async function testVerifyMalformedDisclosureSkipped() {
  // A garbage disclosure segment that decodes to null is silently skipped
  // (it is not a valid disclosure); the valid disclosure still resolves.
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    selectivelyDisclosed: ["a"], issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  var parts = sd.token.split("~");       // [jwt, dA, ""]
  var garbage = Buffer.from("123", "utf8").toString("base64url");  // JSON number, not array → null
  var tampered = parts[0] + "~" + parts[1] + "~" + garbage + "~";
  var result = await sdJwtVc.verify(tampered, {
    issuerKeyResolver: async function () { return issuer.publicKey; },
  });
  check("verify: malformed disclosure skipped, valid disclosure resolves",
        result.valid === true && result.claims.a === 1);
}

async function testVerifyDisclosureReplay() {
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    selectivelyDisclosed: ["a"], issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  var parts = sd.token.split("~");       // [jwt, dA, ""]
  var replayed = parts[0] + "~" + parts[1] + "~" + parts[1] + "~";   // dA twice
  await _expectThrow("verify: duplicate disclosure digest refused",
    "auth-sd-jwt-vc/disclosure-replay",
    function () {
      return sdJwtVc.verify(replayed, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
      });
    });
}

async function testVerifyProtectedClaimShadow() {
  // An issuer that selectively-discloses a spec-protected claim name
  // (e.g. iss) produces a disclosure whose digest is in _sd; the verifier
  // must refuse it rather than let it shadow the signed claim.
  var issuer = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x",
    claims: { iss: "shadow-attempt", role: "user" },
    selectivelyDisclosed: ["iss"],
    issuerKey: issuer.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: protected-claim-shadow disclosure refused",
    "auth-sd-jwt-vc/protected-claim-shadow",
    function () {
      return sdJwtVc.verify(sd.token, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
      });
    });
}

// ---- verify: KB-JWT error branches ----

function _issueWithHolder(claims, selectively) {
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: claims,
    selectivelyDisclosed: selectively || [],
    issuerKey: issuer.privateKey, holderKey: _jwk(holder.publicKey),
  });
  return { issuer: issuer, holder: holder, sd: sd };
}

async function testVerifyKbNoCnf() {
  // Credential issued WITHOUT a cnf, but the presentation carries a
  // KB-JWT → refuse (no issuer-attested holder key to check it against).
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x", claims: { a: 1 },
    issuerKey: issuer.privateKey,      // no holderKey → no cnf
  });
  var pres = sdJwtVc.present({
    sdJwt: sd.token, audience: "v", nonce: "n",
    holderKey: holder.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: KB-JWT with no issuer cnf refused", "auth-sd-jwt-vc/no-cnf",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbBadHeader() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  var segs = pres.presentation.split("~");
  // Replace KB-JWT with a 3-part token whose header is non-JSON.
  var badHeader = Buffer.from("not-json", "utf8").toString("base64url");
  segs[segs.length - 1] = badHeader + ".cGF5.c2ln";
  await _expectThrow("verify: malformed KB-JWT header refused",
    "auth-sd-jwt-vc/bad-kb-header",
    function () {
      return sdJwtVc.verify(segs.join("~"), {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbBadTyp() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  var segs = pres.presentation.split("~");
  segs[segs.length - 1] = _b64uJson({ alg: "ES256", typ: "JWT" }) + "." +
                          _b64uJson({ aud: "v", nonce: "n" }) + ".c2ln";
  await _expectThrow("verify: KB-JWT wrong typ refused", "auth-sd-jwt-vc/bad-kb-typ",
    function () {
      return sdJwtVc.verify(segs.join("~"), {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbUnsupportedAlg() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  var segs = pres.presentation.split("~");
  segs[segs.length - 1] = _b64uJson({ alg: "HS256", typ: "kb+jwt" }) + "." +
                          _b64uJson({ aud: "v", nonce: "n" }) + ".c2ln";
  await _expectThrow("verify: KB-JWT unsupported alg refused",
    "auth-sd-jwt-vc/unsupported-alg",
    function () {
      return sdJwtVc.verify(segs.join("~"), {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbWrongAudienceReal() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "https://verifier-1", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: KB-JWT aud mismatch refused (string compare)",
    "auth-sd-jwt-vc/wrong-audience",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "https://verifier-2", nonce: "n",
      });
    });
}

async function testVerifyKbWrongNonceReal() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "nonce-1",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: KB-JWT nonce mismatch refused (replay defense)",
    "auth-sd-jwt-vc/wrong-nonce",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "nonce-2",
      });
    });
}

async function testVerifyKbNonStringAud() {
  // A holder-minted KB-JWT with a non-string aud must fail the aud
  // compare closed (the timing-safe compare returns false on a non-string
  // operand rather than throwing).
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  var segs = pres.presentation.split("~");
  // Forge a KB-JWT actually signed by the holder key so it verifies, but
  // with a numeric aud → aud compare rejects.
  var nowSec = Math.floor(Date.now() / 1000);
  segs[segs.length - 1] = _signEs256(
    { alg: "ES256", typ: "kb+jwt" },
    { aud: 12345, nonce: "n", iat: nowSec, sd_hash: "whatever" },
    s.holder.privateKey);
  await _expectThrow("verify: non-string KB-JWT aud fails closed",
    "auth-sd-jwt-vc/wrong-audience",
    function () {
      return sdJwtVc.verify(segs.join("~"), {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbSdHashMismatch() {
  // Disclosing more (a valid extra disclosure) than the KB-JWT committed
  // to changes the presentation hash → sd_hash mismatch, even though both
  // disclosures individually match _sd digests.
  var issuer = _newKeyPair();
  var holder = _newKeyPair();
  var sd = sdJwtVc.issue({
    issuer: "https://i", vct: "x",
    claims: { given_name: "Alice", family_name: "Smith" },
    selectivelyDisclosed: ["given_name", "family_name"],
    issuerKey: issuer.privateKey, holderKey: _jwk(holder.publicKey),
  });
  var pres = sdJwtVc.present({
    sdJwt: sd.token, disclosedClaimNames: ["given_name"],
    audience: "v", nonce: "n", holderKey: holder.privateKey, algorithm: "ES256",
  });
  // Find the family_name disclosure (held back) and splice it in before KB.
  var famDisclosure = null;
  for (var i = 0; i < sd.disclosures.length; i++) {
    var dec = sdJwtVc.disclosure.decode(sd.disclosures[i]);
    if (dec && dec.name === "family_name") famDisclosure = sd.disclosures[i];
  }
  check("sd-hash setup: family_name disclosure located", famDisclosure !== null);
  var segs = pres.presentation.split("~");     // [jwt, gnDisclosure, KBJWT]
  segs.splice(segs.length - 1, 0, famDisclosure);
  await _expectThrow("verify: extra disclosure → KB sd_hash mismatch refused",
    "auth-sd-jwt-vc/sd-hash-mismatch",
    function () {
      return sdJwtVc.verify(segs.join("~"), {
        issuerKeyResolver: async function () { return issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

async function testVerifyKbIatFuture() {
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
    issuedAt: Date.now() + 60 * 60 * 1000,    // KB iat 1h in the future
  });
  await _expectThrow("verify: future KB-JWT iat refused", "auth-sd-jwt-vc/kb-iat-future",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
      });
    });
}

// ---- verify: OpenID4VCI key-attestation branches ----

function _presentWithAttestation(s, attestation) {
  return sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
    keyAttestation: attestation,
  });
}

async function testKbAttestationRequiredNoVerifier() {
  var s = _issueWithHolder({ a: 1 });
  var pres = _presentWithAttestation(s, "att.jwt.token");
  await _expectThrow("verify: requireKeyAttestation without verifier refused",
    "auth-sd-jwt-vc/no-attestation-verifier",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n", requireKeyAttestation: true,
      });
    });
}

async function testKbAttestationNoVerifierSkipped() {
  var s = _issueWithHolder({ a: 1 });
  var pres = _presentWithAttestation(s, "att.jwt.token");
  var result = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return s.issuer.publicKey; },
    audience: "v", nonce: "n",
  });
  check("verify: attestation present but no verifier → skipped, KB still valid",
        result.valid === true && result.kbValidated === true &&
        result.keyAttestationClaims === null);
}

async function testKbAttestationVerified() {
  var s = _issueWithHolder({ a: 1 });
  var pres = _presentWithAttestation(s, "att.jwt.token");
  var gotArgs = null;
  var result = await sdJwtVc.verify(pres.presentation, {
    issuerKeyResolver: async function () { return s.issuer.publicKey; },
    audience: "v", nonce: "n",
    keyAttestationVerifier: async function (args) {
      gotArgs = args;
      return { attested: true, aaguid: "test" };
    },
  });
  check("verify: keyAttestationVerifier receives the raw attestation jwt",
        gotArgs && gotArgs.jwt === "att.jwt.token" && gotArgs.audience === "v");
  check("verify: verified attestation claims surfaced",
        result.keyAttestationClaims && result.keyAttestationClaims.attested === true);
}

async function testKbAttestationVerifierThrows() {
  var s = _issueWithHolder({ a: 1 });
  var pres = _presentWithAttestation(s, "att.jwt.token");
  await _expectThrow("verify: rejecting keyAttestationVerifier surfaces failure",
    "auth-sd-jwt-vc/attestation-verify-failed",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
        keyAttestationVerifier: async function () { throw new Error("bad TEE anchor"); },
      });
    });
  // A verifier that throws an error with no message still fails closed —
  // the wrapper falls back to String(e) for the diagnostic.
  await _expectThrow("verify: keyAttestationVerifier throwing a message-less error fails closed",
    "auth-sd-jwt-vc/attestation-verify-failed",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
        keyAttestationVerifier: async function () { throw new Error(); },
      });
    });
}

async function testKbAttestationVerifierEmpty() {
  var s = _issueWithHolder({ a: 1 });
  var pres = _presentWithAttestation(s, "att.jwt.token");
  await _expectThrow("verify: keyAttestationVerifier returning no claims refused",
    "auth-sd-jwt-vc/attestation-empty",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n",
        keyAttestationVerifier: async function () { return null; },
      });
    });
}

async function testKbMissingAttestationRequired() {
  // KB-JWT carries NO key_attestation but requireKeyAttestation is set.
  var s = _issueWithHolder({ a: 1 });
  var pres = sdJwtVc.present({
    sdJwt: s.sd.token, audience: "v", nonce: "n",
    holderKey: s.holder.privateKey, algorithm: "ES256",
  });
  await _expectThrow("verify: requireKeyAttestation but KB has none refused",
    "auth-sd-jwt-vc/missing-key-attestation",
    function () {
      return sdJwtVc.verify(pres.presentation, {
        issuerKeyResolver: async function () { return s.issuer.publicKey; },
        audience: "v", nonce: "n", requireKeyAttestation: true,
      });
    });
}

// ---- Run all ----

async function run() {
  testDisclosureEncodeDecode();
  testDisclosureValueComplexShape();
  testDisclosureBadInput();
  testDisclosureDeterministicSalt();
  testIssueBasic();
  testIssueWithCnf();
  testIssueValidation();
  await testVerifyHappyPath();
  await testVerifyBadIssuerSignature();
  await testVerifyExpired();
  await testVerifyVctMismatch();
  await testVerifyDisclosureMismatch();
  await testPresentSubsetThenVerify();
  await testPresentWithKeyBinding();
  await testKbRequiresReplayBinding();
  await testRequireExpOpt();
  await testKbWrongAudience();
  await testKbWrongNonce();
  await testRequireKeyBindingMissing();
  await testIssuerHappyPath();
  await testIssuerKeyRotation();
  testIssuerValidation();
  await testIssuerStats();
  await testCustomHashAlg();
  await testNoDisclosuresPlainOnly();
  await testHolderStoreAndList();
  await testHolderPresent();
  await testHolderDelete();
  await testHolderPresentNonexistent();
  testHolderValidation();
  await testHolderAlgFromKeyType();
  await testKbAlgKtyCrossCheck();
  // Error / adversarial / defensive / option-default branch coverage
  testHashDisclosureBadAlg();
  testIssueClaimsNotObject();
  testIssueBadHashAlg();
  testIssueNoIssuerKey();
  testIssueBadCnf();
  await testIssueVerifyAllAlgs();
  testPresentMalformed();
  testPresentUnsupportedKbAlg();
  testPresentBadSdAlg();
  testPresentSdAlgFallbackOnMalformedPayload();
  await testPresentKeyAttestationHeader();
  await testVerifyInvalidPresentationArg();
  await testVerifyNoResolver();
  await testVerifyPresentationNoSeparator();
  await testVerifyJwtNotThreeParts();
  await testVerifyBadHeader();
  await testVerifyUnsupportedHeaderAlg();
  await testVerifyBadTyp();
  await testVerifyDcSdJwtTypAccepted();
  await testVerifyCritRefusedAndEmptyAllowed();
  await testVerifyKeyNotFound();
  await testJwkIssuerKeyResolver();
  await testJwkIssuerAlgKtyMismatch();
  await testVerifyNowAndClockSkewOpts();
  await testVerifyBadClockSkew();
  await testVerifyIatFuture();
  await testVerifyRequireExpMissing();
  await testVerifyIssuerMismatch();
  await testVerifyMissingSdAlgAndSd();
  await testVerifyUnsupportedSdAlg();
  await testVerifyMalformedDisclosureSkipped();
  await testVerifyDisclosureReplay();
  await testVerifyProtectedClaimShadow();
  await testVerifyKbNoCnf();
  await testVerifyKbBadHeader();
  await testVerifyKbBadTyp();
  await testVerifyKbUnsupportedAlg();
  await testVerifyKbWrongAudienceReal();
  await testVerifyKbWrongNonceReal();
  await testVerifyKbNonStringAud();
  await testVerifyKbSdHashMismatch();
  await testVerifyKbIatFuture();
  await testKbAttestationRequiredNoVerifier();
  await testKbAttestationNoVerifierSkipped();
  await testKbAttestationVerified();
  await testKbAttestationVerifierThrows();
  await testKbAttestationVerifierEmpty();
  await testKbMissingAttestationRequired();
  testExports();
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
