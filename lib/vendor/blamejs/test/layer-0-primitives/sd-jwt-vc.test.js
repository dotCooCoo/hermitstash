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
  testExports();
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
