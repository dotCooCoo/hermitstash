// Regression coverage for security behaviors that had silently drifted into
// being non-functional (no-MVP violations) and were repaired in v1.12.0:
//   - the IP blocklist matched nothing (lookup never translated to the hash)
//   - the blind index was an unkeyed, plaintext-recomputable hash
//   - upload counters were a non-atomic read-modify-write
// These tests exist so those features can't silently rot back to "shipped but
// dead" without a red test.
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var fs = require("fs");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var testDbPath = path.join(__dirname, "..", "..", "data", "test-secreg-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var clientIp = require("../../lib/client-ip");
var fieldCrypto = require("../../lib/field-crypto");
var db, bundlesRepo, accessCodeService, accessCodesRepo;

before(async function () {
  await vault.init();
  db = require("../../lib/db");
  bundlesRepo = require("../../app/data/repositories/bundles.repo");
  accessCodeService = require("../../app/domain/access-code.service");
  accessCodesRepo = require("../../app/data/repositories/bundleAccessCodes.repo");
});

function seedCode(shareId, email, code) {
  accessCodesRepo.create({
    bundleShareId: shareId, email: email, code: code, attempts: 0, status: "pending",
    expiresAt: new Date(Date.now() + 600000).toISOString(), createdAt: new Date().toISOString(),
  });
}

after(function () {
  ["", "-shm", "-wal", ".enc"].forEach(function (s) { try { fs.unlinkSync(testDbPath + s); } catch (_e) {} });
});

describe("IP blocklist actually blocks (was 100% dead — raw IP compared to stored hash)", function () {
  it("findOne({ ip }) matches a blocked IP", function () {
    db.blockedIps.insert({ ip: "203.0.113.7", reason: "abuse", blockedBy: "admin" });
    assert.ok(db.blockedIps.findOne({ ip: "203.0.113.7" }), "a blocked IP must be found by its raw address");
  });
  it("the stored ip column is a hash, not the plaintext IP", function () {
    var ins = db.blockedIps.insert({ ip: "203.0.113.8", reason: "x", blockedBy: "admin" });
    var raw = db.rawGet("SELECT ip FROM blocked_ips WHERE _id = ?", ins._id);
    assert.notStrictEqual(raw.ip, "203.0.113.8", "ip must be hashed at rest");
    assert.ok(/^[0-9a-f]{128}$/.test(raw.ip), "ip is a hash digest");
  });
  it("an IPv4-mapped IPv6 peer is canonicalized and still caught", function () {
    db.blockedIps.insert({ ip: "203.0.113.9", reason: "x", blockedBy: "admin" });
    assert.strictEqual(clientIp.canonicalize("::ffff:203.0.113.9"), "203.0.113.9");
    assert.ok(db.blockedIps.findOne({ ip: clientIp.canonicalize("::ffff:203.0.113.9") }), "mapped peer must hit the block");
  });
  it("a non-blocked IP does not match", function () {
    assert.ok(!db.blockedIps.findOne({ ip: "198.51.100.1" }), "an unblocked IP must not match");
  });
});

describe("keyed-MAC blind index + dual-read (was unkeyed, plaintext-recomputable)", function () {
  it("lookup by a sealed field finds the row, and the stored digest is the keyed MAC (64 hex), not the legacy unkeyed SHA3 (128 hex)", function () {
    var u = db.users.insert({ email: "Drift@Ex.com", displayName: "D" });
    var found = db.users.findOne({ email: "drift@ex.com" });
    assert.ok(found && found._id === u._id, "lookup by email must resolve via the keyed index");
    var raw = db.rawGet("SELECT emailHash FROM users WHERE _id = ?", u._id);
    var keyed = fieldCrypto.derivedKeyed("hs-email", "drift@ex.com", false);
    var legacy = b.crypto.namespaceHash("hs-email", "drift@ex.com");
    assert.strictEqual(raw.emailHash, keyed, "stored emailHash is the keyed MAC");
    assert.notStrictEqual(raw.emailHash, legacy, "stored emailHash is NOT the legacy plaintext-recomputable digest");
  });
  it("dual-read resolves a pre-migration row still carrying the legacy digest", function () {
    var u = db.users.insert({ email: "legacy@ex.com", displayName: "L" });
    var legacy = b.crypto.namespaceHash("hs-email", "legacy@ex.com");
    db.rawExec("UPDATE users SET emailHash = ? WHERE _id = ?", legacy, u._id);
    var found = db.users.findOne({ email: "legacy@ex.com" });
    assert.ok(found && found._id === u._id, "a legacy-digest row must still resolve via dual-read");
  });
  it("IN-list lookup hashes each element with dual-read", function () {
    var u = db.users.insert({ email: "inlist@ex.com", displayName: "I" });
    var legacy = b.crypto.namespaceHash("hs-email", "inlist@ex.com");
    db.rawExec("UPDATE users SET emailHash = ? WHERE _id = ?", legacy, u._id);
    var rows = db.users.find({ email: { $in: ["inlist@ex.com", "nobody@ex.com"] } });
    assert.ok(rows.some(function (r) { return r._id === u._id; }), "IN-list dual-read must find the legacy-digest row");
  });
  it("count() translates a sealed-field predicate (the column fast-path used to compare plaintext to ciphertext → always 0)", function () {
    db.users.insert({ email: "Counted@Ex.com", displayName: "C" });
    assert.strictEqual(db.users.count({ email: "counted@ex.com" }), 1, "count by a sealed email must translate to the keyed index, not match the sealed column with plaintext");
    assert.strictEqual(db.users.count({ email: "nobody-counted@ex.com" }), 0, "count by an absent email is 0");
  });
});

describe("atomic bundle counters (was a non-atomic read-modify-write)", function () {
  it("incrementCounters returns the new authoritative values and clamps at 0", function () {
    var bun = db.bundles.insert({ shareId: "sr-" + b.crypto.generateToken(4), status: "complete", receivedFiles: 0, totalSize: 0 });
    var c1 = bundlesRepo.incrementCounters(bun._id, 1, 100);
    assert.strictEqual(c1.receivedFiles, 1);
    assert.strictEqual(c1.totalSize, 100);
    var c2 = bundlesRepo.incrementCounters(bun._id, 1, 50);
    assert.strictEqual(c2.receivedFiles, 2);
    assert.strictEqual(c2.totalSize, 150);
    // A negative delta (sync replace / removal) can't drive either below zero.
    var c3 = bundlesRepo.incrementCounters(bun._id, -5, -1000);
    assert.strictEqual(c3.receivedFiles, 0);
    assert.strictEqual(c3.totalSize, 0);
  });
});

describe("cert revocation actually revokes (same lookup class as the blocklist)", function () {
  it("isCertRevoked matches a revoked fingerprint and not an unrevoked one", function () {
    var cu = require("../../lib/cert-utils");
    var fp = "AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD";
    db.certRevocations.insert({ fingerprintHash: cu.hashCertFingerprint(fp), cn: "x", reason: "compromise", revokedAt: new Date().toISOString() });
    assert.strictEqual(cu.isCertRevoked(fp), true, "a revoked fingerprint must be detected");
    assert.strictEqual(cu.isCertRevoked("99:88:77:66:55"), false, "an unrevoked fingerprint must not match");
  });
});

describe("email access-code gate works after the keyed-index migration (service computed the unkeyed digest while the column is stored keyed → was dead)", function () {
  it("verifyCode accepts the correct email + code", function () {
    var shareId = "b-" + b.crypto.generateToken(4);
    seedCode(shareId, "gate@ex.com", "123456");
    assert.strictEqual(accessCodeService.verifyCode({ shareId: shareId, email: "gate@ex.com", code: "123456" }).success, true, "correct email+code must verify (keyed digest must match the stored keyed digest)");
  });
  it("verifyCode rejects a wrong code", function () {
    var shareId = "b-" + b.crypto.generateToken(4);
    seedCode(shareId, "gate@ex.com", "654321");
    assert.strictEqual(accessCodeService.verifyCode({ shareId: shareId, email: "gate@ex.com", code: "000000" }).success, false, "wrong code must fail");
  });
  it("verifyCode rejects an unknown email (record not found)", function () {
    var shareId = "b-" + b.crypto.generateToken(4);
    seedCode(shareId, "gate@ex.com", "111111");
    assert.strictEqual(accessCodeService.verifyCode({ shareId: shareId, email: "other@ex.com", code: "111111" }).success, false, "wrong email must not resolve a record");
  });
});

describe("verification-token cleanup is type-scoped (a resent verification email must not wipe a pending password reset)", function () {
  it("createVerificationToken clears only EMAIL tokens, leaving password_reset intact", function () {
    var createVerificationToken = require("../../routes/verification").createVerificationToken;
    var u = db.users.insert({ email: "tokclean@ex.com", displayName: "T", authType: "local", role: "user", status: "active", createdAt: new Date().toISOString() });
    var future = new Date(Date.now() + 600000).toISOString();
    db.verificationTokens.insert({ userId: u._id, token: "seed-pwreset", type: "password_reset", expiresAt: future, createdAt: new Date().toISOString() });
    db.verificationTokens.insert({ userId: u._id, token: "seed-email", type: "email", expiresAt: future, createdAt: new Date().toISOString() });

    // Issuing a fresh email verification token clears existing EMAIL tokens only.
    createVerificationToken(u._id);

    var rows = db.verificationTokens.find({ userId: u._id });
    var pw = rows.filter(function (t) { return t.type === "password_reset"; });
    var em = rows.filter(function (t) { return t.type === "email"; });
    assert.strictEqual(pw.length, 1, "the pending password-reset token must survive an email-verification resend");
    assert.strictEqual(em.length, 1, "the prior email token is replaced by exactly one fresh email token");
  });
});
