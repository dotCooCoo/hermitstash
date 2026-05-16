"use strict";
/**
 * b.mail.greylist — RFC 6647 greylisting. Tests the triplet
 * fingerprint, defer→retry-after-delay→accept-first-pass→whitelisted
 * lifecycle, CIDR aggregation, allowed-source bypass, TTL expiry.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _ctx(overrides) {
  return Object.assign({
    ip:       "203.0.113.42",
    mailFrom: "sender@example.com",
    rcptTo:   "alice@operator.example",
  }, overrides || {});
}

function testSurface() {
  check("create is fn",                typeof b.mail.greylist.create === "function");
  check("compliancePosture is fn",     typeof b.mail.greylist.compliancePosture === "function");
  check("PROFILES frozen",             Object.isFrozen(b.mail.greylist.PROFILES));
  check("MailGreylistError is fn",     typeof b.mail.greylist.MailGreylistError === "function");
}

async function testFirstSeenDeferred() {
  var gl = b.mail.greylist.create();
  var v = await gl.check(_ctx());
  check("first-seen: defer",          v.action === "defer");
  check("first-seen: reason",          v.reason === "first-seen");
  check("first-seen: firstSeenAt",     typeof v.firstSeenAt === "number");
}

async function testRetryTooSoonDeferred() {
  var gl = b.mail.greylist.create();
  var ctx = _ctx();
  await gl.check(ctx);
  var v = await gl.check(ctx);
  check("retry too soon: defer",       v.action === "defer");
  check("retry too soon: reason",      v.reason === "retry-too-soon");
}

async function testRetryAfterDelayAccepted() {
  var gl = b.mail.greylist.create({ minDelayMs: 50 });
  var ctx = _ctx();
  await gl.check(ctx);
  await new Promise(function (r) { setTimeout(r, 80); });
  var v = await gl.check(ctx);
  check("retry after delay: accept-first-pass", v.action === "accept-first-pass");
  check("retry after delay: reason",            v.reason === "retry-after-delay");
  check("retry after delay: ttlExpiresAt set",  typeof v.ttlExpiresAt === "number");
}

async function testWhitelistedAcceptsImmediately() {
  var gl = b.mail.greylist.create({ minDelayMs: 50 });
  var ctx = _ctx();
  await gl.check(ctx);
  await new Promise(function (r) { setTimeout(r, 80); });
  await gl.check(ctx);                 // first-pass → whitelisted
  var v = await gl.check(ctx);          // subsequent
  check("whitelisted: accept",          v.action === "accept");
  check("whitelisted: reason",          v.reason === "whitelisted");
}

async function testWhitelistExpired() {
  var gl = b.mail.greylist.create({ minDelayMs: 10, whitelistTtlMs: 20 });
  var ctx = _ctx();
  await gl.check(ctx);                                            // defer
  await new Promise(function (r) { setTimeout(r, 30); });
  await gl.check(ctx);                                            // accept-first-pass
  // After whitelistTtlMs(20ms) the entry expires; simulate via
  // ctx.now far in the future.
  var v = await gl.check(Object.assign({}, ctx, { now: Date.now() + 1000 * 60 * 60 }));
  check("whitelist expired: defer",     v.action === "defer");
  check("whitelist expired: reason",    v.reason === "whitelist-expired-resnap");
}

async function testTripletKeyedByAllThree() {
  var gl = b.mail.greylist.create();
  await gl.check(_ctx());

  // Different mailFrom → different fingerprint → first-seen defer.
  var v2 = await gl.check(_ctx({ mailFrom: "other@example.com" }));
  check("different mailFrom is first-seen", v2.reason === "first-seen");

  // Different rcptTo → different fingerprint.
  var v3 = await gl.check(_ctx({ rcptTo: "bob@operator.example" }));
  check("different rcptTo is first-seen",   v3.reason === "first-seen");
}

async function testCidrAggregation() {
  // Same /24 cluster: 203.0.113.42 and 203.0.113.43 should share
  // a fingerprint under strict profile (ipv4Prefix=24).
  var gl = b.mail.greylist.create({ minDelayMs: 50 });
  await gl.check(_ctx({ ip: "203.0.113.42" }));
  await new Promise(function (r) { setTimeout(r, 80); });
  // Different IP in same /24 — retry-after-delay path should hit.
  var v = await gl.check(_ctx({ ip: "203.0.113.43" }));
  check("CIDR aggregation: same /24 → accept-first-pass",
    v.action === "accept-first-pass");
}

async function testDifferentSubnetIsFirstSeen() {
  var gl = b.mail.greylist.create();
  await gl.check(_ctx({ ip: "203.0.113.42" }));
  var v = await gl.check(_ctx({ ip: "198.51.100.42" }));
  check("different /24: first-seen",    v.reason === "first-seen");
}

async function testAllowedSourcesBypass() {
  var gl = b.mail.greylist.create({
    allowedSources: ["203.0.113.42"],
  });
  var v = await gl.check(_ctx());
  check("allowed-source: accept",       v.action === "accept");
  check("allowed-source: reason",       v.reason === "allowed-source");
}

async function testBounceMailFromAccepted() {
  // RFC 5321 §3.3 bounce sender (empty reverse-path) keys with the
  // empty string. Same triplet contract.
  var gl = b.mail.greylist.create();
  var v = await gl.check(_ctx({ mailFrom: "" }));
  check("bounce mailfrom: first-seen",  v.reason === "first-seen");
}

async function testRefusesBadInput() {
  var gl = b.mail.greylist.create();
  var threw1 = null;
  try { await gl.check(null); } catch (e) { threw1 = e; }
  check("null ctx refused",             threw1 && threw1.code === "mail-greylist/bad-input");

  var threw2 = null;
  try { await gl.check({ ip: "203.0.113.42", mailFrom: "a@b.com" }); }
  catch (e) { threw2 = e; }
  check("missing rcptTo refused",       threw2 && threw2.code === "mail-greylist/bad-input");

  var threw3 = null;
  try { await gl.check({ ip: "", mailFrom: "a@b.com", rcptTo: "c@d.com" }); }
  catch (e) { threw3 = e; }
  check("empty ip refused",             threw3 && threw3.code === "mail-greylist/bad-input");

  var threw4 = null;
  try { await gl.check({ ip: "not-an-ip", mailFrom: "a@b.com", rcptTo: "c@d.com" }); }
  catch (e) { threw4 = e; }
  check("bad IP refused",               threw4 && threw4.code === "mail-greylist/bad-input");
}

async function testIpv6Triplet() {
  var gl = b.mail.greylist.create({ minDelayMs: 30 });
  var ctx = _ctx({ ip: "2001:db8::42" });
  var v1 = await gl.check(ctx);
  check("ipv6 first-seen: defer",       v1.action === "defer");
  await new Promise(function (r) { setTimeout(r, 50); });
  var v2 = await gl.check(ctx);
  check("ipv6 retry: accept-first-pass", v2.action === "accept-first-pass");
}

async function testCompliancePosture() {
  check("hipaa → strict",     b.mail.greylist.compliancePosture("hipaa") === "strict");
  check("unknown → null",     b.mail.greylist.compliancePosture("foo") === null);
}

async function testProfileResolution() {
  var gl = b.mail.greylist.create({ profile: "balanced" });
  check("profile balanced",   gl.profile === "balanced");
  var threw = null;
  try { b.mail.greylist.create({ profile: "yolo" }); }
  catch (e) { threw = e; }
  check("bad profile refused", threw && threw.code === "mail-greylist/bad-profile");
}

async function testGc() {
  var gl = b.mail.greylist.create();
  await gl.check(_ctx());
  // Wait briefly, then gc with a very short olderThanMs.
  await new Promise(function (r) { setTimeout(r, 30); });
  var r = await gl.gc({ olderThanMs: 10 });
  check("gc removed at least 1",        r.removed >= 1);
}

async function testFingerprintHashStable() {
  var fp1 = b.mail.greylist._hashFingerprint("203.0.113.0/24", "a@b.com", "c@d.com");
  var fp2 = b.mail.greylist._hashFingerprint("203.0.113.0/24", "a@b.com", "c@d.com");
  check("fingerprint deterministic",    fp1 === fp2);
  // Hex, not raw plaintext on disk.
  check("fingerprint hex-shaped",       /^[0-9a-f]+$/.test(fp1));
  check("fingerprint length",           fp1.length >= 32);
}

async function run() {
  testSurface();
  await testFirstSeenDeferred();
  await testRetryTooSoonDeferred();
  await testRetryAfterDelayAccepted();
  await testWhitelistedAcceptsImmediately();
  await testWhitelistExpired();
  await testTripletKeyedByAllThree();
  await testCidrAggregation();
  await testDifferentSubnetIsFirstSeen();
  await testAllowedSourcesBypass();
  await testBounceMailFromAccepted();
  await testRefusesBadInput();
  await testIpv6Triplet();
  await testCompliancePosture();
  await testProfileResolution();
  await testGc();
  await testFingerprintHashStable();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
