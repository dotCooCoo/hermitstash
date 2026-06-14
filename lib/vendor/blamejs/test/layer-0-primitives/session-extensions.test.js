"use strict";
/**
 * b.session — v0.8.61 extensions:
 *   - clientIpPrefix fingerprint field (auto /24 IPv4 + /64 IPv6 mask)
 *   - PQC-sealed sid cookie default (token = vault.seal(sid))
 *   - Pluggable session store via b.session.useStore + stores.localDbThin
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;

function _makeReq(headers) {
  return {
    headers: headers || {},
    socket:  { remoteAddress: (headers && headers["x-forwarded-for"]) || "" },
  };
}

async function testSealedCookieDefault() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-1", data: { role: "user" } });
    check("create returns string token",                typeof s.token === "string");
    check("token is sealed (vault: prefix)",            s.token.indexOf("vault:") === 0);

    var info = await b.session.verify(s.token);
    check("verify accepts sealed token",                info && info.userId === "u-1");

    // Pre-v0.8.61 raw-sid format: a 64-char hex string (64 random
    // bytes hex-encoded). The sealed-cookie default refuses it cleanly.
    var raw = "deadbeefcafef00d".repeat(4);
    var nullInfo = await b.session.verify(raw);
    check("verify refuses pre-v0.8.61 raw-format token", nullInfo === null);

    // A garbage sealed envelope (right prefix, wrong ciphertext) also
    // returns null rather than throwing — caller's re-auth flow.
    var bogus = await b.session.verify("vault:not-real-ciphertext");
    check("verify refuses tampered sealed envelope",     bogus === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testSealedCookieRotateAndDestroy() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-sealed-r-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-2" });
    var rotated = await b.session.rotate(s.token);
    check("rotate returns sealed token",                 rotated && rotated.token.indexOf("vault:") === 0);
    check("rotate token differs from original",          rotated.token !== s.token);
    var oldStill = await b.session.verify(s.token);
    check("old token no longer verifies",                oldStill === null);
    var newOk = await b.session.verify(rotated.token);
    check("new token verifies",                          newOk && newOk.userId === "u-2");

    var destroyed = await b.session.destroy(rotated.token);
    check("destroy unseals + deletes",                   destroyed === true);
    var afterDestroy = await b.session.verify(rotated.token);
    check("verify returns null after destroy",           afterDestroy === null);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v4-"));
  try {
    await setupTestDb(tmpDir);
    // Same /24, different last octet — should NOT drift.
    var req1 = _makeReq({ "x-forwarded-for": "203.0.113.10", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.250", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: same /24 — no drift", info && info.fingerprintDrift === false);

    // Different /24 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "198.51.100.1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v4: cross-/24 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-v6-"));
  try {
    await setupTestDb(tmpDir);
    // Same /64, different host bits.
    var req1 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678::1", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "2001:db8:1234:5678:abcd:ef01:2345:6789", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: same /64 — no drift", info && info.fingerprintDrift === false);

    // Different /64 — should drift.
    var req3 = _makeReq({ "x-forwarded-for": "2001:db8:1234:9999::1", "user-agent": "ua1" });
    var info2 = await b.session.verify(s.token, {
      req: req3,
      fingerprintFields: ["clientIpPrefix", "userAgent"],
    });
    check("clientIpPrefix v6: cross-/64 — drift detected", info2 && info2.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClientIpPrefixV4MappedV6() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-prefix-mapped-"));
  try {
    await setupTestDb(tmpDir);
    // ::ffff:1.2.3.4 (v4-mapped-v6) is bucketed as v4 /24.
    var req1 = _makeReq({ "x-forwarded-for": "::ffff:203.0.113.5", "user-agent": "ua1" });
    var s = await b.session.create({
      userId:            "u-1",
      req:               req1,
      fingerprintFields: ["clientIpPrefix"],
    });
    var req2 = _makeReq({ "x-forwarded-for": "203.0.113.99", "user-agent": "ua1" });
    var info = await b.session.verify(s.token, {
      req: req2,
      fingerprintFields: ["clientIpPrefix"],
    });
    check("clientIpPrefix: ::ffff: maps to v4 /24 bucket", info && info.fingerprintDrift === false);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testPluggableStore() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-store-"));
  try {
    await setupTestDb(tmpDir);
    var storeFile = path.join(tmpDir, "thin-sessions.db");
    var store = b.session.stores.localDbThin({ file: storeFile });
    b.session.useStore(store);

    var s = await b.session.create({ userId: "u-1", data: { team: "a" } });
    var info = await b.session.verify(s.token);
    check("pluggable store: create + verify round-trip", info && info.userId === "u-1");
    check("pluggable store: data round-trips",           info.data && info.data.team === "a");

    var n = await b.session.count();
    check("pluggable store: count reads from thin DB",   n === 1);

    var revoked = await b.session.destroyAllForUser("u-1");
    check("pluggable store: destroyAllForUser drops 1",  revoked === 1);

    // Revert to default so subsequent tests don't carry the override.
    b.session.useStore(null);
    store.close();
    check("pluggable store: useStore(null) reverts",     true);
  } finally {
    b.session.useStore(null);
    await teardownTestDb(tmpDir);
  }
}

async function testPluggableStoreValidation() {
  var threw = false;
  try { b.session.useStore({ execute: function () {} }); }
  catch (e) { threw = /executeOne/.test(e.message); }
  check("useStore: missing executeOne refused", threw);

  threw = false;
  try { b.session.useStore("not-an-object"); }
  catch (e) { threw = /must expose execute/.test(e.message); }
  check("useStore: non-object refused", threw);

  threw = false;
  try { b.session.stores.localDbThin({}); }
  catch (e) { threw = /session-stores\/bad-file/.test(e.message) && e instanceof TypeError; }
  check("stores.localDbThin: missing file refused", threw);
}

async function testUpdateDataReplaceAndMerge() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({
      userId: "u-1",
      data:   { theme: "light", roles: ["user"], counter: 1 },
    });

    // Default = full replace. counter / roles drop; only `theme` lands.
    var ok = await b.session.updateData(s.token, { theme: "dark" });
    check("updateData: returns true on hit",                ok === true);
    var v1 = await b.session.verify(s.token);
    check("updateData: replaced payload — theme=dark",      v1.data.theme === "dark");
    check("updateData: replaced payload — counter dropped", v1.data.counter === undefined);
    check("updateData: replaced payload — roles dropped",   v1.data.roles === undefined);

    // Merge mode preserves existing keys, replaces named keys.
    await b.session.updateData(s.token, { roles: ["admin"], counter: 2 }, { merge: true });
    var v2 = await b.session.verify(s.token);
    check("updateData merge: theme preserved",              v2.data.theme === "dark");
    check("updateData merge: roles updated",                Array.isArray(v2.data.roles) && v2.data.roles[0] === "admin");
    check("updateData merge: counter updated",              v2.data.counter === 2);

    // Setting data: null clears the payload.
    await b.session.updateData(s.token, null);
    var v3 = await b.session.verify(s.token);
    check("updateData null: data cleared",                  v3.data === null);

    // Unknown / invalid token returns false (no throw).
    var miss = await b.session.updateData("vault:not-a-real-token", { x: 1 });
    check("updateData: unknown token returns false",        miss === false);

    var pre = await b.session.updateData("not-sealed-prefix", { x: 1 });
    check("updateData: pre-v0.8.61 raw token returns false", pre === false);

    // Bad shape refused at config time.
    var threw = false;
    try { await b.session.updateData(s.token, [1, 2, 3]); }
    catch (e) { threw = /must be a plain object or null/.test(e.message); }
    check("updateData: array refused",                      threw);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testUpdateDataPreservesFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-update-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = {
      headers: { "user-agent": "ua-fp-1", "x-forwarded-for": "203.0.113.10" },
      socket:  { remoteAddress: "203.0.113.10" },
    };
    var s = await b.session.create({
      userId:            "u-1",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });

    // updateData replaces operator data wholesale BUT must preserve the
    // reserved __bj_fingerprint binding so verify() with the same req
    // still surfaces fingerprintDrift: false.
    await b.session.updateData(s.token, { roles: ["admin"] });
    var info = await b.session.verify(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("updateData preserves fingerprint binding",       info && info.fingerprintDrift === false);
    check("updateData payload reflects the write",           info.data.roles[0] === "admin");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testRotateRekeysFingerprint() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-rotate-fp-"));
  try {
    await setupTestDb(tmpDir);
    var req = _makeReq({ "user-agent": "ua-rot-1", "x-forwarded-for": "203.0.113.10" });
    var s = await b.session.create({
      userId:            "u-rot",
      data:              { roles: ["user"] },
      req:               req,
      fingerprintFields: ["clientIp", "userAgent"],
    });
    var pre = await b.session.verify(s.token, { req: req, fingerprintFields: ["clientIp", "userAgent"] });
    check("rotate-fp: pre-rotation no drift", pre && pre.fingerprintDrift === false);

    // Rotation (login transition / role escalation) moves the sid. __bj_fingerprint
    // is sid-keyed, so the new session must RE-KEY the binding to the new sid from
    // the live request — otherwise verify(newToken, sameReq) recomputes against the
    // new sid and falsely reports drift (logout under strict operators), or the
    // binding silently breaks.
    var rotated = await b.session.rotate(s.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: rotation returns a new token", rotated && typeof rotated.token === "string");

    var sameDevice = await b.session.verify(rotated.token, {
      req: req, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: same device → no drift after rotation (binding re-keyed)",
          sameDevice && sameDevice.fingerprintDrift === false);
    check("rotate-fp: operator data carried across rotation",
          sameDevice && sameDevice.data && sameDevice.data.roles && sameDevice.data.roles[0] === "user");

    // A different device must still drift — proves the binding is live, not dropped.
    var otherReq = _makeReq({ "user-agent": "ua-OTHER", "x-forwarded-for": "198.51.100.7" });
    var otherDevice = await b.session.verify(rotated.token, {
      req: otherReq, fingerprintFields: ["clientIp", "userAgent"],
    });
    check("rotate-fp: different device → drift after rotation (binding still enforced)",
          otherDevice && otherDevice.fingerprintDrift === true);
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testLogoutEmitsClearSiteData() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ses-logout-"));
  try {
    await setupTestDb(tmpDir);
    var s = await b.session.create({ userId: "u-logout" });
    check("session created", typeof s.token === "string");

    var headers = {};
    var res = {
      setHeader: function (k, v) { headers[k] = v; },
    };
    var destroyed = await b.session.logout(res, s.token);

    check("logout returns true (session destroyed)", destroyed === true);
    check("logout emits Clear-Site-Data header",
      typeof headers["Clear-Site-Data"] === "string" &&
      headers["Clear-Site-Data"].indexOf('"cookies"') !== -1 &&
      headers["Clear-Site-Data"].indexOf('"storage"') !== -1);
    check("logout expires the session cookie",
      typeof headers["Set-Cookie"] === "string" &&
      /(^|;)\s*Max-Age=0/.test(headers["Set-Cookie"]) &&
      headers["Set-Cookie"].indexOf("sid=;") === 0);
    check("logout cookie is Secure + HttpOnly",
      /HttpOnly/.test(headers["Set-Cookie"]) && /Secure/.test(headers["Set-Cookie"]));

    // The session is gone cluster-wide.
    var after = await b.session.verify(s.token);
    check("logout destroyed the session (verify returns null)", after === null);

    // Custom cookie name + an unknown Clear-Site-Data directive throws.
    var s2 = await b.session.create({ userId: "u-logout-2" });
    var h2 = {}; var res2 = { setHeader: function (k, v) { h2[k] = v; } };
    await b.session.logout(res2, s2.token, { cookieName: "__Host-sid" });
    check("logout honors custom cookieName", h2["Set-Cookie"].indexOf("__Host-sid=;") === 0);

    // An unknown directive throws BEFORE any side effect — the session is NOT
    // destroyed and no client-wipe headers are queued (validate-before-revoke).
    var s3 = await b.session.create({ userId: "u-logout-3" });
    var h3 = {}; var res3 = { setHeader: function (k, v) { h3[k] = v; } };
    var threw = null;
    try { await b.session.logout(res3, s3.token, { types: ["bogus"] }); }
    catch (e) { threw = e; }
    check("logout rejects an unknown Clear-Site-Data directive", threw !== null);
    check("logout did NOT queue headers on the bad-directive throw",
      h3["Clear-Site-Data"] === undefined && h3["Set-Cookie"] === undefined);
    check("logout did NOT destroy the session on the bad-directive throw",
      (await b.session.verify(s3.token)) !== null);

    var badRes = null;
    try { await b.session.logout({}, "x"); } catch (e) { badRes = e; }
    check("logout rejects a res without setHeader", badRes && badRes.code === "session/bad-res");
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testLogoutEmitsClearSiteData();
  await testSealedCookieDefault();
  await testSealedCookieRotateAndDestroy();
  await testClientIpPrefixV4();
  await testClientIpPrefixV6();
  await testClientIpPrefixV4MappedV6();
  await testPluggableStore();
  await testPluggableStoreValidation();
  await testUpdateDataReplaceAndMerge();
  await testUpdateDataPreservesFingerprint();
  await testRotateRekeysFingerprint();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message, e.stack); process.exit(1); }
  );
}
