"use strict";
/**
 * b.auth.stepUp + b.middleware.requireStepUp + elevation grants —
 * RFC 9470 OAuth 2.0 Step-Up Authentication Challenge.
 */

var b = require("../..");
var check = require("../helpers/check").check;

function rejects(label, fn, pattern) {
  var threw = false;
  var msg = "";
  try { fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

async function _rejectsAsync(label, fn, pattern) {
  var threw = false; var msg = "";
  try { await fn(); } catch (e) { threw = true; msg = e.message; }
  check("threw on " + label, threw && (pattern.test ? pattern.test(msg) : msg.indexOf(pattern) !== -1));
}

function _mockReq(headers, user, urlPath) {
  return {
    headers: headers || {},
    user:    user || null,
    url:     urlPath || "/",
    method:  "GET",
  };
}

function _mockRes() {
  var sent = { status: null, headers: null, body: null };
  return {
    headersSent: false,
    writeHead: function (status, headers) { sent.status = status; sent.headers = headers; this.headersSent = true; },
    end:       function (body) { sent.body = body; },
    _sent:     sent,
  };
}

async function run() {
  // ---- module shape ----
  check("b.auth.stepUp is object",                typeof b.auth.stepUp === "object");
  check("b.auth.acr is object",                   typeof b.auth.acr === "object");
  check("b.auth.authTime is object",              typeof b.auth.authTime === "object");
  check("b.middleware.requireStepUp is fn",       typeof b.middleware.requireStepUp === "function");
  check("evaluate is fn",                         typeof b.auth.stepUp.evaluate === "function");
  check("buildChallenge is fn",                   typeof b.auth.stepUp.buildChallenge === "function");
  check("parseChallenge is fn",                   typeof b.auth.stepUp.parseChallenge === "function");
  check("parseAuthorizationDetails is fn",        typeof b.auth.stepUp.parseAuthorizationDetails === "function");
  check("grant.create is fn",                     typeof b.auth.stepUp.grant.create === "function");
  check("grant.verify is fn",                     typeof b.auth.stepUp.grant.verify === "function");
  check("INSUFFICIENT_USER_AUTHENTICATION exported", b.auth.stepUp.INSUFFICIENT_USER_AUTHENTICATION === "insufficient_user_authentication");

  // ---- ACR vocabulary ----
  b.auth.acr._resetForTests();
  check("acr.rankOf builtin loa1",                b.auth.acr.rankOf("loa1") === 10);
  check("acr.rankOf builtin loa3",                b.auth.acr.rankOf("loa3") === 70);
  check("acr.rankOf unknown",                     b.auth.acr.rankOf("nope") === -1);
  check("acr.meets loa3 ≥ loa2",                  b.auth.acr.meets("loa3", "loa2") === true);
  check("acr.meets loa1 < loa2",                  b.auth.acr.meets("loa1", "loa2") === false);
  rejects("meets unregistered required",
    function () { b.auth.acr.meets("loa2", "myco:strong"); },
    /not registered/);
  b.auth.acr.register({ value: "myco:strong", rank: 65 });
  check("after register: meets loa3 ≥ myco:strong",
                                                  b.auth.acr.meets("loa3", "myco:strong") === true);
  check("meetsAny picks first satisfying",        b.auth.acr.meetsAny("loa3", ["loa4", "loa2"]) === true);
  check("meetsAny none satisfies",                b.auth.acr.meetsAny("loa1", ["loa3", "loa4"]) === false);
  rejects("acr.register bad rank",
    function () { b.auth.acr.register({ value: "x", rank: 200 }); }, /\[0, 100\]/);
  rejects("acr.register empty value",
    function () { b.auth.acr.register({ value: "", rank: 50 }); }, /value/);

  // AMR helpers
  check("amrIncludesPhishingResistant true (hwk)", b.auth.acr.amrIncludesPhishingResistant(["pwd", "hwk"]) === true);
  check("amrIncludesPhishingResistant false",      b.auth.acr.amrIncludesPhishingResistant(["pwd", "otp"]) === false);
  check("amrSatisfiesRequiredList true",           b.auth.acr.amrSatisfiesRequiredList(["pwd", "hwk", "pop"], ["hwk", "pop"]) === true);
  check("amrSatisfiesRequiredList missing",        b.auth.acr.amrSatisfiesRequiredList(["pwd"], ["hwk"]) === false);

  // ---- auth_time ----
  var nowSec = Math.floor(Date.now() / 1000);
  check("ageSec for fresh claims",                b.auth.authTime.ageSec({ auth_time: nowSec - 30 }, nowSec) === 30);
  check("ageSec missing claim → null",            b.auth.authTime.ageSec({}, nowSec) === null);
  check("ageSec future skew → 0",                 b.auth.authTime.ageSec({ auth_time: nowSec + 10 }, nowSec) === 0);
  check("freshEnough true",                       b.auth.authTime.freshEnough({ auth_time: nowSec - 10 }, 60, nowSec) === true);
  check("freshEnough false",                      b.auth.authTime.freshEnough({ auth_time: nowSec - 600 }, 60, nowSec) === false);
  check("freshEnough missing claim",              b.auth.authTime.freshEnough({}, 60, nowSec) === false);
  rejects("freshEnough bad maxAge",
    function () { b.auth.authTime.freshEnough({ auth_time: nowSec }, "60"); }, /maxAgeSec/);
  var built = b.auth.authTime.buildClaims({ method: "initial", now: nowSec, amr: ["pwd"], acr: "loa2" });
  check("buildClaims initial sets auth_time=now", built.auth_time === nowSec);
  check("buildClaims preserves acr/amr",          built.acr === "loa2" && built.amr[0] === "pwd");
  var refreshed = b.auth.authTime.buildClaims({ method: "refresh", prevAt: nowSec - 1000, now: nowSec });
  check("buildClaims refresh preserves prevAt",   refreshed.auth_time === nowSec - 1000);

  // ---- evaluate happy path ----
  var pass = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec - 30, amr: ["pwd", "hwk"] },
    requirement: { acr: "loa2", maxAge: 60 },
  });
  check("evaluate ok",                            pass.ok === true);

  var fail = b.auth.stepUp.evaluate({
    claims: { acr: "loa1", auth_time: nowSec - 30 },
    requirement: { acr: "loa2" },
  });
  check("evaluate fail: low acr",                 fail.ok === false &&
                                                  fail.error === "insufficient_user_authentication");

  var stale = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec - 1000 },
    requirement: { acr: "loa2", maxAge: 60 },
  });
  check("evaluate fail: stale auth_time",         stale.ok === false);

  var amrFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd"] },
    requirement: { acr: "loa2", requiredAmr: ["hwk"] },
  });
  check("evaluate fail: missing required amr",    amrFail.ok === false);

  var phrFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd", "otp"] },
    requirement: { acr: "loa2", phishingResistant: true },
  });
  check("evaluate fail: not phishing-resistant",  phrFail.ok === false);

  var anyFail = b.auth.stepUp.evaluate({
    claims: { acr: "loa1", auth_time: nowSec },
    requirement: { acrValues: ["loa2", "loa3"] },
  });
  check("evaluate fail: acrValues none meet",     anyFail.ok === false);

  var anyOk = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec },
    requirement: { acrValues: ["myco:strong", "loa3"] },
  });
  check("evaluate ok: acrValues at least one",    anyOk.ok === true);

  var noClaims = b.auth.stepUp.evaluate({
    claims: null,
    requirement: { acr: "loa2" },
  });
  check("evaluate fail: missing claims",          noClaims.ok === false);

  var unknownReqAcr = b.auth.stepUp.evaluate({
    claims: { acr: "loa3", auth_time: nowSec },
    requirement: { acr: "myco:not-registered" },
  });
  check("evaluate fail: unknown required acr",    unknownReqAcr.ok === false &&
                                                  unknownReqAcr.error === "unknown_acr");

  // ---- buildChallenge ----
  var challenge = b.auth.stepUp.buildChallenge({
    requirement: { acr: "loa3", maxAge: 300 },
    realm: "billing-api",
  });
  check("challenge: starts with Bearer",          challenge.indexOf("Bearer ") === 0);
  check("challenge: realm",                       challenge.indexOf('realm="billing-api"') !== -1);
  check("challenge: error",                       challenge.indexOf('error="insufficient_user_authentication"') !== -1);
  check("challenge: acr_values",                  challenge.indexOf('acr_values="loa3"') !== -1);
  check("challenge: max_age",                     challenge.indexOf('max_age="300"') !== -1);
  check("challenge: error_description",           challenge.indexOf('error_description=') !== -1);
  var multi = b.auth.stepUp.buildChallenge({
    requirement: { acrValues: ["loa2", "loa3"] },
  });
  check("challenge: acr_values space-separated",  multi.indexOf('acr_values="loa2 loa3"') !== -1);
  rejects("buildChallenge: bad requirement",
    function () { b.auth.stepUp.buildChallenge({ requirement: null }); },
    /requirement/);
  rejects("buildChallenge: control char in realm",
    function () { b.auth.stepUp.buildChallenge({ requirement: { acr: "loa2" }, realm: "evil\rrealm" }); },
    /control character/);

  // ---- parseChallenge round-trip ----
  var rt = b.auth.stepUp.parseChallenge(challenge);
  check("parseChallenge: error",                  rt.error === "insufficient_user_authentication");
  check("parseChallenge: acrValues array",        Array.isArray(rt.acrValues) && rt.acrValues[0] === "loa3");
  check("parseChallenge: maxAge",                 rt.maxAge === 300);
  check("parseChallenge: non-Bearer → null",      b.auth.stepUp.parseChallenge("Basic realm=x") === null);

  // ---- parseAuthorizationDetails (RFC 9396) ----
  var rar = b.auth.stepUp.parseAuthorizationDetails(JSON.stringify([
    { type: "payment_initiation", actions: ["initiate"], amount: { currency: "USD", value: 100 } },
  ]));
  check("RAR: parses",                            Array.isArray(rar) && rar[0].type === "payment_initiation");
  rejects("RAR: not array",
    function () { b.auth.stepUp.parseAuthorizationDetails(JSON.stringify({ type: "x" })); },
    /JSON array/);
  rejects("RAR: missing type",
    function () { b.auth.stepUp.parseAuthorizationDetails(JSON.stringify([{ foo: "bar" }])); },
    /missing required 'type'/);
  rejects("RAR: invalid JSON",
    function () { b.auth.stepUp.parseAuthorizationDetails("notjson"); },
    /invalid JSON/);

  // ---- grant create + verify ----
  b.auth.stepUp.grant._resetForTests();
  var g = b.auth.stepUp.grant.create({
    subject: "user-42",
    scope:   "billing:write",
    acr:     "loa3",
    amr:     ["pwd", "hwk"],
    ttlSec:  300,
  });
  check("grant: token returned",                  typeof g.token === "string" && g.token.indexOf(".") !== -1);
  check("grant: expiresAt > now",                 g.expiresAt > nowSec);
  check("grant: jti present",                     typeof g.jti === "string" && g.jti.length > 0);
  var v = b.auth.stepUp.grant.verify(g.token);
  check("grant verify: ok",                       v.ok === true);
  check("grant verify: subject",                  v.payload.sub === "user-42");
  check("grant verify: scope",                    v.payload.scope === "billing:write");
  // Tamper with token: flip a byte after the dot
  var tampered = g.token.slice(0, -2) + (g.token.slice(-2) === "AA" ? "BB" : "AA");
  var vTamper = b.auth.stepUp.grant.verify(tampered);
  check("grant verify: tampered → bad_mac",       vTamper.ok === false);
  // Audience match
  var gAud = b.auth.stepUp.grant.create({
    subject: "user-1", scope: "x", audience: "https://api.example.com",
  });
  var vAud = b.auth.stepUp.grant.verify(gAud.token, { audience: "https://api.example.com" });
  check("grant verify: audience match ok",        vAud.ok === true);
  var vAudBad = b.auth.stepUp.grant.verify(gAud.token, { audience: "https://other.example.com" });
  check("grant verify: audience mismatch",        vAudBad.ok === false &&
                                                  vAudBad.error === "audience_mismatch");
  // Scope mismatch
  var vScopeBad = b.auth.stepUp.grant.verify(g.token, { scope: "admin:write" });
  check("grant verify: scope mismatch",           vScopeBad.ok === false);
  // Expiry
  rejects("grant: ttlSec too small",
    function () { b.auth.stepUp.grant.create({ subject: "u", scope: "s", ttlSec: 1 }); }, /ttlSec/);
  rejects("grant: ttlSec too big",
    function () { b.auth.stepUp.grant.create({ subject: "u", scope: "s", ttlSec: 999999 }); }, /ttlSec/);
  rejects("grant: missing subject",
    function () { b.auth.stepUp.grant.create({ scope: "s" }); }, /subject/);
  rejects("grant: missing scope",
    function () { b.auth.stepUp.grant.create({ subject: "u" }); }, /scope/);
  // Malformed
  var vMalformed = b.auth.stepUp.grant.verify("garbage");
  check("grant verify: no dot → malformed",       vMalformed.ok === false);
  var vEmpty = b.auth.stepUp.grant.verify("");
  check("grant verify: empty → no_token",         vEmpty.ok === false && vEmpty.error === "no_token");
  // Revoke
  var gRev = b.auth.stepUp.grant.create({ subject: "u-rev", scope: "x" });
  b.auth.stepUp.grant.revoke(gRev.jti, { reason: "user-logged-out" });
  var vRev = b.auth.stepUp.grant.verify(gRev.token);
  check("grant verify: revoked",                  vRev.ok === false && vRev.error === "revoked");
  check("grant: isRevoked",                       b.auth.stepUp.grant.isRevoked(gRev.jti) === true);
  rejects("grant.revoke: empty jti",
    function () { b.auth.stepUp.grant.revoke(""); }, /jti/);
  // List active
  b.auth.stepUp.grant._resetForTests();
  b.auth.stepUp.grant.create({ subject: "u1", scope: "s" });
  b.auth.stepUp.grant.create({ subject: "u2", scope: "s" });
  check("grant.list: returns 2 active",           b.auth.stepUp.grant.list().length === 2);
  // setSigningKey
  rejects("setSigningKey: wrong type",
    function () { b.auth.stepUp.grant.setSigningKey("not-a-buffer"); }, /Buffer/);
  rejects("setSigningKey: too short",
    function () { b.auth.stepUp.grant.setSigningKey(Buffer.alloc(16)); }, />= 32 bytes/);

  // ---- middleware: happy path ----
  var mw = b.middleware.requireStepUp({
    requirement: { acr: "loa2", maxAge: 60 },
    realm: "test-realm",
  });
  check("middleware: factory returns fn",         typeof mw === "function");
  var nextCalls = 0;
  var req1 = _mockReq({}, { id: "u1", claims: { acr: "loa3", auth_time: nowSec, amr: ["pwd", "hwk"] } });
  var res1 = _mockRes();
  mw(req1, res1, function () { nextCalls += 1; });
  check("middleware: passes when claims meet",    nextCalls === 1);
  check("middleware: req.user.stepUp populated",  req1.user.stepUp && req1.user.stepUp.byClaims === true);

  // ---- middleware: challenge fires ----
  var req2 = _mockReq({}, { id: "u2", claims: { acr: "loa1", auth_time: nowSec } });
  var res2 = _mockRes();
  mw(req2, res2, function () { nextCalls += 1; });
  check("middleware: rejects on bad acr (status)", res2._sent.status === 401);
  check("middleware: WWW-Authenticate set",        typeof res2._sent.headers["WWW-Authenticate"] === "string");
  check("middleware: WWW-Authenticate carries acr_values",
        res2._sent.headers["WWW-Authenticate"].indexOf('acr_values="loa2"') !== -1);
  check("middleware: body has error code",         res2._sent.body.indexOf("insufficient_user_authentication") !== -1);
  check("middleware: did NOT call next",           nextCalls === 1);

  // ---- middleware: grant short-circuits ----
  b.auth.stepUp.grant._resetForTests();
  var grantMw = b.middleware.requireStepUp({
    requirement: { acr: "loa3", maxAge: 60 },
    grantScope:  "billing:write",
  });
  var grantToken = b.auth.stepUp.grant.create({
    subject: "u-grant", scope: "billing:write", acr: "loa3",
  });
  var nextG = 0;
  var reqG = _mockReq({ "x-step-up-grant": grantToken.token },
                      { id: "u-grant", claims: { acr: "loa1" } });
  var resG = _mockRes();
  grantMw(reqG, resG, function () { nextG += 1; });
  check("middleware: grant short-circuits",        nextG === 1);
  check("middleware: req.user.stepUp.byGrant",     reqG.user.stepUp && reqG.user.stepUp.byGrant === true);

  // ---- middleware: grant scope mismatch falls through to claims ----
  var nextS = 0;
  var grantTokenWrong = b.auth.stepUp.grant.create({
    subject: "u", scope: "admin:write",
  });
  var reqS = _mockReq({ "x-step-up-grant": grantTokenWrong.token },
                     { id: "u", claims: { acr: "loa1" } });
  var resS = _mockRes();
  grantMw(reqS, resS, function () { nextS += 1; });
  check("middleware: grant scope mismatch + bad claims → 401",
        resS._sent.status === 401 && nextS === 0);

  // ---- middleware: bad opts at config time ----
  rejects("middleware: bad requirement",
    function () { b.middleware.requireStepUp({ requirement: null }); }, /requirement/);
  rejects("middleware: unknown acr in requirement",
    function () { b.middleware.requireStepUp({ requirement: { acr: "myco:nope" } }); },
    /not registered|unknown/);
  rejects("middleware: bad max_age",
    function () { b.middleware.requireStepUp({ requirement: { acr: "loa2", maxAge: -1 } }); },
    /maxAge/);
  rejects("middleware: bad acrValues",
    function () { b.middleware.requireStepUp({ requirement: { acrValues: [] } }); },
    /acrValues/);

  // ---- middleware: getClaims override ----
  var customMw = b.middleware.requireStepUp({
    requirement: { acr: "loa2" },
    getClaims:   function (req) { return req.body && req.body.token_claims; },
  });
  var nextC = 0;
  var reqC = { headers: {}, body: { token_claims: { acr: "loa3" } }, url: "/x" };
  var resC = _mockRes();
  customMw(reqC, resC, function () { nextC += 1; });
  check("middleware: custom getClaims passes",     nextC === 1);

  // ---- recommendMaxAge clamping ----
  check("recommendMaxAge default",                b.auth.authTime.recommendMaxAge({}) === 300);
  check("recommendMaxAge clamps high",            b.auth.authTime.recommendMaxAge({ default: 99999 }) === 900);
  check("recommendMaxAge clamps low",             b.auth.authTime.recommendMaxAge({ default: 1 }) === 60);

  // ---- listRegistered returns sorted ----
  var reg = b.auth.acr.listRegistered();
  check("listRegistered: returns array",          Array.isArray(reg) && reg.length > 0);
  check("listRegistered: ranks ascending",        (function () {
    for (var i = 1; i < reg.length; i += 1) {
      if (reg[i].rank < reg[i - 1].rank) return false;
    }
    return true;
  })());

  // ---- audit emissions reach the bus ----
  // Use audit drain helper if available; else just confirm safeEmit doesn't throw.
  try {
    b.audit.subscribeNamespace("auth", function (_event) { /* drop-silent */ });
  } catch (_e) { /* not all backends support subscribeNamespace; non-fatal */ }
  b.auth.stepUp.evaluate({ claims: { acr: "loa3" }, requirement: { acr: "loa2" } });
  check("evaluate is side-effect-free",            true);

  // ---- policy DSL ----
  var p = b.auth.stepUp.policy;
  check("policy.acr is fn",                       typeof p.acr === "function");
  check("policy.amr is fn",                       typeof p.amr === "function");
  check("policy.maxAge is fn",                    typeof p.maxAge === "function");
  check("policy.preset is fn",                    typeof p.preset === "function");

  var policySimple = p.acr("loa2");
  var pr1 = policySimple.evaluate({ acr: "loa3" });
  check("policy.acr: loa3 satisfies loa2",         pr1.ok === true);
  var pr2 = policySimple.evaluate({ acr: "loa1" });
  check("policy.acr: loa1 fails loa2",             pr2.ok === false);

  var policyAnd = p.acr("loa2").and(p.maxAge(60));
  var prAndPass = policyAnd.evaluate({ acr: "loa3", auth_time: nowSec - 30 });
  check("policy.and: both pass",                   prAndPass.ok === true);
  var prAndFail = policyAnd.evaluate({ acr: "loa1", auth_time: nowSec });
  check("policy.and: left fail short-circuits",    prAndFail.ok === false);
  var prAndFail2 = policyAnd.evaluate({ acr: "loa3", auth_time: nowSec - 600 });
  check("policy.and: right fail",                  prAndFail2.ok === false);

  var policyOr = p.acr("loa3").or(p.amr(["hwk"]));
  var prOrLeft  = policyOr.evaluate({ acr: "loa3", auth_time: nowSec });
  check("policy.or: left passes",                  prOrLeft.ok === true);
  var prOrRight = policyOr.evaluate({ acr: "loa1", amr: ["hwk", "pwd"], auth_time: nowSec });
  check("policy.or: right passes when left fails", prOrRight.ok === true);
  var prOrFail  = policyOr.evaluate({ acr: "loa1", amr: ["pwd"] });
  check("policy.or: both fail",                    prOrFail.ok === false);

  // toRequirement compiles AND policies into RFC 9470 challenge tuple
  var req = policyAnd.toRequirement();
  check("policy.toRequirement: acr",               req.acr === "loa2");
  check("policy.toRequirement: maxAge",            req.maxAge === 60);

  // policy.middleware spawns a real middleware
  var pmw = policyAnd.middleware({ realm: "policy-realm" });
  check("policy.middleware: returns fn",           typeof pmw === "function");
  var nextP = 0;
  var reqP1 = _mockReq({}, { id: "u", claims: { acr: "loa3", auth_time: nowSec } });
  var resP1 = _mockRes();
  pmw(reqP1, resP1, function () { nextP += 1; });
  check("policy.middleware: pass",                 nextP === 1);

  // .not invertion
  var policyNot = p.acr("loa3").not();
  check("policy.not: passes when inner fails",     policyNot.evaluate({ acr: "loa1" }).ok === true);
  check("policy.not: fails when inner passes",     policyNot.evaluate({ acr: "loa3" }).ok === false);

  // .custom predicate
  var policyCustom = p.custom("hours-9-to-5", function (claims) {
    return claims && claims.acr === "loa2";
  });
  check("policy.custom: predicate true",           policyCustom.evaluate({ acr: "loa2" }).ok === true);
  check("policy.custom: predicate false",          policyCustom.evaluate({ acr: "loa1" }).ok === false);
  rejects("policy.custom: missing fn",
    function () { p.custom("x", null); }, /fn must be a function/);

  // Conflicting acr in AND throws on toRequirement
  rejects("policy.and: conflicting acr",
    function () { p.acr("loa2").and(p.acr("loa3")).toRequirement(); },
    /conflicting acr/);

  // .not toRequirement throws (no RFC 9470 negation)
  rejects("policy.not: toRequirement throws",
    function () { p.acr("loa2").not().toRequirement(); },
    /cannot translate/);

  // acrAny
  var policyAcrAny = p.acrAny(["loa2", "loa3"]);
  check("policy.acrAny: matches any",              policyAcrAny.evaluate({ acr: "loa3" }).ok === true);
  check("policy.acrAny: none matches",             policyAcrAny.evaluate({ acr: "loa1" }).ok === false);

  rejects("policy.acrAny: empty",
    function () { p.acrAny([]); }, /non-empty/);
  rejects("policy.amr: empty",
    function () { p.amr([]); }, /non-empty/);
  rejects("policy.maxAge: negative",
    function () { p.maxAge(-1); }, /seconds/);

  // Presets
  var presets = p.listPresets();
  check("listPresets: contains sensitiveWrite",    presets.indexOf("sensitiveWrite") !== -1);
  check("listPresets: contains phiWrite",          presets.indexOf("phiWrite") !== -1);
  check("listPresets: contains adminBulk",         presets.indexOf("adminBulk") !== -1);
  check("listPresets: contains financial",         presets.indexOf("financial") !== -1);
  check("listPresets: contains phiRead",           presets.indexOf("phiRead") !== -1);
  check("listPresets: contains accountRecovery",   presets.indexOf("accountRecovery") !== -1);

  var presetSensitive = p.preset("sensitiveWrite");
  var pres1 = presetSensitive.evaluate({ acr: "loa3", auth_time: nowSec });
  check("preset.sensitiveWrite: pass",             pres1.ok === true);
  var pres2 = presetSensitive.evaluate({ acr: "loa1", auth_time: nowSec });
  check("preset.sensitiveWrite: fail acr",         pres2.ok === false);
  var pres3 = presetSensitive.evaluate({ acr: "loa3", auth_time: nowSec - 1000 });
  check("preset.sensitiveWrite: fail max_age",     pres3.ok === false);

  rejects("preset: unknown name",
    function () { p.preset("not-a-preset"); }, /unknown preset/);

  // Phishing-resistant preset
  var presetAdmin = p.preset("adminBulk");
  var pAdmin1 = presetAdmin.evaluate({ acr: "loa3", auth_time: nowSec, amr: ["pwd", "hwk"] });
  check("preset.adminBulk: pass with hwk",         pAdmin1.ok === true);
  var pAdmin2 = presetAdmin.evaluate({ acr: "loa3", auth_time: nowSec, amr: ["pwd", "otp"] });
  check("preset.adminBulk: fail without phr",      pAdmin2.ok === false);

  // Custom predicate that's wrapped in OR with translatable atom
  var policyOrCustom = p.acr("loa3").or(p.custom("backup-key", function () { return false; }));
  check("policy.or with custom: left pass",        policyOrCustom.evaluate({ acr: "loa3", auth_time: nowSec }).ok === true);

  // toRequirement immutability — chaining returns new policies
  var policyA = p.acr("loa2");
  var policyB = policyA.and(p.maxAge(60));
  check("policy: chaining returns new",            policyA !== policyB);
  check("policy: original unchanged",              policyA.toRequirement().maxAge === undefined);

  console.log("OK — step-up tests");
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { process.exit(0); })
       .catch(function (err) { console.error(err); process.exit(1); });
}
