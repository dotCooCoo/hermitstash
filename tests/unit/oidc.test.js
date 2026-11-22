// Unit coverage for OpenID Connect sign-in: settings validation, claim
// handling, client rebuild on reload, and the account-resolution matrix in
// authService.resolveOidcUser (provisioning, linking, groups, admin sync, the
// last-admin guard and the duplicate-row cleanup).
var { describe, it, before } = require("node:test");
var assert = require("node:assert");
var path = require("path");
var b = require("../../lib/vendor/blamejs");

var testId = b.crypto.generateToken(4);
var scratch = require("../helpers/isolate-db");
process.env.HERMITSTASH_DB_PATH = path.join(scratch.dir, "test-oidc-" + testId + ".db");

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var vault = require("../../lib/vault");
var policy = require("../../lib/oidc-policy");
var config = require("../../lib/config");
var db, oidc, authService, usersRepo;

var ISS = "https://idp.example";
var n = 0;
function uniq(p) { n += 1; return p + "-" + testId + "-" + n; }

before(async function () {
  await vault.init();
  db = require("../../lib/db");
  oidc = require("../../lib/oidc");
  authService = require("../../app/domain/auth/auth.service");
  usersRepo = require("../../app/data/repositories/users.repo");
});

function insert(fields) {
  return usersRepo.create(Object.assign({ role: "user", status: "active", createdAt: new Date().toISOString() }, fields));
}

function identity(over) {
  return Object.assign({ issuer: ISS, sub: uniq("sub"), email: null, displayName: "X", avatar: "", groups: null }, over || {});
}

// A NULL column reads back as an absent field.
function nil(v, msg) {
  assert.ok(v === null || v === undefined, msg || ("expected no value, got " + v));
}

function reasonOf(fn) {
  try { fn(); } catch (e) { return e.oidcReason || ("no-reason:" + e.message); }
  return null;
}

describe("oidc-policy: OIDC_ALLOW_INTERNAL", function () {
  it("accepts IPv4 and IPv6 ranges", function () {
    var r = policy.parseInternalCidrs(["10.0.0.0/8", "fd00::/8", " 192.168.1.5/32 "]);
    assert.strictEqual(r.error, null);
    assert.deepStrictEqual(r.cidrs, ["10.0.0.0/8", "fd00::/8", "192.168.1.5/32"]);
  });
  it("refuses a bare address, a /0, a bad prefix and a hostname", function () {
    assert.match(policy.parseInternalCidrs(["10.0.0.5"]).error, /prefix length/);
    assert.match(policy.parseInternalCidrs(["0.0.0.0/0"]).error, /between 1 and 32/);
    assert.match(policy.parseInternalCidrs(["10.0.0.0/33"]).error, /between 1 and 32/);
    assert.match(policy.parseInternalCidrs(["idp.lan/24"]).error, /not an IP address range/);
  });
  it("accepts shared, loopback and link-local ranges", function () {
    var r = policy.parseInternalCidrs(["100.100.100.100/32", "127.0.0.1/32", "fe80::/10", "::1/128", "fd7a:115c:a1e0::/48"]);
    assert.strictEqual(r.error, null);
  });
  it("refuses a range that reaches outside the internal blocks", function () {
    ["8.8.8.8/32", "0.0.0.0/1", "10.0.0.0/7", "172.32.0.0/16", "2001:db8::/32", "::ffff:10.0.0.1/128"].forEach(function (c) {
      assert.match(policy.parseInternalCidrs([c]).error, /not inside a private/, c + " is refused");
    });
  });
});

describe("oidc-policy: issuer scheme", function () {
  it("allows https anywhere", function () {
    assert.strictEqual(policy.issuerPolicy("https://idp.example/realms/a", []).error, null);
  });
  it("allows http only for an IP inside an allowed range", function () {
    assert.strictEqual(policy.issuerPolicy("http://10.0.0.5:8080/realms/a", ["10.0.0.0/24"]).error, null);
    assert.match(policy.issuerPolicy("http://10.0.1.5:8080", ["10.0.0.0/24"]).error, /must use https/);
    assert.match(policy.issuerPolicy("http://10.0.0.5:8080", []).error, /must use https/);
    assert.match(policy.issuerPolicy("http://keycloak.lan", ["10.0.0.0/8"]).error, /must use https/, "a hostname is not an IP inside a range");
  });
});

describe("oidc-policy: validateOidcConfig", function () {
  var base = { enabled: true, issuer: "https://idp.example", clientID: "c", allowlist: [], requiredGroup: "", autoProvision: false, scopes: ["openid"], groupsClaim: "groups", allowInternal: [] };
  function v(over) { return policy.validateOidcConfig(Object.assign({}, base, over)); }
  it("accepts a complete configuration", function () { assert.strictEqual(v({}), null); });
  it("requires an issuer and a client ID when enabled", function () {
    assert.match(v({ issuer: "" }), /OIDC_ISSUER is required/);
    assert.match(v({ clientID: "" }), /OIDC_CLIENT_ID is required/);
  });
  it("refuses auto-provision with no allowlist and no required group", function () {
    assert.match(v({ autoProvision: true }), /OIDC_AUTO_PROVISION/);
    assert.strictEqual(v({ autoProvision: true, allowlist: ["a@b.test"] }), null);
    assert.strictEqual(v({ autoProvision: true, requiredGroup: "staff" }), null);
  });
  it("checks ranges, groups claim and scopes even while disabled", function () {
    assert.match(v({ enabled: false, allowInternal: ["nope"] }), /OIDC_ALLOW_INTERNAL/);
    assert.match(v({ enabled: false, groupsClaim: "a.__proto__.b" }), /may not contain/);
    assert.match(v({ enabled: false, scopes: ["bad\"scope"] }), /OIDC_SCOPES/);
  });
  it("refuses OIDC_TRUST_UNVERIFIED_EMAIL without a required group, enabled or disabled", function () {
    assert.match(v({ trustUnverifiedEmail: true }), /OIDC_TRUST_UNVERIFIED_EMAIL needs OIDC_REQUIRED_GROUP/);
    assert.match(v({ enabled: false, trustUnverifiedEmail: true }), /OIDC_TRUST_UNVERIFIED_EMAIL needs OIDC_REQUIRED_GROUP/);
    assert.strictEqual(v({ trustUnverifiedEmail: true, requiredGroup: "staff" }), null);
  });
});

describe("oidc-policy: httpsIssuerOrigin", function () {
  it("returns the origin of an https issuer with a dotted host name", function () {
    assert.strictEqual(policy.httpsIssuerOrigin("https://idp.example.com/realms/a"), "https://idp.example.com");
    assert.strictEqual(policy.httpsIssuerOrigin("https://idp.example.com:8443/x"), "https://idp.example.com:8443");
  });
  it("returns null for http, IP literals, single labels, wildcards and a trailing dot", function () {
    ["http://idp.example.com", "https://[::1]/x", "https://[fd00::1]", "https://10.0.0.1/x", "https://localhost",
      "https://*.example.com", "https://idp.example.com.", "", "not a url"].forEach(function (iss) {
      assert.strictEqual(policy.httpsIssuerOrigin(iss), null, iss);
    });
  });
});

describe("oidc: claim helpers", function () {
  it("accepts only the boolean email_verified true", function () {
    assert.strictEqual(oidc.verifiedEmail({ email: "A@B.test", email_verified: true }), "a@b.test");
    assert.strictEqual(oidc.verifiedEmail({ email: "a@b.test", email_verified: "true" }), null);
    assert.strictEqual(oidc.verifiedEmail({ email: "a@b.test" }), null);
    assert.strictEqual(oidc.verifiedEmail({ email: "x@a.test@b.test", email_verified: true }), null);
  });
  it("reads groups from arrays, strings and dotted paths", function () {
    assert.deepStrictEqual(oidc.extractGroups({ groups: ["a", "b"] }, "groups"), ["a", "b"]);
    assert.deepStrictEqual(oidc.extractGroups({ groups: "a" }, "groups"), ["a"]);
    assert.deepStrictEqual(oidc.extractGroups({ realm_access: { roles: ["r"] } }, "realm_access.roles"), ["r"]);
    assert.deepStrictEqual(oidc.extractGroups({ groups: ["a", 5, null, "", "b"] }, "groups"), ["a", "b"]);
    assert.strictEqual(oidc.extractGroups({ groups: { a: 1 } }, "groups"), null, "a malformed claim is unknown, not empty");
    assert.strictEqual(oidc.extractGroups({}, "groups"), null, "an absent claim is unknown, not empty");
    assert.strictEqual(oidc.extractGroups({ groups: ["a"] }, "__proto__"), null);
  });
  it("treats an oversized group list as unknown and skips oversized entries", function () {
    var many = [];
    for (var i = 0; i < 1500; i++) many.push("g" + i);
    assert.strictEqual(oidc.extractGroups({ groups: many }, "groups"), null);
    var out = oidc.extractGroups({ groups: ["a", "x".repeat(300)] }, "groups");
    assert.deepStrictEqual(out, ["a"]);
  });
  it("reports the state of a groups claim", function () {
    assert.deepStrictEqual(oidc.readGroups({ groups: ["a"] }, "groups"), { list: ["a"], state: "ok" });
    assert.deepStrictEqual(oidc.readGroups({ groups: [] }, "groups"), { list: [], state: "ok" });
    assert.strictEqual(oidc.readGroups({}, "groups").state, "absent");
    assert.strictEqual(oidc.readGroups({ groups: null }, "groups").state, "absent");
    assert.strictEqual(oidc.readGroups({ realm: 5 }, "realm.roles").state, "absent");
    assert.strictEqual(oidc.readGroups({ groups: { a: 1 } }, "groups").state, "malformed");
    assert.strictEqual(oidc.readGroups({ groups: 7 }, "groups").state, "malformed");
    assert.strictEqual(oidc.readGroups({ groups: "x".repeat(257) }, "groups").state, "malformed");
    var exact = [];
    for (var i = 0; i < 1000; i++) exact.push("g" + i);
    assert.strictEqual(oidc.readGroups({ groups: exact }, "groups").state, "ok", "1000 groups are read");
    var over = exact.concat(["g1000"]);
    var r = oidc.readGroups({ groups: over }, "groups");
    assert.strictEqual(r.state, "truncated");
    assert.strictEqual(r.list, null);
  });
  it("keeps only bounded https avatars and clean display names", function () {
    assert.strictEqual(oidc.cleanAvatar("https://img.example/a.png"), "https://img.example/a.png");
    assert.strictEqual(oidc.cleanAvatar("http://img.example/a.png"), "");
    assert.strictEqual(oidc.cleanAvatar("javascript:alert(1)"), "");
    assert.strictEqual(oidc.cleanAvatar("https://img.example/" + "a".repeat(3000)), "");
    assert.strictEqual(oidc.cleanDisplayName("Al\u0000ice\n", null), "Alice");
    assert.strictEqual(oidc.cleanDisplayName("", "bob@x.test"), "bob");
    assert.strictEqual(oidc.cleanDisplayName("y".repeat(500), null).length, 100);
  });
  it("stores an avatar only from the required origin", function () {
    var o = { requireOrigin: true, origin: "https://idp.example.com" };
    assert.strictEqual(oidc.cleanAvatar("https://idp.example.com/pic/a.png", o), "https://idp.example.com/pic/a.png");
    assert.strictEqual(oidc.cleanAvatar("https://cdn.example.com/a.png", o), "", "another host");
    assert.strictEqual(oidc.cleanAvatar("https://idp.example.com:8443/a.png", o), "", "another port");
    assert.strictEqual(oidc.cleanAvatar("http://idp.example.com/a.png", o), "", "http");
    assert.strictEqual(oidc.cleanAvatar("https://user:pw@idp.example.com/a.png", o), "", "credentials in the URL");
    assert.strictEqual(oidc.cleanAvatar("https://idp.example.com/a.png", { requireOrigin: true, origin: null }), "", "no origin stores nothing");
  });
  it("reads an email only when no email_verified claim is present", function () {
    assert.strictEqual(oidc.assertedEmail({ email: "A@Corp.test" }), "a@corp.test");
    assert.strictEqual(oidc.assertedEmail({ email: "a@corp.test", email_verified: false }), null);
    assert.strictEqual(oidc.assertedEmail({ email: "a@corp.test", email_verified: "true" }), null);
    assert.strictEqual(oidc.assertedEmail({ email: "a@corp.test", email_verified: null }), null);
    assert.strictEqual(oidc.assertedEmail({ upn: "a@corp.test" }), null);
    assert.strictEqual(oidc.assertedEmail({ preferred_username: "a@corp.test" }), null);
    assert.strictEqual(oidc.assertedEmail({ email: "x@a.test@b.test" }), null);
  });
  it("marks a guest account by its acct claim", function () {
    assert.strictEqual(oidc.externalAccount({ acct: 1 }), true);
    assert.strictEqual(oidc.externalAccount({ acct: "0" }), true);
    assert.strictEqual(oidc.externalAccount({ acct: 0 }), false);
    assert.strictEqual(oidc.externalAccount({}), false);
  });
  it("audits only the fixed reason", function () {
    var e = new Error("token endpoint returned 400: {\"error_description\":\"secret\"}");
    assert.strictEqual(oidc.auditReason(e), "callback failed");
    e.oidcReason = "auth-oauth/token-error-400";
    assert.strictEqual(oidc.auditReason(e), "auth-oauth/token-error-400");
  });
});

describe("oidc: client rebuild on reload", function () {
  it("builds a new client with a new generation when an OIDC setting changes", function () {
    config.updateSettings({ oidcEnabled: "true", oidcIssuer: "https://idp-one.example", oidcClientID: "same-client" });
    var first = oidc.getClient("oidc");
    assert.strictEqual(oidc.getClient("oidc"), first, "the client is cached between logins");
    config.updateSettings({ oidcIssuer: "https://idp-two.example" });
    var second = oidc.getClient("oidc");
    assert.notStrictEqual(second, first, "an issuer change with the same client ID builds a new client");
    assert.ok(second.generation > first.generation, "the generation moves on");
    config.updateSettings({ siteName: "Unrelated " + testId });
    assert.strictEqual(oidc.getClient("oidc"), second, "an unrelated setting keeps the client");
    config.updateSettings({ oidcEnabled: "false" });
    assert.throws(function () { oidc.getClient("oidc"); }, function (e) { return e.oidcReason === "not-configured"; });
  });
});

describe("resolveOidcUser: provisioning", function () {
  var pol = { autoProvision: true, allowlist: ["ok@corp.test"], requiredGroup: "", adminGroup: "", allowedDomains: [] };

  it("creates an allowlisted user without the first-user-admin rule", function () {
    var id = identity({ email: "ok@corp.test" });
    var r = authService.resolveOidcUser(id, pol);
    assert.strictEqual(r.isNew, true);
    assert.strictEqual(r.user.authType, "oidc");
    assert.strictEqual(r.user.role, "user");
    assert.strictEqual(r.user.oidcSubject, ISS + "|" + id.sub);
  });
  it("refuses when auto-provision is off, the user is not allowlisted, or the email is unverified", function () {
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: "ok2@corp.test" }), Object.assign({}, pol, { autoProvision: false, allowlist: ["ok2@corp.test"] })); }), "provision-denied");
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: "nope@corp.test" }), pol); }), "provision-denied");
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: null }), pol); }), "no-verified-email");
  });
  it("provisions through the required group and applies allowedDomains", function () {
    var gp = Object.assign({}, pol, { allowlist: [], requiredGroup: "staff" });
    assert.strictEqual(authService.resolveOidcUser(identity({ email: uniq("g") + "@corp.test", groups: ["staff"] }), gp).isNew, true);
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: uniq("g") + "@corp.test", groups: ["other"] }), gp); }), "group-denied");
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: uniq("g") + "@else.test", groups: ["staff"] }), Object.assign({}, gp, { allowedDomains: ["corp.test"] })); }), "domain-not-allowed");
  });
  it("creates the user as admin when it is in the admin group", function () {
    var ap = Object.assign({}, pol, { allowlist: [], requiredGroup: "staff", adminGroup: "admins" });
    var r = authService.resolveOidcUser(identity({ email: uniq("a") + "@corp.test", groups: ["staff", "admins"] }), ap);
    assert.strictEqual(r.user.role, "admin");
  });
  it("removes its own row when an earlier row for the subject already exists", function () {
    var sub = uniq("dup");
    var earlier = insert({ email: uniq("e") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, createdAt: "2000-01-01T00:00:00.000Z" });
    // Simulate the race: the lookup ran before the other callback's insert.
    var real = usersRepo.findByOidcSubject;
    usersRepo.findByOidcSubject = function () { return null; };
    try {
      var dupEmail = uniq("dup") + "@corp.test";
      var r = authService.resolveOidcUser(identity({ sub: sub, email: dupEmail }), Object.assign({}, pol, { allowlist: [dupEmail] }));
      assert.strictEqual(r.user._id, earlier._id, "the earlier row wins");
      assert.strictEqual(r.isNew, false);
    } finally {
      usersRepo.findByOidcSubject = real;
    }
    assert.strictEqual(usersRepo.findAllByOidcSubject(ISS + "|" + sub).length, 1, "the duplicate was removed");
  });
});

describe("resolveOidcUser: returning and linked accounts", function () {
  var pol = { autoProvision: false, allowlist: [], requiredGroup: "", adminGroup: "", allowedDomains: [] };

  it("links an account by verified email and keeps its authType", function () {
    var email = uniq("link") + "@corp.test";
    var u = insert({ email: email, authType: "tailscale", displayName: "T", emailConfirmedVia: "verification", emailConfirmedAt: new Date().toISOString() });
    var id = identity({ email: email });
    var r = authService.resolveOidcUser(id, pol);
    assert.strictEqual(r.linked, true);
    assert.strictEqual(r.user._id, u._id);
    assert.strictEqual(r.user.authType, "tailscale");
    assert.strictEqual(r.user.oidcSubject, ISS + "|" + id.sub);
    assert.strictEqual(r.user.oidcLabel, email);
    var again = authService.resolveOidcUser(identity({ sub: id.sub, email: email }), pol);
    assert.strictEqual(again.linked, false, "the second login finds it by subject");
  });
  it("does not link a tailscale account with no recorded confirmation", function () {
    var email = uniq("tsleg") + "@corp.test";
    var u = insert({ email: email, authType: "tailscale" });
    assert.strictEqual(u.emailConfirmedVia, "legacy");
    var err = null;
    try { authService.resolveOidcUser(identity({ email: email }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "email-unconfirmed");
    assert.strictEqual(err.accountId, u._id);
    assert.strictEqual(err.revokeUserId, undefined);
    nil(usersRepo.findById(u._id).oidcSubject);
  });
  it("refuses a different subject, a pending account and a suspended account", function () {
    var e1 = uniq("bound") + "@corp.test";
    insert({ email: e1, authType: "oidc", oidcSubject: ISS + "|someone" });
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: e1 }), pol); }), "subject-mismatch");
    var e2 = uniq("pending") + "@corp.test";
    insert({ email: e2, authType: "local", status: "pending" });
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: e2 }), pol); }), "account-pending");
    var sub = uniq("susp");
    insert({ email: uniq("s") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, status: "suspended" });
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ sub: sub }), pol); }), "account-suspended");
  });
  it("treats the same sub at another issuer as a different identity", function () {
    var sub = uniq("shared");
    var e = uniq("iss") + "@corp.test";
    insert({ email: e, authType: "oidc", oidcSubject: ISS + "|" + sub });
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ issuer: "https://other.example", sub: sub, email: e }), pol); }), "subject-mismatch");
  });
  it("re-checks allowedDomains and the required group, asking for session revocation", function () {
    var sub = uniq("ret");
    var u = insert({ email: uniq("r") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: sub, groups: ["x"] }), Object.assign({}, pol, { requiredGroup: "staff" })); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "group-denied");
    assert.strictEqual(err.revokeUserId, u._id);
    err = null;
    try { authService.resolveOidcUser(identity({ sub: sub }), Object.assign({}, pol, { allowedDomains: ["other.test"] })); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "domain-not-allowed");
    assert.strictEqual(err.revokeUserId, u._id);
  });
  it("refuses a bound account whose verified provider email moved to a domain outside allowedDomains", function () {
    var sub = uniq("moved");
    var u = insert({ email: uniq("m") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var dp = Object.assign({}, pol, { allowedDomains: ["corp.test"] });
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: sub, email: uniq("m") + "@else.test" }), dp); } catch (e) { err = e; }
    assert.ok(err, "the login is refused");
    assert.strictEqual(err.oidcReason, "domain-not-allowed");
    assert.strictEqual(err.revokeUserId, u._id);
    assert.strictEqual(authService.resolveOidcUser(identity({ sub: sub, email: uniq("m") + "@corp.test" }), dp).user._id, u._id);
  });
  it("refreshes the display name and avatar of an OIDC account only", function () {
    var sub = uniq("refresh");
    insert({ email: uniq("f") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, displayName: "Old" });
    var r = authService.resolveOidcUser(identity({ sub: sub, displayName: "New", avatar: "https://img.example/a.png" }), pol);
    assert.strictEqual(r.user.displayName, "New");
    assert.strictEqual(r.user.avatar, "https://img.example/a.png");
  });
});

describe("resolveOidcUser: admin group", function () {
  var pol = { autoProvision: false, allowlist: [], requiredGroup: "", adminGroup: "admins", allowedDomains: [] };

  it("promotes and demotes, and asks for revocation on demotion", function () {
    insert({ email: uniq("spare") + "@corp.test", authType: "local", role: "admin" });
    var sub = uniq("adm");
    insert({ email: uniq("adm") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var up = authService.resolveOidcUser(identity({ sub: sub, groups: ["admins"] }), pol);
    assert.deepStrictEqual(up.roleChange, { from: "user", to: "admin" });
    assert.strictEqual(up.user.role, "admin");
    assert.strictEqual(up.revokeSessions, false);
    var down = authService.resolveOidcUser(identity({ sub: sub, groups: [] }), pol);
    assert.deepStrictEqual(down.roleChange, { from: "admin", to: "user" });
    assert.strictEqual(down.revokeSessions, true);
  });
  it("refuses an admin whose groups are unknown and leaves the role alone", function () {
    var sub = uniq("unk");
    var u = insert({ email: uniq("u") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, role: "admin" });
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: sub, groups: null }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "groups-unavailable");
    assert.strictEqual(err.revokeUserId, undefined, "sessions are not ended");
    assert.strictEqual(err.accountId, u._id);
    assert.strictEqual(usersRepo.findById(u._id).role, "admin");
  });
  it("signs in a non-admin whose groups are unknown when no group is required", function () {
    var sub = uniq("unkuser");
    insert({ email: uniq("u") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, role: "user" });
    var r = authService.resolveOidcUser(identity({ sub: sub, groups: null }), pol);
    assert.strictEqual(r.roleChange, null);
    assert.strictEqual(r.user.role, "user");
  });
  it("never demotes the last active admin", function () {
    var admins = usersRepo.findAll({ role: "admin" });
    admins.forEach(function (a) { usersRepo.update(a._id, { $set: { role: "user" } }); });
    var sub = uniq("last");
    insert({ email: uniq("l") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, role: "admin" });
    var r = authService.resolveOidcUser(identity({ sub: sub, groups: [] }), pol);
    assert.strictEqual(r.roleSyncRefused, true);
    assert.strictEqual(r.user.role, "admin");
    admins.forEach(function (a) { usersRepo.update(a._id, { $set: { role: "admin" } }); });
  });
  it("does not touch roles when the admin group is not set", function () {
    var sub = uniq("noadm");
    insert({ email: uniq("n") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, role: "admin" });
    var r = authService.resolveOidcUser(identity({ sub: sub, groups: [] }), Object.assign({}, pol, { adminGroup: "" }));
    assert.strictEqual(r.user.role, "admin");
    assert.strictEqual(r.roleChange, null);
  });
});

describe("oidcSubject storage", function () {
  it("stores the subject sealed and looks it up case-sensitively through the blind index", function () {
    var sub = "CaseSensitive-" + testId;
    insert({ email: uniq("c") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var raw = db.rawGet("SELECT oidcSubject, oidcSubjectHash FROM users WHERE oidcSubjectHash IS NOT NULL ORDER BY rowid DESC LIMIT 1");
    assert.ok(raw.oidcSubject.indexOf(sub) === -1, "the column holds ciphertext, not the subject");
    assert.ok(raw.oidcSubjectHash, "the blind index is populated");
    assert.ok(usersRepo.findByOidcSubject(ISS + "|" + sub), "exact-case lookup finds it");
    assert.strictEqual(usersRepo.findByOidcSubject(ISS + "|" + sub.toLowerCase()), null, "a different case is a different subject");
  });
});

function confirmed(via) {
  return { emailConfirmedVia: via, emailConfirmedAt: new Date().toISOString() };
}

describe("resolveOidcUser: linking by email needs a confirmed address", function () {
  var pol = { autoProvision: false, allowlist: [], requiredGroup: "", adminGroup: "", allowedDomains: [] };

  it("refuses an unconfirmed (legacy) account and writes nothing", function () {
    var email = uniq("legacy") + "@corp.test";
    var u = insert({ email: email, authType: "local", passwordHash: "x" });
    var before = usersRepo.findById(u._id);
    var err = null;
    try { authService.resolveOidcUser(identity({ email: email }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "email-unconfirmed");
    assert.strictEqual(err.accountId, u._id);
    assert.strictEqual(err.revokeUserId, undefined);
    var after = usersRepo.findById(u._id);
    nil(after.oidcSubject);
    nil(after.oidcLabel);
    assert.strictEqual(after.emailConfirmedVia, before.emailConfirmedVia);
  });
  it("refuses an account whose single sign-on was unlinked", function () {
    var email = uniq("blocked") + "@corp.test";
    var u = insert(Object.assign({ email: email, authType: "local" }, confirmed("verification")));
    usersRepo.setOidcSubject(u._id, ISS + "|" + uniq("old"), email);
    usersRepo.clearOidcSubject(u._id);
    assert.strictEqual(reasonOf(function () { authService.resolveOidcUser(identity({ email: email }), pol); }), "auto-link-blocked");
    nil(usersRepo.findById(u._id).oidcSubject);
  });
  ["verification", "invite", "google", "oidc"].forEach(function (via) {
    it("links an account confirmed by " + via + " and records the label", function () {
      var email = uniq("c-" + via) + "@corp.test";
      var u = insert(Object.assign({ email: email, authType: "local" }, confirmed(via)));
      var r = authService.resolveOidcUser(identity({ email: email }), pol);
      assert.strictEqual(r.linked, true);
      assert.strictEqual(r.user._id, u._id);
      assert.strictEqual(r.user.oidcLabel, email);
    });
  });
  it("records an oidc confirmation when a bound account signs in with a matching verified address", function () {
    var email = uniq("bound-leg") + "@corp.test";
    var sub = uniq("bl");
    var u = insert({ email: email, authType: "local", oidcSubject: ISS + "|" + sub });
    assert.strictEqual(u.emailConfirmedVia, "legacy");
    var r = authService.resolveOidcUser(identity({ sub: sub, email: email }), pol);
    assert.strictEqual(r.user.emailConfirmedVia, "oidc");
    assert.ok(r.user.emailConfirmedAt);
    var other = uniq("bound-other") + "@corp.test";
    var sub2 = uniq("bl2");
    var u2 = insert({ email: other, authType: "local", oidcSubject: ISS + "|" + sub2 });
    var r2 = authService.resolveOidcUser(identity({ sub: sub2, email: uniq("different") + "@corp.test" }), pol);
    assert.strictEqual(r2.user.emailConfirmedVia, "legacy", "a different provider address confirms nothing");
    assert.strictEqual(u2._id, r2.user._id);
  });
});

describe("resolveOidcUser: unverified email", function () {
  var pol = { autoProvision: true, allowlist: [], requiredGroup: "staff", adminGroup: "", allowedDomains: [], trustUnverifiedEmail: true };

  it("provisions a group member with no recorded confirmation", function () {
    var email = uniq("entra") + "@corp.test";
    var r = authService.resolveOidcUser(identity({ unverifiedEmail: email, groups: ["staff"] }), pol);
    assert.strictEqual(r.isNew, true);
    assert.strictEqual(r.user.email, email);
    nil(r.user.emailConfirmedVia);
    nil(r.user.emailConfirmedAt);
    assert.strictEqual(r.user.oidcLabel, email);
    assert.strictEqual(authService.emailIsVerified(r.user), false, "never claims uploads");
  });
  it("never matches an existing account", function () {
    var email = uniq("taken") + "@corp.test";
    var u = insert(Object.assign({ email: email, authType: "local", displayName: "Keep" }, confirmed("verification")));
    var err = null;
    try { authService.resolveOidcUser(identity({ unverifiedEmail: email, groups: ["staff"] }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "email-in-use-unverified");
    assert.strictEqual(err.accountId, u._id);
    var after = usersRepo.findById(u._id);
    nil(after.oidcSubject);
    assert.strictEqual(after.displayName, "Keep");
  });
  it("is ignored when the setting is off", function () {
    var email = uniq("off") + "@corp.test";
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ unverifiedEmail: email, groups: ["staff"] }), Object.assign({}, pol, { trustUnverifiedEmail: false }));
    }), "no-verified-email");
  });
  it("ignores the allowlist for a non-member", function () {
    var email = uniq("allow") + "@corp.test";
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ unverifiedEmail: email, groups: ["other"] }), Object.assign({}, pol, { allowlist: [email] }));
    }), "group-denied");
  });
  it("refuses a guest account and an unverified address without a required group", function () {
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ unverifiedEmail: uniq("guest") + "@corp.test", unverifiedExternal: true, groups: ["staff"] }), pol);
    }), "unverified-email-external");
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ unverifiedEmail: uniq("ng") + "@corp.test", groups: ["staff"] }), Object.assign({}, pol, { requiredGroup: "" }));
    }), "unverified-email-needs-group");
  });
  it("refuses a guest identity on a returning sign-in, without writing", function () {
    var id = identity({ unverifiedEmail: uniq("was-member") + "@corp.test", groups: ["staff"] });
    var created = authService.resolveOidcUser(id, pol).user;
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: id.sub, unverifiedExternal: true, groups: ["staff"], displayName: "Changed" }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "unverified-email-external");
    assert.strictEqual(err.accountId, created._id);
    assert.strictEqual(err.revokeUserId, undefined);
    assert.notStrictEqual(usersRepo.findById(created._id).displayName, "Changed");
    assert.strictEqual(authService.resolveOidcUser(identity({ sub: id.sub, unverifiedExternal: true, groups: ["staff"] }), Object.assign({}, pol, { trustUnverifiedEmail: false })).user._id, created._id,
      "the guest check applies only under OIDC_TRUST_UNVERIFIED_EMAIL");
  });
  it("applies allowedDomains on provisioning and on a returning sign-in", function () {
    var dp = Object.assign({}, pol, { allowedDomains: ["corp.test"] });
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ unverifiedEmail: uniq("d") + "@else.test", groups: ["staff"] }), dp);
    }), "domain-not-allowed");
    var id = identity({ unverifiedEmail: uniq("ret") + "@corp.test", groups: ["staff"] });
    var created = authService.resolveOidcUser(id, dp).user;
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: id.sub, unverifiedEmail: uniq("moved") + "@else.test", groups: ["staff"] }), dp); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "domain-not-allowed");
    assert.strictEqual(err.revokeUserId, created._id);
    assert.strictEqual(authService.resolveOidcUser(identity({ sub: id.sub, unverifiedEmail: id.unverifiedEmail, groups: ["staff"] }), dp).user._id, created._id);
  });
  it("maps a duplicate-address insert race to the right reason", function () {
    var real = usersRepo.create;
    usersRepo.create = function () { var e = new Error("UNIQUE constraint failed: users.emailHash"); throw e; };
    try {
      assert.strictEqual(reasonOf(function () {
        authService.resolveOidcUser(identity({ unverifiedEmail: uniq("race") + "@corp.test", groups: ["staff"] }), pol);
      }), "email-in-use-unverified");
      assert.strictEqual(reasonOf(function () {
        authService.resolveOidcUser(identity({ email: uniq("race2") + "@corp.test", groups: ["staff"] }), pol);
      }), "provision-denied");
    } finally {
      usersRepo.create = real;
    }
  });
});

describe("resolveOidcUser: groups that cannot be read", function () {
  var pol = { autoProvision: true, allowlist: [], requiredGroup: "staff", adminGroup: "", allowedDomains: [] };

  it("refuses a bound account without ending sessions or writing", function () {
    var sub = uniq("gu");
    var u = insert({ email: uniq("gu") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, displayName: "Same" });
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: sub, groups: null, displayName: "Changed" }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "groups-unavailable");
    assert.strictEqual(err.revokeUserId, undefined);
    assert.strictEqual(err.accountId, u._id);
    assert.strictEqual(usersRepo.findById(u._id).displayName, "Same");
  });
  it("refuses provisioning with groups-unavailable", function () {
    assert.strictEqual(reasonOf(function () {
      authService.resolveOidcUser(identity({ email: uniq("gp") + "@corp.test", groups: null }), pol);
    }), "groups-unavailable");
  });
  it("still ends sessions when the group list lacks the group", function () {
    var sub = uniq("gd");
    var u = insert({ email: uniq("gd") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var err = null;
    try { authService.resolveOidcUser(identity({ sub: sub, groups: ["other"] }), pol); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "group-denied");
    assert.strictEqual(err.revokeUserId, u._id);
  });
});

describe("linkOidcIdentity", function () {
  var pol = { requiredGroup: "", allowedDomains: [] };

  it("binds the subject, sets the label and clears an unlink block", function () {
    var email = uniq("lk") + "@corp.test";
    var u = insert({ email: email, authType: "local", passwordHash: "x" });
    usersRepo.clearOidcSubject(u._id);
    assert.ok(usersRepo.findById(u._id).oidcAutoLinkBlockedAt);
    var id = identity({ email: email });
    var r = authService.linkOidcIdentity(usersRepo.findById(u._id), id, pol);
    assert.deepStrictEqual(r, { alreadyLinked: false, emailMatched: true });
    var after = usersRepo.findById(u._id);
    assert.strictEqual(after.oidcSubject, ISS + "|" + id.sub);
    assert.strictEqual(after.oidcLabel, email);
    nil(after.oidcAutoLinkBlockedAt);
    assert.strictEqual(after.emailConfirmedVia, "oidc", "a matching verified address is confirmed");
    assert.strictEqual(authService.linkOidcIdentity(after, id, pol).alreadyLinked, true);
  });
  it("does not confirm the address when the provider email differs or is unverified", function () {
    var u = insert({ email: uniq("lk2") + "@corp.test", authType: "local" });
    var r = authService.linkOidcIdentity(u, identity({ email: uniq("elsewhere") + "@corp.test" }), pol);
    assert.strictEqual(r.emailMatched, false);
    assert.strictEqual(usersRepo.findById(u._id).emailConfirmedVia, "legacy");
    var u2 = insert({ email: uniq("lk3") + "@corp.test", authType: "local" });
    authService.linkOidcIdentity(u2, identity({ unverifiedEmail: u2.email }), Object.assign({}, pol, { trustUnverifiedEmail: true }));
    var after2 = usersRepo.findById(u2._id);
    assert.strictEqual(after2.emailConfirmedVia, "legacy");
    assert.strictEqual(after2.oidcLabel, u2.email);
  });
  it("refuses a subject held by another account and an account bound to another subject", function () {
    var sub = uniq("held");
    insert({ email: uniq("holder") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    var u = insert({ email: uniq("me") + "@corp.test", authType: "local" });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(u, identity({ sub: sub }), pol); }), "link-subject-in-use");
    var bound = insert({ email: uniq("bound") + "@corp.test", authType: "local", oidcSubject: ISS + "|" + uniq("mine") });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(bound, identity(), pol); }), "link-other-subject");
  });
  it("refuses a provider email that belongs to another account", function () {
    var otherEmail = uniq("theirs") + "@corp.test";
    insert({ email: otherEmail, authType: "local" });
    var u = insert({ email: uniq("mine") + "@corp.test", authType: "local" });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(u, identity({ email: otherEmail }), pol); }), "link-email-other-account");
    var trust = Object.assign({}, pol, { trustUnverifiedEmail: true });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(u, identity({ unverifiedEmail: otherEmail }), trust); }), "link-email-other-account",
      "an unverified provider address held by another account is refused too");
    nil(usersRepo.findById(u._id).oidcSubject);
  });
  it("refuses a guest identity under OIDC_TRUST_UNVERIFIED_EMAIL", function () {
    var u = insert({ email: uniq("gl") + "@corp.test", authType: "local" });
    var trust = Object.assign({}, pol, { trustUnverifiedEmail: true });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(u, identity({ unverifiedExternal: true }), trust); }), "unverified-email-external");
    nil(usersRepo.findById(u._id).oidcSubject);
  });
  it("refuses a suspended or pending account", function () {
    var s = insert({ email: uniq("susp") + "@corp.test", authType: "local", status: "suspended" });
    var p = insert({ email: uniq("pend") + "@corp.test", authType: "local", status: "pending" });
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(s, identity(), pol); }), "account-not-active");
    assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(p, identity(), pol); }), "account-not-active");
  });
  it("refuses on domain and group without asking for revocation", function () {
    var u = insert({ email: uniq("dom") + "@corp.test", authType: "local" });
    var err = null;
    try { authService.linkOidcIdentity(u, identity({ email: uniq("x") + "@else.test" }), { allowedDomains: ["corp.test"] }); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "domain-not-allowed");
    assert.strictEqual(err.revokeUserId, undefined);
    err = null;
    try { authService.linkOidcIdentity(u, identity({ groups: null }), { requiredGroup: "staff" }); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "groups-unavailable");
    assert.strictEqual(err.revokeUserId, undefined);
    err = null;
    try { authService.linkOidcIdentity(u, identity({ groups: ["other"] }), { requiredGroup: "staff" }); } catch (e) { err = e; }
    assert.strictEqual(err.oidcReason, "group-denied");
    assert.strictEqual(err.revokeUserId, undefined);
    nil(usersRepo.findById(u._id).oidcSubject);
  });
  it("removes its binding when another account bound the subject at the same time", function () {
    var sub = uniq("lrace");
    var u = insert({ email: uniq("lr") + "@corp.test", authType: "local" });
    var real = usersRepo.findByOidcSubject;
    usersRepo.findByOidcSubject = function () { return null; };
    insert({ email: uniq("lr-other") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub });
    try {
      assert.strictEqual(reasonOf(function () { authService.linkOidcIdentity(u, identity({ sub: sub }), pol); }), "link-subject-in-use");
    } finally {
      usersRepo.findByOidcSubject = real;
    }
    nil(usersRepo.findById(u._id).oidcSubject);
    assert.strictEqual(usersRepo.findAllByOidcSubject(ISS + "|" + sub).length, 1);
  });
});

describe("signInMethods and emailIsVerified", function () {
  function withConfig(over, fn) {
    var saved = {};
    Object.keys(over).forEach(function (k) { saved[k] = config[k]; config[k] = over[k]; });
    try { return fn(); } finally { Object.keys(saved).forEach(function (k) { config[k] = saved[k]; }); }
  }

  it("counts each method only while it is enabled", function () {
    var u = insert({ email: uniq("m") + "@corp.test", authType: "local", passwordHash: "x", googleId: "g-" + testId, tailscaleId: "t-" + testId + "@tailnet", oidcSubject: ISS + "|" + uniq("m") });
    db.credentials.insert({ userId: u._id, credentialId: "cred-" + testId, publicKey: "pk", counter: 0, createdAt: new Date().toISOString() });
    var on = withConfig({
      localAuth: true, passkeyEnabled: true, google: { clientID: "gc" },
      oidc: Object.assign({}, config.oidc, { enabled: true, issuer: "https://idp.example.com", clientID: "c" }),
      tailscale: Object.assign({}, config.tailscale, { enabled: true, ssoEnabled: true }),
    }, function () { return authService.signInMethods(u); });
    assert.deepStrictEqual(on, ["password", "passkey", "google", "oidc", "tailscale"]);
    var off = withConfig({
      localAuth: false, passkeyEnabled: false, google: { clientID: "" },
      oidc: Object.assign({}, config.oidc, { enabled: false }),
      tailscale: Object.assign({}, config.tailscale, { enabled: true, ssoEnabled: false }),
    }, function () { return authService.signInMethods(u); });
    assert.deepStrictEqual(off, []);
  });
  it("applies EMAIL_VERIFICATION only to legacy accounts", function () {
    var now = new Date().toISOString();
    var legacy = { status: "active", emailConfirmedVia: "legacy", emailConfirmedAt: now };
    var recorded = { status: "active", emailConfirmedVia: "invite", emailConfirmedAt: now };
    var none = { status: "active", emailConfirmedVia: null, emailConfirmedAt: null };
    var pending = { status: "pending", emailConfirmedVia: "verification", emailConfirmedAt: now };
    withConfig({ emailVerification: true }, function () {
      assert.strictEqual(authService.emailIsVerified(legacy), true);
      assert.strictEqual(authService.emailIsVerified(recorded), true);
      assert.strictEqual(authService.emailIsVerified(none), false);
      assert.strictEqual(authService.emailIsVerified(pending), false);
    });
    withConfig({ emailVerification: false }, function () {
      assert.strictEqual(authService.emailIsVerified(legacy), false);
      assert.strictEqual(authService.emailIsVerified(recorded), true);
      assert.strictEqual(authService.emailIsVerified(none), false);
    });
    assert.strictEqual(authService.emailConfirmedForLinking(legacy), false);
    assert.strictEqual(authService.emailConfirmedForLinking(recorded), true);
    assert.strictEqual(authService.emailConfirmedForLinking(none), false);
  });
});

describe("users.repo confirmation bookkeeping", function () {
  it("defaults to legacy for an active row and to null for a pending row", function () {
    var a = usersRepo.create({ email: uniq("ra") + "@corp.test", status: "active", createdAt: new Date().toISOString() });
    assert.strictEqual(a.emailConfirmedVia, "legacy");
    assert.ok(a.emailConfirmedAt);
    var p = usersRepo.create({ email: uniq("rp") + "@corp.test", status: "pending", createdAt: new Date().toISOString() });
    nil(p.emailConfirmedVia);
    nil(p.emailConfirmedAt);
    var x = usersRepo.create({ email: uniq("rx") + "@corp.test", status: "active", emailConfirmedVia: null, emailConfirmedAt: null });
    nil(x.emailConfirmedVia, "an explicit null is kept");
  });
  it("records legacy on an email change that does not say how it was confirmed", function () {
    var u = insert(Object.assign({ email: uniq("chg") + "@corp.test", authType: "local" }, confirmed("verification")));
    usersRepo.update(u._id, { $set: { email: uniq("chg2") + "@corp.test" } });
    assert.strictEqual(usersRepo.findById(u._id).emailConfirmedVia, "legacy");
    usersRepo.update(u._id, { $set: { email: uniq("chg3") + "@corp.test", emailConfirmedVia: "verification", emailConfirmedAt: new Date().toISOString() } });
    assert.strictEqual(usersRepo.findById(u._id).emailConfirmedVia, "verification");
  });
  it("clearOidcSubject removes the blind index and sets the unlink block", function () {
    var subject = ISS + "|" + uniq("clr");
    var u = insert({ email: uniq("clr") + "@corp.test", authType: "local" });
    usersRepo.setOidcSubject(u._id, subject, "label@corp.test");
    assert.strictEqual(usersRepo.findByOidcSubject(subject)._id, u._id);
    usersRepo.clearOidcSubject(u._id);
    assert.strictEqual(usersRepo.findByOidcSubject(subject), null);
    var raw = db.rawGet("SELECT oidcSubject, oidcSubjectHash, oidcLabel, oidcAutoLinkBlockedAt FROM users WHERE _id = ?", u._id);
    assert.strictEqual(raw.oidcSubject, null);
    assert.strictEqual(raw.oidcSubjectHash, null);
    assert.strictEqual(raw.oidcLabel, null);
    assert.ok(raw.oidcAutoLinkBlockedAt);
  });
  it("stores the label sealed", function () {
    var u = insert({ email: uniq("lbl") + "@corp.test", authType: "local" });
    usersRepo.setOidcSubject(u._id, ISS + "|" + uniq("lbl"), "visible-" + testId + "@corp.test");
    var raw = db.rawGet("SELECT oidcLabel FROM users WHERE _id = ?", u._id);
    assert.ok(raw.oidcLabel && raw.oidcLabel.indexOf("visible-") === -1, "the column holds ciphertext");
    assert.strictEqual(usersRepo.findById(u._id).oidcLabel, "visible-" + testId + "@corp.test");
  });
});

describe("migrateEmailConfirmation", function () {
  var { DatabaseSync } = require("node:sqlite");

  function preUpgrade() {
    var mem = new DatabaseSync(":memory:");
    mem.exec("CREATE TABLE users (_id TEXT PRIMARY KEY, googleId TEXT, tailscaleId TEXT, oidcSubjectHash TEXT, email TEXT, emailHash TEXT, passwordHash TEXT, status TEXT, createdAt TEXT)");
    mem.exec("CREATE TABLE credentials (_id TEXT PRIMARY KEY, userId TEXT)");
    var ins = mem.prepare("INSERT INTO users (_id, googleId, tailscaleId, oidcSubjectHash, email, emailHash, passwordHash, status, createdAt) VALUES (?, ?, ?, ?, 'e', ?, ?, ?, '2026-01-01T00:00:00.000Z')");
    ins.run("google", "gid", null, null, "h1", null, "active");
    ins.run("oidc-only", null, null, "sh2", "h2", null, "active");
    ins.run("oidc-pw", null, null, "sh3", "h3", "pw", "active");
    ins.run("oidc-passkey", null, null, "sh4", "h4", null, "active");
    ins.run("local", null, null, null, "h5", "pw", "active");
    ins.run("pending", null, null, null, "h6", "pw", "pending");
    ins.run("noemail", null, "ts", null, null, null, "active");
    mem.prepare("INSERT INTO credentials (_id, userId) VALUES ('c1', 'oidc-passkey')").run();
    return mem;
  }
  function via(mem, id) { return mem.prepare("SELECT emailConfirmedVia v, emailConfirmedAt a FROM users WHERE _id = ?").get(id); }

  it("backfills each kind of account", function () {
    var mem = preUpgrade();
    assert.strictEqual(db.migrateEmailConfirmation(mem), true);
    assert.strictEqual(via(mem, "google").v, "google");
    assert.strictEqual(via(mem, "google").a, "2026-01-01T00:00:00.000Z");
    assert.strictEqual(via(mem, "oidc-only").v, "oidc");
    assert.strictEqual(via(mem, "oidc-pw").v, "legacy");
    assert.strictEqual(via(mem, "oidc-passkey").v, "legacy");
    assert.strictEqual(via(mem, "local").v, "legacy");
    assert.strictEqual(via(mem, "pending").v, null);
    assert.strictEqual(via(mem, "noemail").v, null);
    mem.prepare("UPDATE users SET emailConfirmedVia = 'verification' WHERE _id = 'local'").run();
    assert.strictEqual(db.migrateEmailConfirmation(mem), false, "a second run does nothing");
    assert.strictEqual(via(mem, "local").v, "verification");
    mem.close();
  });
  it("rolls back the columns and throws when the backfill fails", function () {
    var mem = preUpgrade();
    mem.exec("CREATE TRIGGER boom BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'injected'); END");
    assert.throws(function () { db.migrateEmailConfirmation(mem); }, /Database migration for email confirmation failed: .*injected/);
    var cols = mem.prepare("PRAGMA table_info(users)").all().map(function (c) { return c.name; });
    assert.strictEqual(cols.indexOf("emailConfirmedVia"), -1);
    assert.strictEqual(cols.indexOf("emailConfirmedAt"), -1);
    mem.close();
  });
});

describe("completeLogin against a stub provider", function () {
  var ENTRA = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0";
  var GENERIC = "https://idp.example.com/realms/a";

  function stub(claims, userinfo, opts) {
    opts = opts || {};
    var seen = { authParams: null, userinfoCalls: 0 };
    var client = {
      authorizationUrl: async function (p) { seen.authParams = p; return { url: "https://idp.example.com/auth?x=1", state: "st", nonce: "n", verifier: "v" }; },
      parseCallback: async function () { return { code: "c" }; },
      exchangeCode: async function () { return { claims: claims, accessToken: opts.noAccessToken ? undefined : "at" }; },
      fetchUserInfo: async function () {
        seen.userinfoCalls += 1;
        if (opts.userinfoError) throw opts.userinfoError;
        return userinfo;
      },
    };
    return { client: client, seen: seen };
  }

  async function run(issuer, claims, userinfo, opts) {
    opts = opts || {};
    config.updateSettings({ oidcEnabled: "true", oidcIssuer: issuer, oidcClientID: "client-" + testId });
    var entry = oidc.getClient("oidc");
    var s = stub(Object.assign({ iss: issuer, sub: uniq("s") }, claims), userinfo, opts);
    entry.client = s.client;
    var req = { session: {}, query: { code: "c", state: "st" } };
    await oidc.startLogin("oidc", req, opts.start);
    var id = await oidc.completeLogin("oidc", req, opts.complete || {});
    return { id: id, seen: s.seen, req: req };
  }

  it("reports the unverified email only when allowed and when no claim set says otherwise", async function () {
    var r = await run(GENERIC, { email: "u@corp.test" }, { sub: "x" }, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.email, null);
    assert.strictEqual(r.id.unverifiedEmail, "u@corp.test");
    r = await run(GENERIC, { email: "u@corp.test" }, {}, { complete: {} });
    assert.strictEqual(r.id.unverifiedEmail, null, "not reported unless allowed");
    r = await run(GENERIC, { email: "u@corp.test", email_verified: false }, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedEmail, null, "an explicit false in the id_token wins");
    r = await run(GENERIC, { email: "u@corp.test" }, { email_verified: "false" }, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedEmail, null, "an email_verified in userinfo wins");
    r = await run(GENERIC, {}, { email: "ui@corp.test" }, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedEmail, "ui@corp.test", "userinfo supplies the address");
  });
  it("flags guest accounts, and for Entra an absent acct claim", async function () {
    var r = await run(GENERIC, { email: "g@corp.test", acct: 1 }, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedExternal, true);
    r = await run(ENTRA, { email: "g@corp.test" }, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedExternal, true, "Entra without acct");
    r = await run(GENERIC, { email: "g@corp.test" }, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedExternal, false, "another issuer without acct");
    r = await run(ENTRA, { email: "g@corp.test", acct: 0 }, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedExternal, false, "Entra member");
    r = await run(ENTRA, {}, {}, { complete: { allowUnverifiedEmail: true } });
    assert.strictEqual(r.id.unverifiedExternal, true, "a guest without any email is flagged too");
    assert.strictEqual(r.id.unverifiedEmail, null);
    r = await run(ENTRA, {}, {}, {});
    assert.strictEqual(r.id.unverifiedExternal, false, "not flagged when the setting is off");
  });
  it("reports where the groups came from or why they are missing", async function () {
    var need = { complete: { needGroups: true } };
    var r = await run(GENERIC, { groups: ["a"] }, {}, need);
    assert.strictEqual(r.id.groupsStatus, "id-token");
    assert.deepStrictEqual(r.id.groups, ["a"]);
    r = await run(GENERIC, {}, { groups: ["b"] }, need);
    assert.strictEqual(r.id.groupsStatus, "userinfo");
    assert.deepStrictEqual(r.id.groups, ["b"]);
    r = await run(GENERIC, {}, { sub: "x" }, need);
    assert.strictEqual(r.id.groupsStatus, "absent");
    assert.strictEqual(r.id.groups, null);
    var uiErr = new Error("boom"); uiErr.code = "auth-oauth/userinfo-status";
    r = await run(GENERIC, {}, null, Object.assign({ userinfoError: uiErr }, need));
    assert.strictEqual(r.id.groupsStatus, "userinfo-failed");
    assert.strictEqual(r.id.userinfoError, "auth-oauth/userinfo-status");
    var rawErr = new Error("Bad things <html>");
    r = await run(GENERIC, {}, null, Object.assign({ userinfoError: rawErr }, need));
    assert.strictEqual(r.id.userinfoError, "userinfo-request", "an unrecognized error is not quoted");
    r = await run(GENERIC, {}, {}, Object.assign({ noAccessToken: true }, need));
    assert.strictEqual(r.id.groupsStatus, "no-access-token");
    r = await run(GENERIC, { _claim_names: { groups: "src1" } }, { sub: "x" }, need);
    assert.strictEqual(r.id.groupsStatus, "overage");
    r = await run(GENERIC, { groups: { bad: true } }, { groups: ["ignored"] }, need);
    assert.strictEqual(r.id.groupsStatus, "malformed");
    assert.strictEqual(r.id.groups, null, "a malformed id_token claim does not fall back to userinfo");
  });
  it("keeps an avatar only from the issuer origin", async function () {
    var r = await run(GENERIC, { picture: "https://idp.example.com/pic.png" }, {}, {});
    assert.strictEqual(r.id.avatar, "https://idp.example.com/pic.png");
    r = await run(GENERIC, { picture: "https://graph.example.net/pic.png" }, {}, {});
    assert.strictEqual(r.id.avatar, "");
  });
  it("asks for a fresh sign-in when linking and checks auth_time", async function () {
    var userId = "u-" + testId;
    var nowSec = Math.floor(Date.now() / 1000);
    var r = await run(GENERIC, { auth_time: nowSec }, {}, { start: { linkUserId: userId } });
    assert.deepStrictEqual(r.seen.authParams, { prompt: "login", maxAge: 0 });
    assert.strictEqual(r.id.linkUserId, userId);
    await assert.rejects(run(GENERIC, {}, {}, { start: { linkUserId: userId } }), function (e) { return e.oidcReason === "link-stale-auth"; }, "a missing auth_time is refused");
    await assert.rejects(run(GENERIC, { auth_time: "now" }, {}, { start: { linkUserId: userId } }), function (e) { return e.oidcReason === "link-stale-auth"; }, "a non-numeric auth_time is refused");
    await assert.rejects(run(GENERIC, { auth_time: nowSec - 3600 }, {}, { start: { linkUserId: userId } }), function (e) { return e.oidcReason === "link-stale-auth"; });
    r = await run(GENERIC, { auth_time: nowSec - 3600 }, {}, {});
    assert.strictEqual(r.id.linkUserId, null, "a plain login ignores auth_time");
    assert.deepStrictEqual(r.seen.authParams, {});
  });
  it("reads a pending link without consuming it", async function () {
    config.updateSettings({ oidcEnabled: "true", oidcIssuer: GENERIC, oidcClientID: "client-" + testId });
    var entry = oidc.getClient("oidc");
    entry.client = stub({ iss: GENERIC, sub: "s" }, {}).client;
    var req = { session: {} };
    assert.strictEqual(oidc.pendingLinkUserId(req), null);
    await oidc.startLogin("oidc", req, { linkUserId: "abc" });
    assert.strictEqual(oidc.pendingLinkUserId(req), "abc");
    assert.ok(req.session.oidcState, "the state is still there");
    await assert.rejects(oidc.startLogin("oidc", req, { linkUserId: "x".repeat(65) }), function (e) { return e.oidcReason === "bad-link-request"; });
    config.updateSettings({ oidcEnabled: "false" });
  });
});
