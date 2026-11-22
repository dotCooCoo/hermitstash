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
    assert.deepStrictEqual(oidc.extractGroups({ groups: { a: 1 } }, "groups"), []);
    assert.strictEqual(oidc.extractGroups({}, "groups"), null, "an absent claim is unknown, not empty");
    assert.strictEqual(oidc.extractGroups({ groups: ["a"] }, "__proto__"), null);
  });
  it("caps oversized group lists and entries", function () {
    var many = [];
    for (var i = 0; i < 1500; i++) many.push("g" + i);
    many.push("x".repeat(300));
    var out = oidc.extractGroups({ groups: many }, "groups");
    assert.strictEqual(out.length, 1000);
    assert.ok(out.every(function (g) { return g.length <= 256; }));
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
    var u = insert({ email: email, authType: "tailscale", displayName: "T" });
    var id = identity({ email: email });
    var r = authService.resolveOidcUser(id, pol);
    assert.strictEqual(r.linked, true);
    assert.strictEqual(r.user._id, u._id);
    assert.strictEqual(r.user.authType, "tailscale");
    assert.strictEqual(r.user.oidcSubject, ISS + "|" + id.sub);
    var again = authService.resolveOidcUser(identity({ sub: id.sub, email: email }), pol);
    assert.strictEqual(again.linked, false, "the second login finds it by subject");
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
  it("leaves the role alone when groups are unknown", function () {
    var sub = uniq("unk");
    insert({ email: uniq("u") + "@corp.test", authType: "oidc", oidcSubject: ISS + "|" + sub, role: "admin" });
    var r = authService.resolveOidcUser(identity({ sub: sub, groups: null }), pol);
    assert.strictEqual(r.roleChange, null);
    assert.strictEqual(r.user.role, "admin");
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
