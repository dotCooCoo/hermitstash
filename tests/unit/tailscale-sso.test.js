const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const b = require("../../lib/vendor/blamejs");

// Isolated test database.
var testId = b.crypto.generateToken(4);
var scratch = require("../helpers/isolate-db");
var testDbPath = path.join(scratch.dir, "test-tssso-" + testId + ".db");
process.env.HERMITSTASH_DB_PATH = testDbPath;
process.env.LOCAL_AUTH = "true";
process.env.EMAIL_VERIFICATION = "false";
// Tailscale on so identityFrom/provisioning are live; the gate fields are set
// per-case by mutating the live config object below.
process.env.TAILSCALE_ENABLED = "true";
process.env.TAILSCALE_SSO = "true";

Object.keys(require.cache).forEach(function (k) {
  if (k.includes("hermitstash") && !k.includes("node_modules") && !k.includes("test")) delete require.cache[k];
});

var projectRoot = path.join(__dirname, "..", "..");
var config = require(path.join(projectRoot, "lib", "config"));
var vault = require(path.join(projectRoot, "lib", "vault"));
var tailscale = require(path.join(projectRoot, "lib", "tailscale"));
var authService = require(path.join(projectRoot, "app", "domain", "auth", "auth.service"));
var usersRepo = require(path.join(projectRoot, "app", "data", "repositories", "users.repo"));

function setGate(opts) {
  config.tailscale.enabled = true;
  config.tailscale.ssoEnabled = true;
  config.tailscale.ssoRequiredGrant = opts.grant || "";
  config.tailscale.ssoAllowlist = opts.allowlist || [];
}

// Build a loopback request carrying the raw Tailscale-User-* family, as the
// serve proxy would. identityFrom resolves it through the peer-gate directly.
function reqWith(identity) {
  var headers = {};
  if (identity) {
    if (identity.login) headers["tailscale-user-login"] = identity.login;
    if (identity.name) headers["tailscale-user-name"] = identity.name;
    if (identity.profilePic) headers["tailscale-user-profile-pic"] = identity.profilePic;
    if (identity.caps) headers["tailscale-app-capabilities"] = identity.caps;
  }
  return { headers: headers, socket: { remoteAddress: "127.0.0.1" } };
}

before(async function () { await vault.init(); });

after(function () {
  try { fs.unlinkSync(testDbPath); } catch {}
  try { fs.unlinkSync(testDbPath + "-shm"); } catch {}
  try { fs.unlinkSync(testDbPath + "-wal"); } catch {}
});

describe("tailscale — identityFrom (peer-gated family → normalized identity)", function () {
  it("returns null when the feature is disabled", function () {
    config.tailscale.enabled = false;
    assert.strictEqual(tailscale.identityFrom(reqWith({ login: "a@ex.com" })), null);
    config.tailscale.enabled = true;
  });
  it("returns null when SSO is off", function () {
    config.tailscale.ssoEnabled = false;
    assert.strictEqual(tailscale.identityFrom(reqWith({ login: "a@ex.com" })), null);
    config.tailscale.ssoEnabled = true;
  });
  it("returns null under Funnel (no login header)", function () {
    setGate({ allowlist: ["a@ex.com"] });
    assert.strictEqual(tailscale.identityFrom(reqWith(null)), null);
    assert.strictEqual(tailscale.identityFrom(reqWith({ name: "No Login" })), null);
  });
  it("normalizes a present identity (login lowercased, name cleaned)", function () {
    setGate({ allowlist: ["a@ex.com"] });
    var id = tailscale.identityFrom(reqWith({ login: "Alice@Example.com", name: "Alice A", profilePic: "https://x/y.jpg" }));
    assert.strictEqual(id.login, "alice@example.com");
    assert.strictEqual(id.displayName, "Alice A");
    assert.strictEqual(id.profilePicUrl, "https://x/y.jpg");
  });
});

describe("tailscale — parseCaps (Tailscale-App-Capabilities JSON)", function () {
  it("parses the documented JSON object into capability keys", function () {
    var caps = tailscale.parseCaps('{"example.com/cap/hermitstash":[{"action":["*"],"resources":["*"]}]}');
    assert.deepStrictEqual(caps, ["example.com/cap/hermitstash"]);
  });
  it("yields no caps for a non-object / malformed header (fail-closed)", function () {
    assert.deepStrictEqual(tailscale.parseCaps("not json"), []);
    assert.deepStrictEqual(tailscale.parseCaps('["arr"]'), []);
    assert.deepStrictEqual(tailscale.parseCaps(""), []);
  });
});

describe("tailscale — provisioningDecision (admin-gated)", function () {
  it("allows via allowlist login match", function () {
    setGate({ allowlist: ["alice@example.com"] });
    var d = tailscale.provisioningDecision({ login: "alice@example.com", caps: [] });
    assert.strictEqual(d.allowed, true);
    assert.strictEqual(d.via, "allowlist");
  });
  it("allows via capability grant match", function () {
    setGate({ grant: "example.com/cap/hermitstash" });
    var d = tailscale.provisioningDecision({ login: "bob@example.com", caps: ["example.com/cap/hermitstash"] });
    assert.strictEqual(d.allowed, true);
    assert.strictEqual(d.via, "grant");
  });
  it("refuses when neither grant nor allowlist matches (safe default)", function () {
    setGate({ grant: "example.com/cap/hermitstash", allowlist: ["someone@else.com"] });
    var d = tailscale.provisioningDecision({ login: "mallory@example.com", caps: ["other/cap"] });
    assert.strictEqual(d.allowed, false);
  });
  it("refuses everyone when the gate is unset (SSO on, provisioning off)", function () {
    setGate({});
    assert.strictEqual(tailscale.provisioningDecision({ login: "x@ex.com", caps: [] }).allowed, false);
  });
});

describe("tailscale.middleware — peer-gated identity strip (anti-spoof boundary)", function () {
  var tailscaleMod = require(path.join(projectRoot, "lib", "tailscale"));
  function mreq(remoteAddr, headers) {
    return { headers: Object.assign({}, headers), socket: { remoteAddress: remoteAddr } };
  }
  function run(req) { return new Promise(function (res) { tailscaleMod.middleware(req, {}, function () { res(); }); }); }

  it("trusts the family from a loopback peer (the serve proxy)", async function () {
    config.tailscale.enabled = true; config.tailscale.ssoEnabled = true;
    var req = mreq("127.0.0.1", { "tailscale-user-login": "alice@example.com", "tailscale-user-name": "Alice" });
    await run(req);
    assert.ok(req.tailscaleIdentity, "loopback peer identity should be set");
    assert.strictEqual(req.tailscaleIdentity.login, "alice@example.com");
  });

  it("strips a forged family from a non-loopback peer (full-impersonation defense)", async function () {
    config.tailscale.enabled = true; config.tailscale.ssoEnabled = true;
    var req = mreq("203.0.113.5", { "tailscale-user-login": "attacker@example.com" });
    await run(req);
    assert.ok(!req.tailscaleIdentity, "non-loopback peer identity must NOT be set");
    assert.strictEqual(req.headers["tailscale-user-login"], undefined, "forged header must be stripped");
    // identityFrom must also refuse it.
    assert.strictEqual(tailscaleMod.identityFrom(req), null);
  });

  it("strips the family when the feature is disabled, even from loopback", async function () {
    config.tailscale.enabled = false;
    var req = mreq("127.0.0.1", { "tailscale-user-login": "alice@example.com" });
    await run(req);
    assert.strictEqual(req.tailscaleIdentity, null);
    assert.strictEqual(req.headers["tailscale-user-login"], undefined, "family stripped when disabled");
    config.tailscale.enabled = true;
  });
});

describe("auth.service.resolveTailscaleUser", function () {
  it("refuses a new tailnet user when the gate is closed", function () {
    setGate({});
    assert.throws(function () {
      authService.resolveTailscaleUser({ login: "nogate@example.com", displayName: "No Gate", caps: [] });
    }, /not permitted/i);
  });

  it("provisions an allowlisted user (first user → admin) with email set", function () {
    setGate({ allowlist: ["admin@example.com"] });
    var r = authService.resolveTailscaleUser({ login: "admin@example.com", displayName: "Admin", caps: [] });
    assert.strictEqual(r.isNew, true);
    assert.strictEqual(r.user.authType, "tailscale");
    assert.strictEqual(r.user.tailscaleId, "admin@example.com");
    assert.strictEqual(r.user.email, "admin@example.com");
    assert.strictEqual(r.user.role, "admin", "first-ever user provisions as admin");
  });

  it("signs in a returning user (same login → same account, not new)", function () {
    setGate({ allowlist: ["admin@example.com"] });
    var again = authService.resolveTailscaleUser({ login: "Admin@Example.com", displayName: "Admin", caps: [] });
    assert.strictEqual(again.isNew, false);
    assert.strictEqual(again.user.tailscaleId, "admin@example.com");
  });

  it("provisions via capability grant (subsequent user → role user)", function () {
    setGate({ grant: "example.com/cap/hermitstash" });
    var r = authService.resolveTailscaleUser({ login: "granted@example.com", displayName: "Granted", caps: ["example.com/cap/hermitstash"] });
    assert.strictEqual(r.isNew, true);
    assert.strictEqual(r.user.role, "user");
  });

  it("provisions a non-email login with no email (own namespace)", function () {
    setGate({ allowlist: ["ghuser@github"] });
    var r = authService.resolveTailscaleUser({ login: "ghuser@github", displayName: "GH User", caps: [] });
    assert.strictEqual(r.isNew, true);
    assert.strictEqual(r.user.tailscaleId, "ghuser@github");
    assert.ok(!r.user.email, "a non-address login provisions without an email");
    // A second no-email tailnet user must not collide on the UNIQUE emailHash index.
    setGate({ allowlist: ["ghuser2@github"] });
    var r2 = authService.resolveTailscaleUser({ login: "ghuser2@github", displayName: "GH Two", caps: [] });
    assert.strictEqual(r2.isNew, true);
  });

  it("refuses cross-provider takeover of an existing email account", function () {
    // A local account already owns the address.
    usersRepo.create({ email: "clash@example.com", displayName: "Local", authType: "local",
      role: "user", status: "active", createdAt: new Date().toISOString() });
    setGate({ allowlist: ["clash@example.com"] });
    assert.throws(function () {
      authService.resolveTailscaleUser({ login: "clash@example.com", displayName: "TS Clash", caps: [] });
    }, /already exists/i);
  });

  it("refuses a suspended returning tailscale account", function () {
    setGate({ allowlist: ["susp@example.com"] });
    var r = authService.resolveTailscaleUser({ login: "susp@example.com", displayName: "Susp", caps: [] });
    usersRepo.update(r.user._id, { $set: { status: "suspended" } });
    assert.throws(function () {
      authService.resolveTailscaleUser({ login: "susp@example.com", displayName: "Susp", caps: [] });
    }, /suspended/i);
  });
});
