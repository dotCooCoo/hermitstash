var apiKeysRepo = require("../app/data/repositories/apiKeys.repo");
var usersRepo = require("../app/data/repositories/users.repo");
var { sha3Hash, generateToken } = require("../lib/crypto");
var { parseJson } = require("../lib/multipart");
var requireAdmin = require("../middleware/require-admin");
var audit = require("../lib/audit");
var { VALID_SCOPES } = require("../app/security/scope-policy");

module.exports = function (app) {
  // List API keys
  app.get("/admin/apikeys/api", function(req, res) {
    if (!requireAdmin(req, res)) return;
    var keys = apiKeysRepo.findAll({});
    // Don't expose the hash
    var safe = keys.map(function(k) {
      return { _id: k._id, name: k.name, prefix: k.prefix, permissions: k.permissions, userId: k.userId, lastUsed: k.lastUsed, createdAt: k.createdAt };
    });
    res.json({ keys: safe });
  });

  // Generate new API key
  app.post("/admin/apikeys/create", async function(req, res) {
    if (!requireAdmin(req, res)) return;
    var body = await parseJson(req);
    var name = String(body.name || "").trim().slice(0, 100);
    var rawPerms = String(body.permissions || "upload").trim().toLowerCase();
    var permList = rawPerms.split(",").map(function(s) { return s.trim(); }).filter(function(s) { return VALID_SCOPES.indexOf(s) !== -1; });
    if (permList.length === 0) return res.status(400).json({ error: "Invalid permissions. Valid scopes: " + VALID_SCOPES.join(", ") });
    var permissions = permList.join(",");
    if (!name) return res.status(400).json({ error: "Name required." });

    // Generate a random key with a recognizable prefix
    var rawKey = "hs_" + generateToken(32);
    var prefix = rawKey.substring(0, 7); // "hs_xxxx" for identification
    var keyHash = sha3Hash(rawKey);

    apiKeysRepo.create({
      name: name,
      keyHash: keyHash,
      prefix: prefix,
      permissions: permissions,
      userId: req.user._id,
      createdAt: new Date().toISOString(),
    });

    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "API key created: " + name, req: req });
    // Return the full key ONCE — it can never be retrieved again
    res.json({ success: true, key: rawKey, prefix: prefix });
  });

  // Revoke API key
  app.post("/admin/apikeys/:id/revoke", async function(req, res) {
    if (!requireAdmin(req, res)) return;
    var key = apiKeysRepo.findOne({ _id: req.params.id });
    if (!key) return res.status(404).json({ error: "Not found." });
    apiKeysRepo.remove(key._id);
    audit.log(audit.ACTIONS.ADMIN_SETTINGS_CHANGED, { details: "API key revoked: " + key.name, req: req });
    res.json({ success: true });
  });
};
