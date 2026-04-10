const config = require("../lib/config");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
const requireAuth = require("../middleware/require-auth");
const { send, host } = require("../middleware/send");

module.exports = function (app) {
  // Landing
  app.get("/", (req, res) => {
    if (req.user) return res.redirect("/dashboard");
    if (!config.landingEnabled) return res.redirect("/drop");
    send(res, "landing", {
      user: null, allowedExtensions: config.allowedExtensions,
      heroTitle: config.heroTitle, heroSubtitle: config.heroSubtitle,
      showMaintainerSupport: config.showMaintainerSupport,
    });
  });

  // Dashboard
  app.get("/dashboard", (req, res) => {
    if (!requireAuth(req, res)) return;

    // Claim unclaimed public uploads matching this user's email
    if (req.user.email) {
      const unclaimed = filesRepo.findAll({ uploaderEmail: req.user.email, uploadedBy: "public" });
      for (const f of unclaimed) {
        filesRepo.update(f._id, { $set: { uploadedBy: req.user._id } });
      }
    }

    const userFiles = filesRepo.findAll({ uploadedBy: req.user._id })
      .filter(f => f.status !== "chunking" && f.vaultEncrypted !== "true")
      .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));

    // Fetch user's bundles
    const userBundles = bundlesRepo.findAll({ ownerId: req.user._id })
      .filter(b => b.status === "complete")
      .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));

    // Group files by bundle, separate standalone files
    var bundleFileMap = {};
    var standaloneFiles = [];
    for (var i = 0; i < userFiles.length; i++) {
      var f = userFiles[i];
      if (f.bundleShareId) {
        if (!bundleFileMap[f.bundleShareId]) bundleFileMap[f.bundleShareId] = [];
        bundleFileMap[f.bundleShareId].push(f);
      } else {
        standaloneFiles.push(f);
      }
    }

    // Enrich bundles with their files
    var bundlesWithFiles = [];
    for (var j = 0; j < userBundles.length; j++) {
      var b = userBundles[j];
      bundlesWithFiles.push({
        bundle: b,
        files: bundleFileMap[b.shareId] || [],
      });
    }

    send(res, "dashboard", { user: req.user, files: standaloneFiles, bundles: bundlesWithFiles, host: host(req) });
  });
};
