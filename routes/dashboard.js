var config = require("../lib/config");
var filesRepo = require("../app/data/repositories/files.repo");
var bundlesRepo = require("../app/data/repositories/bundles.repo");
var requireAuth = require("../middleware/require-auth");
var { send, host } = require("../middleware/send");
var { emailIsVerified } = require("../app/domain/auth/auth.service");

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

    // Reassign anonymous public uploads matching this user's email — ONLY when the
    // account's email is proven (verification operative + account active). Email
    // equality is not proof of control: without this gate, an attacker who changes
    // their account email to a victim's anonymous-upload address (see
    // routes/profile.js) would silently acquire the victim's "public" uploads on the
    // next dashboard load. An unverified address must never trigger a claim.
    if (req.user.email && emailIsVerified(req.user)) {
      var unclaimed = filesRepo.findAll({ uploaderEmail: req.user.email, uploadedBy: "public" });
      for (var f of unclaimed) {
        filesRepo.update(f._id, { $set: { uploadedBy: req.user._id } });
      }
    }

    var userFiles = filesRepo.findAll({ uploadedBy: req.user._id })
      .filter(f => f.status !== "chunking" && f.vaultEncrypted !== "true")
      .sort((a, b) => (b.createdAt || "").localeCompare(a.createdAt || ""));

    // Fetch user's bundles
    var userBundles = bundlesRepo.findAll({ ownerId: req.user._id })
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

  // Legal pages — configurable via admin settings, sensible defaults
  app.get("/privacy", (req, res) => {
    send(res, "legal", { user: req.user || null, pageTitle: "Privacy Policy", content: config.privacyPolicy || null, defaultPage: "privacy" });
  });
  app.get("/terms", (req, res) => {
    send(res, "legal", { user: req.user || null, pageTitle: "Terms of Service", content: config.termsOfService || null, defaultPage: "terms" });
  });
  app.get("/cookies", (req, res) => {
    send(res, "legal", { user: req.user || null, pageTitle: "Cookie Policy", content: config.cookiePolicy || null, defaultPage: "cookies" });
  });
};
