var { send } = require("./send");
var audit = require("../lib/audit");
var logger = require("../app/shared/logger");
var { hasScope } = require("../app/security/scope-policy");

/**
 * Admin access guard — works as both:
 *   - 3-arg middleware: app.post("/admin/x", requireAdmin, handler)
 *   - 2-arg inline guard: if (!requireAdmin(req, res)) return;
 * Existing callers continue to work. New routes should prefer the middleware form.
 */
module.exports = function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    if (req.user) {
      audit.log(audit.ACTIONS.ADMIN_ACCESS_DENIED, {
        details: "path: " + req.pathname,
        req: req,
      });
    }
    logger.error("requireAdmin denied", { method: req.method, path: req.pathname, user: req.user ? req.user._id + "/" + req.user.role : "none" });
    send(res, "error", { title: "Forbidden", message: "Admin access required.", user: req.user }, 403);
    if (typeof next === "function") return;
    return false;
  }

  // Block API keys from admin routes unless they have admin scope
  if (req.apiKey) {
    if (!hasScope(req.apiKey, "admin")) {
      audit.log(audit.ACTIONS.ADMIN_ACCESS_DENIED, {
        details: "API key lacks admin scope, path: " + req.pathname,
        req: req,
      });
      send(res, "error", { title: "Forbidden", message: "API key does not have admin access.", user: req.user }, 403);
      if (typeof next === "function") return;
      return false;
    }
  }

  if (typeof next === "function") return next();
  return true;
};
