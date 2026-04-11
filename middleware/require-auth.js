var { prefersJson } = require("./require-access");

module.exports = function requireAuth(req, res) {
  if (!req.user) {
    if (prefersJson(req)) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Authentication required." }));
    } else {
      res.redirect("/auth/login");
    }
    return false;
  }
  return true;
};
