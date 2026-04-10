module.exports = function requireAuth(req, res) {
  if (!req.user) {
    res.redirect("/auth/login");
    return false;
  }
  return true;
};
