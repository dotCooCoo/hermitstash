var { users } = require("../lib/db");
var audit = require("../lib/audit");

module.exports = function attachUser(req, res, next) {
  if (req.session.userId) {
    var user = users.findOne({ _id: req.session.userId });
    if (user && user.status === "active") {
      req.user = user;
    } else {
      // Suspended or deleted — clear session and log
      audit.log(audit.ACTIONS.SUSPENDED_USER_BLOCKED, {
        targetId: req.session.userId,
        details: user ? "status: " + user.status : "user not found",
        req: req,
      });
      req.user = null;
      delete req.session.userId;
    }
  } else {
    req.user = null;
  }
  next();
};
