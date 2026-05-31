var clientIp = require("../lib/client-ip");
var { blockedIps } = require("../lib/db");
var b = require("../lib/vendor/blamejs");

module.exports = function ipCheck(req, res, next) {
  var ip = clientIp.getIp(req);
  if (ip && blockedIps.findOne({ ip: ip })) {
    return b.problemDetails.send(res, {
      type: "https://hermitstash.com/problems/forbidden",
      title: "Forbidden",
      status: 403,
      detail: "Access denied.",
    });
  }
  next();
};
