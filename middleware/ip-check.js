var { blockedIps } = require("../lib/db");
var rateLimit = require("../lib/rate-limit");

module.exports = function ipCheck(req, res, next) {
  var ip = rateLimit.getIp(req);
  if (ip && blockedIps.findOne({ ip: ip })) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("Access denied");
  }
  next();
};
